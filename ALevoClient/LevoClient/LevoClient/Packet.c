#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Packet.h"
#include "rc4.h"
#include "md5.h"
#include <errno.h>

extern void log_i(char *str);
extern void log_e(char *str,char *i);
extern char errbuf[PCAP_ERRBUF_SIZE];

int send_eth(unsigned short int proto, unsigned short int len) {
	int t = sizeof(struct ETH) + len;
	memcpy(eth->dest, des_addr, 6);
	memcpy(eth->source, src_addr, 6);
	eth->proto = htons(proto);
    t=pcap_sendpacket(adapterHandle, buf, t);
    if (t != 0) {
        log_e("send:", pcap_geterr(adapterHandle));
	}
	return(t);
}

int send_eapol(unsigned char type, unsigned short int len) {
	int t = sizeof(struct EAPOL) + len;
	eapol->ver = 1;
	eapol->type = type;
	eapol->len = htons(len);
	t = send_eth(ETH_P_PAE, t);
	return(t);
}

int send_eap(unsigned char code, unsigned short int len) {
	int t = sizeof(struct EAP) + len;
	eap->code = code;
	eap->len = htons(t);
	t = send_eapol(EAPOL_EAPPACKET, t);
	return(t);
}

int eapol_start() {
	int t;
	status = ZTE_START;
	t = send_eapol(EAPOL_START, 0);
	log_i("EAPOL Start");
	return(t);
}
int eapol_logoff() {
	int t;
	status = ZTE_LOGOFF;
	t = send_eapol(EAPOL_LOGOFF, 0);
	log_i("EAPOL Logoff");
	return(t);
}

int eap_identity() {
	int t;
	log_i("EAP Request Identity");
	t = strlen(strcpy((char *)last, username));
	t = send_eap(EAP_RESPONSE, t);
	log_i("EAP Response Identity");
	return(t);
}
int eap_md5() {
	int t;
	unsigned char tb[PKT_SIZE];
	MD5_CTX context;
	log_i("EAP Request MD5");
	t = 0;
	tb[t++] = eap->id;
	t += strlen(strcat(strcpy((char *)tb + t, password), salt));
	memcpy(tb + t, md5->value, 16);
	t += 16;
	MD5Init(&context);
	MD5Update(&context, tb, t);
	MD5Final(tb + t, &context);
	memcpy(md5->value, tb + t, 16);
	t = sizeof(struct EAP_Md5) + strlen(strcpy((char *)md5->username, username)) - 1;
	t = send_eap(EAP_RESPONSE, t);
	log_i("EAP Response MD5");
	return(t);
}
int eapol_key_rc4() {
	int t;
	unsigned char enckey[] = { 0x02,0x0E,0x05,0x04,0x66,0x40,0x19,0x75,0x06,0x06,0x00,0x16,0xD3,0xF3,0xAC,0x02 };
	unsigned char wholekey[20];
	log_i("EAPOL Request Key RC4");
	t = sizeof(struct EAP_Key) + ntohs(key->keylen) - 16;
	//key
	memcpy(wholekey, key->keyiv, 16);
	memcpy(wholekey + 16, key->rc + 4, 4);
	rc4_crypt(enckey, ntohs(key->keylen), wholekey, 20);
	memcpy(key->key, enckey, ntohs(key->keylen));
	//hash
	memset(key->keysignature, 0, 16);
	hmac_md5((unsigned char *)eapol, sizeof(struct EAPOL) + t, &key->keyindex, 1, wholekey);
	memcpy(key->keysignature, wholekey, 16);
	t = send_eapol(EAPOL_KEY, t);
	log_i("EAPOL Response Key RC4");
	return(t);
}

int get_netlink_status() {
	/*
	struct ifreq ifr;
	struct ethtool_value edata;
	edata.cmd = ETHTOOL_GLINK;
	edata.data = 0;
	memset(&ifr,0, sizeof(struct ifreq));
	strcpy(ifr.ifr_name, dev);
	ifr.ifr_data = (char *)&edata;
	if (ioctl(sockfd, SIOCETHTOOL, &ifr) < 0){
	writelog(LOG_ERR, "ioctl: %s\n", strerror(errno));
	return(0);
	}
	return(edata.data);
	*/
	return 1;
}
int get_packet(u_char *args, const struct pcap_pkthdr *pcaket_header, const u_char *packet)
{
	int t = 1, tag = -1;
	if (packet) {
		memcpy(buf, packet, PKT_SIZE);
	}
	else
		t = 0;
	if (t > 0) {
		if (eth->proto == htons(ETH_P_PAE) && !memcmp(eth->dest, src_addr, 6)) {
			tag = 1;
			switch (eapol->type) {
			case EAPOL_EAPPACKET:
				switch (eap->code) {
				case EAP_REQUEST:
					status = ZTE_LOGNIG;
					switch (eap->type) {
					case EAP_TYPE_IDENTITY:
						eap_identity();
						break;
					case EAP_TYPE_NOTIFICATION:
						log_e("EAP Request Notification :", last);
						break;
					case EAP_TYPE_MD5:
						eap_md5();
						break;
					default:
						log_e("Unknow eap type:", eap->type);
						break;
					}
					break;
				case EAP_SUCCESS:
					status = ZTE_SUCCESS;
					log_i("EAP Success");
					break;
				case EAP_FAILURE:
					status = ZTE_FAILURE;
					last[last[0] + 1] = '\0';
					log_i("EAP Failure");
					log_e("", last + 1);
					break;
				default:
					log_e("Unknow eapol type:", eap->code);
					break;
				}
				break;
			case EAPOL_KEY:
				switch (eap->code) {
				case EAP_KEY_RC4:
					status = ZTE_KEEP;
					eapol_key_rc4();
					break;
				default:
					log_e("Unknow key type:", eap->code);
					break;
				}
				break;
			default:
				log_e("Unknow packet type:", eapol->type);
				break;
			}
		}
	}
	else {
		t = get_netlink_status();
		if (t == 1 && errno == EAGAIN) {
			if (status != EAP_SUCCESS) {
				if (status == EAP_FAILURE) {
					log_i("Timeout,try to reconnection");
				}
				eapol_start();
			}
		}
		else if (t == 0) {
			status = EAP_FAILURE;
			if (tag > 0) {
				log_e("Waiting for link...","");
				tag = 0;
			}
		}
	}
	return status;
}
void initialize(char *username_r, char *password_r, unsigned char *mac, pcap_t *Handle)
{
	des_addr[0] =  0x01 ;
	des_addr[1] =  0x80 ;
	des_addr[2] =  0xc2 ;
	des_addr[3] =  0x00 ;
	des_addr[4] =  0x00 ;
	des_addr[5] =  0x03 ;

	strncpy((char *)src_addr, (char *)mac, 6);
	adapterHandle = Handle;
	username = username_r;
	password = password_r;
}
#ifndef    __Packet_H__
#define  __Packet_H__

//WinPcap
#define MAX_NETCARD 10
#include "pcap.h"
#define HANDLETIMEOUT 10

#define ETHER_ADDR_LEN 6
#define PKT_SIZE 2048
#define salt "zte142052"
#define ETH_P_PAE 0x888e

enum  EAP_STATUS {
    ZTE_START = 1,
    ZTE_LOGNIG = 2,
    ZTE_LOGOFF = 3,
    ZTE_SUCCESS = 4,
    ZTE_FAILURE = 5,
    ZTE_KEEP = 6,
    ZTE_DHCPING = 7,
    ZTE_DHCPED = 8,
};

	enum EAP_Packet {
		EAPOL_EAPPACKET = 0,//认证包标志
		EAPOL_START = 1,
		EAPOL_LOGOFF = 2,
		EAPOL_KEY = 3,//key标志
		EAP_REQUEST = 1,
		EAP_RESPONSE = 2,
		EAP_SUCCESS = 3,
		EAP_FAILURE = 4,
		EAP_TYPE_IDENTITY = 1,
		EAP_TYPE_NOTIFICATION = 2,
		EAP_TYPE_MD5 = 4,
		EAP_KEY_RC4 = 1
	};
	enum EAP_LOG {
		LOG_ERR = 3,  //错误，有通知
		LOG_INFO = 0, //正常，无通知
		LOG_WARNING = 2,  //警告，有通知
		LOG_NOTICE = 1  //正常，有通知
	};
#pragma pack(1)
	struct ETH
	{
		unsigned char dest[6]; //Destination
		unsigned char source[6]; //Source
		unsigned short int proto; //Type
	};

	struct EAPOL
	{
		unsigned char ver; //Version
		unsigned char type; //Type
		unsigned short int len; //Length
	};

	struct EAP
	{
		unsigned char code;//Code
		unsigned char id;//Id
		unsigned short int len; //Length
		unsigned char type; //Type
	};

	struct EAP_Md5
	{
		unsigned char len;//EAP-MD5 Value-Size
		unsigned char value[16];//EAP-MD5 Value
		unsigned char username[1];//Username
	};

	struct EAP_Key
	{
		unsigned char keytype;//Key Descriptor Type
		unsigned short int keylen; //Key Length
		unsigned char rc[8];//Replay Counter
		unsigned char keyiv[16];//Key IV
		unsigned char keyindex;//Key Index
		unsigned char keysignature[16];//Key Signature
		unsigned char key[16];//Key
	};
#pragma pack()
	unsigned char buf[PKT_SIZE], des_addr[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };
	struct ETH *eth = (struct ETH *)buf;
	struct EAPOL *eapol = (struct EAPOL *)(buf + sizeof(struct ETH));
	struct EAP *eap = (struct EAP *)(buf + sizeof(struct ETH) + sizeof(struct EAPOL));
	unsigned char *last = (unsigned char *)(buf + sizeof(struct ETH) + sizeof(struct EAPOL) + sizeof(struct EAP));
	struct EAP_Key *key = (struct EAP_Key *)(buf + sizeof(struct ETH) + sizeof(struct EAPOL));
	struct EAP_Md5 *md5 = (struct EAP_Md5 *)(buf + sizeof(struct ETH) + sizeof(struct EAPOL) + sizeof(struct EAP));
	pcap_t *adapterHandle;//网卡句柄

	int status;
	int send_eth(unsigned short int proto, unsigned short int len);
	int send_eapol(unsigned char type, unsigned short int len);
	int send_eap(unsigned char code, unsigned short int len);
	int eapol_start();
	int eapol_logoff();
	int eap_identity();
	int eap_md5();
	int eapol_key_rc4();
	int get_netlink_status();
	void get_packet(u_char *args, const struct pcap_pkthdr *pcaket_header, const u_char *packet);
	void initialize(char *username_r, char *password_r, unsigned char *mac, pcap_t *Handle);

#endif
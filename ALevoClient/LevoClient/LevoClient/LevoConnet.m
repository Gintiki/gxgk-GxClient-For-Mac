//
//  Zlevo.m
//  MZlevoclient
//
//  Created by iBcker on 13-5-8.
//  Copyright (c) 2013年 iBcker. All rights reserved.
//

#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <net/if_dl.h>

#import "LevoConnet.h"
#import "PreferencesModel.h"

#import <stdio.h>
#import <stdlib.h>
#import <stdint.h>

#import <string.h>
#import <ctype.h>
#import <errno.h>

#import <sys/types.h>
#import <sys/socket.h>
#import <sys/ioctl.h>
#import <sys/stat.h>

#import <netinet/in.h>
#import <arpa/inet.h>
#import <net/if.h>
#import <net/ethernet.h>

//------bsd/apple mac
#import <net/if_var.h>
#import <net/if_dl.h>
#import <net/if_types.h>

#import <getopt.h>
#import <iconv.h>
#import <signal.h>
#import <unistd.h>
#import <fcntl.h>
#import <assert.h>

#import "Packet.h"

int bsd_get_mac(const char ifname[], uint8_t eth_addr[]);

/* ZlevoClient Version */
#define LENOVO_VER "1.0"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

#define LOCKFILE "/var/run/aLevoClient.pid"

#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

PreferencesModel *config;

void(^ConnetSucessBlock)(void);
void(^ConnetFailBlock)(void);

struct follow {
    uint32_t	inBytes;	//进包
    uint32_t 	outBytes;	//出包
    struct timeval time ;
};

//网卡指针
pcap_t *handle = NULL;
int lockfile;
char errbuf[PCAP_ERRBUF_SIZE];
char *dev = NULL;   /* 连接的设备名 */
char dev_if_name[64];
int         exit_flag = 0;

int         username_length;
int         password_length;
u_int       local_ip = 0;
u_char      local_mac[ETHER_ADDR_LEN]; /* MAC地址 */

@implementation LevoConnet

IMP_SINGLETON(LevoConnet)


- (id)init
{
    if(self=[super init]){
        config=[PreferencesModel sharedInstance];
    }
    return self;
}

void init_info()
{
    if(username == NULL || password == NULL){
        fprintf (stderr,"Error: NO Username or Password promoted.\n"
                 "Try zlevoclient --help for usage.\n");
        [[PreferencesModel sharedInstance] pushErrorLog:@"Error :用户名或密码读取错误"];
    }
    username_length = (int)strlen(username);
    password_length = (int)strlen(password);
    
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  init_device
 *  Description:  初始化设备。主要是找到打开网卡、获取网卡MAC、IP，
 *  同时设置pcap的初始化工作句柄。
 * =====================================================================================
 */
void init_device()
{
    struct          bpf_program fp;			/* compiled filter program (expression) */
    char            filter_exp[51];         /* filter expression [3] */
    pcap_if_t       *alldevs,*alldevsp,*alldevsp2;
    pcap_addr_t     *addrs;
    
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        [[PreferencesModel sharedInstance] pushErrorLog:@"Error: in pcap_findalldevs"];
        //		exit(1);
	}
    
    /* 使用第一块设备 */
    dev=NULL;
    alldevsp=alldevs;
    alldevsp2=alldevs;
    if ([PreferencesModel sharedInstance].Device.length>0) {
        while (alldevsp&&alldevsp->name) {
            if ([[NSString stringWithUTF8String:alldevsp->name] isEqualToString:[PreferencesModel sharedInstance].Device]) {
                dev=alldevsp->name;
                break;
            }
            alldevsp=alldevsp->next;
        }
    }
    if(dev == NULL) {
        while (alldevsp2) {
            if (alldevsp2->name) {
                dev = alldevsp2->name;
                [PreferencesModel sharedInstance].Device=[NSString stringWithUTF8String:dev];
                break;
            }
            alldevsp2=alldevsp2->next;
        }
    }
    strcpy (dev_if_name, dev);
    
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n",
                errbuf);
        [[PreferencesModel sharedInstance] pushErrorLog:@"Error: Couldn't find the device"];
//		exit(EXIT_FAILURE);
    }
	
	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        [[PreferencesModel sharedInstance] pushErrorLog:[NSString stringWithFormat:@"Error: Couldn't open device %s",dev]];
//		exit(EXIT_FAILURE);
	}
    
	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
        [[PreferencesModel sharedInstance] pushErrorLog:[NSString stringWithFormat:@"Error:网卡%s无效",dev]];
        return;
//		exit(EXIT_FAILURE);
	}
    
    /* Get IP ADDR and MASK */
    for (addrs = alldevs->addresses; addrs; addrs=addrs->next) {
        if (addrs->addr->sa_family == AF_INET) {
            local_ip = ((struct sockaddr_in *)addrs->addr)->sin_addr.s_addr;
        }
    }
    

    if (bsd_get_mac (dev, local_mac) != 0) {
		fprintf(stderr, "FATIL: Fail getting BSD/MACOS Mac Address.\n");
        [[PreferencesModel sharedInstance] pushErrorLog:@"Error: 读取mac地址错误"];
//		exit(EXIT_FAILURE);
    }
    
    /* construct the filter string */
    sprintf(filter_exp, "ether dst %02x:%02x:%02x:%02x:%02x:%02x"
            " and ether proto 0x888e",
            local_mac[0], local_mac[1],
            local_mac[2], local_mac[3],
            local_mac[4], local_mac[5]);
    
	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        [[PreferencesModel sharedInstance] pushErrorLog:[NSString stringWithFormat:@"Error: Couldn't parse filter %s: %s",filter_exp, pcap_geterr(handle)]];
//		exit(EXIT_FAILURE);
	}
    
	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        [[PreferencesModel sharedInstance] pushErrorLog:[NSString stringWithFormat:@"Error: Couldn't install filter %s: %s",filter_exp, pcap_geterr(handle)]];
//		exit(EXIT_FAILURE);
	}
    pcap_freecode(&fp);
    pcap_freealldevs(alldevs);
}

static void
signal_interrupted (int signo)
{
    fprintf(stdout,"\n&&Info: USER Interrupted. \n");
    eapol_logoff();
    if (handle) {
        pcap_breakloop (handle);
        pcap_close (handle);
        handle=NULL;
    }
//    exit (EXIT_FAILURE);
}

void
flock_reg ()
{
    char buf[16];
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;
    fl.l_pid = getpid();
    
    //阻塞式的加锁
    if (fcntl (lockfile, F_SETLKW, &fl) < 0){
        perror ("fcntl_reg");
        [[PreferencesModel sharedInstance] pushErrorLog:@"Error: Can't lock file"];
//        exit(EXIT_FAILURE);
    }
    
    //把pid写入锁文件
    assert (0 == ftruncate (lockfile, 0) );
    sprintf (buf, "%ld", (long)getpid());
    assert (-1 != write (lockfile, buf, strlen(buf) + 1));
}

int
program_running_check()
{
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;
    
    //尝试获得文件锁
    if (fcntl (lockfile, F_GETLK, &fl) < 0){
        perror ("fcntl_get");
        [[PreferencesModel sharedInstance] pushErrorLog:@"Error: Can't get lock lock"];
//        exit(EXIT_FAILURE);
    }
    
    if (exit_flag) {
        if (fl.l_type != F_UNLCK) {
            if ( kill (fl.l_pid, SIGINT) == -1 )
                perror("kill");
            fprintf (stdout, "&&Info: Kill Signal Sent to PID %d.\n", fl.l_pid);
        }
        else
            fprintf (stderr, "&&Info: NO zLenovoClient Running.\n");
        [[PreferencesModel sharedInstance] pushErrorLog:@"Error: One Client Already Running"];
//        exit (EXIT_FAILURE);
    }
    
    
    //没有锁，则给文件加锁，否则返回锁着文件的进程pid
    if (fl.l_type == F_UNLCK) {
        flock_reg ();
        return 0;
    }
    
    return fl.l_pid;
}

-(BOOL)isRunningCheck
{
    //打开锁文件
    lockfile = open (LOCKFILE, O_RDWR | O_CREAT , LOCKMODE);
    if (lockfile < 0){
        [[PreferencesModel sharedInstance] pushErrorLog:@"Error: Lockfile error"];
        perror ("Lockfile");
        return YES;
    }
    int ins_pid;
    if ( (ins_pid = program_running_check ()) ) {
        fprintf(stderr,"@@ERROR: ZLevoClient Already "
                "Running with PID %d\n", ins_pid);
        [[PreferencesModel sharedInstance] pushErrorLog:@"Error: One Client Already Running"];
        return YES;
    }
    return NO;
}

- (void)initEnvironment
{
    username = (char *)[[PreferencesModel sharedInstance].UserName cStringUsingEncoding:NSUTF8StringEncoding];
    password = (char *)[[PreferencesModel sharedInstance].UserPwd cStringUsingEncoding:NSUTF8StringEncoding];
    dev=NULL;
    init_info();
    init_device();
    initialize(username, password, local_mac, handle);
}


- (void)connetNeedInit:(BOOL)init sucess:(void(^)(void))sucess andFail:(void(^)(void))fail
{
    ConnetSucessBlock=[sucess copy];
    ConnetFailBlock=[fail copy];

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        if (!handle) {
            [self initEnvironment];
        }
        eapol_start();
        pcap_loop (handle, -1, get_packet, NULL);   /* main loop */
        NSLog(@">>>>>>>pcap_loop--");
//        pcap_close (handle);
//        handle=NULL;
        ConnetSucessBlock=nil;
        ConnetFailBlock=nil;
        dispatch_async(dispatch_get_main_queue(), ^{
           fail();
        });
    });
}

- (void)cancle
{
    NSLog(@">>>>>>>cancle");
    if (handle) {
        pcap_breakloop(handle);
        NSLog(@">>>>>>>pcap_breakloop");
    }
}

- (void)cancleWithcloseHandle
{
    [self cancle];
    pcap_close (handle);
    handle=NULL;
}

-(void)checkOnline:(void(^)(BOOL online))onLine
{
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        if ([self PingHost:(char *)[[[PreferencesModel sharedInstance] CheckOfflineHost] UTF8String]]||[self PingHost:CheckOfflineHost1]||[self PingHost:CheckOfflineHost2]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                onLine(YES);
            });
        }else{
            dispatch_async(dispatch_get_main_queue(), ^{
                onLine(NO);
            });
        }        
    });
}

- (BOOL)PingHost:(char *)ip
{
    if (!ip) {
        return NO;
    }
    char sh[100]="ping -c 1 -W 500 ";
    strcat(sh,ip);
    if (0==system(sh)||0==system(sh)||0==system(sh)) {
        return YES;
    }
    return NO;
}

void executeSystem(const char *cmd, char *result)
{
    char buf_ps[1024];
    char ps[1024]={0};
    FILE *ptr;
    strcpy(ps, cmd);
    if((ptr=popen(ps, "r"))!=NULL)
    {
        while(fgets(buf_ps, 1024, ptr)!=NULL)
        {
            strcat(result, buf_ps);
            if(strlen(result)>=1024)
                break;
        }
        pclose(ptr);
        ptr = NULL;
    }
    else
    {
        printf("error\n");
    }
}


int bsd_get_mac(const char ifname[], uint8_t eth_addr[])
{
    struct ifreq *ifrp;
    struct ifconf ifc;
    char buffer[720];
    int socketfd,error,len,space=0;
    ifc.ifc_len=sizeof(buffer);
    len=ifc.ifc_len;
    ifc.ifc_buf=buffer;
    
    socketfd=socket(AF_INET,SOCK_DGRAM,0);
    
    if((error=ioctl(socketfd,SIOCGIFCONF,&ifc))<0)
    {
        perror("ioctl faild");
//        exit(1);
        return 1;
    }
    if(ifc.ifc_len<=len)
    {
        ifrp=ifc.ifc_req;
        do
        {
            struct sockaddr *sa=&ifrp->ifr_addr;
            
            if(((struct sockaddr_dl *)sa)->sdl_type==IFT_ETHER) {
                if (strcmp(ifname, ifrp->ifr_name) == 0){
                    memcpy (eth_addr, LLADDR((struct sockaddr_dl *)&ifrp->ifr_addr), 6);
                    return 0;
                }
            }
            ifrp=(struct ifreq*)(sa->sa_len+(caddr_t)&ifrp->ifr_addr);
            space+=(int)sa->sa_len+sizeof(ifrp->ifr_name);
        }
        while(space<ifc.ifc_len);
    }
    return 1;
}



- (NSArray *)readDeviceList
{
    pcap_if_t       *alldevs;
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, NULL) == -1)
	{
        return  nil;
	}
    NSMutableArray *arr=[[NSMutableArray alloc] initWithCapacity:8];
    while (alldevs&&alldevs->name) {
        [arr addObject:[NSString stringWithUTF8String:alldevs->name]];
        alldevs=alldevs->next;
    }
    return  (NSArray*)arr;
}

- (NSString *)readIpString
{
    return [self getIpString:[self selectedDev]];
}

- (NSString *)selectedDevName
{
    pcap_if_t *dev=[self selectedDev];
    if (dev&&dev->name) {
        return [NSString stringWithUTF8String:dev->name];
    }else{
        return nil;
    }
}

static pcap_if_t *alldevices;

- (pcap_if_t *)selectedDev
{
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevices, NULL) != -1)
	{
//        alldevices=NULL;
        pcap_if_t *palldevices=alldevices;
        if ([PreferencesModel sharedInstance].Device.length>0) {
            while (alldevices&&alldevices->name) {
                if ([[NSString stringWithUTF8String:alldevices->name] isEqualToString:[PreferencesModel sharedInstance].Device]) {
                    return alldevices;
                }
                alldevices=alldevices->next;
            }
        }
        if (palldevices&&palldevices->name) {
            [PreferencesModel sharedInstance].Device=[NSString stringWithUTF8String:palldevices->name];
            return palldevices;
        }else{
            [PreferencesModel sharedInstance].Device=@"";
            return NULL;
        }
    }
    return NULL;
}

- (NSString *)getIpString:(pcap_if_t *)alldevs
{
    if (alldevs&&alldevs->addresses) {
        pcap_addr_t     *addrs;
        /* Get IP ADDR and MASK */
        for (addrs = alldevs->addresses; addrs; addrs=addrs->next) {
            if (addrs->addr->sa_family == AF_INET) {
                u_int _ip = ((struct sockaddr_in *)addrs->addr)->sin_addr.s_addr;
                return [NSString stringWithUTF8String:inet_ntoa(*(struct in_addr*)&_ip)];
            }
        }
    }
    return @"0.0.0.0";
}

- (NSString *)readMacAddress
{
    u_char   mac_addr[ETHER_ADDR_LEN]; /* MAC地址 */
    pcap_if_t *_dev=[self selectedDev];
    if (_dev&&_dev->name) {
        if (bsd_get_mac (_dev->name, mac_addr) == 0) {
            /* construct the filter string */
            return [NSString stringWithFormat:@"%02x:%02x:%02x:%02x:%02x:%02x",mac_addr[0],mac_addr[1],mac_addr[2], mac_addr[3],mac_addr[4], mac_addr[5]];
        }
    }
    return @"";
}

- (NSString *)getGateWay
{
    char result[1024];
    executeSystem( "route -n get default|egrep gateway:|sed 's/.*gateway/gateway/'", result);
    printf("%s", result );
    char *p=&result[0];
    while ((char)p[0]!='g'&&(char)p[1]!='a'&&(char)p[2]!='t') {
        p++;
    }
    
    NSString *res=[NSString stringWithFormat:@"%s",p];
    NSRange range=[res rangeOfString:@"gateway:"];
    if (range.location==0) {
        NSString *gateway=[res substringFromIndex:range.location+range.length];
        return [gateway stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    }
    return @"";
}

-(void)getKbps:(int)sec speed:(void(^)(float upSpeed,float downSpeed))update
{
    dispatch_async(dispatch_get_main_queue(), ^{
        char *dev=[self selectedDev]->name;
        char *dev2=dev;
        struct follow f1;
        f1.inBytes=0;
        f1.outBytes=0;
        [self checkNetworkflow:dev f:&f1];
        [self performBlockInBackground:^{
            struct follow f2;
            f2.inBytes=0;
            f2.outBytes=0;
            [self checkNetworkflow:dev2 f:&f2];
            uint32_t up=f2.outBytes-f1.outBytes;
            uint32_t down=f2.inBytes-f1.inBytes;
            uint32_t usec=f2.time.tv_usec-f1.time.tv_usec;
            float sup=up*1.0/usec;
            float sdown=down*1.0/usec;
            update(sup,sdown);
        } afterDelay:1];
    });
}

-(void)checkNetworkflow:(char *)dev f:(struct follow *)_fcount
{
    struct ifaddrs *ifa_list = 0, *ifa;
    if (getifaddrs(&ifa_list) == -1)
    {
        return;
    }
    struct follow *fcount=_fcount;
    fcount->inBytes=0;
    fcount->outBytes=0;
    gettimeofday(&(fcount->time), NULL);
    
    for (ifa = ifa_list; ifa; ifa = ifa->ifa_next)
    {
        if (AF_LINK != ifa->ifa_addr->sa_family)continue;
        if (!(ifa->ifa_flags & IFF_UP) && !(ifa->ifa_flags & IFF_RUNNING))continue;
        if (ifa->ifa_data == 0)continue;
        if (strcmp(ifa->ifa_name,dev)) {
            struct if_data *if_data = (struct if_data *)ifa->ifa_data;
            fcount->inBytes += if_data->ifi_ibytes;
            fcount->outBytes += if_data->ifi_obytes;
        }
    }
    freeifaddrs(ifa_list);
}

@end

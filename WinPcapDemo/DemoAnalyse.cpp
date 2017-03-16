#include "demo.h"
#include "Protocols.h"

int main() {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	//char source[PCAP_ERRBUF_SIZE + 1];
	u_int netmask;
	char packet_filter[] = "ip and udp";
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

	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL) {
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	} else {
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;
	}

	//���������
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//���������
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;

	}

	printf("\nlistening on %s...\n", d->description);

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	/* ��ʼ���� */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 1;
}

/* ÿ�β������ݰ�ʱ��libpcap�����Զ���������ص����� */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	struct tm * ltime;
	char timestr[16];
	time_t local_tv_sec;
	IpHeader  *ih;
	UdpHeader *uh;
	u_int ipLen;
	u_short nSrcPort, nDstPort;

	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

	/* ���IP���ݰ�ͷ����λ�� */
	ih = (IpHeader *)(pkt_data + 
		14); //��̫��ͷ������

	/* ���UDP�ײ���λ�� */
	ipLen = (ih->nVerHl & 0xf) * 4;
	uh = (UdpHeader *)((u_char *)ih + ipLen);

	/* ��ӡIP Header */
	/*
	printf("%d %d %d\n", ih->nVerHl, ih->nTos, ih->nTotalLen);
	printf("%d %d\n", ih->nIdent, ih->nFragOff, ih->nTotalLen);
	printf("%d %d %d\n", ih->nTtl, ih->nProtocol, ih->nCrc);
	printf("%d.%d.%d.%d\n",
			ih->sSrcIp.byte1,
			ih->sSrcIp.byte2,
			ih->sSrcIp.byte3,
			ih->sSrcIp.byte4);	
	printf("%d.%d.%d.%d\n",
			ih->sDstIp.byte1,
			ih->sDstIp.byte2,
			ih->sDstIp.byte3,
			ih->sDstIp.byte4);
	*/

	/* �������ֽ�����ת���������ֽ����� */
	nSrcPort = ntohs(uh->nSrcPort);
	nDstPort = ntohs(uh->nDstPort);

	/* ��ӡIP��ַ��UDP�˿� */
	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
		ih->sSrcIp.byte1,
		ih->sSrcIp.byte2,
		ih->sSrcIp.byte3,
		ih->sSrcIp.byte4,
		nSrcPort,
		ih->sDstIp.byte1,
		ih->sDstIp.byte2,
		ih->sDstIp.byte3,
		ih->sDstIp.byte4,
		nDstPort);
}

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


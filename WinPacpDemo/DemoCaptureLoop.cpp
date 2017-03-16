#include "demo.h"

int main() {

	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
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

	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
	
	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
}

#include "demo.h"
#include "Protocols.h"

int main(int argc, char **argv) {
	pcap_t *fp;
	char * fileStr = "dumpfile.libpcap";
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	char source[PCAP_ERRBUF_SIZE + 1];


	if (argc != 2) {
		printf("usage: %s filename", argv[0]);
		return -1;

	}

	/* ������WinPcap�﷨����һ��Դ�ַ��� */
	if (pcap_createsrcstr(source, // Դ�ַ���
		PCAP_SRC_FILE,  // ����Ҫ�򿪵��ļ�
		NULL,           // Զ������
		NULL,			// Զ�������˿�
		fileStr,        // ����Ҫ�򿪵��ļ���
		errbuf          // ���󻺳���
		) != 0) {
		fprintf(stderr, "\nError creating a source string\n");
		return -1;
	}

	/* ���豸 */
	if ((fp = pcap_open(source,          // �豸��
		65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ�� see more(F12 in VS)
		1000,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
		)) == NULL) {
		fprintf(stderr, "\nUnable to open the file %s.\n", source);
		return -1;
	}

	// ��ȡ���������ݰ���ֱ��EOFΪ��
	pcap_loop(fp, 0, dispatcher_handler, NULL);

	return 0;
}

#define LINE_LEN 16
void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	u_int i = 0;

	/* ��ӡpktʱ�����pkt���� */
	printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

	/* ��ӡ���ݰ� */
	for (i = 1; (i < header->caplen + 1); i++)
	{
		printf("%.2x ", pkt_data[i - 1]);
		if ((i % LINE_LEN) == 0) printf("\n");
	}

	printf("\n\n");

}

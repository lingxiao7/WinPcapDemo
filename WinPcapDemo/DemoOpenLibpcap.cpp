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

	/* 根据新WinPcap语法创建一个源字符串 */
	if (pcap_createsrcstr(source, // 源字符串
		PCAP_SRC_FILE,  // 我们要打开的文件
		NULL,           // 远程主机
		NULL,			// 远程主机端口
		fileStr,        // 我们要打开的文件名
		errbuf          // 错误缓冲区
		) != 0) {
		fprintf(stderr, "\nError creating a source string\n");
		return -1;
	}

	/* 打开设备 */
	if ((fp = pcap_open(source,          // 设备名
		65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式。 see more(F12 in VS)
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
		)) == NULL) {
		fprintf(stderr, "\nUnable to open the file %s.\n", source);
		return -1;
	}

	// 读取并解析数据包，直到EOF为真
	pcap_loop(fp, 0, dispatcher_handler, NULL);

	return 0;
}

#define LINE_LEN 16
void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	u_int i = 0;

	/* 打印pkt时间戳和pkt长度 */
	printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

	/* 打印数据包 */
	for (i = 1; (i < header->caplen + 1); i++)
	{
		printf("%.2x ", pkt_data[i - 1]);
		if ((i % LINE_LEN) == 0) printf("\n");
	}

	printf("\n\n");

}

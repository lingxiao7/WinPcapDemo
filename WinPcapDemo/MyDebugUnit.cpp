//#if 0
#define _CRT_SECURE_NO_DEPRECATE
#include "pcap.h"
//#include <winsock2.h>
#include <IPHlpApi.h>
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib,"wpcap")
#pragma comment(lib,"ws2_32")
//=========���ݰ��ṹ����========================
typedef struct IP_Address //32λ��IP��ַ
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;

}ip_address;


typedef struct Hard_Mac //48λ��MAC��ַ
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}Hard_Mac;

/* Ethernet header */
typedef struct Ethernet_Header //112λ 48λSMac+48λSMac+16λЭ������ ��̫��ͷ
{
	Hard_Mac DMac; //(1)48λĿMAC��ַ
	Hard_Mac SMac; //(2)48λԴMAC��ַ
	WORD PType; //(3)16λЭ������
}Ethernet_Header;
typedef struct ARP_Header //����ARP�ײ�
{
	Ethernet_Header FrameHeader;//֡ͷ
	WORD HardWare; //(4)16λ����Ӳ������
	WORD PType3; //(5)16λЭ������
	u_char HLeng; //(6)8λӲ����ַ����
	u_char PLeng; //(7)16λЭ���ַ����
	WORD Oper; //(8)16λ����ѡ��
	Hard_Mac SMac3; //(9)48λԴMAC��ַ
	ip_address Saddr; //(10)32λԴIP��ַ
	Hard_Mac DMac3; //(11)48λĿ��MAC��ַ
	ip_address Daddr; //(12)32λĿ��IP��ַ
	BYTE      padding[18]; //���0
}ARP_Header;

//=====================================================================
//���APR���ݰ�
//======================================================================
ARP_Header filtpacket(char ip[4 * 4])
{
	int j = 0;
	for (int i = 0; i < sizeof(ip); i++) {
		if (ip[i] == '.') {
			//char myip = strcat(ip[j],ip[]);
		}
	}
	ARP_Header ARPH; //���͵�ARP���ṹ
					 //�ȳ�ʼ������ARP��MAC��ַ


	ARPH.DMac3.byte1 = 0xD0; ARPH.DMac3.byte2 = 0x67; ARPH.DMac3.byte3 = 0xE5;
	ARPH.DMac3.byte4 = 0x21; ARPH.DMac3.byte5 = 0xA4; ARPH.DMac3.byte6 = 0x1C; //Ŀ��MAC��ַ
																			   //ARPH.DMac3.byte1 = 0x00; ARPH.DMac3.byte2 = 0x0f; ARPH.DMac3.byte3 = 0xe2;
																			   //ARPH.DMac3.byte4 = 0x80; ARPH.DMac3.byte5 = 0xb8; ARPH.DMac3.byte6 = 0x2d;  //Ŀ��MAC��ַ

	ARPH.SMac3.byte1 = 0xD0; ARPH.SMac3.byte2 = 0x67; ARPH.SMac3.byte3 = 0xE5;
	ARPH.SMac3.byte4 = 0x21; ARPH.SMac3.byte5 = 0x9C; ARPH.SMac3.byte6 = 0x8E; //ԴMAC��ַ
																			   //ARPH.SMac3.byte1 = 0xD0; ARPH.SMac3.byte2 = 0x67; ARPH.SMac3.byte3 = 0xE5;
																			   //ARPH.SMac3.byte4 = 0x21; ARPH.SMac3.byte5 = 0xA4; ARPH.SMac3.byte6 = 0x1C; //ԴMAC��ַ

	ARPH.FrameHeader.SMac.byte1 = 0xD0; ARPH.FrameHeader.SMac.byte2 = 0x67; ARPH.FrameHeader.SMac.byte3 = 0xE5;
	ARPH.FrameHeader.SMac.byte4 = 0x21; ARPH.FrameHeader.SMac.byte5 = 0x9C; ARPH.FrameHeader.SMac.byte6 = 0x8E; //ԴMAC��ַ
																												//ARPH.FrameHeader.SMac.byte1 = 0xD0; ARPH.FrameHeader.SMac.byte2 = 0x67; ARPH.FrameHeader.SMac.byte3 = 0xE5;
																												//ARPH.FrameHeader.SMac.byte4 = 0x21; ARPH.FrameHeader.SMac.byte5 = 0xA4; ARPH.FrameHeader.SMac.byte6 = 0x1C; //ԴMAC��ַ
																												//ARPH.FrameHeader.DMac.byte1 = 0xD0; ARPH.FrameHeader.DMac.byte2 = 0x67; ARPH.FrameHeader.DMac.byte3 = 0xE5;
																												//ARPH.FrameHeader.DMac.byte4 = 0x21; ARPH.FrameHeader.DMac.byte5 = 0xA4; ARPH.FrameHeader.DMac.byte6 = 0x1C; //Ŀ��MAC��ַ
																												//ARPH.FrameHeader.DMac.byte1 = 0x00; ARPH.FrameHeader.DMac.byte2 = 0x0f; ARPH.FrameHeader.DMac.byte3 = 0xe2;
																												//ARPH.FrameHeader.DMac.byte4 = 0x80; ARPH.FrameHeader.DMac.byte5 = 0xb8; ARPH.FrameHeader.DMac.byte6 = 0x2d;   //Ŀ��MAC��ַ


	ARPH.FrameHeader.DMac.byte1 = 0xff; ARPH.FrameHeader.DMac.byte2 = 0xff; ARPH.FrameHeader.DMac.byte3 = 0xff;
	ARPH.FrameHeader.DMac.byte4 = 0xff; ARPH.FrameHeader.DMac.byte5 = 0xff; ARPH.FrameHeader.DMac.byte6 = 0xff;
	ARPH.FrameHeader.PType = htons(0x0806);//Э������ΪARP

	ARPH.HardWare = htons(0x0001);//10M Ethernet

	ARPH.PType3 = htons(0x0800);//Э������ΪIP

	ARPH.HLeng = 6; //Ӳ����ַ����

	ARPH.PLeng = 4; //IP��ַ����

	ARPH.Oper = htons(0x0002); //�������
							   //hostent myhost;
							   //myhost = gethostbyname();

							   //ARPH.Daddr.byte1 = 10; ARPH.Daddr.byte2 = 3; ARPH.Daddr.byte3 = 130; ARPH.Daddr.byte4 = 227; //Ŀ��IP��ַ
							   //ARPH.Daddr.byte1 = 10; ARPH.Daddr.byte2 = 3; ARPH.Daddr.byte3 = 130; ARPH.Daddr.byte4 = 227; //Ŀ��IP��ַ

	ARPH.Saddr.byte1 = 10; ARPH.Saddr.byte2 = 3; ARPH.Saddr.byte3 = 128; ARPH.Saddr.byte4 = 1; //ԴIP��ַ
	ARPH.Daddr.byte1 = 0; ARPH.Daddr.byte2 = 0; ARPH.Daddr.byte3 = 0; ARPH.Daddr.byte4 = 0; //Ŀ��IP��ַ
	int i;
	for (i = 0; i<18; i++)
	{
		ARPH.padding[i] = 0;
	}
	return ARPH;
};
//==========================================================
//�������ݰ�
//==========================================================
void SendPacket(pcap_t *adhandle, ARP_Header ARPH)
{
	//const u_char *Buff;
	//Buff = &ARPH.FrameHeader.DMac.byte1 ; //�ṹ�׵�ַ����Buff

	if (pcap_sendpacket(adhandle, // Adapter
		(u_char *)&ARPH, // buffer with the packet
		sizeof(ARPH)// size
		) != 0)
	{
		printf("�������ݰ�ʧ��\n");
	}
	//else
	//printf("�������ݰ��ɹ���\n");
}
//=======================================================
//�������ݰ�
//=======================================================
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	//struct tm *ltime;
	//char timestr[16];  

	/* convert the timestamp to readable format */
	// ltime=localtime(&header->ts.tv_sec);
	//strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* print timestamp and length of the packet */
	//printf("%s.%.6d len:%d \n", timestr, header->ts.tv_usec, header->len);

	ARP_Header *ah;

	ah = (ARP_Header *)(pkt_data);

	if (1//ah->FrameHeader.PType == 1544 //&&
		 /*ah->Oper == 512 &&
		 ah->Daddr.byte1 == 172 &&
		 ah->Daddr.byte2 == 18 &&
		 ah->Daddr.byte3 == 19 &&
		 ah->Daddr.byte4 == 116
		 && ah->Saddr.byte1 == 172 &&
		 ah->Saddr.byte2 == 18 &&
		 ah->Saddr.byte3 == 19 &&
		 ah->Saddr.byte4 == 103*/
		)
	{
		/*���ԴIP��ַ��Ŀ��IP��ַ*/
		printf("\n%d.%d.%d.%d-> %d.%d.%d.%d\n",
			ah->Saddr.byte1,
			ah->Saddr.byte2,
			ah->Saddr.byte3,
			ah->Saddr.byte4,
			ah->Daddr.byte1,
			ah->Daddr.byte2,
			ah->Daddr.byte3,
			ah->Daddr.byte4);
		/*���Ŀ�ĵ�ַ�����Դ��ַ������Э������*/
		Hard_Mac SMAC, DMAC;
		Ethernet_Header *eh;
		eh = (Ethernet_Header*)pkt_data;
		SMAC = eh->SMac;
		printf("Դ��ַ %.2x--%.2x--%.2x--%.2x--%.2x--%.2x\n"
			, SMAC.byte1, SMAC.byte2, SMAC.byte3, SMAC.byte4, SMAC.byte5, SMAC.byte6);
		// printf("Դ��ַ %.2x--%.2x--%.2x--%.2x--%.2x--%.2x\n"
		//       ,ah->FrameHeader.SMac.byte1,ah->FrameHeader.SMac.byte2,ah->FrameHeader.SMac.byte3,ah->FrameHeader.SMac.byte4,ah->FrameHeader.SMac.byte5,ah->FrameHeader.SMac.byte6);
		DMAC = eh->DMac;
		printf("Ŀ�ĵ�ַ %.2x--%.2x--%.2x--%.2x--%.2x--%.2x\n"
			, DMAC.byte1, DMAC.byte2, DMAC.byte3, DMAC.byte4, DMAC.byte5, DMAC.byte6);
		printf("֡Э�� %.4x\n", ntohs(eh->PType));
		printf("Ӳ������%.4x\n", ntohs(ah->HardWare));
		printf("Э������%.4x\n", ntohs(ah->PType3));
		printf("��������%.4x\n", ntohs(ah->Oper));
		printf("��������%x\n", ah->padding);
		printf("\n\n==============================================================\n");
	}
}
int main()
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;                                     //��ѯ��������������������Ϣ   mac���򽻻�������arp������ȡ
	pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
	}
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
	{
		pAdapter = pAdapterInfo;
	}
	printf("IP��ַ��%s\n", pAdapter->IpAddressList.IpAddress.String);
	//������
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char packet_filter[] = "arp";
	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name, // name of the device
		65536,   // portion of the packet to capture.  
				 // 65536 grants that the whole packet will be captured on  all the MACs.
		1,       // promiscuous mode
		1000,     // read timeout
		errbuf   // error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	/*  if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
	fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
	Free the device list
	pcap_freealldevs(alldevs);
	return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */

	//

	while (9)
	{
		SendPacket(adhandle, filtpacket(pAdapter->IpAddressList.IpAddress.String));
		//Sleep(20);
	}
	//pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;


}
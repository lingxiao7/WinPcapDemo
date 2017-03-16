#ifndef _PROTOCOLS_H
#define _PROTOCOLS_H

#include "pcap.h"

#pragma pack(1)

/* 0.0.0.0 */
/* IP Address Struct */
typedef struct IpAddr
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}IpAddr;

/* 00.00.00.00.00.00 */
/* MAC Address Struct */
struct MacAddr
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
};

/*                                         Ethernet_II
|---------------------------------------------------------------------------------------------|
|        |         6         |         6         |  2  |............|            4            |
|Preamble|Destination Address|    Source Address |EType|FFFF(<=1500)|Frame Check Sequence(CRC)|
|---------------------------------------------------------------------------------------------|
*/
/* EthernetHeader Struct */
struct EthernetHeader
{
	MacAddr sDstMac;		// Ŀ��MAC��ַ
	MacAddr sSrcMac;		// ԴMAC��ַ
	u_short nEthType;		// ����֡����
};

/*     Internet Protocol(IPv4) over Ethernet ARP packet
|------------------------------------------------------------------|
| 0 |                    Hardware type(HTYPE)                      |
| 2 |                    Protocol type(PTYPE)                      |
| 4 | Hardware address length(HLEN)	Protocol address length(PLEN)  |
| 6 |                       Operation(OPER)                        |
| 8 |                Sender hardware address(SHA)                  |
|14 |                Sender protocol address(SPA)                  |
|18 |                Target hardware address(THA)                  |
|24 |                Target protocol address(TPA)                  |
|------------------------------------------------------------------|
*/
/* ArpHeader Struct */
struct ArpHeader
{
	u_short nHardType;		// Ӳ������		(Headware type)
	u_short nProtoType;		// Э������		(Protocol type)
	u_char  nMacLen;		// Ӳ����ַ���� (Hardware address length)
	u_char  nProtoLen;		// Э���ַ���� (Protocol address length)
	u_short nOpCode;		// ��������		(Operation)
	MacAddr sSrcMac;		// ԴMAC��ַ	(Sender hardware address)
	IpAddr  sSrcIp;			// ԴIP��ַ		(Sender protocol address)
	MacAddr sDstMac;		// Ŀ��MAC��ַ	(Target hardware address)
	IpAddr  sDstIp;			// Ŀ��IP��ַ	(Target protocol address)
};

/*EArpHeader Struct */
struct EArpHeader
{
	EthernetHeader FrameHeader;
	u_short nHardType;		// Ӳ������		(Headware type)
	u_short nProtoType;		// Э������		(Protocol type)
	u_char  nMacLen;		// Ӳ����ַ���� (Hardware address length)
	u_char  nProtoLen;		// Э���ַ���� (Protocol address length)
	u_short nOpCode;		// ��������		(Operation)
	MacAddr sSrcMac;		// ԴMAC��ַ	(Sender hardware address)
	IpAddr  sSrcIp;			// ԴIP��ַ		(Sender protocol address)
	MacAddr sDstMac;		// Ŀ��MAC��ַ	(Target hardware address)
	IpAddr  sDstIp;			// Ŀ��IP��ַ	(Target protocol address)
	//BYTE    padding[18];	//���0
};

/*               IPv4 Header Format
|-----------------------------------------------------|
|Offsets|Octet| 4  | 4  |   8    |        16          |
| Octet | Bit |---------------------------------------|
|   0   |   0 |ver |len |  tos   |   Total length     |
|   4   |  32 |   identification |flg| Fragment offset|
|   8   |  64 |    TTL  | Proto  |   Header checksum  |
|  12   |  96 |           Source address              |
|  16   | 128 |         Destination address           |
|  20   | 160 |               Option                  |
|-----------------------------------------------------|
*/
/* IpHeader Struct */
typedef struct IpHeader {
	u_char  nVerHl;			// �汾			(Vesion)
							//+�ײ�����		(Header length)
	u_char  nTos;           // ��������		(Type of service)
	u_short nTotalLen;      // �ܳ�			(Total length)
	u_short nIdent;			// ��ʶ			(Identification)
	u_short nFragOff;       // ��־λ		(Flags)
							//+��ƫ����		(Fragment offset)
	u_char  nTtl;			// ���ʱ��		(Time to live)
	u_char  nProtocol;		// Э��			(Protocol)
	u_short nCrc;			// �ײ�У���	(Header checksum)
	IpAddr  sSrcIp;			// Դ��ַ		(Source address)
	IpAddr  sDstIp;			// Ŀ�ĵ�ַ		(Destination address)
	u_int   nOpPad;			// ѡ�������	(Option + Padding)
}IpHeader;

/*                 UDP Header
|-----------------------------------------------------|
|Offsets|Octet|         16       |        16          |
| Octet | Bit |---------------------------------------|
|   0   |  0  |     Source port  |  Destination port  |
|   4   | 32  |  Datagram length |   Header checksum  |
|-----------------------------------------------------|
*/
/* UdpHeader Struct */
typedef struct UdpHeader {
	u_short nSrcPort;		// Դ�˿�		(Source port)
	u_short nDstPort;		// Ŀ�Ķ˿�		(Destination port)
	u_short nLen;			// ���ݰ�����	(Datagram length)
	u_short nCrc;			// У���		(Checksum)
}UdpHeader;

/*                                                         TCP Header
|--------------------------------------------------------------------------------------------------------------|
|Offsets|Octet| 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15	16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31|
| Octet | Bit |------------------------------------------------------------------------------------------------|
|   0   |   0 |                      Source port	           |                Destination port               |
|   4   |  32 |                                         Sequence number                                        |
|   8	|  64 |                                 Acknowledgment number(if ACK set)                              |
|    	|     |            |Reserved|N | C| E| U| A| P| R| S| F|                                               |
|  12	|  96 | Data offset|(0 0 0) |S | W| C| R| C| S| S| Y| I|                  Window Size                  |
|    	|     |            |        |  | R| E| G| K| H| T| N| N|                                               |
|  16	| 128 |                       Checksum                 |            Urgent pointer(if URG set)         |
|  20   | 160 |            Options(if data offset > 5. Padded at the end with "0" bytes if necessary.)         |
|--------------------------------------------------------------------------------------------------------------|
*/
/* TcpHeader Struct */
typedef struct TcpHeader
{
	u_short nSrcPort;		// ԭ�˿ں�		(Source port)
	u_short nDstPort;		// Ŀ�Ķ˿ں�	(Destination port)
	u_long  nSeqNum;		// ���к�		(Sequence number)
	u_long  nAckNum;		// ȷ�����к�	(Acknowledgment number)
	u_char  rReserved1 : 4;	// ����			(Reserved)
	u_char  nHeaderLen : 4;	// λ��			(Data offset)
	u_char  bFin : 1;		// FIN
	u_char  bSyn : 1;		// SYN
	u_char  bRst : 1;		// RST
	u_char  bPsh : 1;		// PSH
	u_char  bAck : 1;		// ACK
	u_char  bUgr : 1;		// UGR
	u_char  rReserved2 : 2;	// ����
	u_short nWinSize;		// ���ڴ�С		(Window Size)
	u_short nCheckSum;		// У���		(Checksum)
	u_short nUrgPtr;			// ����ָ�� (Urgent pointer)
}TcpHeader;

/*                ICMP Header
|-----------------------------------------------------|
|Offsets|Octet|    8    |    8   |         16         |
| Octet | Bit |---------------------------------------|
|   0   |  0  |   Type  |  Code  |   Header checksum  |
|-----------------------------------------------------|
*/
/* ICMP Header Struct */
typedef struct IcmpHeader
{
	u_char nType;			// ��Ϣ����		(Type)
	u_char nCode;			// ��Ϣ����		(Code)
	u_short nCheckSum;		// У���		(Header checksum)
							// ...							// �򵥽�����ֻ����������ֶ�
}IcmpHeader;

/*                IGMP Header
|-----------------------------------------------------|
|Offsets|Octet|    8    |    8   |         16         |
| Octet | Bit |---------------------------------------|
|   0   |  0  |   Type  |  Code  |   Header checksum  |
|-----------------------------------------------------|
/* IGMP Header Struct */
typedef struct IgmpHeader
{
	u_char nType;			// ��Ϣ����		(Type)
	u_char nCode;			// ��Ϣ����		(Code)
	u_short nCheckSum;		// У���		(Header checksum
							// ...							// �򵥽�����ֻ����������ֶ�
}IgmpHeader;
#pragma pack()
#endif
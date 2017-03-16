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
	MacAddr sDstMac;		// 目标MAC地址
	MacAddr sSrcMac;		// 源MAC地址
	u_short nEthType;		// 数据帧类型
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
	u_short nHardType;		// 硬件类型		(Headware type)
	u_short nProtoType;		// 协议类型		(Protocol type)
	u_char  nMacLen;		// 硬件地址长度 (Hardware address length)
	u_char  nProtoLen;		// 协议地址长度 (Protocol address length)
	u_short nOpCode;		// 操作类型		(Operation)
	MacAddr sSrcMac;		// 源MAC地址	(Sender hardware address)
	IpAddr  sSrcIp;			// 源IP地址		(Sender protocol address)
	MacAddr sDstMac;		// 目标MAC地址	(Target hardware address)
	IpAddr  sDstIp;			// 目标IP地址	(Target protocol address)
};

/*EArpHeader Struct */
struct EArpHeader
{
	EthernetHeader FrameHeader;
	u_short nHardType;		// 硬件类型		(Headware type)
	u_short nProtoType;		// 协议类型		(Protocol type)
	u_char  nMacLen;		// 硬件地址长度 (Hardware address length)
	u_char  nProtoLen;		// 协议地址长度 (Protocol address length)
	u_short nOpCode;		// 操作类型		(Operation)
	MacAddr sSrcMac;		// 源MAC地址	(Sender hardware address)
	IpAddr  sSrcIp;			// 源IP地址		(Sender protocol address)
	MacAddr sDstMac;		// 目标MAC地址	(Target hardware address)
	IpAddr  sDstIp;			// 目标IP地址	(Target protocol address)
	//BYTE    padding[18];	//填充0
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
	u_char  nVerHl;			// 版本			(Vesion)
							//+首部长度		(Header length)
	u_char  nTos;           // 服务类型		(Type of service)
	u_short nTotalLen;      // 总长			(Total length)
	u_short nIdent;			// 标识			(Identification)
	u_short nFragOff;       // 标志位		(Flags)
							//+段偏移量		(Fragment offset)
	u_char  nTtl;			// 存活时间		(Time to live)
	u_char  nProtocol;		// 协议			(Protocol)
	u_short nCrc;			// 首部校验和	(Header checksum)
	IpAddr  sSrcIp;			// 源地址		(Source address)
	IpAddr  sDstIp;			// 目的地址		(Destination address)
	u_int   nOpPad;			// 选项与填充	(Option + Padding)
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
	u_short nSrcPort;		// 源端口		(Source port)
	u_short nDstPort;		// 目的端口		(Destination port)
	u_short nLen;			// 数据包长度	(Datagram length)
	u_short nCrc;			// 校验和		(Checksum)
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
	u_short nSrcPort;		// 原端口号		(Source port)
	u_short nDstPort;		// 目的端口号	(Destination port)
	u_long  nSeqNum;		// 序列号		(Sequence number)
	u_long  nAckNum;		// 确认序列号	(Acknowledgment number)
	u_char  rReserved1 : 4;	// 保留			(Reserved)
	u_char  nHeaderLen : 4;	// 位移			(Data offset)
	u_char  bFin : 1;		// FIN
	u_char  bSyn : 1;		// SYN
	u_char  bRst : 1;		// RST
	u_char  bPsh : 1;		// PSH
	u_char  bAck : 1;		// ACK
	u_char  bUgr : 1;		// UGR
	u_char  rReserved2 : 2;	// 保留
	u_short nWinSize;		// 窗口大小		(Window Size)
	u_short nCheckSum;		// 校验和		(Checksum)
	u_short nUrgPtr;			// 紧急指针 (Urgent pointer)
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
	u_char nType;			// 消息类型		(Type)
	u_char nCode;			// 消息代码		(Code)
	u_short nCheckSum;		// 校验和		(Header checksum)
							// ...							// 简单解析，只定义上面的字段
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
	u_char nType;			// 消息类型		(Type)
	u_char nCode;			// 消息代码		(Code)
	u_short nCheckSum;		// 校验和		(Header checksum
							// ...							// 简单解析，只定义上面的字段
}IgmpHeader;
#pragma pack()
#endif
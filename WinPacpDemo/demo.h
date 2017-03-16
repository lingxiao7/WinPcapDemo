#ifndef _DEMO_H
#define _DEMO_H
#include "pcap.h"
#include "Protocols.h"

/*  ����ԭ�� */
void ifprint(pcap_if_t *d);
char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

/* packet handler ����ԭ�� */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/* dispatcher handler ����ԭ�� */
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

EArpHeader filtpacket();
#endif
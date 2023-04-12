/* Copyright Ionescu Matei-Stefan - 323CAb - 2022-2023 */
#ifndef _ARP_H_
#define _ARP_H_

#include "protocols.h"
#include "types.h"

#define IPV4_PROT_SIZE 4
#define ETHERNET_HTYPE 1
#define ARP_REQUEST_OP 1
#define ARP_REPLY_OP 2

/* update the mac_next_hop value to the mac of the next hop if it is found in
 the cache or send an arp request otherwise */
int get_next_hop_mac(hashtable_t *arp_cache, linked_list_t *arp_waiting_list,
					 struct next_hop_t *next_hop, uint8_t *mac_next_hop,
					 char *packet, int packet_len, uint32_t router_ip_addr);

/* process an arp packet that the router received */
void process_arp_packet(char *packet, int packet_len, int interface,
						hashtable_t *arp_cache,
						linked_list_t *arp_waiting_list);

#endif

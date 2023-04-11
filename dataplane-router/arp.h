#ifndef _ARP_H_
#define _ARP_H_

#include "utils/hashtable.h"
#include "utils/linkedlist.h"
#include "protocols.h"

int get_next_hop_mac(hashtable_t *arp_cache, linked_list_t *arp_waiting_queue, struct next_hop_t *next_hop, uint8_t *mac_next_hop, char *packet, int packet_len, uint32_t router_ip_addr);

void process_arp_packet(char *packet, int packet_len, int interface, hashtable_t *arp_cache, linked_list_t *arp_waiting_queue);

#endif
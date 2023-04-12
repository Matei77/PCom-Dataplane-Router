/* Copyright Ionescu Matei-Stefan - 323CAb - 2022-2023 */
#include "arp.h"
#include "hashtable.h"
#include "lib.h"
#include "linkedlist.h"
#include "protocols.h"
#include "types.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

/* update the mac_next_hop value to the mac of the next hop if it is found in
 the cache or send an arp request otherwise */
int get_next_hop_mac(hashtable_t *arp_cache, linked_list_t *arp_waiting_list,
					 struct next_hop_t *next_hop, uint8_t *mac_next_hop,
					 char *packet, int packet_len, uint32_t router_ip_addr)
{

	/* check if packet is in cache */
	if (ht_has_key(arp_cache, &next_hop->ip)) {
		/* set the mac_next_hop */
		memcpy(mac_next_hop, (uint8_t *)ht_get(arp_cache, &next_hop->ip),
			   SIZE_OF_MAC);

		/* success */
		return 1;

	} else {
		/* add packet to wating arp list */
		struct waiting_packet_t *waiting_pack =
			malloc(sizeof(struct waiting_packet_t));

		waiting_pack->packet = malloc(packet_len);
		memcpy(waiting_pack->packet, packet, packet_len);
		waiting_pack->packet_len = packet_len;
		waiting_pack->next_hop = next_hop;

		ll_add_nth_node(arp_waiting_list, 0, waiting_pack);

		/* generate arp request */
		char arp_request_packet[MAX_PACKET_LEN];
		memset(arp_request_packet, 0, MAX_PACKET_LEN);

		/* get mac of the of the interface the packet will be sent on */
		uint8_t mac[6];
		get_interface_mac(next_hop->interface, mac);

		/* set ether header */
		struct ether_header *eth_hdr =
			(struct ether_header *)arp_request_packet;

		eth_hdr->ether_type = htons(ETHERTYPE_ARP);
		memcpy(eth_hdr->ether_shost, mac, SIZE_OF_MAC);
		memset(eth_hdr->ether_dhost, 0xFF, SIZE_OF_MAC);

		/* set arp header */
		struct arp_header *arp_hdr =
			(struct arp_header *)(arp_request_packet +
								  sizeof(struct ether_header));

		arp_hdr->htype = htons(ETHERNET_HTYPE);
		arp_hdr->ptype = htons(ETHERTYPE_IP);
		arp_hdr->hlen = SIZE_OF_MAC;
		arp_hdr->plen = IPV4_PROT_SIZE;
		arp_hdr->op = htons(ARP_REQUEST_OP);
		memcpy(arp_hdr->sha, mac, SIZE_OF_MAC);
		memset(arp_hdr->tha, 0, SIZE_OF_MAC);
		arp_hdr->tpa = next_hop->ip;

		uint32_t router_ip_addr;
		get_interface_ip_uint32(next_hop->interface, &router_ip_addr);
		arp_hdr->spa = htonl(router_ip_addr);

		send_to_link(next_hop->interface, arp_request_packet,
					 sizeof(struct ether_header) + sizeof(struct arp_header));

		return 0;
	}
}

/* process an arp packet that the router received */
void process_arp_packet(char *packet, int packet_len, int interface,
						hashtable_t *arp_cache, linked_list_t *arp_waiting_list)
{
	struct ether_header *eth_hdr = (struct ether_header *)packet;
	struct arp_header *arp_hdr =
		(struct arp_header *)(packet + sizeof(struct ether_header));

	/* check for arp request */
	if (ntohs(arp_hdr->op) == ARP_REQUEST_OP) {
		/* change op to reply */
		arp_hdr->op = htons(2);
		uint8_t router_mac[6];
		get_interface_mac(interface, router_mac);

		for (int i = 0; i < 6; i++) {
			arp_hdr->tha[i] = arp_hdr->sha[i];
			eth_hdr->ether_dhost[i] = arp_hdr->sha[i];
		}

		for (int i = 0; i < 6; i++) {
			arp_hdr->sha[i] = router_mac[i];
			eth_hdr->ether_shost[i] = router_mac[i];
		}

		uint32_t aux;
		aux = arp_hdr->spa;
		arp_hdr->spa = arp_hdr->tpa;
		arp_hdr->tpa = aux;

		/* send the response to the arp request */
		send_to_link(interface, packet, packet_len);

		/* check for arp reply */
	} else if (ntohs(arp_hdr->op) == ARP_REPLY_OP) {
		/* add the (ip, mac) pair received in the arp cache */
		ht_put(arp_cache, &(arp_hdr->spa), sizeof(uint32_t), arp_hdr->sha,
			   sizeof(arp_hdr->sha));

		ll_node_t *iter = arp_waiting_list->head;
		int nr = 0;

		/* check the waiting packs list */
		while (iter != NULL) {
			struct waiting_packet_t *waiting_pack =
				(struct waiting_packet_t *)iter->data;

			/* a waiting pack is found in the queue */
			if (ht_has_key(arp_cache, &(waiting_pack->next_hop->ip))) {

				uint8_t *next_hop_mac;
				next_hop_mac =
					(uint8_t *)ht_get(arp_cache, &waiting_pack->next_hop->ip);

				struct ether_header *waiting_pack_eth_hdr =
					(struct ether_header *)waiting_pack->packet;

				memcpy(waiting_pack_eth_hdr->ether_dhost, next_hop_mac,
					   SIZE_OF_MAC);

				send_to_link(waiting_pack->next_hop->interface,
							 waiting_pack->packet, waiting_pack->packet_len);

				iter = iter->next;

				/* remove the sent packet */
				ll_remove_nth_node(arp_waiting_list, nr);

			} else {
				iter = iter->next;
				nr++;
			}
		}
	}
}

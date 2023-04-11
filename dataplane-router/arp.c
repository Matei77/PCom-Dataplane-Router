#include "arp.h"
#include "lib.h"
#include "protocols.h"
#include "utils/types.h"
#include "utils/hashtable.h"
#include "utils/linkedlist.h"

#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int get_next_hop_mac(hashtable_t *arp_cache, linked_list_t *arp_waiting_queue, struct next_hop_t *next_hop, uint8_t *mac_next_hop, char *packet, int packet_len, uint32_t router_ip_addr) {

	printf("check if packet is in cache:");
	// check if packet is in cache
	if (ht_has_key(arp_cache, &next_hop->ip)) {
		// set the mac_next_hop
		printf("true\n");
		memcpy (mac_next_hop, (uint8_t *) ht_get(arp_cache, &next_hop->ip), 6);
		printf("mac next hop: ");
		for (int i = 0; i < 5; i++)
			printf("%X.", mac_next_hop[i]);
		printf("%X\n", mac_next_hop[5]);
		return 1;
	} else {
		printf("false\n");
		// add packet to wating arp queue
		struct waiting_packet_t *waiting_pack = malloc(sizeof(struct waiting_packet_t));
		printf("waiting_pack malloc\n");
		waiting_pack->packet = malloc(packet_len);
		printf("waiting_pack->packet malloc\n");
		memcpy(waiting_pack->packet, packet, packet_len);

		waiting_pack->packet_len = packet_len;

		waiting_pack->next_hop = next_hop;

		printf("before ll_add_nth_node\n");
		printf("arp_waiting_queue pointer: %lu\n", arp_waiting_queue);
		ll_add_nth_node(arp_waiting_queue, 0, waiting_pack);
		printf("added packet to wating packets queue\n");

		// generate arp request
		char arp_request_packet[MAX_PACKET_LEN];
		memset(arp_request_packet, 0, MAX_PACKET_LEN);

		// set ether header
		struct ether_header *eth_hdr = (struct ether_header *) arp_request_packet;
		eth_hdr->ether_type = htons(ETHERTYPE_ARP);

		uint8_t mac[6];
		get_interface_mac(next_hop->inteface, mac);
		for (int i = 0; i < 6; i++) {
			eth_hdr->ether_shost[i] = mac[i];
		}
		
		for (int i = 0; i < 6; i++) {
			eth_hdr->ether_dhost[i] = 0xFF;
		}

		// set arp header
		struct arp_header *arp_hdr = (struct arp_header *)(arp_request_packet + sizeof(struct ether_header));
		arp_hdr->htype = htons(1);
		arp_hdr->ptype = htons(ETHERTYPE_IP);
		arp_hdr->hlen = 6;
		arp_hdr->plen = 4;
		arp_hdr->op = htons(1);

		for (int i = 0; i < 6; i++) {
			arp_hdr->sha[i] = mac[i];
		}
		arp_hdr->spa = htonl(router_ip_addr);
		
		for (int i = 0; i < 6; i++) {
			arp_hdr->tha[i] = 0x0;
		}
		arp_hdr->tpa = next_hop->ip;

		send_to_link(next_hop->inteface, arp_request_packet, sizeof(struct ether_header) + sizeof(struct arp_header));
		printf("sent arp packet:\n");
		printf("\tarp_hdr->op: %u\n", arp_hdr->op);
		printf("\tarp_hdr->sender ip: %u\n", arp_hdr->spa);
		printf("\tarp_hdr->receiver ip: %u\n", arp_hdr->tpa);
		printf("\tarp_hdr->sender mac:");
		for (int i = 0; i < 5; i++)
			printf("%X.", arp_hdr->sha[i]);
		printf("%X\n", arp_hdr->sha[5]);
		printf("\tarp_hdr->receiver mac:");
		for (int i = 0; i < 5; i++)
			printf("%X.", arp_hdr->tha[i]);
		printf("%X\n", arp_hdr->tha[5]);
	
		return 0;
	}
	
}

void process_arp_packet(char *packet, int packet_len, int interface, hashtable_t *arp_cache, linked_list_t *arp_waiting_queue) {
	struct ether_header *eth_hdr = (struct ether_header *)packet;
	struct arp_header *arp_hdr = (struct arp_header *)(packet + sizeof(struct ether_header));

	printf("arp_hdr->op: %u\n", arp_hdr->op);
	printf("arp_hdr->sender ip: %u\n", arp_hdr->spa);
	printf("arp_hdr->receiver ip: %u\n", arp_hdr->tpa);
	printf("arp_hdr->sender mac:");
	for (int i = 0; i < 5; i++)
		printf("%X.", arp_hdr->sha[i]);
	printf("%X\n", arp_hdr->sha[5]);
	printf("arp_hdr->receiver mac:");
	for (int i = 0; i < 5; i++)
		printf("%X.", arp_hdr->tha[i]);
	printf("%X\n", arp_hdr->tha[5]);
	
	// check for arp request
	if (ntohs(arp_hdr->op) == 1) {
		// change op to reply
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

		printf("\tarp_hdr->op: %u\n", arp_hdr->op);
		printf("\tarp_hdr->sender ip: %u\n", arp_hdr->spa);
		printf("\tarp_hdr->receiver ip: %u\n", arp_hdr->tpa);
		printf("\tarp_hdr->sender mac:");
		for (int i = 0; i < 5; i++)
			printf("%X.", arp_hdr->sha[i]);
		printf("%X\n", arp_hdr->sha[5]);
		printf("\tarp_hdr->receiver mac:");
		for (int i = 0; i < 5; i++)
			printf("%X.", arp_hdr->tha[i]);
		printf("%X\n", arp_hdr->tha[5]);
		// send the response to the arp request
		send_to_link(interface, packet, packet_len);
	
	} else if (ntohs(arp_hdr->op) == 2) {
		ht_put(arp_cache, &arp_hdr->spa, sizeof(uint32_t), arp_hdr->sha, sizeof(arp_hdr->sha));
		
		ll_node_t *iter = arp_waiting_queue->head;
		int nr = 0;
		while (iter != NULL) {
			struct waiting_packet_t *waiting_pack = (struct waiting_packet_t *)iter->data;
			
			// a waiting pack is found in the queue
			if (ht_has_key(arp_cache, &waiting_pack->next_hop->ip) == 1) {
				printf("found wating packet\n");
				uint8_t *next_hop_mac;
				next_hop_mac = (uint8_t *) ht_get(arp_cache, &waiting_pack->next_hop->ip);
				
				struct ether_header *waiting_pack_eth_hdr = (struct ether_header *) waiting_pack->packet;

				memcpy(waiting_pack_eth_hdr->ether_dhost, next_hop_mac, 6);
				printf("-------------------------------------\n");
				printf("waiting_pack_eth_hdr->ether_dhost: \n");
				for (int i = 0; i < 5; i++)
					printf("%X.", waiting_pack_eth_hdr->ether_dhost[i]);
				printf("%X\n", waiting_pack_eth_hdr->ether_dhost[5]);

				printf("waiting_pack->next_hop->inteface: %d\n", waiting_pack->next_hop->inteface);
				printf("waiting packet type: %X\n", waiting_pack_eth_hdr->ether_type);
				
				printf("-------------------------------------\n");
				
				int rc = 0;
				rc = send_to_link(waiting_pack->next_hop->inteface, waiting_pack->packet, waiting_pack->packet_len);
				printf("send_to_link size: %d\n", rc);

				iter = iter->next;
		
				ll_remove_nth_node(arp_waiting_queue, nr);
				
			} else {
				iter = iter->next;
				nr++;
			}
		}
	}

	
	
}

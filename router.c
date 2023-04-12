// Copyright Ionescu Matei-Stefan - 323CAb - 2022-2023
#include "lib.h"
#include "protocols.h"
#include "ipv4.h"
#include "lpm.h"
#include "ether.h"
#include "hashtable.h"
#include "types.h"
#include "arp.h"
#include "linkedlist.h"

#include <netinet/in.h>

#define MAX_RTABLE_ENTRIES 100000

int main(int argc, char *argv[])
{
	char packet[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry route_table[MAX_RTABLE_ENTRIES];
	int rt_size = 0;

	// read the routing table from file
	rt_size = read_rtable(argv[1], route_table);

	// create trie structure from the routing table
	struct trie_node_t *rt_trie_root = populate_trie(route_table, rt_size);

	// create arp cache to store (ip address, mac) pairs using hashtable
	hashtable_t *arp_cache = ht_create(INITIAL_BUCKETS_NR, hash_function_int, compare_function_uint32);

	// create list of packet that are waiting for arp reply
	linked_list_t *arp_waiting_list = ll_create(sizeof(struct waiting_packet_t));


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(packet, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) packet;
		
		// checks if the received package was sent to the correct MAC destination
		if (!check_ether_header(*eth_hdr, interface))
			continue;

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			process_ip_packet(packet, len, interface, rt_trie_root, arp_cache, arp_waiting_list);
		}

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			process_arp_packet(packet, len, interface, arp_cache, arp_waiting_list);
		}
	}
}
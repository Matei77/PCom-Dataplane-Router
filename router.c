#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "dataplane-router/ipv4.h"
#include "dataplane-router/lpm.h"
#include "dataplane-router/ether.h"
#include "dataplane-router/utils/hashtable.h"
#include "dataplane-router/utils/types.h"
#include "dataplane-router/arp.h"
#include "dataplane-router/utils/linkedlist.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_RTABLE_ENTRIES 100000

int main(int argc, char *argv[])
{
	char packet[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry route_table[MAX_RTABLE_ENTRIES];
	int rt_size = 0;
	rt_size = read_rtable(argv[1], route_table);

	struct trie_node_t *rt_trie_root = populate_trie(route_table, rt_size);

	hashtable_t *arp_cache = ht_create(INITIAL_BUCKETS_NR, hash_function_string, compare_function_strings);

	linked_list_t *arp_waiting_queue = ll_create(sizeof(struct waiting_packet_t));
	printf("arp_waiting_queue pointer: %lu\n", arp_waiting_queue);


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(packet, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) packet;

		printf("ehter->shost: ");
		for (int i = 0; i < 5; i++)
			printf("%X.", eth_hdr->ether_shost[i]);
		printf("%X\n", eth_hdr->ether_shost[5]);

		printf("ehter->dhost: ");
		for (int i = 0; i < 5; i++)
			printf("%X.", eth_hdr->ether_dhost[i]);
		printf("%X\n", eth_hdr->ether_dhost[5]);

		printf("ether->type: %X\n", eth_hdr->ether_type);
		
		/* checks if the received package was sent to the correct MAC destination
		and if the Ether Type is IPv4 or ARP */
		if (!check_ether_header(*eth_hdr, interface))
			{
			printf("wrong ether headerd\n");
			continue;
			}

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			process_ip_packet(packet, len, interface, route_table, rt_trie_root, arp_cache, arp_waiting_queue);
		}

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			process_arp_packet(packet, len, interface, arp_cache, arp_waiting_queue);
		}
	}
}

/* Note that packets received are in network order,
any header field which has more than 1 byte will need to be conerted to
host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
sending a packet on the link, */
#include "ipv4.h"
#include "lib.h"
#include "protocols.h"
#include "icmp.h"
#include "lpm.h"
#include "queue.h"
#include "arp.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

void get_interface_ip_uint32(int interface, uint32_t *ip) {
	char *char_router_ip_addr;
	char_router_ip_addr = get_interface_ip(interface);

	inet_pton(AF_INET, char_router_ip_addr, ip);
	*ip = htonl(*ip);
}



void process_ip_packet(char *packet, size_t len, int interface, struct route_table_entry *route_table, struct trie_node_t *rt_trie_root, hashtable_t *arp_cache, linked_list_t *arp_waiting_queue) {
	// get the IPv4 header
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	printf("\tip_hdr->daddr: %u\n\tip_hdr->saddr: %u\n\tip_hdr->ttl: %u\n", ip_hdr->daddr, ip_hdr->saddr, ip_hdr->ttl);

	// check if the router is the destination of the packet
	uint32_t router_ip_addr;
	get_interface_ip_uint32(interface, &router_ip_addr);
	printf("\t\trouter_ip_addr: %u\n", router_ip_addr);
	printf("\t\trouter_ip_addr_string: %s\n", get_interface_ip(interface));

	if (ip_hdr->daddr == router_ip_addr) {
		respond_to_icmp();
		return;
	}

	// check if the checksum of the header is correct
	uint16_t recv_sum = ntohs(ip_hdr->check);
	printf("\trecv_sum with no ntohs: %u", ip_hdr->check);
	printf("\trecv_sum: %u\n", recv_sum);
	
	ip_hdr->check = 0;

	printf("\tcalc_sum: %u\n", checksum((void *) ip_hdr, sizeof(struct iphdr)));
	if (checksum((void *) ip_hdr, sizeof(struct iphdr)) != recv_sum) {
		printf("checksum bad\n");
		return;
	}
	
	// check if the TTL was exceeded
	if (ntohs(ip_hdr->ttl) > 1) {
		--(ip_hdr->ttl);
	} else {
		send_time_exceeded_icmp();
		printf("ttl bad\n");
		return;
	}
	
	// search routing table
	struct next_hop_t *next_hop = find_next_hop(ntohl(ip_hdr->daddr), rt_trie_root);

	if (!next_hop) {
		send_dest_unreachable_icmp();
		printf("next_hop = NULL\n");
		return;
	}
	printf("next_hop->interface: %d\n next_hop->ip: %u\n", next_hop->inteface, next_hop->ip);
	printf("htonl(next_hop->ip): %u\n", htonl(next_hop->ip));
	printf("ntohl(next_hop->ip): %u\n", ntohl(next_hop->ip));
	
	// update checksum
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((void *) ip_hdr, sizeof(struct iphdr)));
	
	// rewrite l2 addresses
	struct ether_header *eth_hdr = (struct ether_header *)packet;

	// update sender mac address
	uint8_t mac[6];
	get_interface_mac(interface, mac);
	for (int i = 0; i < 6; i++) {
		eth_hdr->ether_shost[i] = mac[i];
	}
	
	// update receiver mac address
	uint8_t mac_next_hop[6];

	if (get_next_hop_mac(arp_cache, arp_waiting_queue, next_hop, mac_next_hop, packet, len, router_ip_addr) == 0)
		return;
	
	for (int i = 0; i < 6; i++) {
		eth_hdr->ether_dhost[i] = mac_next_hop[i];
	}

	printf("\tipv4 new ehter->shost: ");
	for (int i = 0; i < 5; i++)
		printf("%X.", eth_hdr->ether_shost[i]);
	printf("%X\n", eth_hdr->ether_shost[5]);

	printf("\tipv4 new ehter->dhost: ");
	for (int i = 0; i < 5; i++)
		printf("%X.", eth_hdr->ether_dhost[i]);
	printf("%X\n", eth_hdr->ether_dhost[5]);


	// send the packet to the next hop
	send_to_link(next_hop->inteface, packet, len);
}

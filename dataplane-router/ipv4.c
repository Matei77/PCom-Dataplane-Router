/* Copyright Ionescu Matei-Stefan - 323CAb - 2022-2023 */
#include "ipv4.h"
#include "arp.h"
#include "icmp.h"
#include "lib.h"
#include "lpm.h"
#include "protocols.h"

#include <string.h>

void process_ip_packet(char *packet, size_t len, int interface,
					   struct trie_node_t *rt_trie_root, hashtable_t *arp_cache,
					   linked_list_t *arp_waiting_list)
{
	/* get the IPv4 header */
	struct iphdr *ip_hdr =
		(struct iphdr *)(packet + sizeof(struct ether_header));

	/* check if the router is the destination of the packet */
	uint32_t router_ip_addr;
	get_interface_ip_uint32(interface, &router_ip_addr);

	if (ip_hdr->daddr == htonl(router_ip_addr)) {
		respond_to_icmp(packet, len, interface);
		return;
	}

	/* check if the checksum of the header is correct */
	uint16_t recv_sum = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
	if (checksum((void *)ip_hdr, sizeof(struct iphdr)) != recv_sum) {
		return;
	}

	/* check if the TTL was exceeded */
	if (ip_hdr->ttl > 1) {
		--(ip_hdr->ttl);
	} else {
		send_time_exceeded_icmp(packet, len, interface);
		return;
	}

	/* search routing table trie and find the ip address and interface of the
	 next hop */
	struct next_hop_t *next_hop =
		find_next_hop(ntohl(ip_hdr->daddr), rt_trie_root);

	/* if the next hop was not found send destination unreachable icmp message
	 */
	if (!next_hop) {
		send_dest_unreachable_icmp(packet, len, interface);
		return;
	}

	/* update checksum */
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((void *)ip_hdr, sizeof(struct iphdr)));

	/* rewrite l2 addresses */
	struct ether_header *eth_hdr = (struct ether_header *)packet;
	uint8_t mac[SIZE_OF_MAC];

	/* update sender mac address */
	get_interface_mac(next_hop->interface, mac);
	memcpy(eth_hdr->ether_shost, mac, SIZE_OF_MAC);

	/* update receiver mac address, if the mac address is not known at the
	 moment return */
	if (get_next_hop_mac(arp_cache, arp_waiting_list, next_hop, mac, packet,
						 len, router_ip_addr) == 0)
		return;
	memcpy(eth_hdr->ether_dhost, mac, SIZE_OF_MAC);

	/* send the packet to the next hop */
	send_to_link(next_hop->interface, packet, len);
}

#include "icmp.h"
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

#define ICMP 1

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

void respond_to_icmp(char *packet, size_t len, int interface) {
	char response_packet[MAX_PACKET_LEN];
	memset(response_packet, 0, MAX_PACKET_LEN);

	struct ether_header *rp_eth_hdr = (struct ether_header *)response_packet;
	struct iphdr *rp_ip_hdr = (struct iphdr *)(response_packet + sizeof(struct ether_header));
	struct icmphdr *rp_icmp_hdr = (struct icmphdr *)(response_packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	struct ether_header *pack_eth_hdr = (struct ether_header *)packet;
	struct iphdr *pack_ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	if (pack_ip_hdr->protocol != ICMP)
		return;
	
	struct icmphdr *pack_icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	
	if (pack_icmp_hdr->type != 8)
		return;

	// create ether header
	memcpy(rp_eth_hdr->ether_dhost, pack_eth_hdr->ether_shost, 6);
	memcpy(rp_eth_hdr->ether_shost, pack_eth_hdr->ether_dhost, 6);
	rp_eth_hdr->ether_type = htons(ETHERTYPE_IP);

	// create ipv4 header
	int pack_data_len = len - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct icmphdr);

	rp_ip_hdr->ihl = 5;
	rp_ip_hdr->version = 4;
	rp_ip_hdr->tos = 0;
	rp_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + pack_data_len);
	rp_ip_hdr->id = htons(1);
	rp_ip_hdr->frag_off = htons(0);
	rp_ip_hdr->ttl = 64;
	rp_ip_hdr->protocol = ICMP;
	get_interface_ip_uint32(interface, &rp_ip_hdr->saddr);
	rp_ip_hdr->saddr = htonl(rp_ip_hdr->saddr);
	rp_ip_hdr->daddr = pack_ip_hdr->saddr;
	rp_ip_hdr->check = 0;
	rp_ip_hdr->check = htons(checksum((void *) rp_ip_hdr, sizeof(struct iphdr)));

	// create icmp header
	rp_icmp_hdr->type = 0;
	rp_icmp_hdr->code = 0;
	rp_icmp_hdr->un.echo.id = pack_icmp_hdr->un.echo.id;
	rp_icmp_hdr->un.echo.sequence = pack_icmp_hdr->un.echo.sequence;
	
	memcpy(response_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), pack_icmp_hdr + sizeof(struct icmphdr), pack_data_len);
	
	rp_icmp_hdr->checksum = 0;
	rp_icmp_hdr->checksum = htons(checksum((void *) rp_icmp_hdr, sizeof(struct icmphdr) + pack_data_len));

	int response_packet_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + pack_data_len;

	send_to_link(interface, response_packet, response_packet_len);
}

void send_dest_unreachable_icmp(char *packet, size_t len, int interface) {
	char response_packet[MAX_PACKET_LEN];
	memset(response_packet, 0, MAX_PACKET_LEN);

	struct ether_header *rp_eth_hdr = (struct ether_header *)response_packet;
	struct iphdr *rp_ip_hdr = (struct iphdr *)(response_packet + sizeof(struct ether_header));
	struct icmphdr *rp_icmp_hdr = (struct icmphdr *)(response_packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	struct ether_header *pack_eth_hdr = (struct ether_header *)packet;
	struct iphdr *pack_ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	// create ether header
	memcpy(rp_eth_hdr->ether_dhost, pack_eth_hdr->ether_shost, 6);
	memcpy(rp_eth_hdr->ether_shost, pack_eth_hdr->ether_dhost, 6);
	rp_eth_hdr->ether_type = htons(ETHERTYPE_IP);

	// create ipv4 header
	int pack_iphdr_and_data_len = MIN(len - sizeof(struct ether_header), sizeof(struct iphdr) + 64);

	rp_ip_hdr->ihl = 5;
	rp_ip_hdr->version = 4;
	rp_ip_hdr->tos = 0;
	rp_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + pack_iphdr_and_data_len);
	rp_ip_hdr->id = htons(1);
	rp_ip_hdr->frag_off = htons(0);
	rp_ip_hdr->ttl = 64;
	rp_ip_hdr->protocol = ICMP;
	get_interface_ip_uint32(interface, &rp_ip_hdr->saddr);
	rp_ip_hdr->saddr = htonl(rp_ip_hdr->saddr);
	rp_ip_hdr->daddr = pack_ip_hdr->saddr;
	rp_ip_hdr->check = 0;
	rp_ip_hdr->check = htons(checksum((void *) rp_ip_hdr, sizeof(struct iphdr)));

	// create icmp header
	rp_icmp_hdr->type = 3;
	rp_icmp_hdr->code = 0;
	
	memcpy(response_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), pack_ip_hdr, pack_iphdr_and_data_len);
	
	rp_icmp_hdr->checksum = 0;
	rp_icmp_hdr->checksum = htons(checksum((void *) rp_icmp_hdr, sizeof(struct icmphdr) + pack_iphdr_and_data_len));

	int response_packet_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + pack_iphdr_and_data_len;

	send_to_link(interface, response_packet, response_packet_len);
}

void send_time_exceeded_icmp(char *packet, size_t len, int interface) {
	char response_packet[MAX_PACKET_LEN];
	memset(response_packet, 0, MAX_PACKET_LEN);

	struct ether_header *rp_eth_hdr = (struct ether_header *)response_packet;
	struct iphdr *rp_ip_hdr = (struct iphdr *)(response_packet + sizeof(struct ether_header));
	struct icmphdr *rp_icmp_hdr = (struct icmphdr *)(response_packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	struct ether_header *pack_eth_hdr = (struct ether_header *)packet;
	struct iphdr *pack_ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	// create ether header
	memcpy(rp_eth_hdr->ether_dhost, pack_eth_hdr->ether_shost, 6);
	memcpy(rp_eth_hdr->ether_shost, pack_eth_hdr->ether_dhost, 6);
	rp_eth_hdr->ether_type = htons(ETHERTYPE_IP);

	// create ipv4 header
	int pack_iphdr_and_data_len = MIN(len - sizeof(struct ether_header), sizeof(struct iphdr) + 64);

	rp_ip_hdr->ihl = 5;
	rp_ip_hdr->version = 4;
	rp_ip_hdr->tos = 0;
	rp_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + pack_iphdr_and_data_len);
	rp_ip_hdr->id = htons(1);
	rp_ip_hdr->frag_off = htons(0);
	rp_ip_hdr->ttl = 64;
	rp_ip_hdr->protocol = ICMP;
	get_interface_ip_uint32(interface, &rp_ip_hdr->saddr);
	rp_ip_hdr->saddr = htonl(rp_ip_hdr->saddr);
	rp_ip_hdr->daddr = pack_ip_hdr->saddr;
	rp_ip_hdr->check = 0;
	rp_ip_hdr->check = htons(checksum((void *) rp_ip_hdr, sizeof(struct iphdr)));

	// create icmp header
	rp_icmp_hdr->type = 11;
	rp_icmp_hdr->code = 0;
	
	memcpy(response_packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), pack_ip_hdr, pack_iphdr_and_data_len);
	
	rp_icmp_hdr->checksum = 0;
	rp_icmp_hdr->checksum = htons(checksum((void *) rp_icmp_hdr, sizeof(struct icmphdr) + pack_iphdr_and_data_len));

	int response_packet_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + pack_iphdr_and_data_len;

	send_to_link(interface, response_packet, response_packet_len);
}
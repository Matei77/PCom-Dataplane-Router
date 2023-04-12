/* Copyright Ionescu Matei-Stefan - 323CAb - 2022-2023 */
#include "icmp.h"
#include "arp.h"
#include "ipv4.h"
#include "lib.h"
#include "lpm.h"
#include "protocols.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

/* creates and sends a icmp packet with given type */
void generate_and_send_pack(char *packet, size_t len, int interface,
								  int type)
{
	/* intialize response packet */
	char response_packet[MAX_PACKET_LEN];
	memset(response_packet, 0, MAX_PACKET_LEN);

	/* set the header structures of the response packet */
	struct ether_header *rp_eth_hdr = (struct ether_header *)response_packet;
	struct iphdr *rp_ip_hdr =
		(struct iphdr *)(response_packet + sizeof(struct ether_header));
	struct icmphdr *rp_icmp_hdr =
		(struct icmphdr *)(response_packet + sizeof(struct ether_header) +
						   sizeof(struct iphdr));

	/* set the header structures of the received packet */
	struct ether_header *pack_eth_hdr = (struct ether_header *)packet;
	struct iphdr *pack_ip_hdr =
		(struct iphdr *)(packet + sizeof(struct ether_header));
	struct icmphdr *pack_icmp_hdr =
		(struct icmphdr *)(packet + sizeof(struct ether_header) +
						   sizeof(struct iphdr));

	/* check if we need to respond to the packet */
	if (type == ECHO_REPLY_TYPE) {

		/* if the protocol is not icmp drop the packet */
		if (pack_ip_hdr->protocol != ICMP_PROTOCOL)
			return;

		/* if the type of the received message is not echo request drop the
		 packet */
		if (pack_icmp_hdr->type != ECHO_REQUEST_TYPE)
			return;
	}

	/* create ether header */
	memcpy(rp_eth_hdr->ether_dhost, pack_eth_hdr->ether_shost, SIZE_OF_MAC);
	memcpy(rp_eth_hdr->ether_shost, pack_eth_hdr->ether_dhost, SIZE_OF_MAC);
	rp_eth_hdr->ether_type = htons(ETHERTYPE_IP);

	/* create ipv4 header */
	int pack_data_len;
	if (type == ECHO_REPLY_TYPE) {
		pack_data_len = len - sizeof(struct ether_header) -
			sizeof(struct iphdr) - sizeof(struct icmphdr);
	} else {
		pack_data_len =
			MIN(len - sizeof(struct ether_header), sizeof(struct iphdr) + 64);
	}

	rp_ip_hdr->ihl = 5;
	rp_ip_hdr->version = 4;
	rp_ip_hdr->tos = 0;
	rp_ip_hdr->tot_len =
		htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + pack_data_len);
	rp_ip_hdr->id = htons(1);
	rp_ip_hdr->frag_off = htons(0);
	rp_ip_hdr->ttl = 64;
	rp_ip_hdr->protocol = ICMP_PROTOCOL;
	get_interface_ip_uint32(interface, &rp_ip_hdr->saddr);
	rp_ip_hdr->saddr = htonl(rp_ip_hdr->saddr);
	rp_ip_hdr->daddr = pack_ip_hdr->saddr;
	rp_ip_hdr->check = 0;
	rp_ip_hdr->check = htons(checksum((void *)rp_ip_hdr, sizeof(struct iphdr)));

	/* create icmp header */
	rp_icmp_hdr->type = type;
	rp_icmp_hdr->code = 0;

	if (type == ECHO_REPLY_TYPE) {
		rp_icmp_hdr->un.echo.id = pack_icmp_hdr->un.echo.id;
		rp_icmp_hdr->un.echo.sequence = pack_icmp_hdr->un.echo.sequence;

		memcpy(response_packet + sizeof(struct ether_header) +
				   sizeof(struct iphdr) + sizeof(struct icmphdr),
			   pack_icmp_hdr + sizeof(struct icmphdr), pack_data_len);
	} else {
		memcpy(response_packet + sizeof(struct ether_header) +
				   sizeof(struct iphdr) + sizeof(struct icmphdr),
			   pack_ip_hdr, pack_data_len);
	}

	rp_icmp_hdr->checksum = 0;
	rp_icmp_hdr->checksum = htons(
		checksum((void *)rp_icmp_hdr, sizeof(struct icmphdr) + pack_data_len));

	int response_packet_len = sizeof(struct ether_header) +
		sizeof(struct iphdr) + sizeof(struct icmphdr) + pack_data_len;

	/* send packet */
	send_to_link(interface, response_packet, response_packet_len);
}

/* send a response to a icmp packet targeting the router */
void respond_to_icmp(char *packet, size_t len, int interface)
{
	generate_and_send_pack(packet, len, interface, ECHO_REPLY_TYPE);
}

/* send destination unreachable icmp */
void send_dest_unreachable_icmp(char *packet, size_t len, int interface)
{
	generate_and_send_pack(packet, len, interface, DEST_UNREACHABLE_TYPE);
}

/* send time exceeded icmp */
void send_time_exceeded_icmp(char *packet, size_t len, int interface)
{
	generate_and_send_pack(packet, len, interface, TIME_EXCEEDED_TYPE);
}
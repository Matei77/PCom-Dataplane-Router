#include "lpm.h"
#include "lib.h"
#include "protocols.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

int get_mask_len(uint32_t mask) {
	int nr = 0;
	while (mask != 0) {
		if (mask & 1)
			nr++;
		mask = (mask >> 1);
	}
	return nr;
}

// return a new trie node
struct trie_node_t *get_new_node(void) {
	struct trie_node_t *new_node = (struct trie_node_t *)malloc(sizeof(struct trie_node_t));
	DIE(!new_node, "new_node malloc");

	new_node->is_end = 0;
	new_node->children[0] = NULL;
	new_node->children[1] = NULL;
	new_node->next_hop = NULL;

	return new_node;
}

void insert(struct trie_node_t *root, struct route_table_entry rtb) {
	uint32_t prefix_m = htonl(rtb.prefix & rtb.mask);
	printf("\tprefix: %u\n\tprefix_m: %u", rtb.prefix, prefix_m);
	
	int mask_len = get_mask_len(rtb.mask);
	printf("mask_len: %d\n", mask_len);

	struct trie_node_t *iter = root;

	for (int i = 31; i > 31 - mask_len + 1; i--) {
		int bit = ((prefix_m >> i) & 1);
		if (iter->children[bit] == NULL) {
			iter->children[bit] = get_new_node();
		}
		iter = iter->children[bit];
	}

	iter->is_end = 1;
	iter->next_hop = malloc(sizeof(struct next_hop_t));
	DIE(!iter->next_hop, "iter->next_hop malloc");
	iter->next_hop->inteface = rtb.interface;
	iter->next_hop->ip = rtb.next_hop;
}

struct trie_node_t *populate_trie(struct route_table_entry routing_table[], int rt_size) {
	struct trie_node_t *root = get_new_node();

	for (int i = 0; i < rt_size; i++) {
		insert(root, routing_table[i]);
		printf("inserted node %d in trie\n", i);
	}

	return root;
}

struct next_hop_t *find_next_hop(uint32_t dest_ip, struct trie_node_t *root) {

	struct next_hop_t *next_hop = NULL;
	struct trie_node_t *iter = root;
	printf("before for\n");

	printf("bits:");
	for (int i = 31; i >= 0; i--) {
		int bit = ((dest_ip >> i) & 1);
		printf("%d", bit);
		if (iter == NULL) {
			break;
		}
		if (iter->is_end == 1)
			next_hop = iter->next_hop;
		
		iter = iter->children[bit];
	}

	printf("\nafter for\n");
	return next_hop;
}


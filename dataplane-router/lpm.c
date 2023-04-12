/* Copyright Ionescu Matei-Stefan - 323CAb - 2022-2023 */
#include "lpm.h"
#include "lib.h"
#include "protocols.h"

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* return the lenght of the mask */
int get_mask_len(uint32_t mask)
{
	int nr = 0;
	while (mask != 0) {
		if (mask & 1)
			nr++;
		mask = (mask >> 1);
	}
	return nr;
}

/* return a new trie node */
struct trie_node_t *get_new_node(void)
{
	struct trie_node_t *new_node =
		(struct trie_node_t *)malloc(sizeof(struct trie_node_t));
	DIE(!new_node, "new_node malloc");

	new_node->is_end = 0;
	new_node->children[0] = NULL;
	new_node->children[1] = NULL;
	new_node->next_hop = NULL;

	return new_node;
}

/* insert a new route table entry in the trie */
void insert(struct trie_node_t *root, struct route_table_entry rtb)
{
	/* prefix_m stores the relevant bits of the prefix */
	uint32_t prefix_m = htonl(rtb.prefix & rtb.mask);
	int mask_len = get_mask_len(rtb.mask);

	struct trie_node_t *iter = root;

	/* find where to insert the data according to the prefix_m */
	for (int i = 31; i >= 31 - mask_len; i--) {
		int bit = ((prefix_m >> i) & 1);
		if (iter->children[bit] == NULL) {
			iter->children[bit] = get_new_node();
		}
		iter = iter->children[bit];
	}

	/* add the next hop data at the found position in the trie */
	iter->is_end = 1;
	iter->next_hop = malloc(sizeof(struct next_hop_t));
	DIE(!iter->next_hop, "iter->next_hop malloc");
	iter->next_hop->interface = rtb.interface;
	iter->next_hop->ip = rtb.next_hop;
}

/* add all entries from the routing table in a trie and return the root of the
 * trie */
struct trie_node_t *populate_trie(struct route_table_entry routing_table[],
								  int rt_size)
{
	struct trie_node_t *root = get_new_node();

	for (int i = 0; i < rt_size; i++)
		insert(root, routing_table[i]);

	return root;
}
/* find the longest prefix maching hop with the dest_ip */
struct next_hop_t *find_next_hop(uint32_t dest_ip, struct trie_node_t *root)
{
	struct next_hop_t *next_hop = NULL;
	struct trie_node_t *iter = root;

	for (int i = 31; i >= 0; i--) {
		int bit = ((dest_ip >> i) & 1);

		if (iter->is_end != 0)
			next_hop = iter->next_hop;

		if (iter->children[bit] == NULL) {
			break;
		}

		iter = iter->children[bit];
	}

	return next_hop;
}

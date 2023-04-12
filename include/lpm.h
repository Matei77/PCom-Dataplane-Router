/* Copyright Ionescu Matei-Stefan - 323CAb - 2022-2023 */
#ifndef _LPM_H_
#define _LPM_H_

#include "lib.h"
#include "protocols.h"

#define CHILDREN_NR 2

/* Trie node */
struct trie_node_t {
	struct trie_node_t *children[CHILDREN_NR];
	/* is_end is true if the node
	represents the end of a ip prefix */
	int is_end;
	struct next_hop_t *next_hop;
};

/* return a new trie node */
struct trie_node_t *get_new_node(void);

/* insert a new route table entry in the trie */
void insert(struct trie_node_t *root, struct route_table_entry rtb);

/* add all entries from the routing table in a trie and return the root of the
 * trie */
struct trie_node_t *populate_trie(struct route_table_entry routing_table[],
								  int rt_size);

/* find the longest prefix maching hop with the dest_ip */
struct next_hop_t *find_next_hop(uint32_t dest_ip, struct trie_node_t *root);

#endif /* _LPM_H_ */
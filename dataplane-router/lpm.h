#ifndef _LPM_H_
#define _LPM_H_

#include "lib.h"

#define CHILDREN_NR 2
// Trie node 
struct trie_node_t 
{ 
     struct trie_node_t *children[CHILDREN_NR];
     // is_end is true if the node 
     // represents end of a ip prefix 
     int is_end;
	 struct next_hop_t *next_hop;
};

struct trie_node_t *get_new_node(void);

void insert(struct trie_node_t *root, struct route_table_entry rtb);

struct trie_node_t *populate_trie(struct route_table_entry routing_table[], int rt_size);

struct next_hop_t *find_next_hop(uint32_t dest_ip, struct trie_node_t *root);

#endif /* _LPM_H_ */
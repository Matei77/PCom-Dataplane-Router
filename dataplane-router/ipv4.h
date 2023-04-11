#ifndef _IPV4_H_
#define _IPV4_H_

#include "lpm.h"
#include "lib.h"

void process_ip_packet(char *packet, size_t len, int interface, struct route_table_entry *route_table, struct trie_node_t *rt_trie_root);

#endif /* _IPV4_H_ */

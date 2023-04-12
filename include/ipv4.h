#ifndef _IPV4_H_
#define _IPV4_H_

#include "lpm.h"
#include "types.h"

void process_ip_packet(char *packet, size_t len, int interface, struct trie_node_t *rt_trie_root, hashtable_t *arp_cache, linked_list_t *arp_waiting_queue);

#endif /* _IPV4_H_ */

#ifndef _ETHER_H_
#define _ETHER_H_

#include "protocols.h"

int check_ether_header(struct ether_header eth_hdr, int interface);

#endif /* _ETHER_H_ */

/* Copyright Ionescu Matei-Stefan - 323CAb - 2022-2023 */
#ifndef _ETHER_H_
#define _ETHER_H_

#include "protocols.h"

/* chec if the MAC destination of the package is not the same with the MAC
 address of the router or the broadcast address */
int check_ether_header(struct ether_header eth_hdr, int interface);

#endif /* _ETHER_H_ */

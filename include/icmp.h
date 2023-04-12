/* Copyright Ionescu Matei-Stefan - 323CAb - 2022-2023 */
#ifndef _ICMP_H_
#define _ICMP_H_

#include <netinet/in.h>

#define ICMP_PROTOCOL 1
#define ECHO_REQUEST_TYPE 8
#define ECHO_REPLY_TYPE 0
#define DEST_UNREACHABLE_TYPE 3
#define TIME_EXCEEDED_TYPE 11

/* send a response to a icmp packet targeting the router */
void respond_to_icmp(char *packet, size_t len, int interface);

/* send destination unreachable icmp */
void send_dest_unreachable_icmp(char *packet, size_t len, int interface);

/* send time exceeded icmp */
void send_time_exceeded_icmp(char *packet, size_t len, int interface);

#endif /* _ICMP_H_ */

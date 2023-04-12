#ifndef _ICMP_H_
#define _ICMP_H_

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void respond_to_icmp(char *packet, size_t len, int interface);

void send_time_exceeded_icmp(char *packet, size_t len, int interface);

void send_dest_unreachable_icmp(char *packet, size_t len, int interface);

#endif /* _ICMP_H_ */

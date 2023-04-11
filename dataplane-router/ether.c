#include "ether.h"
#include "lib.h"
#include "protocols.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SIZE_OF_MAC 6

int check_ether_header(struct ether_header eth_hdr, int interface) {

	uint8_t mac[SIZE_OF_MAC];
	get_interface_mac(interface, mac);
	printf("router mac: ");
	for (int i = 0; i < 5; i++)
		printf("%X.", mac[i]);
	printf("%X\n", mac[5]);
	
	// the MAC destination of the package is not the same with the MAC address of the router or the broadcast address
	int ok_mac = 1;
	for (int i = 0; i < SIZE_OF_MAC; ++i) {
		if (eth_hdr.ether_dhost[i] != mac[i])
			ok_mac = 0;
	}

	int ok_broadcast = 1;
	for (int i = 0; i < SIZE_OF_MAC; ++i) {
		if (eth_hdr.ether_dhost[i] != 0xFF)
			ok_broadcast = 0;
	}

	return (ok_mac || ok_broadcast);
}

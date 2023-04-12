**Name: Ionescu Matei-Ștefan**  
**Group: 323CAb**

# PCom Homework #1 - Dataplane Router

The program implenets the dataplane of a router.

## Implementation
All the homework required functionalities are implemented and the homework
gets 100p on the checker.

### Router

When the router program starts it will intialize the **trie** that holds the
routing table, the **list** of packets waiting for an ARP reply and the
**hashtable** that holds the arp cache. Then, when the router receives a
packet it will check if the ethernet header is good. If it is not it will
drop the packet. Then it will process the packet according to its type (ARP
or IPv4).

### IPv4 Protocol

If the received packet is IPv4 the router will do the following operations:
1. It will check if router is the destination of the packet and if it should
send an icmp response.

2. It will check the checksum of the packet.

3. It will check and update the packet TTL field, if it is 1 or less it will
send a time exceeded icmp message and it will drop the packet.

4. It will search the routing table for the next hop it should send the packet
to, if it doesn't find one it sends a destination unreachable icmp message
and drops the packet.

5. It will update checksum.

6. It will rewrite the ethernet header asking for the mac of the next hop using
the ARP protocol if it is not already in the arp cache.

7. It will send the packet to the next hop

### ARP Protocol
The ARP cache is implemented using the **hashtable** data strucure.

When an ARP packet is received the router will check if it is an ARP Reply or
an ARP Request. If it is an ARP Request the router will send back the response.
Otherwise, the router adds the received (ip, mac) pair to the **hashtable** and sends
the packets from the waiting list that required the received mac address. 


### LPM
The longest prefix matched is found using a search in the routing table **trie**.
#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_table_entry *arp_table;
int arp_table_len;

// Searches in a routing table for the best route to a given ip
// Returns the best route or NULL if no route is found
void calculate_best_route(uint32_t ip_dest, struct route_table_entry **best_route) {
	
    int left = 0;
    int right = rtable_len - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;

		if ((ip_dest & rtable[mid].mask) == rtable[mid].prefix) {
			if (((struct route_table_entry *)(*best_route)) == NULL ||
			 ntohl(rtable[mid].mask) > ntohl(((struct route_table_entry *)(*best_route))->mask)) {
				*best_route = &rtable[mid];
			}
		}

        if (ntohl(rtable[mid].prefix) <= ntohl(ip_dest))
            left = mid + 1;
        else
            right = mid - 1;
    }
}

// This function uses insertionsort to sort the routing table
// if the prefix is the same, it sorts by the mask
void insertion_sort_rtable() {
	for (int i = 1; i < rtable_len; ++i) {
		struct route_table_entry key = rtable[i];
		int j = i - 1;

		// sort by the prefix
		while (j >= 0 && ntohl(rtable[j].prefix) > ntohl(key.prefix)) {
			rtable[j + 1] = rtable[j];
			j = j - 1;
		}
		// if the prefix is the same, sort by the mask
		while (j >= 0 && ntohl(rtable[j].prefix) == ntohl(key.prefix) && ntohl(rtable[j].mask) > ntohl(key.mask)) {
			rtable[j + 1] = rtable[j];
			j = j - 1;
		}
		rtable[j + 1] = key;
	}
}

// This functiom uses insertionsort to sort the arp table
void insertion_sort_arp_table() {
	for (int i = 1; i < arp_table_len; ++i) {
		struct arp_table_entry key = arp_table[i];
		int j = i - 1;

		while (j >= 0 && ntohl(arp_table[j].ip) > ntohl(key.ip)) {
			arp_table[j + 1] = arp_table[j];
			j = j - 1;
		}
		arp_table[j + 1] = key;
	}
}

// This function returns the arp table entry for a given ip from the arp table
void get_mac_entry(uint32_t ip, struct arp_table_entry **mac_entry) {
	int left = 0;
	int right = arp_table_len - 1;

	while (left <= right) {
		int mid = left + (right - left) / 2;

		if (arp_table[mid].ip == ip) {
			*mac_entry = &arp_table[mid];
			return;
		}

		if (ntohl(arp_table[mid].ip) <= ntohl(ip))
			left = mid + 1;
		else
			right = mid - 1;
	}
}

// This function sends an ICMP error message to the sender
void send_icmp_error(char *packet, int interface, uint8_t type, uint8_t code) {
	// Get the ethernet header from the packet
	struct ether_header *eth_hdr = (struct ether_header *) packet;

	// Get the IP header from the packet
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	// Get the ICMP header from the packet
	struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	// Save the old ip header
	struct iphdr old_ip_hdr = *ip_hdr;

	// Update the IP header
	ip_hdr->daddr = old_ip_hdr.saddr;
	ip_hdr->saddr = old_ip_hdr.daddr;
	ip_hdr->ttl = TTL;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->check = 0;
	ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

	// Update the ICMP header
	icmp_hdr->type = type;
	icmp_hdr->code = code;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));

	// Update the ethernet header
	uint8_t mac[6];
	get_interface_mac(interface, mac);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, mac, 6);

	// Send the packet
	send_to_link(interface, packet, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
}

// This function sends an ICMP reply message to the sender
void send_icmp_reply(char *packet, int interface, uint8_t type, uint8_t code) {
	// Get the ethernet header from the packet
	struct ether_header *eth_hdr = (struct ether_header *) packet;

	// Get the IP header from the packet
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	// Get the ICMP header from the packet
	struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	// Save the old ip header
	struct iphdr old_ip_hdr = *ip_hdr;

	// Swap the source and destination ip addresses
	ip_hdr->daddr = old_ip_hdr.saddr;
	ip_hdr->saddr = old_ip_hdr.daddr;

	// Update the IP header
	ip_hdr->ttl = TTL;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->check = 0;
	ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

	// Update the ICMP header
	icmp_hdr->type = type;
	icmp_hdr->code = code;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));

	// Update the ethernet header
	uint8_t mac[6];
	get_interface_mac(interface, mac);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, mac, 6);

	// Send the packet
	send_to_link(interface, packet, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
}

// This function gets the router ip from the interface
void get_router_ip(int interface, uint32_t *router_ip) {
	char *interface_ip = get_interface_ip(interface);
	inet_pton(AF_INET, interface_ip, router_ip);
}

int main(int argc, char *argv[])
{
	char packet[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Allocate the routing table
	rtable = malloc(sizeof(struct route_table_entry) * 1000000);

	// Check if the memory was allocated for the routing table
	DIE(rtable == NULL, "memory allocation error for rtable"); 

	// Allocate the arp table
	arp_table = malloc(sizeof(struct  arp_table_entry) * 1000000);

	// Check if the memory was allocated for the arp table
	DIE(arp_table == NULL, "memory allocation error for arp_table");
	
	// Read the routing table from the argv[1] file
	rtable_len = read_rtable(argv[1], rtable);

	// Sort the routing table so we can use binary search to find the best route
	// more efficiently than linear search
	insertion_sort_rtable();

	// Read the arp table from the "arp_table.txt" file
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	// Sort the arp table so we can use binary search to find the mac entry
	// more efficiently than linear search
	insertion_sort_arp_table();

	// Infinite loop to process the packets
	while (1) {
		int interface;
		size_t len;

		// Get the packet from any link and the interface
		// from which the packet was received
		interface = recv_from_any_link(packet, &len);
		DIE(interface < 0, "recv_from_any_link failed");
		
		// Get the ethernet header from the packet
		struct ether_header *eth_hdr = (struct ether_header *) packet;

		// Check if we got an IPv4 packet
		if (eth_hdr->ether_type == ntohs(IP_PROTOCOL)) {
			
			struct iphdr *ip_hdr = (struct iphdr *)((char *)eth_hdr +
						   sizeof(*eth_hdr));
			uint32_t router_ip;
			get_router_ip(interface, &router_ip);

			// Check if the packet is for the router
			if (ip_hdr->daddr == router_ip) {
				send_icmp_reply(packet, interface, 0, 0);
			} else {
				// Get the IP header from the packet
				struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

				// Check the integrity of the packet using the checksum function
				if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0) {
					printf("Packet is corrupted\n");
					fflush(stdout);
					continue;
				}

				// Check if the packet has expired (TTL < 1)
				if (ip_hdr->ttl <= 1) {
					// Time exceeded (ICMP error code 11, type 0)
					// Send an ICMP error message to the sender
					send_icmp_error(packet, interface, 11, 0);
					continue;
				}
				// Decrease the TTL
				int old_ttl = ip_hdr->ttl;
				ip_hdr->ttl -= 1;

				// Update the checksum because we modified the TTL
				int old_check = ip_hdr->check;
				
				// Calculate the new checksum using the formula from the lab
				// https://pcom.pages.upb.ro/labs/lab4/ipv4.html
				ip_hdr->check = ~(~old_check +  ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

				// Now the packet is ready to be forwarded, we need to find the next hop
				struct route_table_entry *best_route = NULL;
				calculate_best_route(ip_hdr->daddr, &best_route);

				// Check if we found a route
				if (best_route == NULL) {
					// Best effort was made, but no route was found :(
					// Host unreachable (ICMP error code 3, type 0)
					// Send an ICMP error message to the sender
					send_icmp_error(packet, interface, 3, 0);
					continue;
				}
				
				// Get the mac entry for the next hop
				struct arp_table_entry *mac_entry;
				get_mac_entry(best_route->next_hop, &mac_entry);
				if (mac_entry == NULL) {
					// The mac entry was not found in the arp table
					continue;
				}
				
				// Now we have the mac entry for the next hop, we can update the ethernet header
				memcpy(eth_hdr->ether_dhost, mac_entry->mac, 6);

				// Get the mac address of the interface
				uint8_t mac[6];
				get_interface_mac(best_route->interface, mac);

				// Update the source mac address
				memcpy(eth_hdr->ether_shost, mac, 6);

				// Forward the packet to the next hop
				send_to_link(best_route->interface, packet, len);
			}

		} else if (eth_hdr->ether_type == ntohs(ARP_PROTOCOL)) {
			// Am incercat sa fac ARP dinamic, dar nu am reusit :(
		} else {
			printf("Ignored non-IPv4 packet or non-ARP packet\n");
			fflush(stdout);
			continue;
		}
	}
}


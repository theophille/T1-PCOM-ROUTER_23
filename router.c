#include <arpa/inet.h>
#include <string.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"

int rtable_size;
struct route_table_entry *rtable;

int atable_size;
struct arp_entry *atable;

uint8_t compare_mac_addresses(uint8_t *fst_mac, uint8_t *scd_mac) {
	for(uint8_t bit = 0; bit < 6; bit++)
		if(fst_mac[bit] != scd_mac[bit])
			return 0;
	return 1;
}

struct route_table_entry *longest_prefix_match(uint32_t dest_ip) {
	uint32_t max_mask = 0x0;
	struct route_table_entry *search_result = NULL;

	for(int i = 0; i < rtable_size; i++) {
		if((dest_ip & rtable[i].mask) == rtable[i].prefix)
			if(rtable[i].mask > max_mask) {
				max_mask = rtable[i].mask;
				search_result = &rtable[i];
			}
	}

	return search_result;
}

void get_mac_address_from_cache(uint32_t ip, uint8_t *mac) {
	for(int i = 0; i < atable_size; i++) {
		if(ip == atable[i].ip) {
			memcpy(mac, atable[i].mac, 6);
			break;
		}
	}
}

void print_mac_address(uint8_t *mac) {
	for(int i = 0; i < 6; i++) {
		printf("%hhx", mac[i]);
		if(i != 5)
			printf(":");
	}
	printf("\n");
}

void ipv4_protocol(char *buf, size_t len) {
	struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));
	uint16_t src_checksum = ip_header->check;
	ip_header->check = 0;
	uint16_t dest_checksum = checksum((uint16_t *)ip_header, sizeof(struct iphdr));
	// printf("Real Checksum -> %hx\n", htons(src_checksum));
	// printf("Recalc Checksum -> %hx\n", htons(dest_checksum));

	struct route_table_entry *next_hop_data;

	enum ip_prot {
		checking_packet,
		checking_packet_err,
		ttl,
		ttl_err,
		finding_route,
		finding_route_err,
		sending_arp,
		end
	};

	enum ip_prot state = checking_packet;

	while(state != end) {
		switch (state) {
			case checking_packet:
				if(ntohs(src_checksum) == dest_checksum)
					state = ttl;
				else state = checking_packet_err;
				break;

			case checking_packet_err:
				write(1, "chk_drop", 9);
				state = end;
				break;

			case ttl:
				if(ip_header->ttl != 0 && ip_header->ttl != 1) {
					ip_header->ttl -= 1;
					state = finding_route;
				} else state = ttl_err;
				break;

			case ttl_err:
				write(1, "ttl_drop", 9);
				state = end;
				break;

			case finding_route:
				next_hop_data = longest_prefix_match(ip_header->daddr);
				if(next_hop_data != NULL)
					state = sending_arp;
				else state = finding_route_err;
				break;

			case finding_route_err:
				write(1, "lpm_drop", 9);
				state = end;
				break;

			case sending_arp:
				ip_header->check = 0x0;
				uint16_t new_chk = checksum((uint16_t *)ip_header, sizeof(struct iphdr));
				ip_header->check = htons(new_chk);
				//printf("CHECK --> %hx\n", ip_header->check);

				struct ether_header *eth_hdr = (struct ether_header *)buf;
				get_interface_mac(next_hop_data->interface, eth_hdr->ether_shost);
				get_mac_address_from_cache(next_hop_data->next_hop, eth_hdr->ether_dhost);
				eth_hdr->ether_type = htons(0x0800);

				// print_mac_address(eth_hdr->ether_dhost);
				// print_mac_address(eth_hdr->ether_shost);

				size_t headers_length = sizeof(sizeof(struct ether_header) + sizeof(struct iphdr));

				// char *send_buf = (char *)calloc(MAX_PACKET_LEN, sizeof(char));
				// memcpy(send_buf, &eth_hdr, sizeof(struct ether_header));
				// memcpy(send_buf + sizeof(struct ether_header), ip_header, sizeof(struct iphdr));
				// memcpy(send_buf + headers_length, buf + headers_length, MAX_PACKET_LEN - headers_length);

				//printf("Interface id: %d\nbuf len: %lu\n", next_hop_data->interface, len);
				send_to_link(next_hop_data->interface, buf, len);

				// struct arp_header arp_header;
				// arp_header.htype = htons(0x1);
				// arp_header.ptype = htons(0x0800);
				// arp_header.hlen = 0x6;
				// arp_header.plen = 0x4;
				// arp_header.op = htons(0x1);
				// get_interface_mac(next_hop_data->interface, arp_header.sha);
				// arp_header.spa = *(uint32_t *)get_interface_ip(next_hop_data->interface);
				// get_mac_address_from_cache(next_hop_data->next_hop, arp_header.tha);
				// arp_header.tpa = htonl(next_hop_data->next_hop);

				state = end;
				break;

			default:
				break;
		}
	}
}

int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);
	
	rtable = (struct route_table_entry *)malloc(80000 * sizeof(struct route_table_entry));
	rtable_size = read_rtable(argv[1], rtable);
	
	atable = (struct arp_entry *)malloc(20 * sizeof(struct arp_entry));
	atable_size = parse_arp_table("arp_table.txt", atable);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		uint8_t *intf_mac = (uint8_t *)malloc(6 * sizeof(uint8_t));
		get_interface_mac(interface, intf_mac);

		if(compare_mac_addresses(eth_hdr->ether_dhost, intf_mac)) {
			switch(ntohs(eth_hdr->ether_type)) {
				case 0x0800:
					ipv4_protocol(buf, len);
					break;
				case 0x0806:
					write(1, "ARP", 4);
					break;
			}
		}
	}
}


#include <arpa/inet.h>
#include <string.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"

int rtable_size;
struct route_table_entry *rtable;

int atable_size;
struct arp_entry *atable;

const size_t iph_len = sizeof(struct iphdr);
const size_t eth_len = sizeof(struct ether_header);
const size_t icmph_len = sizeof(struct icmphdr);
const size_t arph_len = sizeof(struct arp_header);

queue arp_queue;

struct queue_packet {
	int interface;
	size_t len;
	char *buf;
};

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

int get_mac_address_from_cache(uint32_t ip, uint8_t *mac) {
	for(int i = 0; i < atable_size; i++) {
		if(ip == atable[i].ip) {
			memcpy(mac, atable[i].mac, 6);
			return 1;
		}
	}

	return -1;
}

void print_mac_address(uint8_t *mac) {
	for(int i = 0; i < 6; i++) {
		printf("%hhx", mac[i]);
		if(i != 5)
			printf(":");
	}
	printf("\n");
}

struct iphdr *create_ip_header(uint8_t protocol, uint32_t src_ip, uint32_t dest_ip) {
	struct iphdr *ip_header = (struct iphdr*)malloc(sizeof(struct iphdr));
	
	ip_header->version = 4;
	ip_header->ihl = 5;
	ip_header->tos = 0;
	ip_header->tot_len = 0;
	ip_header->id = htons(1);
	ip_header->frag_off = 0;
	ip_header->ttl = 64;
	ip_header->protocol = protocol;
	ip_header->check = 0;
	ip_header->saddr = src_ip;
	ip_header->daddr = dest_ip;

	return ip_header;
}

void send_icmp(char *buf, uint8_t type, uint8_t code, int send_interf) {
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	uint8_t *aux = (uint8_t *)malloc(6 * sizeof(uint8_t));
	memcpy(aux, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, aux, 6);
	free(aux);

	struct iphdr *iphdr_buf_address = (struct iphdr *)(buf + eth_len);
	struct iphdr *new_ip_header = create_ip_header(1, iphdr_buf_address->daddr, iphdr_buf_address->saddr);

	struct icmphdr icmphdr;
	icmphdr.type = type;
	icmphdr.code = code;
	icmphdr.checksum = 0;

	size_t icmp_buf_len;
	char *icmp_buf;

	if(type == 0 && code == 0) {
		icmp_buf_len = eth_len + iph_len + icmph_len + 8;
		icmp_buf = (char *)calloc(icmp_buf_len, sizeof(char));

		struct icmphdr *buf_icmphdr = (struct icmphdr *)(buf + eth_len + iph_len);

		memcpy(icmp_buf, eth_hdr, eth_len);
		memcpy(icmp_buf + eth_len, new_ip_header, iph_len);
		icmphdr.un.echo.id = buf_icmphdr->un.echo.id;
		icmphdr.un.echo.sequence = buf_icmphdr->un.echo.sequence;
		memcpy(icmp_buf + eth_len + iph_len, &icmphdr, icmph_len);
		memcpy(icmp_buf + eth_len + iph_len + icmph_len, buf + eth_len + iph_len, 8);
	}

	if((type == 11 && code == 0) || (type == 3 && code == 0)) {
		icmp_buf_len = eth_len + 2 * iph_len + 16;
		icmp_buf = (char *)calloc(icmp_buf_len, sizeof(char));

		memcpy(icmp_buf, eth_hdr, eth_len);
		memcpy(icmp_buf + eth_len, new_ip_header, iph_len);
		icmphdr.un.echo.id = 0;
		icmphdr.un.echo.sequence = 0;
		memcpy(icmp_buf + eth_len + iph_len, &icmphdr, icmph_len);
		memcpy(icmp_buf + eth_len + iph_len + icmph_len, iphdr_buf_address, iph_len + 8);
	}

	struct icmphdr *icmp_buf_icmphdr = (struct icmphdr *)(icmp_buf + eth_len + iph_len);
	icmp_buf_icmphdr->checksum = htons(checksum((uint16_t *)icmp_buf_icmphdr, icmp_buf_len - eth_len - iph_len));

	struct iphdr *icmp_buf_iphdr = (struct iphdr *)(icmp_buf + eth_len);
	icmp_buf_iphdr->check = htons(checksum((uint16_t *)icmp_buf_iphdr, icmp_buf_len - eth_len));
	icmp_buf_iphdr->tot_len = htons(icmp_buf_len - eth_len);

	send_to_link(send_interf, icmp_buf, icmp_buf_len);

	free(icmp_buf);
}

void ipv4_protocol(char *buf, size_t len, int recv_interf) {
	struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));
	uint16_t src_checksum = ip_header->check;
	ip_header->check = 0;
	uint16_t dest_checksum = checksum((uint16_t *)ip_header, sizeof(struct iphdr));

	struct route_table_entry *next_hop_data;

	enum ip_prot {
		checking_packet,
		checking_packet_err,
		router_as_destination,
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
					state = router_as_destination;
				else state = checking_packet_err;
				break;

			case checking_packet_err:
				write(1, "chk_drop", 9);
				state = end;
				break;

			case router_as_destination:
				char *router_ip = get_interface_ip(recv_interf);
				char r_ip_in_bytes[4];

				int i = 0;
				char *token = strtok(router_ip, ".");

				while(token != NULL) {
					r_ip_in_bytes[i++] = (uint8_t)atoi(token);
					token = strtok(NULL, ".");
				}

				if(ip_header->daddr == *(uint32_t *)r_ip_in_bytes) {
					send_icmp(buf, 0, 0, recv_interf);
				
				state = end;
				} else state = ttl;

				break;

			case ttl:
				if(ip_header->ttl != 0 && ip_header->ttl != 1) {
					ip_header->ttl -= 1;
					state = finding_route;
				} else state = ttl_err;
				break;

			case ttl_err:
				send_icmp(buf, 11, 0, recv_interf);
				state = end;
				break;

			case finding_route:
				next_hop_data = longest_prefix_match(ip_header->daddr);
				if(next_hop_data != NULL) {
					state = sending_arp;
				}
				else state = finding_route_err;
				break;

			case finding_route_err:
				write(1, "lpm_drop", 9);
				send_icmp(buf, 3, 0, recv_interf);
				state = end;
				break;

			case sending_arp:
				ip_header->check = 0x0;
				uint16_t new_chk = checksum((uint16_t *)ip_header, sizeof(struct iphdr));
				ip_header->check = htons(new_chk);
				
				struct ether_header *eth_hdr = (struct ether_header *)buf;
				get_interface_mac(next_hop_data->interface, eth_hdr->ether_shost);
				eth_hdr->ether_type = htons(0x0800);

				if(get_mac_address_from_cache(next_hop_data->next_hop, eth_hdr->ether_dhost) > 0) {
					send_to_link(next_hop_data->interface, buf, len);
				} else {
					size_t broadcast_buf_len = eth_len + arph_len;
					char *broadcast_buf = (char *)calloc(eth_len + arph_len, sizeof(char));
					struct ether_header *b_ether = (struct ether_header *)broadcast_buf;
					memcpy(b_ether->ether_shost, eth_hdr->ether_dhost, 6);
					for(int i = 0; i < 6; i++)
						b_ether->ether_dhost[i] = 0xff;
					b_ether->ether_type = htons(0x0806);

					struct arp_header arp_header;
					arp_header.htype = htons(0x1);
					arp_header.ptype = htons(0x0800);
					arp_header.hlen = 0x6;
					arp_header.plen = 0x4;
					arp_header.op = htons(0x1);
					get_interface_mac(next_hop_data->interface, arp_header.sha);
					inet_pton(AF_INET, get_interface_ip(next_hop_data->interface), &arp_header.spa);
					for(int i = 0; i < 6; i++)
						arp_header.tha[i] = 0x0;
					arp_header.tpa = next_hop_data->next_hop;

					memcpy(broadcast_buf + eth_len, &arp_header, arph_len);

					send_to_link(next_hop_data->interface, broadcast_buf, broadcast_buf_len);

					struct queue_packet *qp = (struct queue_packet *)malloc(sizeof(struct queue_packet));
					qp->interface = next_hop_data->interface;
					qp->buf = (char *)malloc(len);
					qp->len = len;
					memcpy(qp->buf, buf, len);
					queue_enq(arp_queue, qp);

					free(broadcast_buf);
				}

 
				state = end;
				break;

			default:
				break;
		}
	}
}

void arp_protocol(char *buf, size_t len) {
	if(!queue_empty(arp_queue)) {
		struct queue_packet *queue_packet = (struct queue_packet *)queue_deq(arp_queue);
		struct ether_header *buf_eth = (struct ether_header *)buf;
		struct arp_header *buf_arph = (struct arp_header *)(buf + eth_len);
		struct ether_header *q_buf_eth = (struct ether_header *)queue_packet->buf;

		memcpy(q_buf_eth->ether_dhost, buf_eth->ether_shost, 6);

		atable[atable_size].ip = buf_arph->spa;
		memcpy(atable[atable_size].mac, buf_eth->ether_shost, 6);
		atable_size++;

		send_to_link(queue_packet->interface, queue_packet->buf, queue_packet->len);

		free(queue_packet->buf);
		free(queue_packet);
	}
}

int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);
	
	rtable = (struct route_table_entry *)malloc(100000 * sizeof(struct route_table_entry));
	rtable_size = read_rtable(argv[1], rtable);
	
	atable = (struct arp_entry *)malloc(50 * sizeof(struct arp_entry));
	atable_size = 0;

	arp_queue = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		uint8_t *intf_mac = (uint8_t *)malloc(6 * sizeof(uint8_t));
		get_interface_mac(interface, intf_mac);

		uint8_t broadcast_address[6];
		for(int i = 0; i < 6; i++)
			broadcast_address[i] = 0xff;

		struct arp_header *arph = (struct arp_header *)(buf + eth_len);
		if(compare_mac_addresses(eth_hdr->ether_dhost, broadcast_address)
			|| (compare_mac_addresses(eth_hdr->ether_dhost, intf_mac) 
				&& eth_hdr->ether_type == htons(0x0806)
				&& arph->op == htons(0x1))) {
			struct arp_header *bc_arp_header = (struct arp_header *)(buf + eth_len);
			char *intf_ip = get_interface_ip(interface);
			uint32_t nw_intf_ip;
			inet_pton(AF_INET, intf_ip, &nw_intf_ip);

			if(bc_arp_header->tpa == nw_intf_ip) {
				char arp_reply[eth_len + arph_len];
				struct ether_header *arp_reply_eth_hdr = (struct ether_header *)arp_reply;

				memcpy(arp_reply_eth_hdr->ether_shost, intf_mac, 6);
				memcpy(arp_reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				arp_reply_eth_hdr->ether_type = htons(0x0806);

				struct arp_header *arp_header = (struct arp_header *)(arp_reply + eth_len);
				arp_header->htype = htons(0x1);
				arp_header->ptype = htons(0x0800);
				arp_header->hlen = 0x6;
				arp_header->plen = 0x4;
				arp_header->op = htons(0x2);
				memcpy(arp_header->sha, intf_mac, 6);
				arp_header->spa = nw_intf_ip;
				memcpy(arp_header->tha, eth_hdr->ether_shost, 6);
				arp_header->tpa = bc_arp_header->spa;

				send_to_link(interface, arp_reply, eth_len + arph_len);
			}

		} else if(compare_mac_addresses(eth_hdr->ether_dhost, intf_mac)) {

			switch(ntohs(eth_hdr->ether_type)) {
				case 0x0800:
					ipv4_protocol(buf, len, interface);
					break;
				case 0x0806:
					arp_protocol(buf, len);
					break;
			}

		} else {

		}
	}
}
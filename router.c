#include <arpa/inet.h>
#include <string.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define FST_BIT_MASK 0x80000000;

int rtable_size;
struct route_table_entry *rtable;

int atable_size;
struct arp_entry *atable;

const size_t iph_len = sizeof(struct iphdr);
const size_t eth_len = sizeof(struct ether_header);
const size_t icmph_len = sizeof(struct icmphdr);
const size_t arph_len = sizeof(struct arp_header);

queue arp_queue;

/* Queued packet structure */
struct queue_packet {
	int interface;
	uint32_t next_hop;
	size_t len;
	char *buf;
};

struct trie_node {
	struct route_table_entry *rte;
	struct trie_node *zero;
	struct trie_node *one;
};

struct trie_node *prefix_tree;

/* Creates a new trie node and returns it */
struct trie_node *create_trie_node() {
	struct trie_node *tn = (struct trie_node *)malloc(sizeof(struct trie_node));
	tn->zero = NULL;
	tn->one = NULL;
	tn->rte = NULL;
	return tn;
}

/* Creates the trie data structure based on the routing table entry's prefix field*/
struct trie_node *create_prefix_tree() {
	struct trie_node *root = create_trie_node();

	for(uint32_t i = 0; i < rtable_size; i++) {
		uint8_t bit = 0;
		struct trie_node *cursor = root;
		uint32_t current_prefix = ntohl(rtable[i].prefix);
		uint32_t current_mask = ntohl(rtable[i].mask);

		while(bit != 32) {
			/* If the mask is 0, the end of the current prefix is reached */
			if(current_mask == 0)
				break;

			/* Checking if the current bit of the prefix is a 1.
			 * Else, our current bit is 0.
			 * Based on the current bit value, a new node is added to the trie if
			 * it doesn't exist. */
			uint32_t current_bit = current_prefix & FST_BIT_MASK;
			
			if(current_bit == 0x80000000) {
				if(cursor->one == NULL)
					cursor->one = create_trie_node();
				cursor = cursor->one;
			} else {
				if(cursor->zero == NULL)
					cursor->zero = create_trie_node();
				cursor = cursor->zero;
			}

			/* Moving to the next iteration by left shifting all the bits of the
			 * prefix and of the mask by one position and by incrementing the bit
			 * index */
			current_prefix = current_prefix << 1;
			current_mask = current_mask << 1;
			bit++;
		}

		/* Copying the current routing table entry address in the rte field of
		 * the node which was reached by traversing the prefix bits route */
		cursor->rte = &rtable[i];
	}

	return root;
}

/* Searches the LPM in the trie */
struct route_table_entry *longest_prefix_match(uint32_t dest_ip, struct trie_node *root) {
	struct route_table_entry *search_result = NULL;
	struct trie_node *cursor = root;
	uint8_t bit = 0;

	dest_ip = htonl(dest_ip);

	/* Traversing the trie based on the destination ip bits */
	while(bit != 32) {
		/* Checking if the first bit of the destination ip is 1.
		 * Else, the current bit is 0.
		 * Based on the current bit value, the zero or the one node is chosen
		 * if it's NULL. */
		uint32_t current_bit = dest_ip & FST_BIT_MASK;

		if(current_bit == 0x80000000) {
			if(cursor->one != NULL)
				cursor = cursor->one;
			else break;
		} else {
			if(cursor->zero != NULL)
				cursor = cursor->zero;
			else break;
		}

		/* If the current node doesn't have the rte field empty, the address stored
		 * in this field is saved in the search result variable */
		if(cursor->rte != NULL)
			search_result = cursor->rte;

		/* Moving to the next iteration by left shifting all the bits of the
		 * destination ip by one position and by incrementing the bit index*/
		bit++;
		dest_ip = dest_ip << 1;
	}

	return search_result;
}

/* Compares two mac addresses and returns 1 if the addresses are identical
 * and returns 0 if they are different */
uint8_t compare_mac_addresses(uint8_t *fst_mac, uint8_t *scd_mac) {
	for(uint8_t bit = 0; bit < 6; bit++)
		if(fst_mac[bit] != scd_mac[bit])
			return 0;
	return 1;
}

/* Checks the ARP cache and if the ip address is present, returns 1, else -1. */
int get_mac_address_from_cache(uint32_t ip, uint8_t *mac) {
	for(int i = 0; i < atable_size; i++) {
		if(ip == atable[i].ip) {
			memcpy(mac, atable[i].mac, 6);
			return 1;
		}
	}

	return -1;
}

/* Prints a mac address */
void print_mac_address(uint8_t *mac) {
	for(int i = 0; i < 6; i++) {
		printf("%hhx", mac[i]);
		if(i != 5)
			printf(":");
	}
	printf("\n");
}

/* Creates and returns an IP header structure based on the protocol, source ip and
 * and destination ip that it receives*/
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

/* Creates and sends an ICMP message based on the type and code you give */
void send_icmp(char *buf, uint8_t type, uint8_t code, int send_interf) {
	struct ether_header *eth_hdr = (struct ether_header *)buf;

	/* Swapping buffer's ethernet header MAC addresses */
	uint8_t *aux = (uint8_t *)malloc(6 * sizeof(uint8_t));
	memcpy(aux, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, aux, 6);
	free(aux);

	struct iphdr *iphdr_buf_address = (struct iphdr *)(buf + eth_len);

	/* Creating the new packet IP header */
	struct iphdr *new_ip_header = create_ip_header(1, iphdr_buf_address->daddr, iphdr_buf_address->saddr);

	/* Creating the ICMP header */
	struct icmphdr icmphdr;
	icmphdr.type = type;
	icmphdr.code = code;
	icmphdr.checksum = 0;

	/* Initializing the ICMP packet buffer */
	size_t icmp_buf_len;
	char *icmp_buf;

	/* ICMP reply */
	if(type == 0 && code == 0) {
		icmp_buf_len = eth_len + iph_len + icmph_len + 8;
		icmp_buf = (char *)calloc(icmp_buf_len, sizeof(char));

		struct icmphdr *buf_icmphdr = (struct icmphdr *)(buf + eth_len + iph_len);

		/* Filling the ICMP buffer */
		memcpy(icmp_buf, eth_hdr, eth_len);
		memcpy(icmp_buf + eth_len, new_ip_header, iph_len);
		icmphdr.un.echo.id = buf_icmphdr->un.echo.id; /* Copying the old id */
		icmphdr.un.echo.sequence = buf_icmphdr->un.echo.sequence; /* Copying the old sequence */
		memcpy(icmp_buf + eth_len + iph_len, &icmphdr, icmph_len);
		memcpy(icmp_buf + eth_len + iph_len + icmph_len, buf + eth_len + iph_len, 8);
	}

	/* ICMP -> Time exceeded OR ICMP -> Destination unreachable*/
	if((type == 11 && code == 0) || (type == 3 && code == 0)) {
		icmp_buf_len = eth_len + 2 * iph_len + 16;
		icmp_buf = (char *)calloc(icmp_buf_len, sizeof(char));

		/* Filling the ICMP buffer */
		memcpy(icmp_buf, eth_hdr, eth_len);
		memcpy(icmp_buf + eth_len, new_ip_header, iph_len);
		icmphdr.un.echo.id = 0; /* Unused area */
		icmphdr.un.echo.sequence = 0; /* Unused area */
		memcpy(icmp_buf + eth_len + iph_len, &icmphdr, icmph_len);
		memcpy(icmp_buf + eth_len + iph_len + icmph_len, iphdr_buf_address, iph_len + 8);
	}

	/* Calculating the ICMP header checksum */
	struct icmphdr *icmp_buf_icmphdr = (struct icmphdr *)(icmp_buf + eth_len + iph_len);
	icmp_buf_icmphdr->checksum = htons(checksum((uint16_t *)icmp_buf_icmphdr, icmp_buf_len - eth_len - iph_len));

	/* Calculating the IP header checksum*/
	struct iphdr *icmp_buf_iphdr = (struct iphdr *)(icmp_buf + eth_len);
	icmp_buf_iphdr->check = htons(checksum((uint16_t *)icmp_buf_iphdr, icmp_buf_len - eth_len));
	icmp_buf_iphdr->tot_len = htons(icmp_buf_len - eth_len);

	/* Sending the ICMP message through the given interface */
	send_to_link(send_interf, icmp_buf, icmp_buf_len);

	free(icmp_buf);
}

/* Handles IP packets */
void ipv4_protocol(char *buf, size_t len, int recv_interf) {
	struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));
	uint16_t src_checksum = ip_header->check;
	ip_header->check = 0;
	uint16_t dest_checksum = checksum((uint16_t *)ip_header, sizeof(struct iphdr));

	struct route_table_entry *next_hop_data;

	enum ip_prot {
		checking_packet, // the checksum is verified
		checking_packet_err, // the checksum isn't good
		router_as_destination, // checking if the router is the destination. If true, an ICMP REPLY is sent
		ttl, // checking the time to live field
		ttl_err, // the time to live is 0 or 1. An ICMP Time exceeded message is sent
		finding_route, // finding the LPM
		finding_route_err, // LPM not found. Destination unreachable message is sent
		sending, // sending the packet (or an ARP REQUEST packet, and the packet is queued)
		end
	};

	enum ip_prot state = checking_packet;

	/* The IP protocol state machine */
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
				;
				char *router_ip = get_interface_ip(recv_interf);

				uint32_t n_router_ip;
				inet_pton(AF_INET, router_ip, &n_router_ip);

				/* If the router is the destination of the packet, an ICMP reply is sent */
				if(ip_header->daddr == n_router_ip) {
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
				next_hop_data = longest_prefix_match(ip_header->daddr, prefix_tree);
				if(next_hop_data != NULL)
					state = sending;
				else state = finding_route_err;
				break;

			case finding_route_err:
				write(1, "lpm_drop", 9);
				send_icmp(buf, 3, 0, recv_interf);
				state = end;
				break;

			case sending:
				/* Recalculating the checksum of the packet */
				ip_header->check = 0x0;
				uint16_t new_chk = checksum((uint16_t *)ip_header, sizeof(struct iphdr));
				ip_header->check = htons(new_chk);
				
				struct ether_header *eth_hdr = (struct ether_header *)buf;
				get_interface_mac(next_hop_data->interface, eth_hdr->ether_shost);

				/* Searching the mac address associated to the next hop ip address in the ARP cache
				 * If the address is found, the packet is sent (this function also writes the mac 
				 * address at the given address - the second parameter)
				 * If the address couldn't be found, an ARP REQUEST is created and sent and the
				 * packet is queued to be sent when the ARP REPLY will come with the mac address
				 * of the next hop */
				if(get_mac_address_from_cache(next_hop_data->next_hop, eth_hdr->ether_dhost) > 0) {
					/* Sending the packet to the next hop */
					send_to_link(next_hop_data->interface, buf, len);
				} else {
					/* Creating the ARP REQUEST */
					size_t broadcast_buf_len = eth_len + arph_len;
					char *broadcast_buf = (char *)calloc(eth_len + arph_len, sizeof(char));
					struct ether_header *b_ether = (struct ether_header *)broadcast_buf;
					memcpy(b_ether->ether_shost, eth_hdr->ether_dhost, 6);

					/* Filling the destination mac address of the ether header with the broadcast
					 * address which is FF:FF:FF:FF:FF:FF */
					for(int i = 0; i < 6; i++)
						b_ether->ether_dhost[i] = 0xff;
					b_ether->ether_type = htons(0x0806);

					/* Creating the ARP header */
					struct arp_header arp_header;
					arp_header.htype = htons(0x1);
					arp_header.ptype = htons(0x0800);
					arp_header.hlen = 0x6;
					arp_header.plen = 0x4;
					arp_header.op = htons(0x1);
					get_interface_mac(next_hop_data->interface, arp_header.sha);
					inet_pton(AF_INET, get_interface_ip(next_hop_data->interface), &arp_header.spa);
					
					/* Zero-izing the target host address */
					for(int i = 0; i < 6; i++)
						arp_header.tha[i] = 0x0;
					arp_header.tpa = next_hop_data->next_hop;

					memcpy(broadcast_buf + eth_len, &arp_header, arph_len);
					
					/* Sending the ARP REQUEST */
					send_to_link(next_hop_data->interface, broadcast_buf, broadcast_buf_len);
					
					/* Enqueue-ing the IP packet */
					struct queue_packet *qp = (struct queue_packet *)malloc(sizeof(struct queue_packet));
					qp->interface = next_hop_data->interface;
					qp->next_hop = next_hop_data->next_hop;
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

/* Returns a queue that contains all the packets whose next hop ip address
 * is equal to the destination ip given (dest_ip) */
queue get_queue_packets(uint32_t dest_ip) {
	queue matched = queue_create(); // contains the equality matched packets
	queue unmatched = queue_create(); //contains the rest of the packets

	/* Extracing the desired packets */
	while(!queue_empty(arp_queue)) {
		struct queue_packet *qp = (struct queue_packet *)queue_deq(arp_queue);
		
		if(dest_ip == qp->next_hop)
			queue_enq(matched, qp);
		else
			queue_enq(unmatched, qp);
	}

	/* Freeing the arp_queue memory, and assigning it the unmatched queue address */
	free(arp_queue);
	arp_queue = unmatched;
	
	return matched;
}

/* Parses an ARP REPLY */
void parse_arp_reply(char *buf, size_t len) {
	if(!queue_empty(arp_queue)) {
		struct ether_header *buf_eth = (struct ether_header *)buf;
		struct arp_header *buf_arph = (struct arp_header *)(buf + eth_len);

		/* Updating the ARP cache with the new IP -> MAC entry */
		atable[atable_size].ip = buf_arph->spa;
		memcpy(atable[atable_size].mac, buf_eth->ether_shost, 6);
		atable_size++;

		/* Getting all the packets that want to go to the buf_arph->spa address */
		queue matched = get_queue_packets(buf_arph->spa);

		/* Updating the ether_dhost of all these packets and sending them
		 * to the next hop */
		while(!queue_empty(matched)) {
			struct queue_packet *queue_packet = (struct queue_packet *)queue_deq(matched);
			struct ether_header *q_buf_eth = (struct ether_header *)queue_packet->buf;
			
			memcpy(q_buf_eth->ether_dhost, buf_eth->ether_shost, 6);
			
			send_to_link(queue_packet->interface, queue_packet->buf, queue_packet->len);

			free(queue_packet->buf);
			free(queue_packet);
		}

		free(matched);
	}
}

int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);
	
	/* Initializing the routing table */
	rtable = (struct route_table_entry *)malloc(100000 * sizeof(struct route_table_entry));
	rtable_size = read_rtable(argv[1], rtable);
	
	/* Initializing the ARP cache */
	atable = (struct arp_entry *)malloc(50 * sizeof(struct arp_entry));
	atable_size = 0;

	/* Creating the packet's waiting queue */
	arp_queue = queue_create();

	/* Creating the prefix tree (the trie) */
	prefix_tree = create_prefix_tree();

	while (1) {

		int interface;
		size_t len;

		/* Receiving a packet */
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		uint8_t *intf_mac = (uint8_t *)malloc(6 * sizeof(uint8_t));
		get_interface_mac(interface, intf_mac);

		uint8_t broadcast_address[6];
		for(int i = 0; i < 6; i++)
			broadcast_address[i] = 0xff;

		struct arp_header *arph = (struct arp_header *)(buf + eth_len);

		/* Checking if an ARP REQUEST is received */
		/* If true, an ARP REPLY is created and sent */
		/* Else if the destination mac of the packet matches the router's interface mac
		 * address, based on the ether_type the router does something */
		if(compare_mac_addresses(eth_hdr->ether_dhost, broadcast_address)
			|| (compare_mac_addresses(eth_hdr->ether_dhost, intf_mac) 
				&& eth_hdr->ether_type == htons(0x0806)
				&& arph->op == htons(0x1))) {
			struct arp_header *bc_arp_header = (struct arp_header *)(buf + eth_len);
			char *intf_ip = get_interface_ip(interface);
			uint32_t nw_intf_ip;
			inet_pton(AF_INET, intf_ip, &nw_intf_ip);

			/* Checking if the router is the destination of the ARP REQUEST */
			if(bc_arp_header->tpa == nw_intf_ip) {
				/* Building the ARP REPLY ETHERNET header */
				char arp_reply[eth_len + arph_len];
				struct ether_header *arp_reply_eth_hdr = (struct ether_header *)arp_reply;

				memcpy(arp_reply_eth_hdr->ether_shost, intf_mac, 6);
				memcpy(arp_reply_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				arp_reply_eth_hdr->ether_type = htons(0x0806);
				
				/* Building the ARP REPLY ARP header */
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

				/* Sending the ARP REPLY */
				send_to_link(interface, arp_reply, eth_len + arph_len);
			}

		} else if(compare_mac_addresses(eth_hdr->ether_dhost, intf_mac)) {
			switch(ntohs(eth_hdr->ether_type)) {
				/* The IP protocol is in the payload */
				case 0x0800:
					ipv4_protocol(buf, len, interface);
					break;
				
				/* An ARP REPLY was received */
				case 0x0806:
					parse_arp_reply(buf, len);
					break;
			}
		}
	}
}
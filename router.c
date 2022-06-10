#include "queue.h"
#include "skel.h"
#include "arp.h"

#define NR_RTABLE_ENTRIES 100000

int send_ICMP_packet(packet m, uint8_t type) {
	int rc = 0;

	packet ICMP_PACKET;

	ICMP_PACKET.interface = m.interface;
	ICMP_PACKET.len = sizeof(struct ether_header) + 
					  sizeof(struct iphdr) + 
					  sizeof(struct icmphdr);

	memset(ICMP_PACKET.payload, 0, MAX_LEN);

	struct ether_header *new_eth = (struct ether_header *)ICMP_PACKET.payload;
	struct ether_header *m_eth = (struct ether_header *)m.payload;

	memcpy(new_eth->ether_shost, m_eth->ether_dhost, ETH_ALEN);
	memcpy(new_eth->ether_dhost, m_eth->ether_shost, ETH_ALEN);
	new_eth->ether_type = htons(ETHERTYPE_IP);

	struct iphdr *new_ip = (struct iphdr *)(ICMP_PACKET.payload + 
											sizeof(struct ether_header));
	struct iphdr *m_ip = (struct iphdr *)(m.payload + 
											sizeof(struct ether_header));
	new_ip->tos = 0;
	new_ip->tot_len = htons(ICMP_PACKET.len - sizeof(struct ether_header));
	new_ip->frag_off = 0;
	new_ip->protocol = IPPROTO_ICMP;
	new_ip->check = 0;
	new_ip->ttl = 64;
	new_ip->daddr = m_ip->saddr;
	new_ip->saddr = inet_addr(get_interface_ip(m.interface));

	struct icmphdr *new_icmp = (struct icmphdr *)(ICMP_PACKET.payload +
											sizeof(struct ether_header) +
											sizeof(struct iphdr));
	new_icmp->checksum = 0;
	new_icmp->code = 0;
	new_icmp->type = type;

	new_icmp->checksum = icmp_checksum((uint16_t *)new_icmp, sizeof(struct icmphdr));
	new_ip->check = ip_checksum((uint8_t *)new_ip, sizeof(struct iphdr));

	printf("Trimit ICMP packet de tip %d\n", type);
	rc = send_packet(&ICMP_PACKET);
	DIE(rc < 0, "send_packet");
	return rc;
}

struct route_table_entry *get_best_route(uint32_t dest_ip, struct route_table_entry *rtable, int rtable_len) {
    size_t idx = -1;	

    for (size_t i = 0; i < rtable_len; i++) {
        if ((dest_ip & rtable[i].mask) == rtable[i].prefix) {
	    	if (idx == -1) idx = i;
	    	else if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask)) idx = i;
		}
    }
    
    if (idx == -1)
        return NULL;

    else
        return &rtable[idx];
}

int send_ARP_request(packet m) {
	int rc = 0;

	packet arp_request;
	arp_request.len = sizeof(struct ether_header) + sizeof(struct arp_header);
	struct ether_header *eth = (struct ether_header *)arp_request.payload;
	eth->ether_type = htons(ETHERTYPE_ARP);
	rc = hwaddr_aton("ff:ff:ff:ff:ff:ff", eth->ether_dhost);
	DIE(rc < 0, "hwaddr_aton");
	get_interface_mac(m.interface, eth->ether_shost);

	struct arp_header *arp = (struct arp_header *)(arp_request.payload +
											sizeof(struct ether_header));
	arp->op = 1; //request
	arp->htype = 1;
	arp->ptype = 2048;
	arp->hlen = 6;
	arp->plen = 4;
	memcpy(arp->sha, eth->ether_shost, ETH_ALEN);
	arp->spa = inet_addr(get_interface_ip(m.interface));
	memset(arp->tha, 0, ETH_ALEN);

	struct iphdr *iphdr = (struct iphdr *)(m.payload + 
						sizeof(struct ether_header));

	arp->tpa = iphdr->daddr;

	arp_request.interface = 0;
	rc = send_packet(&arp_request);
	DIE(rc < 0, "send_packet");

	return rc;
}

uint8_t *get_MAC_arptable2(uint32_t ip, struct arp_entry *arp_table, int arp_table_len) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip)
			return arp_table[i].mac;
	}

	return NULL;
}

int IP_Protocol(packet m, queue *q, struct arp_entry *arp_table, int arp_table_len, 
					struct route_table_entry *rtable, int rtable_len) {
	int rc = 0;
	struct iphdr *iphdr = (struct iphdr *)(m.payload + 
											sizeof(struct ether_header));

	printf("A intrat pe IP\n");

	int checksum = iphdr->check;
	iphdr->check = 0; // pentru a nu influenta noul checksum
	//Daca checksum pica arunc packetul :))
	if (ip_checksum((uint8_t *)iphdr, sizeof(struct iphdr)) != checksum) {
		printf("Checksum picat\n");
		return 0;
	}

	if (iphdr->ttl <= 1) {
		// send "Time Exceeded" ICMP Packet
		printf("Time exceeded\n");
		rc = send_ICMP_packet(m, ICMP_TIME_EXCEEDED);
		DIE(rc < 0, "send_ICMP_packet");
		return rc;
	}

	iphdr->ttl--;

	//e pentru mine:
	if (iphdr->daddr == inet_addr(get_interface_ip(m.interface))) {
		printf("PACHETUL ARE ADRESA MEA IP! E PENTRU MINE\n");

		if (iphdr->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmphdr = (struct icmphdr *)(m.payload + 
										sizeof(struct ether_header) +
										sizeof(struct iphdr));

			if (icmphdr->type == ICMP_ECHO) {
				printf("Am primit ICMP_ECHO. Trimit pachet ICMP_ECHOREPLAY\n");
				rc = send_ICMP_packet(m, ICMP_ECHOREPLY);
				DIE(rc < 0, "send_ICMP_packet");
				return rc;
			}
		}
	} else {
		printf("Nu e pentru mine\n");
		struct route_table_entry *entry = get_best_route(iphdr->daddr, rtable, rtable_len);
		if (entry == NULL) {
			printf("Trimit pachet host unreacheable\n");
			rc = send_ICMP_packet(m, 3);
			DIE(rc < 0, "send_ICMP_packet");
			return rc;
		}

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		eth_hdr->ether_type = htons(ETHERTYPE_IP);
		memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, ETH_ALEN);
		m.interface = entry->interface;
		iphdr->daddr = entry->next_hop;
		iphdr->saddr = inet_addr(get_interface_ip(m.interface));

		uint8_t *MAC_dest = get_MAC_arptable2(entry->next_hop, arp_table, arp_table_len);
		// if (MAC_dest == NULL) {
		// 	printf("Trimit pachet ARP_Request\n");
		// 	queue_enq(*q, &m);
		// 	rc = send_ARP_request(m);
		// 	return rc;
		// }
		printf("Trimit pachet dupa ce am gasit in arptable intrare\n");
		memcpy(eth_hdr->ether_dhost, MAC_dest, ETH_ALEN);
		
		if (iphdr->protocol == htons(IPPROTO_ICMP)) {
		
			struct icmphdr *icmphdr = (struct icmphdr *)(m.payload + 
											sizeof(struct ether_header) +
											sizeof(struct iphdr));
			
			
			icmphdr->checksum = 0;
			icmphdr->checksum = icmp_checksum((uint16_t *)icmphdr, sizeof(struct icmphdr));
		}

		iphdr->check = 0;
		iphdr->check = ip_checksum((uint8_t *)iphdr, sizeof(struct iphdr));

		rc = send_packet(&m);
		DIE(rc < 0, "send_packet");
		return rc;
	}

	
	return rc;
}

int send_ARP_replay(packet arp_request) {
	packet *arp_replay = (packet *)malloc(sizeof(packet));
	if (arp_replay == NULL) {
		DIE(1, "malloc");
		return -1;
	}

	arp_replay->interface = arp_request.interface;
	arp_replay->len = sizeof(struct ether_header) + sizeof(struct arp_header);
	memcpy(arp_replay->payload, arp_request.payload, MAX_LEN);


	struct ether_header *new_eth = (struct ether_header *)arp_replay->payload;

	struct arp_header *new_arp = (struct arp_header *)(arp_replay->payload +
											sizeof(struct ether_header));
	struct arp_header *old_arp = (struct arp_header *)(arp_request.payload +
											sizeof(struct ether_header));

	uint8_t mac[ETH_ALEN]; 
	get_interface_mac(arp_request.interface, mac);
	memcpy(new_eth->ether_dhost, old_arp->sha, ETH_ALEN);
	memcpy(new_eth->ether_shost, mac, ETH_ALEN);
	new_eth->ether_type = htons(ETHERTYPE_ARP);
	new_arp->op = 2; //replay
	memcpy(new_arp->sha, mac, ETH_ALEN);
	new_arp->spa = old_arp->tpa;
	memcpy(new_arp->tha, old_arp->sha, ETH_ALEN);
	new_arp->tpa = old_arp->spa;

	int rc;
	rc = send_packet(arp_replay);
	DIE(rc < 0, "send_packet");

	return rc;
}

int add_arp_entry2(uint32_t ip, uint8_t *mac, struct arp_entry *arp_table, int arp_table_len) {
	arp_table[arp_table_len].ip = ip;
	memcpy(arp_table[arp_table_len].mac, mac, ETH_ALEN);
	return arp_table_len + 1;
}

int ARP_Protocol(packet m, queue *q, struct arp_entry *arp_table, int *arp_table_len) {
	int rc = 0;
	struct arp_header *arphdr;
	arphdr = (struct arp_header *)(m.payload + 
											sizeof(struct ether_header));

	// ARP-request
	if (arphdr->op == ntohs(1)) {
		printf("Am arp request\n");
		uint32_t ip_addr = inet_addr(get_interface_ip(m.interface));

		printf("Sunt pe cale sa trimit un arp-replay\n");
		//Daca este pentru mine:
		if (arphdr->tpa == ip_addr) {
			printf("Trimite inapoi un ARP-Replay\n");
			rc = send_ARP_replay(m);
			DIE(rc < 0, "send_ARP_replay");
			return rc;
		}

		return rc;
	}

	// ARP-Replay
	if (arphdr->op == ntohs(2)) {
		//Iau adresa MAC cautata si trimit pachetul din coada
		//Trebuie sa iau primul pachet din coada sau altul???
		//Ce se intampla daca pachetele ARP-replay nu vin in ordine????
		printf("Am primit adresa Mac pe care o cautam. Sunt in ARP-Replay\n");

		//adauga intrare in arp_table
		(*arp_table_len) = add_arp_entry2(arphdr->spa, arphdr->sha, arp_table, *arp_table_len);

		if (!queue_empty(*q)) {
			packet *new = (packet *)queue_deq(*q);
			struct ether_header *ethhdr = (struct ether_header *)(new->payload);
		
			memcpy(ethhdr->ether_dhost, arphdr->sha, ETH_ALEN);
			rc = send_packet(new);
			DIE(rc < 0, "send_packet");
		}

		return rc;
	}

	printf("pachetul arp nu e de tipul request and replay. Este de tipul: %d\n", arphdr->op);

	return 0;
}

int deal_with_packet(packet m, queue *q, struct arp_entry *arp_table, int *arp_table_len,
								struct route_table_entry *rtable, 
								int rtable_len) {
	int rc = 0;

	struct ether_header *ethhdr = (struct ether_header *)(m.payload);
	

	if (ntohs(ethhdr->ether_type) == ETHERTYPE_ARP) {
		printf("Am ARP\n");
		rc = ARP_Protocol(m, q, arp_table, arp_table_len);
		DIE(rc < 0, "ARP_Protocol");
		return rc;
	}

	if (ethhdr->ether_type == htons(ETHERTYPE_IP)) {
		printf("Am IP\n");

		uint8_t mac[ETH_ALEN]; 
		get_interface_mac(m.interface, mac);

		//este pachet trimis la adresa mea MAC
		if (memcmp(mac, ethhdr->ether_dhost, ETH_ALEN) == 0) {
			printf("Are adresa mea MAC la destinatie\n");
			rc = IP_Protocol(m, q, arp_table, *arp_table_len, rtable, rtable_len);
			DIE(rc < 0, "IP_Protocol");
			return rc;
		}

		printf("Packetul nu a fost trimis la adresa mea MAC\n");

		return rc;
	}
	printf("Primesc un alt tip de pachet %d\n", ntohs(ethhdr->ether_type));

	return rc;
}

int main(int argc, char *argv[]) {
	printf("Checkpoint1\n");
	packet m;
	int rc;
	queue q = queue_create();
	//list arp_table = NULL;
	struct arp_entry *arp_table = (struct arp_entry *)malloc(100 * sizeof(struct arp_entry));
	int arp_table_len = parse_arp_table("./arp_table.txt", arp_table);
	printf("[%d] - [%s]\n", arp_table[arp_table_len - 1].ip, arp_table[arp_table_len - 1].mac);

	struct route_table_entry *rtable = 
					(struct route_table_entry *)malloc(NR_RTABLE_ENTRIES * 
										sizeof(struct route_table_entry));
	if (rtable == NULL) {
		DIE(1, "malloc");
		return -1;
	}

	int rtable_len = read_rtable(argv[1], rtable);
	DIE(rtable_len < 0, "read_rtable");
	printf("Checkpoint2\n");

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */

		printf("\n\nHai sa vedem ce fac cu pachetul asta\n");
		deal_with_packet(m, &q, arp_table, &arp_table_len, rtable, rtable_len);
		DIE(rc < 0, "deal_with_packet");
	}
}

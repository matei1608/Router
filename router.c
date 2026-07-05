#include "list.h"
#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>
struct TrieNode {
	struct TrieNode* nextValue[2];
	bool final;
	uint32_t nextHop;
	int interface;
};
struct TrieNode *newTrieNode() {
	struct TrieNode *nod = (struct TrieNode *)malloc(sizeof(struct TrieNode));
	for (int i = 0; i <= 1; i++)
		nod->nextValue[i] = NULL;
	nod->final = false;
	nod->nextHop = 0;
	nod->interface = -1;
	return nod;
}
void insert(struct route_table_entry *tEntry, struct TrieNode* root) {
	uint32_t mask = ntohl(tEntry->mask);
	uint32_t next_hop = tEntry->next_hop;
	uint32_t prefix = ntohl(tEntry->prefix);
	int interface = tEntry->interface;
	int lungPrefix = 0;
	//aflu cati biti are prefix;
	for (int d = 31; d >= 0; d--) {
		if (mask & (1 << d))
			lungPrefix++;
		else break;
	}
	//parcurg prefix si adaug in trie
	struct TrieNode *curent = root;
	for (int i = 0; i < lungPrefix; i++) {
		int d = 31 - i;
		int bit = (prefix & (1 << d)) ? 1 : 0;
		if (curent->nextValue[bit] == NULL) {
			curent->nextValue[bit] = newTrieNode();
		}
		curent = curent->nextValue[bit];
	}
	//adaugam nextHop, final, interface in nodul ultimului bit al prefixului
	curent->final = true;
	curent->nextHop = next_hop;
	curent->interface = interface;
}
void search(struct TrieNode* root, uint32_t ipCautat, uint32_t *nextHop, int *interface) {
	//ip cautat trebuie sa fie host order
	struct TrieNode* curent = root;
	*nextHop = 0;
	*interface = -1;
	for (int i = 31; i >= 0; i--) {
		int bit = (ipCautat & (1 << i)) ? 1 : 0;
		if (curent->nextValue[bit] != NULL) {
			curent = curent->nextValue[bit];
			if (curent->final) {
				*nextHop = curent->nextHop;
				*interface = curent->interface;
			}
		}
		else
			break;
	}
}
void ICMP_message(uint8_t type, uint8_t code, struct ether_hdr *headerEther, uint32_t ipInter, int interface, 
				struct ip_hdr ip_nemodificat, struct ip_hdr *headerIp) {
				//trimitem mesaj ICMP de tip Destination unreachable
				char buf1[MAX_PACKET_LEN];
				memset(buf1, 0, MAX_PACKET_LEN);
				struct ether_hdr *Ehdr1 = (struct ether_hdr *)buf1;
				//setam adresa mac destinatie
				memcpy(Ehdr1->ethr_dhost, headerEther->ethr_shost, 6);
				//setam adresa mac sursa
				get_interface_mac(interface, Ehdr1->ethr_shost);
				//setam tipul
				Ehdr1->ethr_type = htons(0x0800);
				struct ip_hdr *ip_hdr1 = (struct ip_hdr *)(((char *)buf1) + 14);
				ip_hdr1->ihl = 5; //modificat
				ip_hdr1->ver = 4;
				ip_hdr1->tos = 0;
				ip_hdr1->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
				ip_hdr1->id = htons(4);
				ip_hdr1->frag = htons(0);
				ip_hdr1->ttl = 64;
				ip_hdr1->proto = 1;
				//nu calculez acum checksum
				ip_hdr1->checksum = 0;
				ip_hdr1->source_addr = ipInter;
				ip_hdr1->dest_addr = headerIp->source_addr; 
				//calculez checksum
				ip_hdr1->checksum = htons(checksum((uint16_t *)ip_hdr1, sizeof(struct ip_hdr)));

				//ICMP header
				struct icmp_hdr *icmp_hdr1 = (struct icmp_hdr *)(((char *) ip_hdr1) + sizeof(struct ip_hdr));
				icmp_hdr1->mtype = type;
				icmp_hdr1->mcode = code;
				icmp_hdr1->check = 0;

				//Adaug payload
				char *payload_icmp = (((char *)icmp_hdr1) + sizeof(struct icmp_hdr));
				memcpy(payload_icmp, &ip_nemodificat, (sizeof(struct ip_hdr) + 8));
				
				//adaug checksum-ul pt ICMP header
				icmp_hdr1->check = htons(checksum((uint16_t *)icmp_hdr1, (sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8)));
				//trimit inapoi pachetul
				send_to_link(sizeof(struct ether_hdr) + 2 * sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 8, buf1, interface);
}

struct wraper {
	int len, interface;
	char buf[MAX_PACKET_LEN];
	uint32_t next_hop;
};
int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	// rtable
	struct route_table_entry *rtable = (struct route_table_entry *)malloc(100005 * sizeof(struct route_table_entry)); 
	int table_len = read_rtable(argv[1], rtable);
	//introduc intrarile din tabel in trie
	struct TrieNode *root = newTrieNode();
	for (int i = 0; i < table_len; i++) {
		insert(&rtable[i], root);
	}
	//cache arp
	struct arp_table_entry cache[150];
	int cache_len = 0;
	//coada
	queue q = create_queue();
	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

    // TODO: Implement the router forwarding logic
		

		//verifica daca el este destinatia
		struct ether_hdr * headerEther;
		headerEther = (struct ether_hdr *)buf;
		//aflam ip-ul interfetei
		char *ipInterString = get_interface_ip(interface);
		uint32_t ipInter;
		inet_pton(AF_INET, ipInterString, &ipInter);
		//ip
		if (ntohs(headerEther->ethr_type) == 0x0800) {
			struct ip_hdr *headerIp;
			headerIp = (struct ip_hdr *)(((char *)buf) + 14);

			//Verifica daca el este destinatia
			
			if (ntohl(ipInter) == ntohl(headerIp->dest_addr)) {
				if (headerIp->proto == 1) {
					struct icmp_hdr *icmp_hdr_ping = (struct icmp_hdr *)(((char *)headerIp) + sizeof(struct ip_hdr));
					if (icmp_hdr_ping->mtype == 8 && icmp_hdr_ping->mcode == 0) {
						char buf_ping[MAX_PACKET_LEN];
						memcpy(buf_ping, buf, len);
						struct icmp_hdr *icmp_reply = (struct icmp_hdr *)(buf_ping + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
						icmp_reply->mtype = 0;
						icmp_reply->mcode = 0;
						//refac checksum
						icmp_reply->check = 0;
						icmp_reply->check = htons(checksum((uint16_t *)icmp_reply, len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));
						//schimb adresele mac
						struct ether_hdr *Ehdr_reply = (struct ether_hdr *)buf_ping;
						//setam adresa mac destinatie
						memcpy(Ehdr_reply->ethr_dhost, headerEther->ethr_shost, 6);
						//setam adresa mac sursa
						get_interface_mac(interface, Ehdr_reply->ethr_shost);
						//schimb adresele ip
						struct ip_hdr *ip_hdr_reply = (struct ip_hdr *)(buf_ping + sizeof(struct ether_hdr));
						//nu calculez acum checksum
						ip_hdr_reply->checksum = 0;
						ip_hdr_reply->source_addr = ipInter;
						ip_hdr_reply->dest_addr = headerIp->source_addr; 
						//calculez checksum
						ip_hdr_reply->checksum = htons(checksum((uint16_t *)ip_hdr_reply, sizeof(struct ip_hdr)));
						send_to_link(len, buf_ping, interface);
					}
				}
				printf("Routerul este destinatia!\n");
				continue;
			}
			//fac copie la header ip si la primii 8 bytes din payload pentru ICMP
			struct ip_hdr ip_nemodificat;
			memcpy(&ip_nemodificat, headerIp, sizeof(struct ip_hdr) + 8);
			//Verificare checksum
			uint16_t ipCheckSumVechi = headerIp->checksum;
			headerIp->checksum = 0;
			uint16_t ipCheckSUmNou = htons(checksum((uint16_t *)headerIp, sizeof(struct ip_hdr)));
			//checksum bun
			if (ipCheckSumVechi == ipCheckSUmNou) {
				headerIp->checksum = ipCheckSumVechi;
				printf("Checksum bun!");
			}
			//checksum gresit
			else {
				printf("Checksum gresit!");
				continue;
			}

			//verificare TTL
			//TTL prea mic
			if (headerIp->ttl == 0 || headerIp->ttl == 1) {
				ICMP_message(11, 0, headerEther, ipInter, interface, ip_nemodificat, headerIp);
				printf("TTL prea mic");
				continue;
			}
			//scadem TTL
			else {
				printf("Am scazut TTL");
				headerIp->ttl--;
			}
			//tabela de routare

			// *** Varianta NOUA TRIE:
			uint32_t ip_cautat = ntohl(headerIp->dest_addr);
			uint32_t next_hop;
			int interfaceG;
			search(root, ip_cautat, &next_hop, &interfaceG);
			if (interfaceG == -1) {
				//void ICMP_message(uint8_t type, uint8_t code, struct ether_hdr *headerEther, uint32_t ipInter, int interface, 
				//struct ip_hdr ip_nemodificat, struct ip_hdr *headerIp) {
				ICMP_message(3, 0, headerEther, ipInter, interface, ip_nemodificat, headerIp);
				printf("Error: Nu am gasit destinatie");
				continue;
			}

			//recalculare checksum pt ttl
			headerIp->checksum = 0;
			uint16_t CSRec = htons(checksum((uint16_t *)headerIp, sizeof(struct ip_hdr)));
			headerIp->checksum = CSRec;

			//Rescriere adrese L2
			//adresa sursa
			get_interface_mac(interfaceG, headerEther->ethr_shost);
			//adresa destinatie
			//caut adresa Ip in cache
			uint32_t ipTarget = next_hop;
			bool macGasit = false;
			for (int i = 0; i < cache_len; i++) {
				if (ipTarget == cache[i].ip) {
					macGasit = true;
					memcpy(headerEther->ethr_dhost, cache[i].mac, 6);
					break;
				}
			}
			if (!macGasit) {
				//daca nu il gasesc in Cache, trebuie sa il adaug in coada
				//si sa dau un ARP Request

				//il bag in coada
				struct wraper *w = (struct wraper *)malloc(sizeof(struct wraper));
				memcpy(w->buf, buf, len);
				w->len = len;
				w->interface = interfaceG;
				w->next_hop = ipTarget;
				//qu_add(q, w);
				queue_enq(q, w);


				//generare arp request
				char arp_request[MAX_PACKET_LEN];
				struct ether_hdr *ether_hdr_req = (struct ether_hdr *)arp_request;
				struct arp_hdr *arp_hdr_req = (struct arp_hdr *)(arp_request + sizeof(struct ether_hdr));
				//umplem headerul ether
				get_interface_mac(interfaceG, ether_hdr_req->ethr_shost);
				memset(ether_hdr_req->ethr_dhost, 0xFF, 6);
				ether_hdr_req->ethr_type = htons(0x0806);
				//umplem headerul arp
			//  struct arp_hdr {
			// 	uint16_t hw_type;   /* Format of hardware address */
			// 	uint16_t proto_type;   /* Format of protocol address */
			// 	uint8_t hw_len;    /* Length of hardware address */
			// 	uint8_t proto_len;    /* Length of protocol address */
			// 	uint16_t opcode;    /* ARP opcode (command) */
			// 	uint8_t shwa[6];  /* Sender hardware address */
			// 	uint32_t sprotoa;   /* Sender IP address */
			// 	uint8_t thwa[6];  /* Target hardware address */
			// 	uint32_t tprotoa;   /* Target IP address */
			// } __attribute__((packed));
				arp_hdr_req->hw_type = htons(1);
				arp_hdr_req->proto_type = htons(0x0800);
				arp_hdr_req->hw_len = 6;
				arp_hdr_req->proto_len = 4;
				arp_hdr_req->opcode = htons(1);
				get_interface_mac(interfaceG, arp_hdr_req->shwa);
				//setam sender ip
				char *stringIp = get_interface_ip(interfaceG);
				inet_pton(AF_INET, stringIp, &arp_hdr_req->sprotoa);
				memset(arp_hdr_req->thwa, 0, 6);
				arp_hdr_req->tprotoa = ipTarget;
				send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), arp_request, interfaceG);
				continue;
			}
			//trimiterea pachetului mai departe
			send_to_link(len, buf, interfaceG);
		}
		else if (ntohs(headerEther->ethr_type) == 0x0806) {
			struct arp_hdr *arp_hdrReply = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
			if (ntohs(arp_hdrReply->opcode) == 1 && arp_hdrReply->tprotoa == ipInter) {
				char buf3[MAX_PACKET_LEN];
				struct ether_hdr *ethr3 = (struct ether_hdr *) buf3;
				struct arp_hdr *arp3 = (struct arp_hdr *) (buf3 + sizeof(struct ether_hdr));
				//umplem headerul ether
				get_interface_mac(interface, ethr3->ethr_shost);
				memcpy(ethr3->ethr_dhost, arp_hdrReply->shwa, 6);
				ethr3->ethr_type = htons(0x0806);
				//umplem headerul arp
				arp3->hw_type = htons(1);
				arp3->proto_type = htons(0x0800);
				arp3->hw_len = 6;
				arp3->proto_len = 4;
				arp3->opcode = htons(2);
				memcpy(arp3->shwa, ethr3->ethr_shost, 6);
				arp3->sprotoa = arp_hdrReply->tprotoa;
				memcpy(arp3->thwa, arp_hdrReply->shwa, 6);
				arp3->tprotoa = arp_hdrReply->sprotoa;
				send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf3, interface);
			}
			else if (ntohs(arp_hdrReply->opcode) == 2) {
				//Verific daca e arp reply
				//adaug in cache adresa MAC a ip-ul doar daca nu a fost adaugata deja
				bool ipGasit = false;
				for (int i = 0; i < cache_len; i++) {
					if (cache[i].ip == arp_hdrReply->sprotoa) {
						ipGasit = true;
						break;
					}
				}
				if (!ipGasit) {
					//daca nu l-am gasit il adaugam in cache
					cache[cache_len].ip = arp_hdrReply->sprotoa;
					memcpy(cache[cache_len].mac, arp_hdrReply->shwa, 6);
					cache_len++;
				}
				//Trimitem pachetele din coada carora le corespunde ip target
				list current = q->head;
				list prev = NULL;
				while (current != NULL) {
					struct wraper *nod_wraper = (struct wraper *)current->element;
					if (nod_wraper->next_hop == arp_hdrReply->sprotoa) {
						char buf_aux[MAX_PACKET_LEN];
						memcpy(buf_aux, nod_wraper->buf, nod_wraper->len);
						struct ether_hdr *ethr_aux = (struct ether_hdr *)(buf_aux);
						//modific MAC destinatie
						memcpy(ethr_aux->ethr_dhost, arp_hdrReply->shwa, 6);
						send_to_link(nod_wraper->len, buf_aux, nod_wraper->interface);
						if (current == q->head) {
							current = current->next;
							queue_deq(q);
						}
						else {
							prev->next = cdr_and_free(current);
							current = prev->next;
						}
					}
					else {
						prev = current;
						current = current->next;
					}
				}
			}
		}



    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}
}


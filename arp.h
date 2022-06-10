#include "skel.h"
#include "list.h"

uint8_t *get_MAC_arptable(unsigned int ip, list table);
list add_arp_entry(unsigned int ip, uint8_t *mac, list table);
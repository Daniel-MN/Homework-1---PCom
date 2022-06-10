#include "arp.h"

uint8_t *get_MAC_arptable(unsigned int ip, list table) {
    list l;
    for (l = table; l != NULL; l = l->next) {

        if (((struct arp_entry *)l->element)->ip == ip) {
            return ((struct arp_entry *)l->element)->mac;
        }
    }

    return NULL; //adresa MAC nu a fost gasita in arp table
}

list add_arp_entry(unsigned int ip, uint8_t *mac, list table) {
    struct arp_entry *entry = 
                        (struct arp_entry *)malloc(sizeof(struct arp_entry));
    if (entry == NULL) {
        DIE(1, "alocarea de memeorie nu a reusit");
        return -1;
    }

    entry->ip = ip;
    memcpy(entry->mac, mac, ETH_ALEN);

    table = cons(entry, table);
    return table;
}
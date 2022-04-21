#ifndef __ARP_H__
#define __ARP_H__

#include "list.h"
#include "ring_buf.h"
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <arpa/inet.h>
#include <stdint.h>

#define ARP_ENTRY_TYPE_DYNAMIC    0
#define ARP_ENTRY_TYPE_STATIC     1

typedef struct arp_entry {
    uint32_t ip;
    uint8_t hwaddr[RTE_ETHER_ADDR_LEN];
    uint8_t type;

    struct arp_entry *next, *prev;
} arp_entry_t;

typedef struct arp_table {
    arp_entry_t *entries;
    int count;
} arp_table_t;

static arp_table_t *arp_table = NULL;

static inline arp_table_t *get_arp_table_instance(void)
{
    if (!arp_table) {
        arp_table = (arp_table_t *)rte_malloc("arp table", sizeof(arp_table_t), 0);
        if (!arp_table)
            EEXIT("failed to malloc arp table");

        memset(arp_table, 0, sizeof(arp_table_t));
    }

    return arp_table;
}

static uint8_t* get_dst_macaddr(uint32_t ip)
{
    arp_table_t *arp_table = get_arp_table_instance();

    for (arp_entry_t *iter = arp_table->entries; iter; iter = iter->next) {
        if (ip == iter->ip)
            return iter->hwaddr;
    }

    return NULL;
}

static inline void print_arp_entry(arp_entry_t *entry)
{
    struct in_addr addr = {
        .s_addr = entry->ip,
    };

    char buf[RTE_ETHER_ADDR_FMT_SIZE] = { 0 };
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, (struct rte_ether_addr *)entry->hwaddr);

    printf("%-15s %-20s %d\n", inet_ntoa(addr), buf, entry->type);
}


#endif

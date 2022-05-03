#ifndef __ARP_H__
#define __ARP_H__

#include "config.h"
#include "list.h"
#include "ring_buf.h"
#include <rte_timer.h>
#include <rte_arp.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>

#define ARP
#define RTE_LOGTYPE_ARP RTE_LOGTYPE_USER1

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
        arp_table = (arp_table_t *)rte_zmalloc(NULL, sizeof(arp_table_t), 0);
        if (!arp_table)
            EEXIT("failed to malloc arp table");
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

static void
process_arp_request(struct rte_arp_hdr *arphdr, struct rte_ether_hdr *ethdr, uint8_t *this_mac_addr)
{
    // set arp type is reply
    arphdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

    // modify ether mac address
    rte_memcpy(ethdr->d_addr.addr_bytes, ethdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ethdr->s_addr.addr_bytes, this_mac_addr, RTE_ETHER_ADDR_LEN);

    // modify arp mac address
    rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes, arphdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes, this_mac_addr, RTE_ETHER_ADDR_LEN);

    // modify arp ip address
    arphdr->arp_data.arp_tip = arphdr->arp_data.arp_sip;
    arphdr->arp_data.arp_sip = THIS_IPV4_ADDR;
}

static void process_arp_reply(struct rte_arp_hdr *arphdr)
{
    arp_table_t *arp_table = get_arp_table_instance();
    uint8_t *hwaddr = get_dst_macaddr(arphdr->arp_data.arp_sip);
    if (!hwaddr) {
        // add arp entry to arp table
        arp_entry_t *arp_entry = rte_malloc(NULL, sizeof(arp_entry_t), 0);
        if (arp_entry) {
            memset(arp_entry, 0, sizeof(arp_entry_t));

            arp_entry->ip = arphdr->arp_data.arp_sip;
            rte_memcpy(arp_entry->hwaddr, arphdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
            arp_entry->type = ARP_ENTRY_TYPE_DYNAMIC;

            LL_ADD(arp_entry, arp_table->entries);
            arp_table->count++;

#if 0
            // print arp talbe
            printf("        arp entry count: %d\n", arp_table->count);
            printf("%-15s %-20s %s\n", "ip", "mac", "type");
            for (arp_entry_t *iter = arp_table->entries; iter; iter = iter->next)
                print_arp_entry(iter);
            printf("-------------------------------------------\n");
#endif
        }
    }
}

static int process_arp_pkt(struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *ethdr = (void *)rte_pktmbuf_mtod(mbuf, struct rte_ehter_hdr *);
    struct rte_arp_hdr *arphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(*ethdr));

    if (arphdr->arp_data.arp_tip != THIS_IPV4_ADDR)
        return -1;

    switch (rte_be_to_cpu_16(arphdr->arp_opcode)) {
    case RTE_ARP_OP_REQUEST: {
        process_arp_request(arphdr, ethdr, g_this_mac_addr);
        io_ring_t *io_ring = get_io_ring_instance();
        en_ring_burst(io_ring->out, &mbuf, 1);
        break;
    }
    case RTE_ARP_OP_REPLY:
        process_arp_reply(arphdr);
        return -1;
    }

    return 0;
}

static void
create_arp_packet(uint8_t *pkt_data,
        uint8_t *src_mac, uint8_t *dst_mac, uint32_t src_ip, uint32_t dst_ip, uint16_t arp_opcode)
{
    struct rte_ether_hdr *ethdr = (struct rte_ether_hdr *)pkt_data;
    rte_memcpy(ethdr->s_addr.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ethdr->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    ethdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(ethdr + 1);
    arphdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arphdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arphdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arphdr->arp_plen = sizeof(uint32_t);
    arphdr->arp_opcode = rte_cpu_to_be_16(arp_opcode);

    rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
    if (!memcmp(dst_mac, g_arp_request_mac, RTE_ETHER_ADDR_LEN)) {
        uint8_t mac[RTE_ETHER_ADDR_LEN] = { 0 };
        rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
    } else {
        rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    }

    arphdr->arp_data.arp_sip = src_ip;
    arphdr->arp_data.arp_tip = dst_ip;
}

static void
send_arp(struct rte_mempool *mpool,
        uint8_t *src_mac, uint8_t *dst_mac, uint32_t src_ip, uint32_t dst_ip, uint16_t arp_opcode)
{
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mpool);
    if (!mbuf) {
        RTE_LOG(WARNING, ARP, "failed to alloc mbuf to send arp\n");
        return;
    }

    mbuf->pkt_len = mbuf->data_len = total_length;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    create_arp_packet(pkt_data, src_mac, dst_mac, src_ip, dst_ip, arp_opcode);

    io_ring_t *io_ring = get_io_ring_instance();
    en_ring_burst(io_ring->out, &mbuf, 1);
}

static void
arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg)
{
    struct rte_mempool *mpool = (struct rte_mempool *)arg;

    for (int i = 0; i < 255; i++) {
        uint32_t dst_ip = (THIS_IPV4_ADDR & 0x00ffffff) | ((i << 24) & 0xff000000);
        uint8_t *dst_mac = get_dst_macaddr(dst_ip);
        if (!dst_mac)
            send_arp(mpool, g_this_mac_addr, g_arp_request_mac, THIS_IPV4_ADDR, dst_ip, RTE_ARP_OP_REQUEST);
        else
            send_arp(mpool, g_this_mac_addr, dst_mac, THIS_IPV4_ADDR, dst_ip, RTE_ARP_OP_REQUEST);
    }
}

#endif

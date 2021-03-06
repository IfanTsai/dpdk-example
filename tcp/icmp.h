#ifndef __ICMP_H__
#define __ICMP_H__

#include "ring_buf.h"
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

static inline void swap_mac(struct rte_ether_hdr *ethdr)
{
    uint8_t tmp_mac[RTE_ETHER_ADDR_LEN];

    rte_memcpy(tmp_mac, &ethdr->d_addr, RTE_ETHER_ADDR_LEN);
    rte_memcpy(&ethdr->d_addr, &ethdr->s_addr, RTE_ETHER_ADDR_LEN);
    rte_memcpy(&ethdr->s_addr, tmp_mac, RTE_ETHER_ADDR_LEN);
}

static inline void swap_ip(struct rte_ipv4_hdr *iphdr)
{
    uint32_t tmp_ip;

    rte_memcpy(&tmp_ip, &iphdr->src_addr, sizeof(tmp_ip));
    rte_memcpy(&iphdr->src_addr, &iphdr->dst_addr, sizeof(tmp_ip));
    rte_memcpy(&iphdr->dst_addr, &tmp_ip, sizeof(tmp_ip));
}

static uint16_t icmp_cksum(struct rte_ipv4_hdr *iphdr, struct rte_icmp_hdr *icmphdr)
{
    uint16_t *addr = (uint16_t *)(void *)icmphdr;
    int count = rte_be_to_cpu_16(iphdr->total_length) - sizeof(*iphdr);

    register long sum = 0;

    while (count > 1) {
        sum += *(unsigned short *)addr++;
        count -= 2;
    }

    if (count > 0)
        sum += *(unsigned char *)addr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}



static int process_icmp_pkt(struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *ethdr = (void *)rte_pktmbuf_mtod(mbuf, struct rte_ehter_hdr *);
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(*ethdr));
    struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
    if (icmphdr->icmp_type != RTE_IP_ICMP_ECHO_REQUEST)
        return -1;

    // swap source and destination value
    swap_mac(ethdr);
    swap_ip(iphdr);

    /**
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |    Type       |     Code      |            Checksum           |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |           Identifier          |       Sequence Number         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Data ...
     * +-+-+-+-+-
     */
    // packet ICMP Reply Message
    icmphdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    icmphdr->icmp_code = 0;
    //icmphdr->icmp_ident = icmphdr->icmp_ident;
    //icmphdr->icmp_seq_nb = icmphdr->icmp_seq_nb;

    // set icmp checksum
    icmphdr->icmp_cksum = 0;
    icmphdr->icmp_cksum = icmp_cksum(iphdr, icmphdr);

    io_ring_t *io_ring = get_io_ring_instance();
    // zero-copy process icmp request mbuf
    en_ring_burst(io_ring->out, &mbuf, 1);

    return 0;
}



#endif

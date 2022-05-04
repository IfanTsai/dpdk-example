#ifndef __UDP_H__
#define __UDP_H__

#include "api.h"
#include "arp.h"
#include "config.h"
#include "list.h"
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>

static int process_udp_pkt(struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udphdr = (void *)((char *)iphdr + sizeof(*iphdr));

    sock_t *sock = get_sock_from_five_tuple(iphdr->dst_addr, udphdr->dst_port, 0, 0, iphdr->next_proto_id);
    if (!sock)
        return -1;

    udp_payload_t *payload = rte_malloc(NULL, sizeof(udp_payload_t), 0);
    if (!payload)
        return -1;

    payload->dip = iphdr->dst_addr;
    payload->sip = iphdr->src_addr;
    payload->sport = udphdr->src_port;
    payload->dport = udphdr->dst_port;
    payload->length = ntohs(udphdr->dgram_len);
    payload->data = rte_malloc(NULL, payload->length - sizeof(struct rte_udp_hdr), 0);
    if (!payload->data) {
        rte_free(payload);

        return -1;
    }
    rte_memcpy(payload->data, udphdr + 1, payload->length);

    rte_ring_mp_enqueue(sock->recvbuf, payload);

    pthread_mutex_lock(&sock->mutex);
    pthread_cond_signal(&sock->cond);
    pthread_mutex_unlock(&sock->mutex);

    rte_pktmbuf_free(mbuf);

    return 0;
}

static void
create_udp_packet(uint8_t *pkt_data, uint16_t len,
        uint8_t *smac, uint8_t *dmac, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint8_t *data)
{
    struct rte_ether_hdr *ethdr = (struct rte_ether_hdr *)pkt_data;
    rte_memcpy(ethdr->s_addr.addr_bytes, smac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ethdr->d_addr.addr_bytes, dmac, RTE_ETHER_ADDR_LEN);
    ethdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *)(pkt_data + sizeof(*ethdr));
    iphdr->version_ihl = 0x45;
    iphdr->type_of_service = 0;
    iphdr->total_length = htons(len - sizeof(struct rte_ether_hdr));
    iphdr->packet_id = 0;
    iphdr->fragment_offset = 0;
    iphdr->time_to_live = 64;
    iphdr->next_proto_id = IPPROTO_UDP;
    iphdr->src_addr = sip;
    iphdr->dst_addr = dip;
    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

    struct rte_udp_hdr *udphdr = (void *)((uint8_t *)iphdr + sizeof(*iphdr));
    udphdr->src_port = sport;
    udphdr->dst_port = dport;
    uint16_t udp_len = len - sizeof(*ethdr) - sizeof(*iphdr);
    rte_memcpy((uint8_t *)(udphdr + 1), data, udp_len - sizeof(*udphdr));
    udphdr->dgram_len = htons(udp_len);
    udphdr->dgram_cksum = 0;
    udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr, udphdr);
}


static void send_udp_pkts(struct rte_mempool *mpool)
{
    for (sock_t *sock = lsock; sock; sock = sock->next) {
        if (sock->protocol != IPPROTO_UDP)
            continue;

        udp_payload_t *payload;
        if (rte_ring_mc_dequeue(sock->sendbuf, (void **)&payload) < 0)
            continue;

        uint8_t *dst_mac = get_dst_macaddr(payload->dip);
        if (!dst_mac) {
            send_arp_pkt(mpool, sock->mac, g_arp_request_mac, payload->sip, payload->dip, RTE_ARP_OP_REQUEST);
            rte_ring_mp_enqueue(sock->sendbuf, payload);
        } else {
            const unsigned total_length =
                sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + payload->length;

            struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mpool);
            if (!mbuf)
                EEXIT("failed to alloc mbuf");
            mbuf->pkt_len = mbuf->data_len = total_length;

            uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
            create_udp_packet(pkt_data, total_length,
                    sock->mac, dst_mac, payload->sip, payload->dip, payload->sport, payload->dport, payload->data);

            io_ring_t *io_ring = get_io_ring_instance();
            en_ring_burst(io_ring->out, &mbuf, 1);
        }
    }
}

#endif

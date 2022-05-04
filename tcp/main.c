#include "udp.h"
#include "tcp.h"
#include "config.h"
#include "kni.h"
#include "arp.h"
#include "icmp.h"
#include "app.h"
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_kni.h>
#include <rte_timer.h>
#include <arpa/inet.h>
#include <stdio.h>

uint8_t g_this_mac_addr[RTE_ETHER_ADDR_LEN] = { 0 };
static struct rte_kni *g_kni;

static inline void port_init(struct rte_mempool *mpool, uint16_t port_id)
{
    // check if eth device is available
    if (rte_eth_dev_count_avail() == 0)
        EEXIT("eth device is not available");

    // get eth device info with specific port
    //struct rte_eth_dev_info dev_info;
    //rte_eth_dev_info_get(port_id, &dev_info);

    // set eth device configure
    struct rte_eth_conf eth_conf = {
        .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN },
    };
    if (rte_eth_dev_configure(port_id, 1, 1, &eth_conf) < 0)
        EEXIT("failed to configure eth, port: %d", port_id);

    int socket_id = rte_eth_dev_socket_id(port_id);

    // initialize rx queue
    if (rte_eth_rx_queue_setup(port_id, 0, 128, socket_id, NULL, mpool) < 0)
        EEXIT("failed to setup rx queue");

    // initialize tx queue
    if (rte_eth_tx_queue_setup(port_id, 0, 512, socket_id, NULL) < 0)
        EEXIT("failed to setup tx queue");

    // start eth device
    if (rte_eth_dev_start(port_id) < 0)
        EEXIT("failed to start eth dev, port: %d", port_id);

    // enable promiscuous
    rte_eth_promiscuous_enable(port_id);
}

static inline void arp_request_timer_init(struct rte_mempool *mpool, struct rte_timer *timer, unsigned lcore_id)
{
    // initialize RTE timer library
    rte_timer_subsystem_init();

    // initialize timer structures
    rte_timer_init(timer);

    // load timer, every second, on lcore specified lcore_id, reloaded automatically
    uint64_t hz = rte_get_timer_hz();
    rte_timer_reset(timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mpool);
}

static void process_recv_pkt(struct rte_mbuf *mbuf)
{
    // parse ether header
    struct rte_ether_hdr *ethdr = (void *)rte_pktmbuf_mtod(mbuf, struct rte_ehter_hdr *);
    switch (rte_be_to_cpu_16(ethdr->ether_type)) {
    case RTE_ETHER_TYPE_ARP:
        if (process_arp_pkt(mbuf) < 0)
            goto mbuf_free;
        break;

    case RTE_ETHER_TYPE_IPV4: {
        // parse ipv4 header
        struct rte_ipv4_hdr *iphdr =
            rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(*ethdr));
        // add arp entry to arp table
        add_arp_entry(iphdr->src_addr, ethdr->s_addr.addr_bytes);

        switch (iphdr->next_proto_id) {
        case IPPROTO_ICMP:
            if (process_icmp_pkt(mbuf) < 0)
                goto mbuf_free;
            break;

        case IPPROTO_UDP:
            if (process_udp_pkt(mbuf) < 0)
                goto mbuf_free;
            break;

        case IPPROTO_TCP:
            if (process_tcp_pkt(mbuf) < 0)
                goto mbuf_free;
            break;

        default:
            goto kni_handle;
        }

        break;
    }

    default:
        goto kni_handle;
    }

    return;

kni_handle:
    rte_kni_tx_burst(g_kni, &mbuf, 1);
mbuf_free:
    rte_pktmbuf_free(mbuf);
}

static void process_recv_pkts(io_ring_t *io_ring)
{
    struct rte_mbuf *mbufs[BURST_SIZE];
    unsigned int nr_recvd = de_ring_burst(io_ring->in, mbufs, BURST_SIZE);
    for (unsigned int i = 0; i < nr_recvd; i++)
        process_recv_pkt(mbufs[i]);
}

static inline void process_send_pkts(struct rte_mempool *mpool)
{
    send_udp_pkts(mpool);
    send_tcp_pkts(mpool);
}

static int lcore_process_pkt_main(void *arg)
{
    struct rte_mempool *mpool = (struct rte_mempool *)arg;
    io_ring_t *io_ring = get_io_ring_instance();

    for (;;) {
        process_recv_pkts(io_ring);
        process_send_pkts(mpool);
        rte_kni_handle_request(g_kni);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    // initialize Environment Abstraction Layer (EAL)
    if (rte_eal_init(argc, argv) < 0) {
        EEXIT("failed to init EAL");
        rte_exit(EXIT_FAILURE, "failed to init EAL");
    }

    // initialize memory pool
    struct rte_mempool *mpool =
        rte_pktmbuf_pool_create("mbuf pool", MBUF_POOL_SIZE, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mpool)
        EEXIT("failed to create memory pool");

    // initialize port
    port_init(mpool, ETH_DEV_PORT_ID);

    if ( !(g_kni = kni_init(mpool, ETH_DEV_PORT_ID)) )
        EEXIT("failed to init kni");

    // get mac address
    rte_eth_macaddr_get(ETH_DEV_PORT_ID, (struct rte_ether_addr *)g_this_mac_addr);

    // initialize io ring buffer
    io_ring_t *io_ring = get_io_ring_instance();
    init_io_ring(io_ring, RING_SIZE);

    // initalize timer
    unsigned int lcore_id = rte_lcore_id();
    struct rte_timer arp_request_timer;
    arp_request_timer_init(mpool, &arp_request_timer, lcore_id);

    // call lcore_proccess_pkt on slave lcore
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(lcore_process_pkt_main, mpool, lcore_id);

    // call udp_server on slave lcore
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(udp_server, NULL, lcore_id);

    // call tcp_server on slave lcore
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(tcp_server, NULL, lcore_id);

    uint64_t prev_tsc = 0;
    struct rte_mbuf *mbufs[BURST_SIZE];

    for (;;) {
        // check timer
        uint64_t cur_tsc = rte_rdtsc();
        uint64_t diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
                rte_timer_manage();    // call timer cb
                prev_tsc = cur_tsc;
        }

        // receive
        unsigned int nr_recvd = rte_eth_rx_burst(ETH_DEV_PORT_ID, 0, mbufs, BURST_SIZE);
        if (nr_recvd > BURST_SIZE)
            EEXIT("too many packets, %d", nr_recvd);

        if (nr_recvd > 0)
            en_ring_burst(io_ring->in, mbufs, nr_recvd);

        // send
        unsigned int nr_send = de_ring_burst(io_ring->out, mbufs, BURST_SIZE);
        if (nr_send > 0) {
            rte_eth_tx_burst(ETH_DEV_PORT_ID, 0, mbufs, nr_send);

            for (unsigned int i = 0; i < nr_send; i++)
                rte_pktmbuf_free(mbufs[i]);
        }
    }

    return 0;
}

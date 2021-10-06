#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <arpa/inet.h>
#include <stdio.h>

#define EEXIT(...) rte_exit(EXIT_FAILURE, ##__VA_ARGS__)

#define MBUF_POOL_SIZE (4096 - 1)
#define ETH_DEV_PORT_ID 0
#define BURST_SIZE 32

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b << 8) + (c << 16) + (d << 24))
#define THIS_IPV4_ADDR MAKE_IPV4_ADDR(192, 168, 1, 26)

static void init_port(struct rte_mempool *mpool)
{
    // check if eth device is available
    if (rte_eth_dev_count_avail() == 0)
        EEXIT("eth device is not available");

    // get eth device info with specific port
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(ETH_DEV_PORT_ID, &dev_info);

    // set eth device configure
    struct rte_eth_conf eth_conf = {
        .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN },
    };
    if (rte_eth_dev_configure(ETH_DEV_PORT_ID, 1, 1, &eth_conf) < 0)
        EEXIT("failed to configure eth, port: %d", ETH_DEV_PORT_ID);

    // initialize rx queue
    int socket_id = rte_eth_dev_socket_id(ETH_DEV_PORT_ID);
    if (rte_eth_rx_queue_setup(ETH_DEV_PORT_ID, 0, 128, socket_id, NULL, mpool) < 0)
        EEXIT("failed to setup rx queue");

    // initialize tx queue
    if (rte_eth_tx_queue_setup(ETH_DEV_PORT_ID, 0, 512, socket_id, NULL) < 0)
        EEXIT("failed to setup tx queue");

    // start eth device
    if (rte_eth_dev_start(ETH_DEV_PORT_ID) < 0)
        EEXIT("failed to start eth dev, port: %d", ETH_DEV_PORT_ID);
}

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

static inline void swap_port(struct rte_udp_hdr *udphdr)
{
    uint16_t tmp_port;

    rte_memcpy(&tmp_port, &udphdr->src_port, sizeof(tmp_port));
    rte_memcpy(&udphdr->src_port, &udphdr->dst_port, sizeof(tmp_port));
    rte_memcpy(&udphdr->dst_port, &tmp_port, sizeof(tmp_port));
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
    init_port(mpool);

    // get mac address
    uint8_t this_mac_addr[RTE_ETHER_ADDR_LEN] = { 0 };
    rte_eth_macaddr_get(ETH_DEV_PORT_ID, (struct rte_ether_addr *)this_mac_addr);

    for (;;) {
        struct rte_mbuf *mbufs[BURST_SIZE];
        // receive
        unsigned int nr_recvd = rte_eth_rx_burst(ETH_DEV_PORT_ID, 0, mbufs, BURST_SIZE);
        if (nr_recvd > BURST_SIZE)
            EEXIT("too many packets, %d", nr_recvd);

        for (unsigned int i = 0; i < nr_recvd; i++) {
            // parse ether header
            struct rte_ether_hdr *ethdr = (void *)rte_pktmbuf_mtod(mbufs[i], struct rte_ehter_hdr *);
            switch (rte_be_to_cpu_16(ethdr->ether_type)) {
                case RTE_ETHER_TYPE_ARP: {
                    // parse arp header
                    struct rte_arp_hdr *arphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_arp_hdr *, sizeof(*ethdr));
                    if (arphdr->arp_data.arp_tip == THIS_IPV4_ADDR) {
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
                    } else {
                        goto mbuf_free;
                    }

                    break;
                }

                case RTE_ETHER_TYPE_IPV4: {
                    // parse ipv4 header
                    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(*ethdr));
                    if (iphdr->next_proto_id == IPPROTO_UDP) {
                        // parse udp header
                        struct rte_udp_hdr *udphdr = (void *)((char *)iphdr + sizeof(*iphdr));
                        *((char *)udphdr + udphdr->dgram_len) = 0;

                        struct in_addr saddr = { .s_addr = iphdr->src_addr };
                        struct in_addr daddr = { .s_addr = iphdr->dst_addr };

                        printf("src: %s:%d\n", inet_ntoa(saddr), ntohs(udphdr->src_port));
                        printf("dst: %s:%d\n", inet_ntoa(daddr), ntohs(udphdr->dst_port));
                        printf("udp msg: %s\n", (char *)(udphdr + 1));

                        // swap source and destination value, in order to echo
                        swap_mac(ethdr);
                        swap_ip(iphdr);
                        swap_port(udphdr);
                    } else {
                        goto mbuf_free;
                    }

                    break;
                }

                default:
                    goto mbuf_free;
            }

            // send
            rte_eth_tx_burst(ETH_DEV_PORT_ID, 0, &mbufs[i], 1);

mbuf_free:
            rte_pktmbuf_free(mbufs[i]);
            mbufs[i] = NULL;
        }
    }

    return 0;
}

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "arp.h"


#define MBUF_POOL_SIZE (4096 - 1)
#define ETH_DEV_PORT_ID 0
#define BURST_SIZE 32

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b << 8) + (c << 16) + (d << 24))
#define THIS_IPV4_ADDR MAKE_IPV4_ADDR(192, 168, 1, 26)

#define TIMER_RESOLUTION_CYCLES (2000000000ULL * 10) /* around 1min at 2 Ghz */

static uint8_t g_arp_request_mac[RTE_ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static uint8_t g_this_mac_addr[RTE_ETHER_ADDR_LEN] = { 0 };

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

static void process_arp_request(struct rte_arp_hdr *arphdr, struct rte_ether_hdr *ethdr, uint8_t *this_mac_addr)
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
        arp_entry_t *arp_entry = rte_malloc("arp entry", sizeof(arp_entry_t), 0);
        if (arp_entry) {
            memset(arp_entry, 0, sizeof(arp_entry_t));

            arp_entry->ip = arphdr->arp_data.arp_sip;
            rte_memcpy(arp_entry->hwaddr, arphdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
            arp_entry->type = ARP_ENTRY_TYPE_DYNAMIC;

            LL_ADD(arp_entry, arp_table->entries);
            arp_table->count++;

            // print arp talbe
            printf("        arp entry count: %d\n", arp_table->count);
            printf("%-15s %-20s %s\n", "ip", "mac", "type");
            for (arp_entry_t *iter = arp_table->entries; iter; iter = iter->next)
                print_arp_entry(iter);
            printf("-------------------------------------------\n");
        }
    }
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
        uint8_t *src_mac, uint8_t *dst_mac,uint32_t src_ip, uint32_t dst_ip, uint16_t arp_opcode)
{
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mpool);
    if (!mbuf)
        EEXIT("failed to alloc mbuf");
    mbuf->pkt_len = mbuf->data_len = total_length;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    create_arp_packet(pkt_data, src_mac, dst_mac, src_ip, dst_ip, arp_opcode);


    rte_eth_tx_burst(ETH_DEV_PORT_ID, 0, &mbuf, 1);
    rte_pktmbuf_free(mbuf);
}

static void
arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, __attribute__((unused)) void *arg)
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

static inline void init_timer(struct rte_mempool *mpool)
{
	// initialize RTE timer library
	rte_timer_subsystem_init();

	// initialize timer structures
    struct rte_timer arp_request_timer;
	rte_timer_init(&arp_request_timer);

	// load timer, every second, on master lcore, reloaded automatically
	uint64_t hz = rte_get_timer_hz();
	unsigned lcore_id = rte_lcore_id();
	rte_timer_reset(&arp_request_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mpool);
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
    rte_eth_macaddr_get(ETH_DEV_PORT_ID, (struct rte_ether_addr *)g_this_mac_addr);

    // initalize timer
   init_timer(mpool);

    uint64_t prev_tsc = 0;

    for (;;) {
        uint64_t cur_tsc = rte_rdtsc();
		uint64_t diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}

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
                    switch (rte_be_to_cpu_16(arphdr->arp_opcode)) {
                    case RTE_ARP_OP_REQUEST:
                        process_arp_request(arphdr, ethdr, g_this_mac_addr);
                        break;
                    case RTE_ARP_OP_REPLY:
                        process_arp_reply(arphdr);
                        goto mbuf_free;
                    default:
                        goto mbuf_free;
                    }
                } else {
                    goto mbuf_free;
                }

                break;
            }

            case RTE_ETHER_TYPE_IPV4: {
                // parse ipv4 header
                struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(*ethdr));
                if (iphdr->next_proto_id == IPPROTO_ICMP) {
                    // parse icmp header
                    struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
                    if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
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
                    }
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

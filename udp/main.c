#include "udp.h"
#include "arp.h"
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include <arpa/inet.h>
#include <stdio.h>

#define MBUF_POOL_SIZE (4096 - 1)
#define ETH_DEV_PORT_ID 0   // eth0
#define BURST_SIZE 32

//#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b << 8) + (c << 16) + (d << 24))
//#define THIS_IPV4_ADDR MAKE_IPV4_ADDR(192, 168, 18, 115)
#define THIS_IPV4_ADDR inet_addr("192.168.18.115")
#define UDP_PORT 8999

#define TIMER_RESOLUTION_CYCLES (2000000000ULL * 1) /* around 10s at 2 Ghz */


static uint8_t g_arp_request_mac[RTE_ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t g_this_mac_addr[RTE_ETHER_ADDR_LEN] = { 0 };

static int udp_server(__attribute__((unused)) void *arg)
{
    int sockfd = _socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in servaddr = { 0 }, cliaddr = { 0 };
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = THIS_IPV4_ADDR;
    servaddr.sin_port = htons(UDP_PORT);

    _bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    char buf[1024] = { 0 };
    socklen_t addrlen = sizeof(cliaddr);
    ssize_t recvd;

    for (;;) {
        memset(buf, 0, sizeof(buf));

        if ( (recvd = _recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&cliaddr, &addrlen)) < 0)
            continue;
        else
            printf("recv from %s:%d, data: %s\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), buf);

        _sendto(sockfd, buf, recvd, 0, (struct sockaddr *)&cliaddr, sizeof(cliaddr));
    }

    _close(sockfd);

    return 0;
}

static void init_port(struct rte_mempool *mpool)
{
    // check if eth device is available
    if (rte_eth_dev_count_avail() == 0)
        EEXIT("eth device is not available");

    // get eth device info with specific port
    //struct rte_eth_dev_info dev_info;
    //rte_eth_dev_info_get(ETH_DEV_PORT_ID, &dev_info);

    // set eth device configure
    struct rte_eth_conf eth_conf = {
        .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN },
    };
    if (rte_eth_dev_configure(ETH_DEV_PORT_ID, 1, 1, &eth_conf) < 0)
        EEXIT("failed to configure eth, port: %d", ETH_DEV_PORT_ID);

    int socket_id = rte_eth_dev_socket_id(ETH_DEV_PORT_ID);

    // initialize rx queue
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

    io_ring_t *io_ring = get_io_ring_instance();
    en_ring_burst(io_ring->out, &mbuf, 1);
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

static inline void init_arp_request_timer(struct rte_mempool *mpool, struct rte_timer *timer, unsigned lcore_id)
{
    // initialize RTE timer library
    rte_timer_subsystem_init();

    // initialize timer structures
    rte_timer_init(timer);

    // load timer, every second, on lcore specified lcore_id, reloaded automatically
    uint64_t hz = rte_get_timer_hz();
    rte_timer_reset(timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mpool);
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


static void send_udp(struct rte_mempool *mpool)
{
    for (struct localhost *host = lhost; host; host = host->next) {
        payload_t *payload;
        if (rte_ring_mc_dequeue(host->sendbuf, (void **)&payload) < 0)
            continue;

        uint8_t *dst_mac = get_dst_macaddr(payload->dip);
        if (!dst_mac) {
            send_arp(mpool, host->mac, g_arp_request_mac, payload->sip, payload->dip, RTE_ARP_OP_REQUEST);
            rte_ring_mp_enqueue(host->sendbuf, payload);
        } else {
            const unsigned total_length =
                sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + payload->length;

            struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mpool);
            if (!mbuf)
                EEXIT("failed to alloc mbuf");
            mbuf->pkt_len = mbuf->data_len = total_length;

            uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
            create_udp_packet(pkt_data, total_length,
                    host->mac, dst_mac, payload->sip, payload->dip, payload->sport, payload->dport, payload->data);

            io_ring_t *io_ring = get_io_ring_instance();
            en_ring_burst(io_ring->out, &mbuf, 1);
        }
    }
}

static int process_udp_pkt(struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udphdr = (void *)((char *)iphdr + sizeof(*iphdr));

    localhost_t *host = get_localhost_from_ip_port_protocol(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
    if (!host)
        return -1;

    payload_t *payload = rte_malloc("payload", sizeof(payload_t), 0);
    if (!payload)
        return -1;

    payload->dip = iphdr->dst_addr;
    payload->sip = iphdr->src_addr;
    payload->sport = udphdr->src_port;
    payload->dport = udphdr->dst_port;
    payload->length = ntohs(udphdr->dgram_len);
    payload->data = rte_malloc("udp data", payload->length - sizeof(struct rte_udp_hdr), 0);
    if (!payload->data) {
        rte_free(payload);

        return -1;
    }
    rte_memcpy(payload->data, udphdr + 1, payload->length);

    rte_ring_mp_enqueue(host->recvbuf, payload);

    pthread_mutex_lock(&host->mutex);
    pthread_cond_signal(&host->cond);
    pthread_mutex_unlock(&host->mutex);

    return 0;
}

static int process_arp_pkt(struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *ethdr = (void *)rte_pktmbuf_mtod(mbuf, struct rte_ehter_hdr *);
    struct rte_arp_hdr *arphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(*ethdr));

    if (arphdr->arp_data.arp_tip != THIS_IPV4_ADDR)
        return -1;

    switch (rte_be_to_cpu_16(arphdr->arp_opcode)) {
    case RTE_ARP_OP_REQUEST:
        process_arp_request(arphdr, ethdr, g_this_mac_addr);
        break;
    case RTE_ARP_OP_REPLY:
        process_arp_reply(arphdr);
        return -1;
    }

    return 0;
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

    return 0;
}


static int lcore_process_pkt(__attribute__((unused)) void *arg)
{
    struct rte_mempool *mpool = (struct rte_mempool *)arg;
    io_ring_t *io_ring = get_io_ring_instance();

    for (;;) {
        struct rte_mbuf *mbufs[BURST_SIZE];
        unsigned int nr_recvd = de_ring_burst(io_ring->in, mbufs, BURST_SIZE);

        for (unsigned int i = 0; i < nr_recvd; i++) {
            // parse ether header
            struct rte_ether_hdr *ethdr = (void *)rte_pktmbuf_mtod(mbufs[i], struct rte_ehter_hdr *);
            switch (rte_be_to_cpu_16(ethdr->ether_type)) {
            case RTE_ETHER_TYPE_ARP:
                if (process_arp_pkt(mbufs[i]) < 0)
                    goto mbuf_free;
                break;

            case RTE_ETHER_TYPE_IPV4: {
                // parse ipv4 header
                struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(*ethdr));
                switch (iphdr->next_proto_id) {
                case IPPROTO_ICMP:
                    if (process_icmp_pkt(mbufs[i]) < 0)
                        goto mbuf_free;
                    break;

                case IPPROTO_UDP:
                    process_udp_pkt(mbufs[i]);
                    goto mbuf_free;

                default:
                    goto mbuf_free;
                }

                break;
            }

            default:
                goto mbuf_free;
            }

            en_ring_burst(io_ring->out, &mbufs[i], 1);
            continue;

mbuf_free:
            rte_pktmbuf_free(mbufs[i]);
        }

        send_udp(mpool);
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
    init_port(mpool);

    // get mac address
    rte_eth_macaddr_get(ETH_DEV_PORT_ID, (struct rte_ether_addr *)g_this_mac_addr);

    // initialize io ring buffer
    io_ring_t *io_ring = get_io_ring_instance();
    init_io_ring(io_ring, RING_SIZE);

    // initalize timer
    unsigned int lcore_id = rte_lcore_id();
    struct rte_timer arp_request_timer;
    init_arp_request_timer(mpool, &arp_request_timer, lcore_id);

    // call lcore_proccess_kt on slave lcore
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(lcore_process_pkt, mpool, lcore_id);

    // call udp_server on slave lcore
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(udp_server, NULL, lcore_id);

    uint64_t prev_tsc = 0;

    for (;;) {
        // check timer
        uint64_t cur_tsc = rte_rdtsc();
        uint64_t diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
                rte_timer_manage();    // call timer cb
                prev_tsc = cur_tsc;
        }

        struct rte_mbuf *mbufs[BURST_SIZE];
        // receive
        unsigned int nr_recvd = rte_eth_rx_burst(ETH_DEV_PORT_ID, 0, mbufs, BURST_SIZE);
        if (nr_recvd > BURST_SIZE)
            EEXIT("too many packets, %d", nr_recvd);

        if (nr_recvd > 0) {
            en_ring_burst(io_ring->in, mbufs, nr_recvd);
        }

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

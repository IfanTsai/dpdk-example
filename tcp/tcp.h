#ifndef __TCP_H__
#define __TCP_H__

#include "api.h"
#include "arp.h"
#include <rte_ip.h>
#include <rte_tcp.h>
#include <limits.h>

static inline tcp_fragment_t *clone_tcp_fragment(tcp_fragment_t *src_fragment)
{
    tcp_fragment_t *dst_fragment = rte_malloc(NULL, sizeof(tcp_fragment_t), 0);
    if (!dst_fragment)
	return NULL;

    return rte_memcpy(dst_fragment, src_fragment, sizeof(tcp_fragment_t));
}

static inline
tcp_fragment_t *create_empty_data_fragment(uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack)
{
    tcp_fragment_t *fragment = rte_malloc(NULL, sizeof(tcp_fragment_t), 0);
    if (!fragment)
	return NULL;

    fragment->sport = sport;
    fragment->dport = dport;
    fragment->seq = seq;
    fragment->ack = ack;
    fragment->win = TCP_INITIAL_WINDOW;
    fragment->data_off = 0x50;
    fragment->data = NULL;
    fragment->length = 0;

    return fragment;
}

static inline tcp_fragment_t *create_ack_fragment(sock_t *sock, struct rte_tcp_hdr *tcphdr)
{
    tcp_fragment_t *fragment =
	create_empty_data_fragment(tcphdr->dst_port, tcphdr->src_port, sock->send_next, sock->recv_next);
    if (!fragment)
	return NULL;

    fragment->flags = RTE_TCP_ACK_FLAG;

    return fragment;
}

static inline int put_ack_fragment_to_send_buf(struct rte_tcp_hdr *tcphdr, sock_t *sock)
{
    tcp_fragment_t *fragment = create_ack_fragment(sock, tcphdr);
    if (!fragment)
	return -1;

    rte_ring_mp_enqueue(sock->sendbuf, fragment);

    return 0;
}

static inline int put_fragment_to_recv_buf(sock_t *sock, struct rte_tcp_hdr *tcphdr, uint8_t *data, uint32_t len)
{
    tcp_fragment_t *fragment =
	create_empty_data_fragment(ntohs(tcphdr->dst_port), ntohs(tcphdr->src_port), 0, 0);

    if (!fragment)
	return -1;

    if (data && len > 0) {
	fragment->data = rte_malloc(NULL, len, 0);
	if (!fragment->data) {
	    rte_free(fragment);
	    return -1;
	}

	rte_memcpy(fragment->data, data, len);
    }

    fragment->length = len;

    rte_ring_mp_enqueue(sock->recvbuf, fragment);
    pthread_mutex_lock(&sock->mutex);
    pthread_cond_signal(&sock->cond);
    pthread_mutex_unlock(&sock->mutex);

    return 0;
}

static uint32_t calc_four_tuple_hash(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
    return sip ^ dip ^ sport ^ dport;
}

static sock_t *create_tcp_sock(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
    sock_t *sock = rte_zmalloc(NULL, sizeof(sock_t), 0);
    if (!sock)
	return NULL;

    sock->sip = sip;
    sock->dip = dip;
    sock->sport = sport;
    sock->dport = dport;
    sock->status = TCP_STATUS_LISTEN;

    char ring_name[32] = { 0 };
    uint32_t hash = calc_four_tuple_hash(sip, dip, sport, dport);
    snprintf(ring_name, sizeof(ring_name), "sendbuf_%x", hash);
    sock->sendbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!sock->sendbuf)
	EEXIT("failed to alloc send buf");

    snprintf(ring_name, sizeof(ring_name), "recvbuf_%x", hash);
    sock->recvbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!sock->recvbuf)
	EEXIT("failed to alloc recv buf");

    sock->protocol = IPPROTO_TCP;
    sock->fd = -1;

    uint32_t next_seed = time(NULL);
    sock->send_next = rand_r(&next_seed) % TCP_MAX_SEQ;

    rte_memcpy(sock->mac, g_this_mac_addr, RTE_ETHER_ADDR_LEN);

    LL_ADD(sock, lsock);

    return sock;
}

static int process_tcp_last_ack(sock_t *sock, struct rte_tcp_hdr *tcphdr)
{
    if (sock->status != TCP_STATUS_LAST_ACK)
	return -1;

    if ( !(tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) )
	return -1;

    sock->status = TCP_STATUS_CLOSED;

    LL_REMOVE(sock, lsock);
    rte_free(sock->sendbuf);
    rte_free(sock->recvbuf);
    rte_free(sock);

    return 0;
}

static int process_tcp_close_wait(sock_t *sock, __attribute__((unused)) struct rte_tcp_hdr *tcphdr)
{
    if (sock->status != TCP_STATUS_CLOSE_WAIT)
	return -1;

    return 0;
}

static int process_tcp_established(sock_t *sock, struct rte_tcp_hdr *tcphdr, uint16_t tcplen)
{
    if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {

    }

    if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) {
	/* put payload fragment to user receive buffer, will get the payload by calling recv */
	tcp_fragment_t *recv_fragment = rte_zmalloc(NULL, sizeof(tcp_fragment_t), 0);
	if (!recv_fragment)
	    return -1;

	uint8_t hdrlen = tcphdr->data_off >> 4;
	int payload_len = tcplen - hdrlen * 4;
	uint8_t *payload = (uint8_t *)tcphdr + hdrlen * 4;
	if (put_fragment_to_recv_buf(sock, tcphdr, payload, payload_len) < 0)
	    return -1;

	/* return ack fragment to send buffer, will return ack to peer */
	sock->send_next = ntohl(tcphdr->recv_ack);
	sock->recv_next += payload_len;

	if (put_ack_fragment_to_send_buf(tcphdr, sock) < 0)
	    return -1;
    }

    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
    }

    if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {
	sock->status = TCP_STATUS_CLOSE_WAIT;

	/* put empty data fragment to receive buffer, will return 0 by calling recv */
	if (put_fragment_to_recv_buf(sock, tcphdr, NULL, 0) < 0)
	    return -1;

	/* return ack fragment to send buffer, will return ack to peer */
	sock->send_next = ntohl(tcphdr->recv_ack);
	sock->recv_next++;

	if (put_ack_fragment_to_send_buf(tcphdr, sock) < 0)
	    return -1;
    }

    return 0;
}

static int process_tcp_syn_rcvd(sock_t *sock, struct rte_tcp_hdr *tcphdr)
{
    if ( !(tcphdr->tcp_flags & RTE_TCP_ACK_FLAG && sock->status == TCP_STATUS_SYN_RCVD) )
	return -1;

    if (ntohl(tcphdr->recv_ack) != sock->send_next + 1)
	return -1;

    sock->status = TCP_STATUS_ESTABLISHED;

    sock_t *listen_sock = get_listen_sock(sock->dport);
    if (!listen_sock)
	EEXIT("failed to get listen socket in TCP_STATUS_SYN_RCVD");

    pthread_mutex_lock(&listen_sock->mutex);
    pthread_cond_signal(&listen_sock->cond);
    pthread_mutex_unlock(&listen_sock->mutex);

    return 0;
}

static int process_tcp_listen(struct rte_tcp_hdr *tcphdr, struct rte_ipv4_hdr *iphdr)
{
    if ( !(tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) )
	return -1;

    sock_t *sock = create_tcp_sock(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
    if (!sock)
	return -1;

    tcp_fragment_t *fragment = create_empty_data_fragment(tcphdr->dst_port, tcphdr->src_port,
							sock->send_next, ntohl(tcphdr->sent_seq) + 1);
    if (!fragment)
	goto err_malloc_fragment;

    fragment->flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;

    rte_ring_mp_enqueue(sock->sendbuf, fragment);

    sock->recv_next = fragment->ack;
    sock->status = TCP_STATUS_SYN_RCVD;

    return 0;

err_malloc_fragment:
    LL_REMOVE(sock, lsock);
    rte_free(sock);

    return -1;
}

static int process_tcp_pkt(struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);

    uint16_t cksum = tcphdr->cksum;
    tcphdr->cksum = 0;
    if (cksum != rte_ipv4_udptcp_cksum(iphdr, tcphdr))
	return -1;

    sock_t *sock = get_sock_from_five_tuple(
	    iphdr->src_addr, tcphdr->src_port, iphdr->dst_addr, tcphdr->dst_port, IPPROTO_TCP);
    if (!sock)
	return -1;

    switch (sock->status) {
    case TCP_STATUS_CLOSED:
	break;

    case TCP_STATUS_LISTEN:
	if (process_tcp_listen(tcphdr, iphdr) < 0)
	    return -1;
	break;

    case TCP_STATUS_SYN_RCVD:
	if (process_tcp_syn_rcvd(sock, tcphdr) < 0)
	    return -1;
	break;

    case TCP_STATUS_SYN_SENT:
	break;

    case TCP_STATUS_ESTABLISHED: {
	uint16_t tcp_len = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
	if (process_tcp_established(sock, tcphdr, tcp_len) < 0)
	    return -1;
	break;
    }
    case TCP_STATUS_FIN_WAIT1:
	break;

    case TCP_STATUS_FIN_WAIT2:
	break;

    case TCP_STATUS_CLOSING:
	break;

    case TCP_STATUS_TIME_WAIT:
	break;

    case TCP_STATUS_CLOSE_WAIT:
	if (process_tcp_close_wait(sock, tcphdr) < 0)
	    return -1;
	break;

    case TCP_STATUS_LAST_ACK:
	if (process_tcp_last_ack(sock, tcphdr) < 0)
	    return -1;
	break;
    }

    return 0;
}

static void
create_tcp_pkt(uint8_t *pkt_data, uint16_t len,
        uint8_t *smac, uint8_t *dmac, uint32_t sip, uint32_t dip, tcp_fragment_t *fragment)
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
    iphdr->next_proto_id = IPPROTO_TCP;
    iphdr->src_addr = sip;
    iphdr->dst_addr = dip;
    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

    struct rte_tcp_hdr *tcphdr = (void *)((uint8_t *)iphdr + sizeof(*iphdr));
    tcphdr->src_port = fragment->sport;
    tcphdr->dst_port = fragment->dport;
    tcphdr->sent_seq = htonl(fragment->seq);
    tcphdr->recv_ack = htonl(fragment->ack);
    tcphdr->data_off = fragment->data_off;
    tcphdr->rx_win = fragment->win;
    tcphdr->tcp_urp = fragment->urp;
    tcphdr->tcp_flags = fragment->flags;

    if (fragment->length > 0) {
	uint8_t *payload = (uint8_t *) (tcphdr + 1) + fragment->option_len * sizeof(uint32_t);
	rte_memcpy(payload, fragment->data, fragment->length);
    }

    tcphdr->cksum = 0;
    tcphdr->cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
}

static void send_tcp(struct rte_mempool *mpool)
{
    for (sock_t *sock = lsock; sock; sock = sock->next) {
	if (sock->protocol != IPPROTO_TCP || !sock->sendbuf)
	    continue;

	tcp_fragment_t *fragment;
	if (rte_ring_mc_dequeue(sock->sendbuf, (void **)&fragment) < 0)
	    continue;

	uint8_t *dst_mac = get_dst_macaddr(sock->sip);  // client ip
	if (!dst_mac) {
	    send_arp(mpool, sock->mac, g_arp_request_mac, sock->dip, sock->sip, RTE_ARP_OP_REQUEST);
	    rte_ring_mp_enqueue(sock->sendbuf, fragment);
	} else {
	    const unsigned total_length =
		sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) +
		fragment->option_len * sizeof(uint32_t) + fragment->length;

	    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mpool);
	    if (!mbuf)
		EEXIT("failed to alloc mbuf");
	    mbuf->pkt_len = mbuf->data_len = total_length;

	    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	    create_tcp_pkt(pkt_data, total_length,
		    sock->mac, dst_mac, sock->dip, sock->sip, fragment);

	    io_ring_t *io_ring = get_io_ring_instance();
	    en_ring_burst(io_ring->out, &mbuf, 1);

	    rte_free(fragment->data);
	    rte_free(fragment);
	}
    }
}

#endif

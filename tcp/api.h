#ifndef __API_H__
#define __API_H__

#include "fd.h"
#include "config.h"
#include "list.h"
#include "ring_buf.h"
#include <rte_eal.h>
#include <rte_ether.h>
#include <arpa/inet.h>
#include <rte_tcp.h>

#define TCP_OPTION_INTS    10

typedef enum {
    TCP_STATUS_CLOSED = 0,
    TCP_STATUS_LISTEN,
    TCP_STATUS_SYN_RCVD,
    TCP_STATUS_SYN_SENT,
    TCP_STATUS_ESTABLISHED,
    TCP_STATUS_FIN_WAIT1,
    TCP_STATUS_FIN_WAIT2,
    TCP_STATUS_CLOSING,
    TCP_STATUS_TIME_WAIT,
    TCP_STATUS_CLOSE_WAIT,
    TCP_STATUS_LAST_ACK,
} tcp_status_t;

typedef struct sock {
    /* for tcp and udp */
    int fd;
    uint32_t sip, dip;
    uint16_t sport, dport;
    uint8_t mac[RTE_ETHER_ADDR_LEN];
    uint8_t protocol;
    struct rte_ring *sendbuf, *recvbuf;
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    /* only for tcp */
    uint32_t send_next, recv_next;
    tcp_status_t status;

    struct sock *prev, *next;
} sock_t;

typedef struct {
    uint32_t sip, dip;
    uint16_t sport, dport;
    unsigned char *data;
    uint16_t length;
} udp_payload_t;

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;
    uint8_t  flags;
    uint16_t win;
    uint16_t cksum;
    uint16_t urp;
    uint32_t option[TCP_OPTION_INTS];
    uint8_t  option_len;
    uint8_t *data;
    uint32_t length;
} tcp_fragment_t;

static sock_t *lsock;

static sock_t *get_sock_from_fd(int fd)
{
    for (sock_t *sock = lsock; sock; sock = sock->next) {
        if (fd == sock->fd) {
            return sock;
        }
    }

    return NULL;
}

static sock_t *get_listen_sock(uint16_t dport)
{
     for (sock_t *sock = lsock; sock; sock = sock->next) {
        if (sock->protocol == IPPROTO_TCP &&
                sock->status == TCP_STATUS_LISTEN && sock->dport == dport) {
            return sock;
        }
    }

     return NULL;
}

static sock_t *get_accept_sock(uint16_t dport)
{
     for (sock_t *sock = lsock; sock; sock = sock->next) {
        if (sock->protocol == IPPROTO_TCP &&
                sock->fd == -1 && sock->dport == dport) {
            return sock;
        }
    }

     return NULL;
}

static sock_t *
get_sock_from_five_tuple(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport, uint8_t protocol)
{
    for (sock_t *sock = lsock; sock; sock = sock->next) {
        if (sip == sock->sip && dip == sock->dip &&
            sport == sock->sport && dport == sock->dport &&
            protocol == sock->protocol) {
            return sock;
        }
    }

    if (protocol != IPPROTO_TCP)
        return NULL;

    // if the tcp status is not ESTABLISHED, maybe is LISTENING
    return get_listen_sock(dport);
}
static int _socket(int domain, int type, __attribute__((unused)) int protocol)
{
    if (domain != AF_INET)
        return -1;

    int fd = get_unused_fd();
    if (fd < 0)
        return -1;

    sock_t *sock = rte_zmalloc("sock", sizeof(sock_t), 0);
    if (!sock)
        return -1;

    if (type == SOCK_STREAM) {
        sock->protocol = IPPROTO_TCP;
    } else if (type == SOCK_DGRAM) {
        sock->protocol = IPPROTO_UDP;
        char ring_name[32] = { 0 };
        snprintf(ring_name, sizeof(ring_name), "sock_recv_buff_%d", fd);
        sock->recvbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),
                    RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!sock->recvbuf)
            goto err_create_recv_buf;

        snprintf(ring_name, sizeof(ring_name), "sock_send_buff_%d", fd);
        sock->sendbuf = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),
                    RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!sock->sendbuf)
            goto err_create_send_buf;
    }

    sock->fd = fd;

    pthread_mutex_init(&sock->mutex, NULL);
    pthread_cond_init(&sock->cond, NULL);

    LL_ADD(sock, lsock);

    return fd;

err_create_send_buf:
    rte_ring_free(sock->recvbuf);
err_create_recv_buf:
    rte_free(sock);

    return -1;
}

static int _bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (addrlen != sizeof(struct sockaddr_in))
        return -1;

    sock_t *sock = get_sock_from_fd(sockfd);
    if (!sock)
        return -1;

    const struct sockaddr_in *addr_in = (const struct sockaddr_in *)addr;
    rte_memcpy(sock->mac, g_this_mac_addr, RTE_ETHER_ADDR_LEN);
    if (sock->protocol == IPPROTO_TCP) {
        sock->dip = addr_in->sin_addr.s_addr;
        sock->dport = addr_in->sin_port;
        sock->status = TCP_STATUS_CLOSED;
    } else {
        sock->sip = addr_in->sin_addr.s_addr;
        sock->sport = addr_in->sin_port;
    }


    return 0;
}

static int _listen(int sockfd, __attribute__((unused)) int backlog)
{
    sock_t *sock = get_sock_from_fd(sockfd);
    if (!sock)
        return -1;

    if (sock->protocol != IPPROTO_TCP)
        return -1;

    sock->status = TCP_STATUS_LISTEN;

    return 0;
}

static int _accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    sock_t *listen_sock = get_sock_from_fd(sockfd);
    if (!listen_sock)
        return -1;

    if (listen_sock->protocol != IPPROTO_TCP)
        return -1;

    sock_t *accept_sock = NULL;

    pthread_mutex_lock(&listen_sock->mutex);
    while ( !(accept_sock = get_accept_sock(listen_sock->dport)))
        pthread_cond_wait(&listen_sock->cond, &listen_sock->mutex);
    pthread_mutex_unlock(&listen_sock->mutex);

    accept_sock->fd = get_unused_fd();
    struct sockaddr_in *src_addr_in = (struct sockaddr_in *)addr;
    src_addr_in->sin_addr.s_addr = accept_sock->sip;
    src_addr_in->sin_port = accept_sock->sport;
    *addrlen = sizeof(struct sockaddr_in);

    return accept_sock->fd;
}

static ssize_t _recv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags)
{
    sock_t *sock = get_sock_from_fd(sockfd);
    if (!sock)
        return -1;

    if (sock->protocol != IPPROTO_TCP)
        return -1;

    tcp_fragment_t *fragment;
    pthread_mutex_lock(&sock->mutex);
    while (rte_ring_mc_dequeue(sock->recvbuf, (void **)&fragment) < 0)
        pthread_cond_wait(&sock->cond, &sock->mutex);
    pthread_mutex_unlock(&sock->mutex);

    if (fragment->length == 0) {
        rte_free(fragment);

        return 0;
    }

    if (len < fragment->length) {
        // put data to user
        rte_memcpy(buf, fragment->data, len);

        // move data forward
        rte_memcpy(fragment->data, fragment->data + len, fragment->length - len);
        fragment->length -= len;

        // put back to the send ring buffer
        rte_ring_mp_enqueue(sock->recvbuf, fragment);

        return len;
    }

    uint16_t data_len = fragment->length;
    rte_memcpy(buf, fragment->data, data_len);
    rte_free(fragment->data);
    rte_free(fragment);

    return data_len;
}

static ssize_t _send(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags)
{
    sock_t *sock = get_sock_from_fd(sockfd);
    if (!sock)
        return -1;

    if (sock->protocol != IPPROTO_TCP)
        return -1;

    tcp_fragment_t *fragment = rte_malloc(NULL, sizeof(tcp_fragment_t), 0);
    if (!fragment)
        return -1;

    fragment->dport = sock->sport;
	fragment->sport = sock->dport;
	fragment->seq = sock->send_next;
	fragment->ack = sock->recv_next;
	fragment->win = TCP_INITIAL_WINDOW;
	fragment->data_off = 0x50;
	fragment->data = NULL;
	fragment->length = 0;
	fragment->flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
	fragment->data = rte_malloc(NULL, len, 0);
	if (!fragment->data) {
	    rte_free(fragment);

	    return -1;
	}

	rte_memcpy(fragment->data, buf, len);
	fragment->length = len;

	rte_ring_mp_enqueue(sock->sendbuf, fragment);

    return len;
}

static ssize_t _recvfrom(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen)
{
    sock_t *sock = get_sock_from_fd(sockfd);
    if (!sock)
        return -1;

    udp_payload_t *payload;
    pthread_mutex_lock(&sock->mutex);
    while (rte_ring_mc_dequeue(sock->recvbuf, (void **)&payload) < 0)
        pthread_cond_wait(&sock->cond, &sock->mutex);
    pthread_mutex_unlock(&sock->mutex);

    struct sockaddr_in *src_addr_in = (struct sockaddr_in *)src_addr;
    src_addr_in->sin_addr.s_addr = payload->sip;
    src_addr_in->sin_port = payload->sport;
    *addrlen = sizeof(struct sockaddr_in);

    if (len < payload->length) {
        // put data to user
        rte_memcpy(buf, payload->data, len);

        // move data forward
        rte_memcpy(payload->data, payload->data + len, payload->length - len);
        payload->length -= len;

        // put back to the send ring buffer
        rte_ring_mp_enqueue(sock->recvbuf, payload);

        return len;
    }

    uint16_t payload_len = payload->length;
    rte_memcpy(buf, payload->data, payload_len);
    rte_free(payload->data);
    rte_free(payload);

    return payload_len;
}

static ssize_t _sendto(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags,
                      const struct sockaddr *dst_addr, socklen_t addrlen)
{
    if (addrlen != sizeof(struct sockaddr_in))
        return -1;

    sock_t *sock = get_sock_from_fd(sockfd);
    if (!sock)
        return -1;

    udp_payload_t *payload = rte_malloc(NULL, sizeof(udp_payload_t), 0);
    if (!payload)
        return -1;

    const struct sockaddr_in *dst_addr_in = (const struct sockaddr_in *)dst_addr;
    payload->dip = dst_addr_in->sin_addr.s_addr;
    payload->dport = dst_addr_in->sin_port;
    payload->sip = sock->sip;
    payload->sport = sock->sport;
    payload->length = len;

    payload->data = rte_zmalloc("udp data", len, 0);
    if (!payload->data)
        return -1;

    rte_memcpy(payload->data, buf, len);

    rte_ring_mp_enqueue(sock->sendbuf, payload);

    return len;
}

static int _close(int fd)
{
    sock_t *sock = get_sock_from_fd(fd);
    if (!sock)
        return -1;

    if (sock->protocol == IPPROTO_TCP && sock->status != TCP_STATUS_LISTEN) {
        tcp_fragment_t *fragment = rte_zmalloc(NULL, sizeof(tcp_fragment_t), 0);
        if (!fragment)
            return -1;

        fragment->sport = sock->dport;
        fragment->dport = sock->sport;
        fragment->seq = sock->send_next;
        fragment->ack = sock->recv_next;
        fragment->flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
        fragment->win = TCP_INITIAL_WINDOW;
        fragment->data_off = 0x50;

        rte_ring_mp_enqueue(sock->sendbuf, fragment);
        sock->status = TCP_STATUS_LAST_ACK;
    } else {
        LL_REMOVE(sock, lsock);
        rte_ring_free(sock->sendbuf);
        rte_ring_free(sock->recvbuf);
        rte_free(sock);
    }

    put_unused_fd(fd);

    return 0;
}

#endif

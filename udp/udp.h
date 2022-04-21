#ifndef __UDP_H__
#define __UDP_H__

#include "fd.h"
#include "list.h"
#include "ring_buf.h"
#include <rte_eal.h>
#include <rte_ether.h>
#include <arpa/inet.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_malloc.h>

extern uint8_t g_this_mac_addr[RTE_ETHER_ADDR_LEN];

typedef struct localhost {
    int fd;
    uint32_t ip;
    uint16_t port;
    uint8_t mac[RTE_ETHER_ADDR_LEN];
    uint8_t protocol;
    struct rte_ring *sendbuf, *recvbuf;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct localhost *prev, *next;
} localhost_t;

typedef struct {
    uint32_t sip, dip;
    uint16_t sport, dport;
    unsigned char *data;
    uint16_t length;
} payload_t;

static localhost_t *lhost;

static localhost_t *get_localhost_from_fd(int fd)
{
    for (localhost_t *host = lhost; host; host = host->next) {
        if (fd == host->fd) {
            return host;
        }
    }

    return NULL;
}

static localhost_t *get_localhost_from_ip_port_protocol(uint32_t ip, uint16_t port, uint8_t protocol)
{
    for (localhost_t *host = lhost; host; host = host->next) {
        if (ip == host->ip && port == host->port && protocol == host->protocol) {
            return host;
        }
    }

    return NULL;

}

static int _socket(int domain, int type, __attribute__((unused)) int protocol)
{
    // only support UDP
    if (type != SOCK_DGRAM)
        return -1;

    if (domain != AF_INET)
        return -1;

    int fd = get_unused_fd();
    if (fd < 0)
        return -1;

    localhost_t *host = rte_zmalloc("localhost", sizeof(localhost_t), 0);
    if (!host)
        return -1;

    host->fd = fd;
    host->protocol = IPPROTO_UDP;
    host->recvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(),
                RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!host->recvbuf)
        goto err_create_recv_buf;

    host->sendbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(),
                RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!host->sendbuf)
        goto err_create_send_buf;


    pthread_mutex_init(&host->mutex, NULL);
    pthread_cond_init(&host->cond, NULL);

    LL_ADD(host, lhost);

    return fd;

err_create_send_buf:
    rte_ring_free(host->recvbuf);
err_create_recv_buf:
    rte_free(host);

    return -1;
}

static int _bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (addrlen != sizeof(struct sockaddr_in))
        return -1;

    localhost_t *host = get_localhost_from_fd(sockfd);
    if (!host)
        return -1;

    const struct sockaddr_in *addr_in = (const struct sockaddr_in *)addr;
    host->port = addr_in->sin_port;
    host->ip = addr_in->sin_addr.s_addr;
    rte_memcpy(host->mac, g_this_mac_addr, RTE_ETHER_ADDR_LEN);

    return 0;
}

static ssize_t _recvfrom(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen)
{
    localhost_t *host = get_localhost_from_fd(sockfd);
    if (!host)
        return -1;

    payload_t *payload;
    pthread_mutex_lock(&host->mutex);
    while (rte_ring_mc_dequeue(host->recvbuf, (void **)&payload) < 0)
        pthread_cond_wait(&host->cond, &host->mutex);
    pthread_mutex_unlock(&host->mutex);

    struct sockaddr_in *src_addr_in = (struct sockaddr_in *)src_addr;
    src_addr_in->sin_addr.s_addr = payload->sip;
    src_addr_in->sin_port = payload->sport;
    *addrlen = sizeof(struct sockaddr_in);

    if (len < payload->length) {
        rte_memcpy(buf, payload->data, len);

        unsigned char *tmp = rte_malloc("udp data", payload->length - len, 0);
        if (!tmp)
            return -1;

        rte_memcpy(tmp, payload->data + len, payload->length - len);
        payload->length -= len;
        rte_free(payload->data);
        payload->data = tmp;

        rte_ring_mp_enqueue(host->recvbuf, payload);

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

    localhost_t *host = get_localhost_from_fd(sockfd);
    if (!host)
        return -1;

    payload_t *payload = rte_malloc("payload", sizeof(payload_t), 0);
    if (!payload)
        return -1;

    const struct sockaddr_in *dst_addr_in = (const struct sockaddr_in *)dst_addr;
    payload->dip = dst_addr_in->sin_addr.s_addr;
    payload->dport = dst_addr_in->sin_port;
    payload->sip = host->ip;
    payload->sport = host->port;
    payload->length = len;

    payload->data = rte_zmalloc("udp data", len, 0);
    if (!payload->data)
        return -1;

    rte_memcpy(payload->data, buf, len);

    rte_ring_mp_enqueue(host->sendbuf, payload);

    return len;
}

static int _close(int fd)
{
    localhost_t *host = get_localhost_from_fd(fd);
    if (!host)
        return -1;

    LL_REMOVE(host, lhost);
    rte_ring_free(host->sendbuf);
    rte_ring_free(host->recvbuf);
    rte_free(host);

    put_unused_fd(fd);

    return 0;
}

#endif

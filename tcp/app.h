#ifndef __APP_H__
#define __APP_H__

#include "api.h"

#define UDP_PORT 8999
#define TCP_PORT 8999
#define BUF_SIZE 1024

static int udp_server(__attribute__((unused)) void *arg)
{
    int sockfd = _socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in servaddr = { 0 }, cliaddr = { 0 };
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = THIS_IPV4_ADDR;
    servaddr.sin_port = htons(UDP_PORT);

    _bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    char buf[BUF_SIZE];
    socklen_t addrlen = sizeof(cliaddr);
    ssize_t recvd;

    for (;;) {
        memset(buf, 0, sizeof(buf));

        ssize_t n = recvd = _recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&cliaddr, &addrlen);
        if (n < 0)
            continue;

        printf("udp recv from %s:%d, data: %s\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), buf);

        _sendto(sockfd, buf, recvd, 0, (struct sockaddr *)&cliaddr, sizeof(cliaddr));
    }

    _close(sockfd);

    return 0;
}

static int tcp_server(__attribute__((unused)) void *arg)
{
    int listenfd = _socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in servaddr = { 0 }, cliaddr = { 0 };
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = THIS_IPV4_ADDR;
    servaddr.sin_port = htons(TCP_PORT);

    _bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

    _listen(listenfd, 128);

    socklen_t addrlen = sizeof(cliaddr);
    for (;;) {
        int connfd = _accept(listenfd, (struct sockaddr *)&cliaddr, &addrlen);
        printf("accepted client, connfd: %d\n", connfd);

        char buf[BUF_SIZE];

        for (;;) {
            memset(buf, 0, sizeof(buf));

            ssize_t n = _recv(connfd, buf, sizeof(buf), 0);
            if (n == 0) {
                _close(connfd);
                break;
            } else if (n < 0) {
                continue;
            }

            printf("tcp recv from %s:%d, data: %s\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port), buf);

            _send(connfd, buf, n, 0);
        }
    }

    _close(listenfd);

    return 0;
}

#endif

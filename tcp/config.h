#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <rte_ether.h>

#define MBUF_POOL_SIZE (4096 - 1)
#define ETH_DEV_PORT_ID 0   // eth0
#define BURST_SIZE 32
#define TIMER_RESOLUTION_CYCLES (2000000000ULL * 1) /* around 10s at 2 Ghz */
#define MAX_PACKET_SIZE 4096

#define TCP_MAX_SEQ        UINT_MAX
#define TCP_INITIAL_WINDOW 14600

//#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b << 8) + (c << 16) + (d << 24))
//#define THIS_IPV4_ADDR MAKE_IPV4_ADDR(192, 168, 18, 115)
#define THIS_IPV4_ADDR inet_addr("192.168.18.115")

static uint8_t g_arp_request_mac[RTE_ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
extern uint8_t g_this_mac_addr[RTE_ETHER_ADDR_LEN];


#endif

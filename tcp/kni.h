#ifndef __KNI_H__
#define __KNI_H__

#include "config.h"
#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_log.h>

static int kni_config_network_if(uint16_t port_id, uint8_t if_up)
{
    if (!rte_eth_dev_is_valid_port(port_id)) {
        RTE_LOG(ERR, KNI, "Invalid port id %d\n", port_id);
        return -EINVAL;
    }

    RTE_LOG(INFO, KNI, "Configure network interface of %d %s\n", port_id, if_up ? "up" : "down");

    rte_eth_dev_stop(port_id);

    int ret = 0;
    if (if_up)
        ret = rte_eth_dev_start(port_id);

    if (ret < 0)
        RTE_LOG(ERR, KNI, "Failed to start port %d\n", port_id);

    return ret;
}

static struct rte_kni *alloc_kni(struct rte_mempool *mpool, uint16_t port_id)
{
    struct rte_kni_conf conf = {
        .group_id = ETH_DEV_PORT_ID,
        .mbuf_size = MAX_PACKET_SIZE,
    };
    snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", port_id);
    rte_eth_macaddr_get(ETH_DEV_PORT_ID, (struct rte_ether_addr *)conf.mac_addr);
    rte_eth_dev_get_mtu(ETH_DEV_PORT_ID, &conf.mtu);

    struct rte_kni_ops ops = {
        .port_id = port_id,
        .config_network_if = kni_config_network_if,
    };

    return rte_kni_alloc(mpool, &conf, &ops);
}

static struct rte_kni *kni_init(struct rte_mempool *mpool, uint16_t port_id)
{
    if (rte_kni_init(port_id) < 0)
        return NULL;

    return alloc_kni(mpool, port_id);
}


#endif

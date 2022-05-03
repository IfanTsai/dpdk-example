#ifndef __RING_BUF_H__
#define __RING_BUF_H__

#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_malloc.h>
#include <string.h>

#define RING_SIZE 1024

#define EEXIT(fmt, ...) \
        rte_exit(EXIT_FAILURE, "[%s:%d] "fmt, __func__, __LINE__, ##__VA_ARGS__)

typedef struct {
    struct rte_ring *in;
    struct rte_ring *out;
} io_ring_t;

static io_ring_t *io_ring = NULL;

static inline io_ring_t *get_io_ring_instance(void)
{
    if (!io_ring) {
        io_ring = rte_malloc("io ring", sizeof(io_ring_t), 0);
        if (!io_ring)
            EEXIT("failed to malloc io ring buffer");

        memset(io_ring, 0, sizeof(io_ring_t));
    }

    return io_ring;
}

/**
 * initalize in ring and out ring
 */
static inline void init_io_ring(io_ring_t *io_ring, int ring_size)
{
    if (!io_ring->in)
        io_ring->in = rte_ring_create("in ring", ring_size, rte_socket_id(),
                RING_F_SP_ENQ | RING_F_SC_DEQ);


    if (!io_ring->out)
        io_ring->out = rte_ring_create("out ring", ring_size, rte_socket_id(),
                RING_F_SP_ENQ | RING_F_SC_DEQ);
}

/**
 * enqueue serverl mbufs on the ring buf (multi-producers safe)
 */
static inline void en_ring_burst(struct rte_ring *ring, struct rte_mbuf **mbufs, unsigned n)
{
    rte_ring_mp_enqueue_burst(ring, (void **)mbufs, n, NULL);
}

/**
 * enqueue serverl mbufs from the ring buf (multi-consumer safe)
 */
static inline unsigned int de_ring_burst(struct rte_ring *ring, struct rte_mbuf **mbufs, unsigned n)
{
    return rte_ring_mc_dequeue_burst(ring, (void **)mbufs, n, NULL);
}

#endif


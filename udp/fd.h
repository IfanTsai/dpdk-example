#ifndef __FD_H__
#define __FD_H__

#define __FD_SETSIZE	65536
#define __NFDBITS	    (8 * sizeof(unsigned long))
#define __FDSET_LONGS	(__FD_SETSIZE / __NFDBITS)

typedef struct {
    unsigned long fds_bits[__FDSET_LONGS];
} __fd_set_t;

static inline void __FD_SET(unsigned long fd, __fd_set_t *fdsetp)
{
	unsigned long tmp = fd / __NFDBITS;
	unsigned long rem = fd % __NFDBITS;
	fdsetp->fds_bits[tmp] |= (1UL << rem);
}

static inline void __FD_CLR(unsigned long fd, __fd_set_t *fdsetp)
{
	unsigned long tmp = fd / __NFDBITS;
	unsigned long rem = fd % __NFDBITS;
	fdsetp->fds_bits[tmp] &= ~(1UL << rem);
}

static inline int __FD_ISSET(unsigned long fd, const __fd_set_t *fdsetp)
{
	unsigned long tmp = fd / __NFDBITS;
	unsigned long rem = fd % __NFDBITS;

	return (fdsetp->fds_bits[tmp] & (1UL << rem)) != 0;
}

static inline void __FD_ZERO(__fd_set_t *fdsetp)
{
    for (int i = __FDSET_LONGS; i; i--)
        fdsetp->fds_bits[i] = 0;
}

static __fd_set_t __fd_set;
static inline int get_unused_fd(void)
{
    for (int fd = 3; fd < __FD_SETSIZE; fd++) {
        if (!__FD_ISSET(fd, &__fd_set)) {
            __FD_SET(fd, &__fd_set);

            return fd;
        }
    }

    return -1;
}

static inline void put_unused_fd(int fd)
{
    __FD_CLR(fd, &__fd_set);
}


#endif

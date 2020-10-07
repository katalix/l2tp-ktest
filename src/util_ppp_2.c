#include <assert.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>

#include "util.h"
#include "util_ppp.h"

int ppp_associate_channel(int pppox_fd, struct ppp *ppp)
{
    assert(pppox_fd >= 0);
    assert(ppp);

    int ppp_fd, idx;

    if (ioctl(pppox_fd, PPPIOCGCHAN, &idx) < 0) {
        err("couldn't get channel index: %m\n");
        return -errno;
    }

    ppp_fd = open("/dev/ppp", O_RDWR);
    if (ppp_fd < 0) {
        err("couldn't open /dev/ppp: %m\n");
        return -errno;
    }

    if (ioctl(ppp_fd, PPPIOCATTCHAN, &idx) < 0) {
        err("couldn't attach to channel %d: %m", idx);
        close(ppp_fd);
        return -errno;
    }

    ppp->fd.ppp = ppp_fd;
    ppp->idx.channel = idx;

    return 0;
}

int ppp_new_unit(struct ppp *ppp)
{
    assert(ppp);

    int idx = -1; /* ppp_generic assigns the index */
    int unit_fd;

    unit_fd = open("/dev/ppp", O_RDWR);
    if (unit_fd < 0) {
        err("couldn't open /dev/ppp: %m\n");
        return -errno;
    }

    if (ioctl(unit_fd, PPPIOCNEWUNIT, &idx) < 0) {
        err("couldn't create new ppp unit: %m\n");
        close(unit_fd);
        return -errno;
    }

    ppp->fd.unit = unit_fd;
    ppp->idx.unit = idx;

    return 0;
}

int ppp_connect_channel(struct ppp *ppp)
{
    assert(ppp);
    assert(ppp->fd.ppp >= 0);
    assert(ppp->idx.unit >= 0);

    if (ioctl(ppp->fd.ppp, PPPIOCCONNECT, &ppp->idx.unit) < 0) {
        err("couldn't attach to PPP unit %d: %m", ppp->idx.unit);
        return -errno;
    }
    return 0;
}

int ppp_establish_pppox(int pppox_fd, struct ppp *ppp)
{
    assert(pppox_fd >= 0);
    assert(ppp);
    assert(ppp->fd.ppp < 0);
    assert(ppp->fd.unit < 0);

    int ret;

    ret = ppp_associate_channel(pppox_fd, ppp);
    if (ret) goto err;

    ret = ppp_new_unit(ppp);
    if (ret) goto err;

    ret = ppp_connect_channel(ppp);
    if (ret) goto err;

    return 0;
err:
    ppp_close(ppp);
    return ret;
}

int ppp_generic_establish_ppp(int fd, int *unit)
{
    assert(fd >= 0);
    struct ppp ppp = INIT_PPP;
    int ret;

    ret = ppp_establish_pppox(fd, &ppp);
    if (ret) return ret;

    /* FIXME: leaks unit fd */

    if (unit) *unit = ppp.idx.unit;
    return ppp.fd.ppp;
}

void ppp_close(struct ppp *ppp)
{
    if (ppp) {
        if (ppp->fd.ppp >= 0) close(ppp->fd.ppp);
        if (ppp->fd.unit >= 0) close(ppp->fd.unit);
        memset(ppp, -1, sizeof(*ppp));
    }
}

/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * @file ppp_bridge_api.c
 *
 * Validation of ppp_generic bridge ioctl api.
 */
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>

#include "util.h"

#ifndef PPPIOCBRIDGECHAN
#define PPPIOCBRIDGECHAN _IOW('t', 53, int)
#endif

#ifndef PPPIOCUNBRIDGECHAN
#define PPPIOCUNBRIDGECHAN _IO('t', 54)
#endif

static pthread_mutex_t race_lock = PTHREAD_MUTEX_INITIALIZER;

static char *bridge_on_pppox_fd(struct l2tp_options *opt)
{
    int fd, id;

    fd = pppoe_create(opt->pw.pppac.id, opt->pw.pppac.peer_mac, opt->ifname);
    if (fd < 0)
        return "failed to create PPPoE socket";

    id = 90210;
    if (0 == ioctl(fd, PPPIOCBRIDGECHAN, &id))
        return "bridged successfully to an invalid id";
    dbg("ioctl: %m\n");
    if (errno != ENOTTY)
        return "unexpected return code from ioctl";

    close(fd);

    return 0;
}

static char *bridge_to_invalid_id(struct l2tp_options *opt)
{
    int fd, ret, id = 90210;
    struct ppp ppp = {};

    fd = pppoe_create(opt->pw.pppac.id, opt->pw.pppac.peer_mac, opt->ifname);
    if (fd < 0)
        return "failed to create PPPoE socket";

    ret = ppp_associate_channel(fd, &ppp);
    if (ret)
        return "failed to associate PPP channel";

    if (0 == ioctl(ppp.fd.ppp, PPPIOCBRIDGECHAN, &id))
        return "bridged successfully to an invalid id";
    dbg("ioctl: %m\n");
    if (errno != ENXIO)
        return "unexpected return code from ioctl";

    ppp_close(&ppp);
    close(fd);

    return 0;
}

static char *unbridge_inval(struct l2tp_options *opt)
{
    struct ppp ppp = {};
    int fd, ret;

    fd = pppoe_create(opt->pw.pppac.id, opt->pw.pppac.peer_mac, opt->ifname);
    if (fd < 0)
        return "failed to create PPPoE socket";

    ret = ppp_associate_channel(fd, &ppp);
    if (ret)
        return "failed to associate PPP channel";

    if (0 == ioctl(ppp.fd.ppp, PPPIOCUNBRIDGECHAN))
        return "unexpected successful unbridge";
    dbg("ioctl: %m\n");
    if (errno != EINVAL)
        return "unexpected return code from ioctl";

    ppp_close(&ppp);
    close(fd);

    return 0;
}

struct ppp_pair {
    struct ppp *c1;
    struct ppp *c2;
};

static int ppp_pair_init(struct l2tp_options *opt, struct ppp *a, struct ppp *b)
{
    assert(opt);
    assert(a);
    assert(b);

    int ret;

    {
        int fd = pppoe_create(opt->pw.pppac.id, opt->pw.pppac.peer_mac, opt->ifname);
        if (fd < 0) return fd;
        ret = ppp_associate_channel(fd, a);
        if (ret) return ret;
        a->fd.pppox = fd;
    }

    {
        int fd = pppoe_create(opt->pw.pppac.id + 10, opt->pw.pppac.peer_mac, opt->ifname);
        if (fd < 0) return fd;
        ret = ppp_associate_channel(fd, b);
        if (ret) return ret;
        b->fd.pppox = fd;
    }

    return 0;
}

static int thread_pair_init(void *(*thread_fn)(void *), pthread_t *t1, void *dptr1, pthread_t *t2, void *dptr2)
{
    assert(thread_fn);
    assert(t1);
    assert(t2);
    int ret;

    ret = pthread_create(t1, NULL, thread_fn, dptr1);
    if (ret) return ret;
    
    ret = pthread_create(t2, NULL, thread_fn, dptr2);
    if (ret) return ret;

    return 0;
}

static void *race_bridge_establish_thread_fn(void *dptr)
{
    struct ppp_pair *pp = dptr;
    pthread_mutex_lock(&race_lock);
    pthread_mutex_unlock(&race_lock);
    ioctl(pp->c1->fd.ppp, PPPIOCBRIDGECHAN, &pp->c2->idx.channel);
    return NULL;
}

static char *race_bridge_establish(struct l2tp_options *opt, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        struct ppp ppp1 = {}, ppp2 = {};
        struct ppp_pair p1 = {
            .c1 = &ppp1,
            .c2 = &ppp2,
        };
        struct ppp_pair p2 = {
            .c1 = &ppp2,
            .c2 = &ppp1,
        };
        pthread_t t1, t2;
        int ret;

        ret = ppp_pair_init(opt, &ppp1, &ppp2);
        if (ret) return "ppp_pair_init failed";

        pthread_mutex_lock(&race_lock);
        ret = thread_pair_init(race_bridge_establish_thread_fn, &t1, &p1, &t2, &p2);
        if (ret) return "thread_pair_init failed";
        pthread_mutex_unlock(&race_lock);

        pthread_join(t1, NULL);
        pthread_join(t2, NULL);

        close(ppp1.fd.pppox);
        close(ppp2.fd.pppox);
        ppp_close(&ppp1);
        ppp_close(&ppp2);
    }

    return 0;
}

static void *race_bridge_disestablish_thread_fn(void *dptr)
{
    struct ppp_pair *pp = dptr;
    pthread_mutex_lock(&race_lock);
    pthread_mutex_unlock(&race_lock);
    ioctl(pp->c1->fd.ppp, PPPIOCUNBRIDGECHAN);
    return NULL;
}

static char *race_bridge_disestablish(struct l2tp_options *opt, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        struct ppp ppp1 = {}, ppp2 = {};
        struct ppp_pair p1 = {
            .c1 = &ppp1,
            .c2 = &ppp2,
        };
        struct ppp_pair p2 = {
            .c1 = &ppp2,
            .c2 = &ppp1,
        };
        pthread_t t1, t2;
        int ret;

        ret = ppp_pair_init(opt, &ppp1, &ppp2);
        if (ret) return "ppp_pair_init failed";

        ret = ppp_bridge_channels(&ppp1, &ppp2);
        if (ret) return "ppp_bridge_channels failed";

        pthread_mutex_lock(&race_lock);
        ret = thread_pair_init(race_bridge_disestablish_thread_fn, &t1, &p1, &t2, &p2);
        if (ret) return "thread_pair_init failed";
        pthread_mutex_unlock(&race_lock);

        pthread_join(t1, NULL);
        pthread_join(t2, NULL);

        close(ppp1.fd.pppox);
        close(ppp2.fd.pppox);
        ppp_close(&ppp1);
        ppp_close(&ppp2);
    }

    return 0;
}

static void show_usage(const char *myname)
{
    printf("Name:     %s\n", myname);
    printf("Desc:     validate ppp_generic PPPIOCBRIDGECHAN and PPPIOCUNBRIDGECHAN API\n");
    printf("Usage:    %s [options]\n", myname);
    printf("          -h    print this usage information\n");
    printf("          -N    specify session interface name\n");
    printf("          -i    specify PPPoE session ID\n");
    printf("          -M    specify PPPoE peer MAC address\n");
}

#define check(_fn) do { \
    char *_r; \
    log(#_fn "\n"); \
    _r = _fn; \
    if (_r != 0) die(#_fn " failed: %s\n", _r); \
    else log("ok\n"); \
} while(0)

int main(int argc, char **argv)
{
    struct l2tp_options opt = {};
    int o;

    while ((o = getopt(argc, argv, "hN:i:M:")) != -1) {
        switch(o) {
            case 'h':
                show_usage(argv[0]);
                exit(EXIT_SUCCESS);
            case 'N':
                if (strlen(optarg) > sizeof(opt.ifname)-1)
                    die("Interface name \"%s\" is too long\n", optarg);
                memcpy(opt.ifname, optarg, strlen(optarg));
                break;
            case 'i':
                opt.pw.pppac.id = atoi(optarg);
                break;
            case 'M':
                if (6 != sscanf(optarg,
                            "%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8,
                            &opt.pw.pppac.peer_mac[0],
                            &opt.pw.pppac.peer_mac[1],
                            &opt.pw.pppac.peer_mac[2],
                            &opt.pw.pppac.peer_mac[3],
                            &opt.pw.pppac.peer_mac[4],
                            &opt.pw.pppac.peer_mac[5]))
                    die("Failed to parse MAC address \"%s\"\n", optarg);
                break;
            default:
                die("failed to parse command line args\n");
        }
    }

    if (!strlen(opt.ifname) || !opt.pw.pppac.id) {
        die("must specify interface name, session ID, and peer MAC\n");
    }

    check(bridge_on_pppox_fd(&opt));
    check(bridge_to_invalid_id(&opt));
    check(unbridge_inval(&opt));
    check(race_bridge_establish(&opt, 100));
    check(race_bridge_disestablish(&opt, 100));

    return 0;
}

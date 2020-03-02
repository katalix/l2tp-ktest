/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * @file tunl_query_race.c
 *
 * Race netlink tunnel get requests with tunnel socket close(2).
 */
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "l2tp_netlink.h"
#include "util.h"

static void *t_nl_get(size_t id, struct racing_threads_tunnel_info *ti, void *dptr)
{
    assert(ti);
    struct l2tp_tunnel_stats s = {0};
    dbg("%s: nl query tid %" PRIu32 "\n", __func__, ti->tid);
    l2tp_nl_tunnel_get(ti->tid, &s);
    return NULL;
}

static void *t_sk_close(size_t id, struct racing_threads_tunnel_info *ti, void *dptr)
{
    assert(ti);
    /* netlink requests are more time consuming than close(2), so sleep a little
     * to give the other thread a chance to get in first in some cases.
     */
    usleep(brandom(0,10000));
    dbg("%s: close fd %d\n", __func__, ti->tunnel_socket_fd);
    close(ti->tunnel_socket_fd);
    return NULL;
}

static void show_usage(const char *myname)
{
   printf("Name:     %s\n", myname);
   printf("Desc:     stresses tunnel query with racing threads\n");
   printf("Usage:    %s [options]\n", myname);
   printf("          -h    print this usage information\n");
   printf("          -c    number of tunnels to create per testcase\n");
   printf("          -f    specify tunnel socket address family (inet or inet6: default is inet)\n");
   printf("          -e    specify tunnel encapsulation (udp or ip: default is ip)\n");
}

int main(int argc, char **argv)
{
    int tunnel_count = 100;
    int opt;
    struct l2tp_options options = {
        .l2tp_version = L2TP_API_PROTOCOL_VERSION_3,
        .create_api = L2TP_NETLINK_API,
        .delete_api = L2TP_NETLINK_API,
        .family = AF_INET,
        .protocol = IPPROTO_L2TP,
        .pseudowire = L2TP_API_SESSION_PW_TYPE_ETH,
        .peer_addr = { .ip = "127.0.0.1", .port = 10000 },
        .local_addr = { .ip = "127.0.0.1", .port = 20000 },
        .tid = 1,
        .ptid = 1,
    };

    while ((opt = getopt(argc, argv, "hc:e:f:")) != -1) {
        switch(opt) {
        case 'h':
            show_usage(argv[0]);
            exit(EXIT_SUCCESS);
        case 'c':
            tunnel_count = atoi(optarg);
            break;
        case 'e':
            if (!parse_encap(optarg, &options.protocol))
                die("Invalid encapsulation %s\n", optarg);
            break;
        case 'f':
            if (!parse_socket_family(optarg, &options.family))
                die("Invalid address family %s\n", optarg);
            break;
        default:
            die("failed to parse command line args\n");
        }
    }

    if (tunnel_count < 0)
        die("command line error: invalid specification for tunnel count or iterations\n");

    if (options.family == AF_INET6) {
        options.local_addr.ip = "::1";
        options.peer_addr.ip = "::1";
    }

    log("Running %i racing tunnels: expect to see netlink errors...\n", tunnel_count);
    tunl_racing_threads(tunnel_count, &options, 1, t_nl_get, NULL, t_sk_close, NULL);
    log("OK\n");

    return 0;
}

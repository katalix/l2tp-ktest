/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * file: icmp_errors.c
 *
 * A tool for testing kernel handling of ICMP errors.
 *
 * Note that the tool expects the destination port not to have anything
 * listening on it, resulting in an ICMP "destination port unreachable"
 * error.  This error case should be reflected back to userspace as an
 * error, either as a failure when calling recvmsg(), or explicitly as
 * an error reported via. cmsg/MSG_ERRQUEUE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <poll.h>
#include <time.h>
#include <linux/l2tp.h>
#include <linux/errqueue.h>
#include <linux/icmp.h>

#include "l2tp_netlink.h"
#include "util.h"

void show_usage(const char *myname)
{
    printf("Name:     %s\n", myname);
    printf("Desc:     explore kernel handling of ICMP errors\n");
    printf("Usage:    %s [options]\n", myname);
    printf("          -h    print this usage information\n");
    printf("\n");
    printf("          Toplevel runtime control options:\n");
    printf("\n");
    printf("          -m    enable MSG_ERRQUEUE\n");
    printf("\n");
    printf("          L2TP protocol control options:\n");
    printf("\n");
    printf("          -v    specify L2TP version (2 or 3: leave unset to test a normal socket)\n");
    printf("          -f    specify tunnel socket address family (inet or inet6: default is inet)\n");
    printf("          -e    specify tunnel encapsulation (udp or ip: default is udp)\n");
    printf("\n");
    printf("          Peer specification:\n");
    printf("\n");
    printf("          -P    specify peer address/port (e.g. -P 192.168.1.12/5555)\n");
    printf("          -L    specify local address/port (e.g. -P 192.168.1.12/5555)\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    bool opt_msg_errqueue = false;
    int tfd = -1;
    int ret, opt;

    /* Protocol options */
    struct l2tp_options lo = {
        .l2tp_version   = 0,
        .create_api = L2TP_NETLINK_API,
        .delete_api = L2TP_NETLINK_API,
        .family     = AF_INET,
        .protocol   = IPPROTO_UDP,
        .tid = brandom(1,65535),
        .ptid = brandom(1,65535),
        .sid = brandom(1,65535),
        .psid = brandom(1,65535),
    };

    /* Parse commandline, doing basic sanity checking as we go */
    while ((opt = getopt(argc, argv, "hmv:f:e:P:L:")) != -1) {
        switch(opt) {
        case 'h':
            show_usage(argv[0]);
            exit(EXIT_SUCCESS);
        case 'm':
            opt_msg_errqueue = true;
            break;
        case 'v':
            lo.l2tp_version = atoi(optarg);
            if (lo.l2tp_version != 3 && lo.l2tp_version != 2)
                die("Invalid l2tp version %s\n", optarg);
            break;
        case 'f':
            if (!parse_socket_family(optarg, &lo.family))
                die("Invalid address family %s\n", optarg);
            break;
        case 'e':
            if (!parse_encap(optarg, &lo.protocol))
                die("Invalid encapsulation %s\n", optarg);
            break;
        case 'P':
            if (!parse_address(optarg, &lo.peer_addr))
                die("Failed to parse peer address %s\n", optarg);
            break;
        case 'L':
            if (!parse_address(optarg, &lo.local_addr))
                die("Failed to parse local address %s\n", optarg);
            break;
        default:
            die("failed to parse command line args\n");
        }
    }

    /* Generate default addresses */
    if (!lo.local_addr.ip) lo.local_addr = *gen_dflt_address(lo.family, true);
    if (!lo.peer_addr.ip) lo.peer_addr = *gen_dflt_address(lo.family, false);

    /* Now we've parsed the commandline, sanity check the combinations of
     * options
     */
    if (lo.l2tp_version == 2) {
        if (lo.protocol != IPPROTO_UDP)
            die("L2TPv2 code supports UDP encapsulation only\n");
    }

    /* Create socket and enable MSG_ERRQUEUE if requested */
    tfd = tunnel_socket(lo.family, lo.protocol, lo.tid, &lo.local_addr, &lo.peer_addr);
    if (tfd < 0) die("Failed to create managed tunnel socket\n");

    if (opt_msg_errqueue) {
        int on = 1;
        if (lo.family == AF_INET) {
            ret = setsockopt(tfd, IPPROTO_IP, IP_RECVERR, (char *)&on, sizeof(on));
            if (ret) die("setsockopt(IP_RECVERR) failed: %s\n", strerror(errno));
        } else if (lo.family == AF_INET6) {
            ret = setsockopt(tfd, IPPROTO_IPV6, IPV6_RECVERR, (char *)&on, sizeof(on));
            if (ret) die("setsockopt(IPV6_RECVERR) failed: %s\n", strerror(errno));
        }
    }

    /* Create kernel context(s) if we've been asked to */
    if (lo.l2tp_version) {
        ret = kernel_tunnel_create(tfd, &lo, NULL);
        if (ret) die("kernel_tunnel_create failed: %s\n", strerror(-ret));
    }

    /* Send a packet */
    {
        char buffer[64] = {};
        struct iovec iov = {
            .iov_base = buffer,
            .iov_len = sizeof(buffer),
        };
        struct msghdr msg = {
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL,
        };
        ssize_t nbytes = sendmsg(tfd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (nbytes != sizeof(buffer)) die("sendmsg failed: %s\n", strerror(errno));
        dbg("sendmsg() %zd bytes\n", nbytes);
    }

    /* Poll... */
    {
        struct pollfd fds[1] = {
            { .fd = tfd, .events = POLLIN|POLLERR },
        };
        ret = poll(&fds[0], 1, 500);
        if (ret == 0) die("poll() timed out waiting for input/error event on tunnel fd\n");
        if (ret < 0) die("poll(): %s\n", strerror(errno));
    }

    /* Recv packet */
    {
        unsigned char cmsg[CMSG_SPACE(sizeof(struct sock_extended_err))];
        unsigned char buffer[512];
        struct iovec iov = {
            .iov_base = buffer,
            .iov_len = sizeof(buffer),
        };
        struct msghdr msg = {
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = &cmsg,
            .msg_controllen = sizeof(cmsg),
            .msg_flags = 0,
        };
        int flags = MSG_NOSIGNAL | (opt_msg_errqueue ? MSG_ERRQUEUE : 0);
        struct cmsghdr *cp;
        ssize_t nbytes;

        dbg("recvmsg(%s)...\n", opt_msg_errqueue ? "MSG_ERRQUEUE" : "");
        nbytes = recvmsg(tfd, &msg, flags);
        dbg("... %zd bytes%s%s%s\n",
                nbytes,
                nbytes < 0 ? " (" : "",
                nbytes < 0 ? strerror(errno) : "",
                nbytes < 0 ? ")" : "");

        if (opt_msg_errqueue) {
            if (nbytes < 0) die("recvmsg: %s\n", strerror(errno));
            for (cp = CMSG_FIRSTHDR(&msg); cp != NULL; cp = CMSG_NXTHDR(&msg, cp)) {
                if ((cp->cmsg_level == SOL_IP) && (cp->cmsg_type == IP_RECVERR)) {
                    struct sock_extended_err err = {};
                    memcpy(&err, CMSG_DATA(cp), sizeof(err));
                    if (err.ee_origin == SO_EE_ORIGIN_ICMP) return 0;
                }

                if ((cp->cmsg_level == SOL_IPV6) && (cp->cmsg_type == IPV6_RECVERR)) {
                    struct sock_extended_err err = {};
                    memcpy(&err, CMSG_DATA(cp), sizeof(err));
                    if (err.ee_origin == SO_EE_ORIGIN_ICMP6) return 0;
                }
            }
            die("no IP[V6]_RECVERR ancillary data reported by recvmsg\n");
        } else {
            if (nbytes >= 0) die("recvmsg reports no error\n");
        }
    }

    return 0;
}

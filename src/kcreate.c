/**
 * file: kcreate.c
 *
 * A tool for creating kernel contexts for L2TP tunnels and sessions.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/l2tp.h>

#include "l2tp_netlink.h"
#include "util.h"

struct runtime_options {
    int     is_managed;
    int     do_delete;
    int     do_close_before_delete;
    int     do_create_session;
    int     do_exit;
    int     do_create_kernel_context;
};

void show_usage(const char *myname)
{
    printf("Name:     %s\n", myname);
    printf("Desc:     create L2TP tunnel and session contexts in the kernel\n");
    printf("Usage:    %s [options]\n", myname);
    printf("          -h    print this usage information\n");
    printf("\n");
    printf("          Toplevel runtime control options:\n");
    printf("\n");
    printf("          -m    create a managed tunnel (default is unmanaged)\n");
    printf("          -n    don't delete the tunnel before exiting\n");
    printf("          -I    don't exit (Immortal mode, prevents tunnel deletion)\n");
    printf("          -u    userspace only: i.e. create socket and bind/connect, but don't create kernel context\n");
    printf("          -x    close tunnel socket fd before deleting tunnel (applies to netlink API only)\n");
    printf("\n");
    printf("          You can control whether to create a session or not by specifying\n"
           "          the pseudowire type using the L2TP protocol control options.\n"
           "          If no pseudowire type is defined then no session will be created.\n");
    printf("\n");
    printf("          L2TP protocol control options:\n");
    printf("\n");
    printf("          -v    specify L2TP version (2 or 3: default is 3)\n");
    printf("          -c    specify L2TP resource creation API (socket or netlink: default is netlink)\n");
    printf("          -d    specify L2TP resource destruction API (socket or netlink: default is netlink)\n");
    printf("          -f    specify tunnel socket address family (inet or inet6: default is inet)\n");
    printf("          -e    specify tunnel encapsulation (udp or ip: default is udp)\n");
    printf("          -p    specify session pseudowire type (ppp or eth)\n");
    printf("          -T    specify local tunnel ID\n");
    printf("          -t    specify peer tunnel ID\n");
    printf("          -S    specify local session ID\n");
    printf("          -s    specify peer session ID\n");
    printf("\n");
    printf("          Peer specification:\n");
    printf("\n");
    printf("          -P    specify peer address/port (e.g. -P 192.168.1.12/5555)\n");
    printf("          -L    specify local address/port (e.g. -P 192.168.1.12/5555)\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    int ret, opt;
    int tfd = -1;
    int ppptctl = -1;
    int pppsctl = -1;

    /* Runtime options */
    struct runtime_options rto = {
        .do_delete = 1,
        .do_exit = 1,
        .do_create_kernel_context = 1,
    };

    /* Protocol options */
    struct l2tp_options lo = {
        .l2tp_version   = 3,
        .create_api = L2TP_NETLINK_API,
        .delete_api = L2TP_NETLINK_API,
        .family     = AF_INET,
        .protocol   = IPPROTO_UDP,
        .pseudowire = L2TP_API_SESSION_PW_TYPE_ETH,
    };

    /* Parse commandline, doing basic sanity checking as we go */
    while ((opt = getopt(argc, argv, "hmnxIuv:c:d:f:e:p:T:t:S:s:P:L:")) != -1) {
        switch(opt) {
        case 'h':
            show_usage(argv[0]);
            exit(EXIT_SUCCESS);
        case 'm':
            rto.is_managed = 1;
            break;
        case 'n':
            rto.do_delete = 0;
            break;
        case 'x':
            rto.do_close_before_delete = 1;
            break;
        case 'I':
            rto.do_exit = 0;
            break;
        case 'u':
            rto.do_create_kernel_context = 0;
            break;
        case 'v':
            lo.l2tp_version = atoi(optarg);
            if (lo.l2tp_version != 3 && lo.l2tp_version != 2)
                die("Invalid l2tp version %s\n", optarg);
            break;
        case 'c':
            if (!parse_api(optarg, &lo.create_api))
                die("Invalid api %s\n", optarg);
            break;
        case 'd':
            if (!parse_api(optarg, &lo.delete_api))
                die("Invalid api %s\n", optarg);
            break;
        case 'f':
            if (0 == strcmp("inet", optarg))
                lo.family = AF_INET;
            else if (0 == strcmp("inet6", optarg))
                lo.family = AF_INET6;
            else
                die("Invalid address family %s\n", optarg);
            break;
        case 'e':
            if (0 == strcmp("udp", optarg))
                lo.protocol = IPPROTO_UDP;
            else if (0 == strcmp("ip", optarg))
                lo.protocol = IPPROTO_L2TP;
            else
                die("Invalid encapsulation %s\n", optarg);
            break;
        case 'p':
            rto.do_create_session = 1;
            if (0 == strcmp("ppp", optarg))
                lo.pseudowire = L2TP_API_SESSION_PW_TYPE_PPP;
            else if (0 == strcmp("eth", optarg))
                lo.pseudowire = L2TP_API_SESSION_PW_TYPE_ETH;
            else
                die("Invalid pseudowire %s\n", optarg);
            break;
        case 'T':
            lo.tid = atoi(optarg);
            if (lo.tid <= 0) die("Invalid ID %s\n", optarg);
            break;
        case 't':
            lo.ptid = atoi(optarg);
            if (lo.ptid <= 0) die("Invalid ID %s\n", optarg);
            break;
        case 'S':
            lo.sid = atoi(optarg);
            if (lo.sid <= 0) die("Invalid ID %s\n", optarg);
            break;
        case 's':
            lo.psid = atoi(optarg);
            if (lo.psid <= 0) die("Invalid ID %s\n", optarg);
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

    /* Generate random tunnel and session ids */
    if (!lo.tid) lo.tid = brandom(1,65535);
    if (!lo.ptid) lo.ptid = brandom(1,65535);
    if (!lo.sid) lo.sid = brandom(1,65535);
    if (!lo.psid) lo.psid = brandom(1,65535);

    /* Generate default addresses */
    if (!lo.local_addr.ip) lo.local_addr = *gen_dflt_address(lo.family, true);
    if (!lo.peer_addr.ip) lo.peer_addr = *gen_dflt_address(lo.family, false);

    /* Now we've parsed the commandline, sanity check the combinations of
     * options
     */
    if (lo.l2tp_version == 2) {
        if (rto.do_create_session &&
            lo.pseudowire != L2TP_API_SESSION_PW_TYPE_PPP)
            die("L2TPv2 code supports PPP pseudowires only\n");
        if (lo.protocol != IPPROTO_UDP)
            die("L2TPv2 code supports UDP encapsulation only\n");
    }
    if (lo.l2tp_version == 3) {
        if (lo.create_api == L2TP_SOCKET_API &&
            lo.pseudowire == L2TP_API_SESSION_PW_TYPE_ETH)
            die("L2TPv3 code doesn't support ETH pw create using the socket API\n");
    }

    if (rto.do_close_before_delete && lo.create_api == L2TP_SOCKET_API) {
        die("Socket API doesn't support close before delete\n");
    }

    dbg("%s tunnel : v%d, %s/%s (create/delete API), %s encap, %s, %s pseudowire : %s on exit\n",
        rto.is_managed ? "MANAGED" : "UNMANAGED",
        lo.l2tp_version,
        lo.create_api == L2TP_SOCKET_API ? "socket" : "netlink",
        lo.delete_api == L2TP_SOCKET_API ? "socket" : "netlink",
        lo.protocol == IPPROTO_UDP ? "UDP" : "IP",
        lo.family == AF_INET ? "inet" : "inet6",
        rto.do_create_session ? lo.pseudowire == L2TP_API_SESSION_PW_TYPE_PPP ? "PPP" : "ETH" : "no",
        rto.do_delete ? "delete" : "don't delete");

    /* Create a tunnel socket ourself if we're running as managed */
    if (rto.is_managed) {
        tfd = tunnel_socket(lo.family, lo.protocol, lo.tid, &lo.local_addr, &lo.peer_addr);
        if (tfd < 0) die("Failed to create managed tunnel socket\n");
    }

    /* Create kernel context(s) if we've been asked to */
    if (rto.do_create_kernel_context) {
        ret = kernel_tunnel_create(tfd, &lo, &ppptctl);
        if (ret) die("kernel_tunnel_create failed: %s\n", strerror(-ret));

        /* Now create a session if we've been asked to */
        if (rto.do_create_session) {
            ret = kernel_session_create(&lo, &pppsctl);
            if (ret) die("kernel_session_create failed: %s\n", strerror(-ret));
        }
    }

    /* Finally delete the tunnel if requested */
    if (rto.do_delete && rto.do_exit) {
        switch(lo.delete_api) {
        case L2TP_NETLINK_API:
            if (rto.do_close_before_delete) {
                close(tfd);
                tfd = -1;
            }
            l2tp_nl_tunnel_delete(lo.tid);
            break;
        case L2TP_SOCKET_API:
            close(pppsctl);
            close(ppptctl);
            close(tfd);
            break;
        default:
            die("Unexpected tunnel delete api\n");
        }
    }

    if (!rto.do_exit) {
        if (tfd >= 0) {
            while (true) {
                char buf[1024] = {};
                ssize_t nb = recv(tfd, buf, sizeof(buf), 0);
                if (nb > 0) {
                    log("received %d bytes on socket %d (tunnel %d)\n", (int)nb, tfd, lo.tid);
                    log("v%d %s frame\n",
                            ((struct l2tp_control_hdr_v3*)buf)->ver,
                            ((struct l2tp_control_hdr_v3*)buf)->t_bit ?  "data" : "control");
                    mem_dump(buf, nb);
                }
            }
        } else {
            while(true) sleep(1);
        }
    }

    return 0;
}

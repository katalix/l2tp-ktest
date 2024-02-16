/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * @file sess_dataif.c
 *
 * Create L2TP session network interfaces.
 *
 * Two instances of the application must be started, one a server and
 * the other a client.
 *
 * Depending on command line arguments, L2TPv2 or v3 tunnel(s) are
 * created using UDP or L2TPIP, and may be created using netlink or
 * the L2TPv2 socket-based API.  Each tunnel runs in its own thread,
 * and creates a number of sessions (each in their own thread). Each
 * session configures its network interface ready for datapath
 * testing. No data packets are sent or received by this app.
 *
 * To test unexpected cleanup scenarios it's possible to close all the
 * tunnel sockets after a configurable timeout.
 *
 * This app creates 1 thread per tunnel and 1 thread per session. To
 * extend system process thread limits:
 *
 * ulimit -s  256
 * ulimit -i  120000
 * echo 120000 > /proc/sys/kernel/threads-max
 * echo 600000 > /proc/sys/vm/max_map_count
 * echo 200000 > /proc/sys/kernel/pid_max
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <linux/l2tp.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <semaphore.h>

#include "l2tp_netlink.h"
#include "util.h"
#include "util_ppp.h"

struct runtime_options {
    int is_client;
    int num_tunnels;
    int num_sessions;
    int timeout;
};

struct session_options {
    struct l2tp_options lo;
    struct runtime_options ro;
    struct tunnel_options *to;
    struct l2tp_pw pw;
};

struct tunnel_options {
    struct l2tp_options lo;
    struct runtime_options ro;
    int tfd;
    int ppptctl;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    struct session_options *so;
    size_t err_count, pkt_count;
};

static sem_t g_running;
static struct tunnel_options *g_all_tunnel_options = NULL;
static size_t g_n_tunnel_options = 0;
static const char *g_status_filename = NULL;
static FILE *g_status_file = NULL;

void show_usage(const char *myname)
{
    printf("Name:     %s\n", myname);
    printf("Desc:     create l2tp sessions in the kernel, ready to pass data.\n");
    printf("Usage:    %s [options]\n", myname);
    printf("          -h    print this usage information\n");
    printf("\n");
    printf("          Top level operational options:\n");
    printf("\n");
    printf("          -C    run in client mode. The server must already be running.\n");
    printf("\n");
    printf("          L2TP protocol control options:\n");
    printf("\n");
    printf("          -v    specify L2TP version (2 or 3: default is 2)\n");
    printf("          -f    specify tunnel socket address family (inet or inet6: default is inet)\n");
    printf("          -e    specify tunnel encapsulation (udp or ip: default is udp)\n");
    printf("          -p    specify session pseudowire type (ppp, pppac, or eth: default ppp)\n");
    printf("          -k    local cookie (4 or 8 hex bytes, default no cookie)\n");
    printf("          -K    peer cookie (4 or 8 hex bytes, default no cookie)\n");
    printf("\n");
    printf("          Network specification:\n");
    printf("\n");
    printf("          -P    specify peer address/port (e.g. -P 192.168.1.12/10000)\n");
    printf("          -L    specify local address/port (e.g. -L 192.168.1.12/20000)\n");
    printf("\n");
    printf("          Limit specification:\n");
    printf("\n");
    printf("          -t    specify number of tunnels to create. Default 1\n");
    printf("          -s    specify number of sessions to create in each tunnel. Default 1\n");
    printf("          -T    timeout in seconds. On expiry, all tunnel sockets are closed. Default 0\n");
    printf("\n");
    printf("          Pseudowire-specific options:\n");
    printf("\n");
    printf("          -N    specify session interface name (eth and pppac pseudowires)\n");
    printf("          -i    specify PPPoE session ID (pppac pseudowire only)\n");
    printf("          -M    specify PPPoE peer MAC address (pppac pseudowire only)\n");
    printf("\n");
}

static void tunnel_indicate_created(struct tunnel_options *to)
{
    char filename[PATH_MAX];
    FILE *f;

    snprintf(filename, PATH_MAX, "%s-created-%u", g_status_filename, to->lo.tid);
    f = fopen(filename, "w");
    if (!f) die("unable to write tunnel created indication");
    fclose(f);
}

static void tunnel_indicate_up(struct tunnel_options *to)
{
    char filename[PATH_MAX];
    FILE *f;

    snprintf(filename, PATH_MAX, "%s-up-%u", g_status_filename, to->lo.tid);
    f = fopen(filename, "w");
    if (!f) die("unable to write tunnel up indication");
    fclose(f);
}

static void tunnel_indicate_down(struct tunnel_options *to)
{
    char filename[PATH_MAX];

    snprintf(filename, PATH_MAX, "%s-up-%u", g_status_filename, to->lo.tid);
    unlink(filename);
}

/* must be called after the kernel context exists! */
static void do_create_tunnel(struct tunnel_options *to)
{
    assert(to);
    int ret;

    dbg("tunnel %u -> peer %u\n", to->lo.tid, to->lo.ptid);

    tunnel_indicate_down(to);

    to->tfd = tunnel_socket(to->lo.family, to->lo.protocol, to->lo.tid, &to->lo.local_addr, &to->lo.peer_addr);
    if (to->tfd < 0) die("Failed to create managed tunnel socket\n");

    ret = kernel_tunnel_create(to->tfd, &to->lo, &to->ppptctl);
    if (ret) die("Failed to create kernel context for tunnel %u/%u\n", to->lo.tid, to->lo.ptid);
}

static void do_create_session(struct session_options *so)
{
    int ret;

    assert(so);

    dbg("session %u/%u -> peer %u/%u\n", so->lo.tid, so->lo.sid, so->lo.ptid, so->lo.psid);

    ret = kernel_session_create(&so->lo, &so->pw);
    if (ret) die("Failed to create kernel context for session %u/%u\n", so->lo.tid, so->lo.sid);

    fprintf(g_status_file, "%s %u/%u to %u/%u\n", so->pw.ifname[0] ? so->pw.ifname : "?",
            so->lo.tid, so->lo.sid, so->lo.ptid, so->lo.psid);
    fflush(g_status_file);
}

static void send_ctrl_packet(struct tunnel_options *to)
{
    union {
        struct l2tp_control_hdr_v2 hdr2;
        struct l2tp_control_hdr_v3 hdr3;
        char buf[64];
    } pkt = {};
    ssize_t nb;
    if (to->lo.l2tp_version == 2) {
        pkt.hdr2.t_bit = pkt.hdr2.l_bit = 1;
        pkt.hdr2.ver = to->lo.l2tp_version;
        pkt.hdr2.tunnel_id = htons(to->lo.ptid);
        pkt.hdr2.length = htons(sizeof(pkt));
    } else {
        pkt.hdr3.t_bit = pkt.hdr3.l_bit = 1;
        pkt.hdr3.ver = to->lo.l2tp_version;
        pkt.hdr3.tunnel_id = htonl(to->lo.ptid);
        pkt.hdr3.length = htons(sizeof(pkt));
    }
    nb = sendto(to->tfd, &pkt, sizeof(pkt), 0, (void*)&to->peer_addr, to->peer_addr_len);
    if (nb > 0) {
        dbg("%s tunl %" PRIu32 "/%" PRIu32 ": sent %d bytes on socket %d\n",
                to->ro.is_client ? "client" : "server",
                to->lo.tid, to->lo.ptid, (int)nb, to->tfd);
        to->pkt_count++;
    } else {
        err("%s tunl %" PRIu32 "/%" PRIu32 ": failed to send data on socket %d: %s\n",
                to->ro.is_client ? "client" : "server",
                to->lo.tid, to->lo.ptid, to->tfd, strerror(errno));
        to->err_count++;
    }
}

static void recv_ctrl_packet(struct tunnel_options *to)
{
    assert(to);
    char buf[1024] = {};
    ssize_t nb = recv(to->tfd, buf, sizeof(buf), 0);
    if (nb > 0) {
        struct l2tp_control_hdr_v2 *hdr = (struct l2tp_control_hdr_v2*) buf;
        dbg("%s tunl %" PRIu32 "/%" PRIu32 ": recv %d bytes on socket %d\n",
                to->ro.is_client ? "client" : "server",
                to->lo.tid, to->lo.ptid, (int)nb, to->tfd);
        dbg("v%d %s frame\n", hdr->ver, hdr->t_bit ? "control" : "data");
        if (opt_debug) mem_dump(buf, nb);
        to->pkt_count++;
    } else {
        err("tunl %" PRIu32 "/%" PRIu32 ": failed to recv data on socket %d: %s\n",
                to->lo.tid, to->lo.ptid, to->tfd, strerror(errno));
        to->err_count++;
    }
}

static void wait_peer(struct tunnel_options *to)
{
    if (to->ro.is_client) {
        send_ctrl_packet(to);
        recv_ctrl_packet(to);
    } else {
        recv_ctrl_packet(to);
        send_ctrl_packet(to);
    }
}

/* Close the tunnel(s).
 */
static void on_quit(int sig)
{
    size_t i;
    signal(sig, SIG_IGN); /* ignore this signal */
    for (i = 0; i < g_n_tunnel_options; i++) {
        close(g_all_tunnel_options[i].tfd);
        sem_post(&g_running);
    }
    g_n_tunnel_options = 0;
    g_all_tunnel_options = NULL;
}

static void *tunnel_thread(void *dptr)
{
    struct tunnel_options *to = dptr;

    tunnel_indicate_created(to);

    /* wait for peer */
    wait_peer(to);
    tunnel_indicate_up(to);

    /* now we've seen data, set the kill timer running:
     * avoid racing around alarm() by only calling this
     * from the first tunnel thread
     */
    if (to->ro.timeout && to == g_all_tunnel_options) {
        signal(SIGALRM, on_quit);
        alarm(to->ro.timeout);
    }

    sem_wait(&g_running);

    return dptr;
}

/* In order to avoid clashing UDP addresses, and to keep the client and
 * server in agreement with respect to tunnel and session IDs, generate
 * IDs algorithmically.
 */
static uint32_t generate_id(uint32_t index, uint32_t seed, bool is_client)
{
    return seed + (2*index) + (is_client ? 1 : 0);
}

static void run_tunnels(struct l2tp_options *lo, struct runtime_options *ro)
{
    assert(lo);
    assert(ro);

    pthread_t *threads;
    struct tunnel_options *tos;
    struct session_options *sos;
    int ret;
    int t, s, n_tunnels, index = 0;

    n_tunnels = ro->num_tunnels;
    threads = scalloc(n_tunnels, sizeof(*threads));
    tos = scalloc(n_tunnels, sizeof(*tos));
    sos = scalloc(n_tunnels * ro->num_sessions, sizeof(*sos));

    sem_init(&g_running, 0, 0);

    /* share these globally so the signal handler can access them */
    if (ro->timeout) {
        g_all_tunnel_options = tos;
        g_n_tunnel_options = n_tunnels;
    }

    /* configure tunnel options and create tunnel sockets */
    for (t = 0; t < n_tunnels; t++) {
        struct tunnel_options *to = &tos[t];

        to->lo = *lo;
        to->ro = *ro;

        to->lo.tid = generate_id(index, 1, to->ro.is_client);
        to->lo.ptid = generate_id(index, 1, !to->ro.is_client);
        to->lo.local_addr.port = generate_id(index, to->lo.local_addr.port, to->ro.is_client);
        to->lo.peer_addr.port = generate_id(index, to->lo.peer_addr.port, !to->ro.is_client);

        ret = tunnel_sk_addr_init(to->lo.family,
                to->lo.protocol,
                to->lo.peer_addr.ip,
                to->lo.peer_addr.port,
                to->lo.ptid,
                &to->peer_addr,
                &to->peer_addr_len);
        assert(ret == 0);

        to->so = &sos[ro->num_sessions * t];
        do_create_tunnel(to);
        for (s = 0; s < ro->num_sessions; s++) {
            struct session_options *so = to->so + s;
            so->lo = to->lo;
            so->ro = to->ro;
            so->to = to;
            ppp_init(&so->pw.typ.ppp);
            so->lo.sid = generate_id(s, 1000*to->lo.tid, so->ro.is_client);
            so->lo.psid = generate_id(s, 1000*to->lo.ptid, !so->ro.is_client);
            do_create_session(so);
        }

        index++;
    }

    /* start tunnel threads */
    for (t = 0; t < n_tunnels; t++) {
        struct tunnel_options *to = &tos[t];
        ret = pthread_create(&threads[t], NULL, tunnel_thread, to);
        if (ret) die("thread spawn failed: %s\n", strerror(ret));
    }

    /* wait for tunnel threads to complete */
    for (t = 0; t < n_tunnels; t++) {
        ret = pthread_join(threads[t], NULL);
        if (ret) err("pthread_join: %s\n", strerror(ret));
    }

    free(tos);
    free(threads);
}

static int str_to_cookie(char *s, uint8_t *cookie)
{
    size_t len;

    assert(s);
    assert(cookie);

    len = strlen(s);
    if (len == 0) {
        return 0;
    } else if (len == 8 || len == 16) {
        int val[8];
        int n = sscanf(s, "%02x%02x%02x%02x%02x%02x%02x%02x",
                       &val[0], &val[1], &val[2], &val[3],
                       &val[4], &val[5], &val[6], &val[7]);
        if (n == 4 || n == 8) {
            int i;
            for (i = 0; i < n; i++) {
                cookie[i] = val[i];
            }
            return n;
        }
    }
    return -EINVAL;
}

int main(int argc, char **argv)
{
    int opt;
    int rc;

    struct l2tp_options lo = {
        .l2tp_version   = 2,
        .create_api = L2TP_NETLINK_API,
        .delete_api = L2TP_NETLINK_API,
        .family     = AF_INET,
        .protocol   = IPPROTO_UDP,
        .pseudowire = L2TP_API_SESSION_PW_TYPE_PPP,
        .mtu = 1400,
        .peer_addr.ip = NULL,
        .local_addr.ip = NULL,
    };
    struct runtime_options ro = {
        .is_client = 0,
        .num_tunnels = 1,
        .num_sessions = 1,
        .timeout = 0,
    };

    /* Parse commandline, doing basic sanity checking as we go */
    while ((opt = getopt(argc, argv, "hCv:c:d:f:e:p:P:L:t:s:T:m:k:K:N:i:M:")) != -1) {
        switch(opt) {
        case 'h':
            show_usage(argv[0]);
            exit(EXIT_SUCCESS);
        case 'C':
            ro.is_client = 1;
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
            if (!parse_socket_family(optarg, &lo.family))
                die("Invalid address family %s\n", optarg);
            break;
        case 'e':
            if (!parse_encap(optarg, &lo.protocol))
                die("Invalid encapsulation %s\n", optarg);
            break;
        case 'p':
            if (!parse_pseudowire_type(optarg, &lo.pseudowire))
                die("Invalid pseudowire %s\n", optarg);
            break;
        case 'P':
            if (!parse_address(optarg, &lo.peer_addr))
                die("Failed to parse peer address %s\n", optarg);
            break;
        case 'L':
            if (!parse_address(optarg, &lo.local_addr))
                die("Failed to parse local address %s\n", optarg);
            break;
        case 't':
            ro.num_tunnels = atoi(optarg);
            break;
        case 's':
            ro.num_sessions = atoi(optarg);
            break;
        case 'T':
            ro.timeout = atoi(optarg);
            break;
        case 'm':
            lo.mtu = atoi(optarg);
            break;
        case 'k':
            rc = str_to_cookie(optarg, &lo.cookie[0]);
            if (rc < 0) {
                die("invalid cookie -- expecting 4 or 8 hex bytes, e.g. 01020304\n");
            }
            lo.cookie_len = rc;
            break;
        case 'K':
            rc = str_to_cookie(optarg, &lo.peer_cookie[0]);
            if (rc < 0) {
                die("invalid cookie -- expecting 4 or 8 hex bytes, e.g. 01020304\n");
            }
            lo.peer_cookie_len = rc;
            break;
        case 'N':
            if (strlen(optarg) > sizeof(lo.ifname)-1)
                die("Interface name \"%s\" is too long\n", optarg);
            memcpy(lo.ifname, optarg, strlen(optarg));
            break;
        case 'i':
            lo.pw.pppac.id = atoi(optarg);
            break;
        case 'M':
            if (6 != sscanf(optarg,
                        "%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8,
                        &lo.pw.pppac.peer_mac[0],
                        &lo.pw.pppac.peer_mac[1],
                        &lo.pw.pppac.peer_mac[2],
                        &lo.pw.pppac.peer_mac[3],
                        &lo.pw.pppac.peer_mac[4],
                        &lo.pw.pppac.peer_mac[5]))
                die("Failed to parse MAC address \"%s\"\n", optarg);
            break;
        default:
            die("failed to parse command line args\n");
        }
    }

    if (!lo.local_addr.ip) lo.local_addr = *gen_dflt_address(lo.family, true);
    if (!lo.peer_addr.ip) lo.peer_addr = *gen_dflt_address(lo.family, false);

    /* Now we've parsed the commandline, sanity check the combinations of
     * options
     */
    if (lo.l2tp_version == 2) {
        if (lo.pseudowire != L2TP_API_SESSION_PW_TYPE_PPP
            && lo.pseudowire != L2TP_API_SESSION_PW_TYPE_PPP_AC)
            die("L2TPv2 code supports PPP or PPPAC pseudowires only\n");
        if (lo.protocol != IPPROTO_UDP)
            die("L2TPv2 code supports UDP encapsulation only\n");
    }
    if (lo.l2tp_version == 3) {
        if (lo.create_api == L2TP_SOCKET_API &&
            lo.pseudowire == L2TP_API_SESSION_PW_TYPE_ETH)
            die("L2TPv3 code doesn't support ETH pw create using the socket API\n");
    }
    if (lo.mtu < 256 || lo.mtu > 1500) {
        die("mtu out of range\n");
    }

    g_status_filename = ro.is_client ? "/tmp/l2tp-ktest-sess-dataif-c" : "/tmp/l2tp-ktest-sess-dataif-s";
    g_status_file = fopen(g_status_filename, "w");
    if (!g_status_file) die("unable to open status file: %s\n", g_status_filename);

    log("%s : v%d, %s/%s (create/delete API), %s encap, %s, %s pseudowire\n",
        ro.is_client ? "CLIENT" : "SERVER",
        lo.l2tp_version,
        lo.create_api == L2TP_SOCKET_API ? "socket" : "netlink",
        lo.delete_api == L2TP_SOCKET_API ? "socket" : "netlink",
        lo.protocol == IPPROTO_UDP ? "UDP" : "IP",
        lo.family == AF_INET ? "inet" : "inet6",
        PWTYPE_STR(lo.pseudowire));

    run_tunnels(&lo, &ro);
    if (g_status_file) fclose(g_status_file);
    unlink(g_status_filename);

    return 0;
}

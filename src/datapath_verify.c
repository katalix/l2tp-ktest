/**
 * @file datapath_verify.c
 *
 * Test L2TP session data paths.
 *
 * In client/server mode two instances of the application must be started.
 * In "auto" mode, the same process creates client/server threads.
 *
 * Depending on command line arguments, L2TPv2 or v3 tunnel(s) are
 * created using UDP or L2TPIP, and may be created using netlink or the
 * L2TPv2 socket-based API.  Each tunnel runs in its own thread,
 * and creates a number of sessions (each in their own thread) which
 * exchange a number of data packets.
 *
 * The application waits for all the threads to complete before validating
 * packet and error counts.
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
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <linux/l2tp.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <stdlib.h>

#include "l2tp_netlink.h"
#include "util.h"

struct runtime_options {
    int is_client;
    int is_auto;
    int num_tunnels;
    int num_sessions;
    int num_data_packets;
    int num_repeats;
    int timeout;
};

struct session_options {
    struct l2tp_options lo;
    struct runtime_options ro;
    struct tunnel_options *to;
    int sfd;
    size_t err_count, pkt_count;
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

static struct tunnel_options *g_all_tunnel_options = NULL;
static size_t g_n_tunnel_options = 0;

#define DATA_PKT_LEN 256
static char DATA_PKT_HDR[] = { 0xfe, 0x11, 0xef, 0x22 };
static size_t DATA_PKT_HDR_LEN = sizeof(DATA_PKT_HDR);

void show_usage(const char *myname)
{
    printf("Name:     %s\n", myname);
    printf("Desc:     create l2tp sessions in the kernel, optionally pass data.\n");
    printf("Usage:    %s [options]\n", myname);
    printf("          -h    print this usage information\n");
    printf("\n");
    printf("          Top level operational options:\n");
    printf("\n");
    printf("          -C    run in client mode. The server must already be running.\n");
    printf("          -A    run in auto mode, spawning both client and server threads.\n");
    printf("\n");
    printf("          L2TP protocol control options:\n");
    printf("\n");
    printf("          -v    specify L2TP version (2 or 3: default is 2)\n");
    printf("          -c    specify L2TP resource creation API (socket or netlink: default is netlink)\n");
    printf("          -d    specify L2TP resource destruction API (socket or netlink: default is netlink)\n");
    printf("          -f    specify tunnel socket address family (inet or inet6: default is inet)\n");
    printf("          -e    specify tunnel encapsulation (udp or ip: default is udp)\n");
    printf("          -p    specify session pseudowire type (ppp or eth: default ppp)\n");
    printf("\n");
    printf("          Peer specification:\n");
    printf("\n");
    printf("          -P    specify peer address/port (e.g. -P 192.168.1.12/10000)\n");
    printf("          -L    specify local address/port (e.g. -L 192.168.1.12/20000)\n");
    printf("\n");
    printf("          Limit specification:\n");
    printf("\n");
    printf("          -t    specify number of tunnels to create. Default 1\n");
    printf("          -s    specify number of sessions to create in each tunnel. Default 1\n");
    printf("          -D    specify number of data packets to send to the peer. Default 1\n");
    printf("          -T    timeout in seconds. On expiry, all tunnel sockets are closed. Default 0\n");
    printf("\n");
}

/* must be called after the kernel context exists! */
static void do_create_tunnel(struct tunnel_options *to)
{
    assert(to);
    int ret;

    dbg("tunnel %u -> peer %u\n", to->lo.tid, to->lo.ptid);

    to->tfd = tunnel_socket(to->lo.family, to->lo.protocol, to->lo.tid, &to->lo.local_addr, &to->lo.peer_addr);
    if (to->tfd < 0) die("Failed to create managed tunnel socket\n");

    ret = kernel_tunnel_create(to->tfd, &to->lo, &to->ppptctl);
    if (ret) die("Failed to create kernel context for tunnel %u/%u\n", to->lo.tid, to->lo.ptid);
}

static void do_create_session(struct session_options *so)
{
    assert(so);
    int ret;

    assert(so->sfd < 0);

    dbg("session %u/%u -> peer %u/%u\n", so->lo.tid, so->lo.sid, so->lo.ptid, so->lo.psid);

    ret = kernel_session_create(&so->lo, &so->sfd);
    if (ret) die("Failed to create kernel context for session %u/%u\n", so->lo.tid, so->lo.sid);

    /* For PPP we expect the kernel session create to have created a session
     * AF_PPPOX socket.
     * For ETH we need to create our own raw socket to use for data transport (TODO).
     */
    if (so->lo.pseudowire == L2TP_API_SESSION_PW_TYPE_ETH) {
        assert(so->sfd < 0);
    } else if (so->lo.pseudowire == L2TP_API_SESSION_PW_TYPE_PPP) {
        assert(so->sfd >= 0);
    }
}

static void gen_prng_buf(uint32_t tid, uint32_t sid, char *out, size_t nbytes)
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    size_t i;

    assert(tid > 0);
    assert(sid > 0);
    assert(nbytes > 0);
    assert(out);

    pthread_mutex_lock(&lock);
    srandom(tid+sid);
    for (i = 0; i < nbytes; i++) {
        long rnd = random();
        out[i] = rnd;
    }
    pthread_mutex_unlock(&lock);
}

static void gen_data_pkt(uint32_t tid, uint32_t sid, char *out, size_t nbytes)
{
    assert(tid > 0);
    assert(sid > 0);
    assert(out);
    assert(nbytes > 0);
    assert(nbytes > DATA_PKT_HDR_LEN);
    memcpy(out, DATA_PKT_HDR, DATA_PKT_HDR_LEN);
    gen_prng_buf(tid, sid, out + DATA_PKT_HDR_LEN, nbytes - DATA_PKT_HDR_LEN);
}

static bool validate_data_packet(struct session_options *so, char *recv, size_t nbytes)
{
    assert(so);
    assert(recv);
    assert(nbytes);
    char buf[DATA_PKT_LEN] = {};
    gen_data_pkt(so->lo.tid, so->lo.sid, buf, sizeof(buf));
    if (nbytes != DATA_PKT_LEN) return false;
    return (0 == memcmp(recv, buf, nbytes));
}

static ssize_t do_send_ppp(struct session_options *so)
{
    assert(so);
    char buf[DATA_PKT_LEN] = {};
    void *data = buf;
    gen_data_pkt(so->lo.ptid, so->lo.psid, buf, sizeof(buf));
    return sendto(so->sfd, data, sizeof(buf), 0, (void*)&so->to->peer_addr, so->to->peer_addr_len);
}

static ssize_t do_send_eth(struct session_options *so)
{
    die("%s: Ethernet data send not yet implemented\n", __func__);
    return -1;
}

static void send_data_packet(struct session_options *so)
{
    assert(so);
    ssize_t nb;

    if (so->lo.pseudowire == L2TP_API_SESSION_PW_TYPE_PPP) {
        nb = do_send_ppp(so);
    } else if (so->lo.pseudowire == L2TP_API_SESSION_PW_TYPE_ETH) {
        nb = do_send_eth(so);
    } else {
        assert(!"unrecognised pseudowire type");
        return;
    }

    if (nb > 0) {
        dbg("%s sess %" PRIu32 "/%" PRIu32 ": sent %d bytes on socket %d\n",
                so->ro.is_client ? "client" : "server",
                so->lo.tid, so->lo.sid, (int)nb, so->sfd);
        so->pkt_count++;
    } else {
        err("%s sess %" PRIu32 "/%" PRIu32 ": failed to send data packet: %s\n",
                so->ro.is_client ? "client" : "server",
                so->lo.tid, so->lo.sid,
                strerror(errno));
        so->err_count++;
    }
}

static bool do_recv_ppp(struct session_options *so)
{
    assert(so);
    char buf[DATA_PKT_LEN + 64];
    ssize_t nb = recv(so->sfd, &buf[0], sizeof(buf), 0);
    if (nb > 0) {
        if (validate_data_packet(so, buf, nb)) {
            return true;
        } else {
            err("%s sess %" PRIu32 "/%" PRIu32 ": failed to validate data packet\n",
                    so->ro.is_client ? "client" : "server",
                    so->lo.tid, so->lo.sid);
            return false;
        }
    }
    err("%s sess %" PRIu32 "/%" PRIu32 ": failed to recv data packet: %s\n",
            so->ro.is_client ? "client" : "server",
            so->lo.tid, so->lo.sid,
            strerror(errno));
    return false;
}

static bool do_recv_eth(struct session_options *so)
{
    die("%s: Ethernet data recv not yet implemented\n", __func__);
    return false;
}

static void recv_data_packet(struct session_options *so)
{
    assert(so);
    bool is_ok;

    if (so->lo.pseudowire == L2TP_API_SESSION_PW_TYPE_PPP) {
        is_ok = do_recv_ppp(so);
    } else if (so->lo.pseudowire == L2TP_API_SESSION_PW_TYPE_ETH) {
        is_ok = do_recv_eth(so);
    } else {
        assert(!"unrecognised pseudowire type");
        return;
    }

    if (is_ok) so->pkt_count++;
    else so->err_count++;
}

static void *session_thread(void *dptr)
{
    struct session_options *so = dptr;
    int m;
    for (m = 0; m < so->ro.num_data_packets; m++) {
        if (so->ro.is_client) {
            send_data_packet(so);
            recv_data_packet(so);
        } else {
            recv_data_packet(so);
            send_data_packet(so);
        }
    }
    return dptr;
}

static void send_ctrl_packet(struct tunnel_options *to)
{
    struct l2tp_control_hdr_v2 hdr2 = {};
    struct l2tp_control_hdr_v3 hdr3 = {};
    ssize_t nb;
    void *data;
    if (to->lo.l2tp_version == 2) {
        hdr2.t_bit = hdr2.l_bit = 1;
        hdr2.ver = to->lo.l2tp_version;
        hdr2.tunnel_id = htons(to->lo.ptid);
        hdr2.length = htons(sizeof(hdr2));
        data = (void*)&hdr2;
        nb = sizeof(hdr2);
    } else {
        hdr3.t_bit = hdr3.l_bit = 1;
        hdr3.ver = to->lo.l2tp_version;
        hdr3.tunnel_id = htonl(to->lo.ptid);
        hdr3.length = htons(sizeof(hdr3));
        data = (void*)&hdr3;
        nb = sizeof(hdr3);
    }
    nb = sendto(to->tfd, data, nb, 0, (void*)&to->peer_addr, to->peer_addr_len);
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

/* Close the tunnel(s) when the timeout fires, the goal being to provoke
 * kernel race conditions by closing sessions while data is in flight.
 */
static void on_timeout(int sig)
{
    size_t i;
    signal(SIGALRM, SIG_IGN); /* ignore this signal */
    for (i = 0; i < g_n_tunnel_options; i++) {
        close(g_all_tunnel_options[i].tfd);
    }
    g_n_tunnel_options = 0;
    g_all_tunnel_options = NULL;
}

static void *tunnel_thread(void *dptr)
{
    struct tunnel_options *to = dptr;
    int ret;
    int s;

    /* wait for peer */
    wait_peer(to);

    /* now we've seen data, set the kill timer running:
     * avoid racing around alarm() by only calling this
     * from the first tunnel thread
     */
    if (to->ro.timeout && to == g_all_tunnel_options) {
        signal(SIGALRM, on_timeout);
        alarm(to->ro.timeout);
    }

    {
        pthread_t *threads = scalloc(to->ro.num_sessions, sizeof(*threads));

        /* start session threads */
        for (s = 0; s < to->ro.num_sessions; s++) {
            struct session_options *so = &to->so[s];
            ret = pthread_create(&threads[s], NULL, session_thread, so);
            if (ret) die("session thread spawn failed: %s\n", strerror(ret));
        }

        /* wait for session threads to complete */
        for (s = 0; s < to->ro.num_sessions; s++) {
            ret = pthread_join(threads[s], NULL);
            if (ret) err("session pthread_join: %s\n", strerror(ret));
        }

        free(threads);
    }

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
    /* For auto mode we're assuming we're setting up the server
     * side first, so validate that assumption now */
    if (ro->is_auto) assert(!ro->is_client);

    pthread_t *threads;
    struct tunnel_options *tos;
    struct session_options *sos;
    int ret;
    int t, s, n_tunnels, index = 0;

    n_tunnels = ro->is_auto ? (2*ro->num_tunnels) : ro->num_tunnels;
    threads = scalloc(n_tunnels, sizeof(*threads));
    tos = scalloc(n_tunnels, sizeof(*tos));
    sos = scalloc(n_tunnels * ro->num_sessions, sizeof(*sos));

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

        if (ro->is_auto && t%2) {
            /* client thread */
            struct addr tmp = to->lo.local_addr;
            to->lo.local_addr = to->lo.peer_addr;
            to->lo.peer_addr = tmp;
            to->ro.is_client = 1;
        }

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
            so->sfd = -1;
            so->lo.sid = generate_id(s, 1000*to->lo.tid, so->ro.is_client);
            so->lo.psid = generate_id(s, 1000*to->lo.ptid, !so->ro.is_client);
            do_create_session(so);
        }

        if (ro->is_auto && t%2) index++;
        else if (!ro->is_auto) index++;
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

    for (t = 0; t < n_tunnels; t++) {
        struct tunnel_options *to = &tos[t];
        size_t t_npkt = 2;
        if (to->err_count) die("Error in tunnel %" PRIu32 "\n", to->lo.tid);
        if (to->pkt_count != t_npkt) {
            die("Tunnel %" PRIu32 ": expect %zd packets, saw %zd packets\n", to->lo.tid, t_npkt, to->pkt_count);
        }
        log("tunl %05" PRIu32 " ", to->lo.tid);
        for (s = 0; s < ro->num_sessions; s++) {
            struct session_options *so = to->so + s;
            if (so->err_count) die("Error in tunnel %" PRIu32 " session %" PRIu32 "\n", to->lo.tid, so->lo.sid);
            if (so->pkt_count != 2 * so->ro.num_data_packets) {
                die("Tunnel %" PRIu32 " session %" PRIu32 ": expect %d packets, saw %zd packets\n",
                        to->lo.tid, so->lo.sid, 2 * so->ro.num_data_packets, so->pkt_count);
            }
            log_raw(".");
        }
        log_raw(" OK\n");
    }

    free(tos);
    free(threads);
}

int main(int argc, char **argv)
{
    int opt;

    struct l2tp_options lo = {
        .l2tp_version   = 2,
        .create_api = L2TP_NETLINK_API,
        .delete_api = L2TP_NETLINK_API,
        .family     = AF_INET,
        .protocol   = IPPROTO_UDP,
        .pseudowire = L2TP_API_SESSION_PW_TYPE_PPP,
        .peer_addr.ip = NULL,
        .local_addr.ip = NULL,
    };
    struct runtime_options ro = {
        .is_client = 0,
        .is_auto = 0,
        .num_tunnels = 1,
        .num_sessions = 1,
        .num_data_packets = 1,
        .timeout = 0,
    };

    /* Parse commandline, doing basic sanity checking as we go */
    while ((opt = getopt(argc, argv, "hACv:c:d:f:e:p:P:L:t:s:D:T:")) != -1) {
        switch(opt) {
        case 'h':
            show_usage(argv[0]);
            exit(EXIT_SUCCESS);
        case 'A':
            ro.is_auto = 1;
            break;
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
            if (0 == strcmp("ppp", optarg))
                lo.pseudowire = L2TP_API_SESSION_PW_TYPE_PPP;
            else if (0 == strcmp("eth", optarg))
                lo.pseudowire = L2TP_API_SESSION_PW_TYPE_ETH;
            else
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
        case 'D':
            ro.num_data_packets = atoi(optarg);
            break;
        case 'T':
            ro.timeout = atoi(optarg);
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
        if (lo.pseudowire != L2TP_API_SESSION_PW_TYPE_PPP)
            die("L2TPv2 code supports PPP pseudowires only\n");
        if (lo.protocol != IPPROTO_UDP)
            die("L2TPv2 code supports UDP encapsulation only\n");
    }
    if (lo.l2tp_version == 3) {
        if (lo.create_api == L2TP_SOCKET_API &&
            lo.pseudowire == L2TP_API_SESSION_PW_TYPE_ETH)
            die("L2TPv3 code doesn't support ETH pw create using the socket API\n");
    }

    if (ro.is_auto && ro.is_client) {
        die("Client mode (-C) and auto mode (-A) cannot be specified together\n");
    }

    /* check port ranges don't overlap when using the same src/dst IP */
    if (0 == strcmp(lo.local_addr.ip, lo.peer_addr.ip)) {
        if (generate_id(ro.num_tunnels, lo.local_addr.port, true) >= lo.peer_addr.port) {
            die("Client/server port range overlaps\n");
        }
    }

    /* FIXME: eth data testing isn't supported yet */
    if (lo.pseudowire == L2TP_API_SESSION_PW_TYPE_ETH) {
        die("I don't currently support Ethernet pseudowires: sorry :-(\n");
    }

    log("%s : v%d, %s/%s (create/delete API), %s encap, %s, %s pseudowire\n",
        ro.is_auto ? "AUTO" : ro.is_client ? "CLIENT" : "SERVER",
        lo.l2tp_version,
        lo.create_api == L2TP_SOCKET_API ? "socket" : "netlink",
        lo.delete_api == L2TP_SOCKET_API ? "socket" : "netlink",
        lo.protocol == IPPROTO_UDP ? "UDP" : "IP",
        lo.family == AF_INET ? "inet" : "inet6",
        lo.pseudowire == L2TP_API_SESSION_PW_TYPE_PPP ? "PPP" : "ETH");

    run_tunnels(&lo, &ro);

    return 0;
}

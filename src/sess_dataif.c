/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * @file sess_dataif.c
 *
 * Create L2TP tunnel and session instances, including a minimal
 * control plane.
 *
 * Two instances of the application must be started, one a server and
 * the other a client.
 *
 * Depending on command line arguments, L2TPv2 or v3 tunnel(s) are
 * created using UDP or L2TPIP, and sessions may be created inside
 * the tunnels.
 *
 * One tunnel/session may be created on initial startup, and an
 * arbitrary number of further tunnels/sessions created by writing extra
 * sets of commandline arguments to a fifo.
 *
 * Runtime information about tunnel and session bringup is written
 * to status files located in /tmp:
 *
 *  - l2tp-ktest-sess-dataif-[cs] contains status for the client
 *    and server process respectively.
 *
 *    The status file is appended each time a session is created in the
 *    kernel, containing the following information:
 *
 *      <ifname> <tid>/<sid> to <peer tid>/<peer sid>
 *
 *  - l2tp-ktest-sess-dataif-[cs]-created-<tid>
 *
 *    Generated when the tunnel with ID <tid> is created in the kernel.
 *
 *  - l2tp-ktest-sess-dataif-[cs]-up-<tid>
 *
 *    Generated when the tunnel with ID <tid> is marked "up", which
 *    occurs after a simple control packet handshake has occurred.
 *
 *    The control packet is useful for exercising the L2TPIP socket types,
 *    which are part of the kernel L2TP subsystem.
 *
 * The status files may be used by test scripts to synchronise test
 * operations with kernel state.
 *
 * To test unexpected cleanup scenarios it's possible to close all the
 * tunnel sockets after a configurable timeout.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <ctype.h>

#include "l2tp_netlink.h"
#include "util.h"
#include "util_ppp.h"
#include "vector.h"

struct tunnel_options {
    enum {
        TUNNEL_STATE_CTRL_TX,
        TUNNEL_STATE_CTRL_RX,
        TUNNEL_STATE_UP,
    } state;
    struct l2tp_options lo;
    int tfd;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    uint32_t index;
    pthread_t thread;
    uint32_t session_index;
};

#define MAX_TUNNELS 10000

static struct tunnel_options *g_all_tunnels[MAX_TUNNELS];
static const char *g_status_filename = NULL;
static const char *g_cmdline_fifo = NULL;
static FILE *g_status_file = NULL;
static size_t g_n_tunnels;
static time_t g_timeout_s;
static sem_t g_tunnel_sem;
static bool g_is_running;
static bool g_is_client;

static const char *g_cmdline_args = "hCT:v:f:e:p:k:K:P:L:m:N:i:M:F:A:";

static void show_usage(const char *myname)
{
    printf("Name:     %s\n", myname);
    printf("Desc:     create l2tp sessions in the kernel, ready to pass data.\n");
    printf("Usage:    %s [options]\n", myname);
    printf("          -h    print this usage information\n");
    printf("\n");
    printf("          Top level operational options:\n");
    printf("\n");
    printf("          -C    run in client mode. The server must already be running.\n");
    printf("          -T    timeout in seconds. On expiry, all tunnel sockets are closed. Default 0\n");
    printf("          -F    read subsequent commandlines from named FIFO.\n");
    printf("\n");
    printf("          L2TP protocol control options:\n");
    printf("\n");
    printf("          -A    add pseudowire to specified tunnel index (FIFO command only)\n");
    printf("          -v    specify L2TP version (2 or 3: default is 0)\n");
    printf("          -f    specify tunnel socket address family (inet or inet6: default is inet)\n");
    printf("          -e    specify tunnel encapsulation (udp or ip: default is udp)\n");
    printf("          -p    specify session pseudowire type (ppp, pppac, or eth: default none)\n");
    printf("          -k    local cookie (4 or 8 hex bytes, default no cookie)\n");
    printf("          -K    peer cookie (4 or 8 hex bytes, default no cookie)\n");
    printf("\n");
    printf("          Network specification:\n");
    printf("\n");
    printf("          -P    specify peer address/port (e.g. -P 192.168.1.12/10000)\n");
    printf("          -L    specify local address/port (e.g. -L 192.168.1.12/20000)\n");
    printf("\n");
    printf("          Pseudowire-specific options:\n");
    printf("\n");
    printf("          -N    specify session interface name (eth and pppac pseudowires)\n");
    printf("          -i    specify PPPoE session ID (pppac pseudowire only)\n");
    printf("          -M    specify PPPoE peer MAC address (pppac pseudowire only)\n");
    printf("          -m    specify MTU\n");
    printf("\n");
}

static void tunnel_indicate_created(const char *path_prefix, uint32_t tid)
{
    char filename[PATH_MAX];
    FILE *f;

    snprintf(filename, PATH_MAX, "%s-created-%u", path_prefix, tid);
    f = fopen(filename, "w");
    if (!f) die("unable to write tunnel created indication");
    fclose(f);
}

static void tunnel_indicate_up(const char *path_prefix, uint32_t tid)
{
    char filename[PATH_MAX];
    FILE *f;

    snprintf(filename, PATH_MAX, "%s-up-%u", path_prefix, tid);
    f = fopen(filename, "w");
    if (!f) die("unable to write tunnel up indication");
    fclose(f);
}

static void tunnel_indicate_down( const char *path_prefix, uint32_t tid)
{
    char filename[PATH_MAX];

    snprintf(filename, PATH_MAX, "%s-up-%u", path_prefix, tid);
    unlink(filename);
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
                g_is_client ? "client" : "server",
                to->lo.tid, to->lo.ptid, (int)nb, to->tfd);
    } else {
        err("%s tunl %" PRIu32 "/%" PRIu32 ": failed to send data on socket %d: %s\n",
                g_is_client ? "client" : "server",
                to->lo.tid, to->lo.ptid, to->tfd, strerror(errno));
    }
}

static void recv_ctrl_packet_1(struct tunnel_options *to)
{
    assert(to);
    char buf[1024] = {};
    ssize_t nb = recv(to->tfd, buf, sizeof(buf), 0);
    if (nb > 0) {
        struct l2tp_control_hdr_v2 *hdr = (struct l2tp_control_hdr_v2*) buf;
        dbg("%s tunl %" PRIu32 "/%" PRIu32 ": recv %d bytes on socket %d\n",
                g_is_client ? "client" : "server",
                to->lo.tid, to->lo.ptid, (int)nb, to->tfd);
        dbg("v%d %s frame\n", hdr->ver, hdr->t_bit ? "control" : "data");
        if (opt_debug) mem_dump(buf, nb);
    } else {
        err("tunl %" PRIu32 "/%" PRIu32 ": failed to recv data on socket %d: %s\n",
                to->lo.tid, to->lo.ptid, to->tfd, strerror(errno));
    }
}

static bool recv_ctrl_packet(struct tunnel_options *to)
{
    struct pollfd fds[1] = {
        { .fd = to->tfd, .events = POLLIN }
    };
    if (poll(fds, 1, 100) > 0) {
        recv_ctrl_packet_1(to);
        return true;
    }
    return false;
}

/* Close the tunnel(s).
 */
static void on_quit(int sig)
{
    size_t i;
    g_is_running = false;
    signal(sig, SIG_IGN); /* ignore this signal */
    for (i = 0; i < g_n_tunnels; i++) {
        sem_post(&g_tunnel_sem);
    }
}

static void *tunnel_thread(void *dptr)
{
    struct tunnel_options *to = dptr;

    tunnel_indicate_created(g_status_filename, to->lo.tid);

    to->state = g_is_client ? TUNNEL_STATE_CTRL_TX : TUNNEL_STATE_CTRL_RX;

    while (g_is_running && to->state != TUNNEL_STATE_UP) {
        if (g_is_client) {
            switch (to->state) {
                case TUNNEL_STATE_CTRL_TX:
                    send_ctrl_packet(to);
                    to->state = TUNNEL_STATE_CTRL_RX;
                    break;
                case TUNNEL_STATE_CTRL_RX:
                    if (recv_ctrl_packet(to))
                        to->state = TUNNEL_STATE_UP;
                    break;
                case TUNNEL_STATE_UP:
                    break;
            }
        } else {
            switch (to->state) {
                case TUNNEL_STATE_CTRL_TX:
                    send_ctrl_packet(to);
                    to->state = TUNNEL_STATE_UP;
                    break;
                case TUNNEL_STATE_CTRL_RX:
                    if (recv_ctrl_packet(to))
                        to->state = TUNNEL_STATE_CTRL_TX;
                    break;
                case TUNNEL_STATE_UP:
                    break;
            }
        }
    }

    if (to->state == TUNNEL_STATE_UP) {
        tunnel_indicate_up(g_status_filename, to->lo.tid);

        /* set the kill timer running if required: avoid racing
         * around alarm() by only calling this from the first
         * tunnel thread
         */
        if (g_timeout_s && to->index == 0) {
            signal(SIGALRM, on_quit);
            alarm(g_timeout_s);
        }
    }

    sem_wait(&g_tunnel_sem);

    return NULL;
}

/* In order to avoid clashing UDP addresses, and to keep the client and
 * server in agreement with respect to tunnel and session IDs, generate
 * IDs algorithmically.
 */
static uint32_t generate_id(uint32_t index, uint32_t seed, bool is_client)
{
    return seed + (2*index) + (is_client ? 1 : 0);
}

static void create_session_1(struct tunnel_options *to)
{
    assert(to);

    uint32_t session_index = to->session_index++;
    uint32_t ptid = to->lo.ptid;
    uint32_t tid = to->lo.tid;
    struct l2tp_pw pw = {};
    uint32_t psid, sid;
    int ret;

    to->lo.sid = sid = generate_id(0, 1000 + to->lo.tid + session_index, g_is_client);
    to->lo.psid = psid = generate_id(0, 1000 + to->lo.ptid + session_index, !g_is_client);

    ppp_init(&pw.typ.ppp);

    dbg("%s: create %s pseudowire in tunnel %u: sid %u -> psid %u\n",
            g_is_client ? "CLIENT" : "SERVER",
            PWTYPE_STR(to->lo.pseudowire),
            to->index,
            sid,
            psid);

    ret = kernel_session_create(&to->lo, &pw);
    if (ret) die("Failed to create kernel context for session %u/%u (%d)\n", tid, sid, ret);

    if (g_status_file) {
        fprintf(g_status_file, "%s %u/%u to %u/%u\n", pw.ifname[0] ? pw.ifname : "?",
                tid, sid, ptid, psid);
        fflush(g_status_file);
    }
}

static void create_tunnel_1(struct tunnel_options *to)
{
    assert(to);
    int ret;

    dbg("create tunnel %u: v%d, %s %s encap tid %u -> ptid %u\n",
            to->index,
            to->lo.l2tp_version,
            to->lo.family == AF_INET ? "inet" : "inet6",
            to->lo.protocol == IPPROTO_UDP ? "UDP" : "IP",
            to->lo.tid,
            to->lo.ptid);

    ret = tunnel_sk_addr_init(to->lo.family,
            to->lo.protocol,
            to->lo.peer_addr.ip,
            to->lo.peer_addr.port,
            to->lo.ptid,
            &to->peer_addr,
            &to->peer_addr_len);
    assert(ret == 0);

    tunnel_indicate_down(g_status_filename, to->lo.ptid);

    to->tfd = tunnel_socket(to->lo.family, to->lo.protocol, to->lo.tid, &to->lo.local_addr, &to->lo.peer_addr);
    if (to->tfd < 0) die("Failed to create managed tunnel socket\n");

    {
        int flags = fcntl(to->tfd, F_GETFL, 0);
        if (flags < 0) die("Failed to get tunnel socket flags\n");
        if (0 != fcntl(to->tfd, F_SETFL, flags|O_NONBLOCK))
            die("Failed to set tunnel socket non-blocking\n");
    }

    ret = kernel_tunnel_create(to->tfd, &to->lo, NULL);
    if (ret) die("Failed to create kernel context for tunnel %u/%u\n", to->lo.tid, to->lo.ptid);
}

static struct tunnel_options *create_tunnel(uint32_t index, struct l2tp_options *lo)
{
    assert(lo);

    struct tunnel_options *to = scalloc(1, sizeof(*to));
    int ret;

    to->lo = *lo;
    to->index = index;

    to->lo.tid = generate_id(index, 1, g_is_client);
    to->lo.local_addr.port = generate_id(index, to->lo.local_addr.port, g_is_client);
    to->lo.ptid = generate_id(index, 1, !g_is_client);
    to->lo.peer_addr.port = generate_id(index, to->lo.peer_addr.port, !g_is_client);

    create_tunnel_1(to);
    if (to->lo.pseudowire != L2TP_API_SESSION_PW_TYPEUNSPECIFIED) {
        create_session_1(to);
    }

    ret = pthread_create(&to->thread, NULL, tunnel_thread, to);
    if (ret) die("thread spawn failed: %s\n", strerror(ret));

    return to;
}

static void add_tunnel(struct l2tp_options *lo)
{
    assert(g_n_tunnels < MAX_TUNNELS);
    uint32_t idx = g_n_tunnels++;
    g_all_tunnels[idx] = create_tunnel(idx, lo);
}

static void wait_tunnel(uint32_t idx)
{
    assert(idx < MAX_TUNNELS);
    struct tunnel_options *to = g_all_tunnels[idx];
    g_all_tunnels[idx] = NULL;
    if (to) {
        assert(to->index == idx);
        pthread_join(to->thread, NULL);
        close(to->tfd);
        free(to);
    }
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

static void parse_l2tp_option(const char arg, char *optarg, struct l2tp_options *lo)
{
    assert(lo);
    int ret;

    switch (arg) {
        case 'v':
            lo->l2tp_version = atoi(optarg);
            if (lo->l2tp_version != 3 && lo->l2tp_version != 2)
                die("Invalid l2tp version %s\n", optarg);
            break;
        case 'f':
            if (!parse_socket_family(optarg, &lo->family))
                die("Invalid address family %s\n", optarg);
            break;
        case 'e':
            if (!parse_encap(optarg, &lo->protocol))
                die("Invalid encapsulation %s\n", optarg);
            break;
        case 'p':
            if (!parse_pseudowire_type(optarg, &lo->pseudowire))
                die("Invalid pseudowire %s\n", optarg);
            break;
        case 'P':
            if (!parse_address(optarg, &lo->peer_addr))
                die("Failed to parse peer address %s\n", optarg);
            break;
        case 'L':
            if (!parse_address(optarg, &lo->local_addr))
                die("Failed to parse local address %s\n", optarg);
            break;
        case 'm':
            lo->mtu = atoi(optarg);
            break;
        case 'k':
            ret = str_to_cookie(optarg, &lo->cookie[0]);
            if (ret < 0) {
                die("invalid cookie -- expecting 4 or 8 hex bytes, e.g. 01020304\n");
            }
            lo->cookie_len = ret;
            break;
        case 'K':
            ret = str_to_cookie(optarg, &lo->peer_cookie[0]);
            if (ret < 0) {
                die("invalid cookie -- expecting 4 or 8 hex bytes, e.g. 01020304\n");
            }
            lo->peer_cookie_len = ret;
            break;
        case 'N':
            if (strlen(optarg) > sizeof(lo->ifname)-1)
                die("Interface name \"%s\" is too long\n", optarg);
            memcpy(lo->ifname, optarg, strlen(optarg));
            break;
        case 'i':
            lo->pw.pppac.id = atoi(optarg);
            break;
        case 'M':
            if (6 != sscanf(optarg,
                        "%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8,
                        &lo->pw.pppac.peer_mac[0],
                        &lo->pw.pppac.peer_mac[1],
                        &lo->pw.pppac.peer_mac[2],
                        &lo->pw.pppac.peer_mac[3],
                        &lo->pw.pppac.peer_mac[4],
                        &lo->pw.pppac.peer_mac[5]))
                die("Failed to parse MAC address \"%s\"\n", optarg);
            break;
        default:
            die("failed to parse command line args\n");
    }
}

static void validate_l2tp_options(struct l2tp_options *lo)
{
    assert(lo);

    if (!lo->local_addr.ip) lo->local_addr = *gen_dflt_address(lo->family, true);
    if (!lo->peer_addr.ip) lo->peer_addr = *gen_dflt_address(lo->family, false);

    if (lo->l2tp_version == 2) {
        if (lo->pseudowire != L2TP_API_SESSION_PW_TYPE_PPP
            && lo->pseudowire != L2TP_API_SESSION_PW_TYPE_PPP_AC)
            die("L2TPv2 code supports PPP or PPPAC pseudowires only\n");
        if (lo->protocol != IPPROTO_UDP)
            die("L2TPv2 code supports UDP encapsulation only\n");
    }
    if (lo->l2tp_version == 3) {
        if (lo->create_api == L2TP_SOCKET_API &&
            lo->pseudowire == L2TP_API_SESSION_PW_TYPE_ETH)
            die("L2TPv3 code doesn't support ETH pw create using the socket API\n");
    }
    if (lo->mtu < 256 || lo->mtu > 1500) {
        die("mtu out of range\n");
    }
}

static void parse_cmdline_args(int nargs, char **args, struct l2tp_options *lo)
{
    int opt;

    optind = 1;

    while ((opt = getopt(nargs, args, g_cmdline_args)) != -1) {
        switch(opt) {
        case 'h':
            show_usage(args[0]);
            exit(EXIT_SUCCESS);
        case 'C':
            g_is_client = true;
            break;
        case 'T':
            g_timeout_s = atoi(optarg);
            break;
        case 'F':
            g_cmdline_fifo = optarg;
            break;
        default:
            parse_l2tp_option(opt, optarg, lo);
        }
    }
}

static void parse_fifo_args(int nargs, char **args, struct l2tp_options *lo, int *add_idx)
{
    int opt;

    optind = 1;

    while ((opt = getopt(nargs, args, g_cmdline_args)) != -1) {
        switch (opt) {
        case 'A':
            *add_idx = atoi(optarg);
            break;
        default:
            parse_l2tp_option(opt, optarg, lo);
        }
    }
}

static char *rstrip(char *s)
{
    size_t l = strlen(s) - 1;
    while (l) {
        if (isspace(s[l])) s[l--] = '\0';
        else break;
    }
    return s;
}

static void handle_fifo_command(char *argv0, char *cmd, struct l2tp_options *dflt_lo)
{
    assert(argv0);
    assert(cmd);
    assert(dflt_lo);

    struct l2tp_options lo = *dflt_lo;
    int add_tunnel_idx = -1;
    char *args[64] = {};
    size_t nargs = 0;
    char *tok;

    args[nargs++] = argv0;

    tok = strtok(cmd, " ");
    if (!tok)
        return;

    args[nargs++] = tok;

    while ((tok = strtok(NULL, " "))) {
        assert(nargs < sizeof(args)/sizeof(args[0]));
        args[nargs++] = rstrip(tok);
    }

    parse_fifo_args(nargs, args, &lo, &add_tunnel_idx);

    if (add_tunnel_idx >= 0 && lo.pseudowire != L2TP_API_SESSION_PW_TYPEUNSPECIFIED) {
        if (add_tunnel_idx < g_n_tunnels) {
            struct tunnel_options *to = g_all_tunnels[add_tunnel_idx];
            lo.l2tp_version = to->lo.l2tp_version;
            lo.create_api = to->lo.create_api;
            lo.delete_api = to->lo.delete_api;
            lo.family = to->lo.family;
            lo.protocol = to->lo.protocol;
            lo.tid = to->lo.tid;
            lo.ptid = to->lo.ptid;
            to->lo = lo;
            create_session_1(to);
        }
    } else {
        add_tunnel(&lo);
    }
}

static void handle_fifo_commands(char *argv0, int fd, struct l2tp_options *dflt_lo)
{
    assert(argv0);
    assert(fd >= 0);
    assert(dflt_lo);

    struct vector buf = {};

    while (true) {
        struct pollfd fds[1] = {
            { .fd = fd, .events = POLLIN }
        };
        char *cmdline;
        int ret;

        ret = poll(fds, 1, 100);
        if (ret < 0) break;
        if (ret > 0) {
            char tmp[1024] = {};
            ssize_t nb;
            nb = read(fd, tmp, sizeof(tmp));
            if (nb < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    continue;
                else
                    break;
            }
            if (nb) vector_append(&buf, tmp, nb);
            while ((cmdline = vector_gets(&buf)))
            {
                handle_fifo_command(argv0, cmdline, dflt_lo);
                free(cmdline);
            }
            if (!nb) break;
        }
    }
}

int main(int argc, char **argv)
{
    struct l2tp_options lo = {
        .l2tp_version   = 0,
        .create_api = L2TP_NETLINK_API,
        .delete_api = L2TP_NETLINK_API,
        .family     = AF_INET,
        .protocol   = IPPROTO_UDP,
        .pseudowire = L2TP_API_SESSION_PW_TYPEUNSPECIFIED,
        .mtu = 1400,
        .peer_addr.ip = NULL,
        .local_addr.ip = NULL,
    };
    int cmd_fd = -1;
    size_t i;

    parse_cmdline_args(argc, argv, &lo);
    validate_l2tp_options(&lo);

    g_status_filename = g_is_client ? "/tmp/l2tp-ktest-sess-dataif-c" : "/tmp/l2tp-ktest-sess-dataif-s";
    g_status_file = fopen(g_status_filename, "w");
    if (!g_status_file) die("unable to open status file: %s\n", g_status_filename);

    log("sess_dataif %s\n", g_is_client ? "CLIENT" : "SERVER");

    sem_init(&g_tunnel_sem, 0, 0);
    g_is_running = true;

    signal(SIGINT, on_quit);
    signal(SIGTERM, on_quit);
    signal(SIGQUIT, on_quit);

    if (lo.l2tp_version)
        add_tunnel(&lo);

    if (g_cmdline_fifo) {

        unlink(g_cmdline_fifo);

        if (0 != mkfifo(g_cmdline_fifo, 0755))
            die("failed to create fifo '%s': %s\n", g_cmdline_fifo, strerror(errno));

        cmd_fd = open(g_cmdline_fifo, O_RDONLY|O_NONBLOCK);
        if (cmd_fd < 0)
            die("failed to open command fifo: %s\n", strerror(errno));

        handle_fifo_commands(argv[0], cmd_fd, &lo);
    }

    for (i = 0; i < g_n_tunnels; i++)
        wait_tunnel(i);

    if (g_status_file) fclose(g_status_file);
    if (g_status_filename) unlink(g_status_filename);
    if (cmd_fd >= 0) close(cmd_fd);
    if (g_cmdline_fifo) unlink(g_cmdline_fifo);

    return 0;
}

/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * @seqnum.c
 *
 * Exercise kernel datapath sequence number implementation.
 *
 * Both L2TPv2 and L2TPv3 support the use of sequence numbers in data packet headers.
 * These sequence numbers are intended to allow the detection of out-of-sequence packets,
 * and optionally to allow reordering of packets.  Unlike the control packet sequence
 * numbers, the data path isn't intended to provide a reliable transport.
 *
 * L2TPv2 offers a feature whereby the LNS can request the LAC starts or stops sending
 * sequence numbers -- typically this will be used during PPP establishment.
 *
 * The L2TP kernel code has the following control knobs which influence data sequencing:
 * 
 *  - lns_mode: controls whether or not the peer can control sequence number toggling
 *  - recv_seq: causes packets without sequence numbers to be discarded
 *  - send_seq: causes packets to be transmitted with sequence numbers
 *  - reorder_timeout: allows OOS packets to be queued and reordered
 * 
 * The L2TP kernel code has the following algorithms and codepaths which need exercising:
 * 
 *  * packet ns parsing and seq state tracking
 *     - difficult to directly test
 *     - depends on L2TP protocol version
 *     - we can probably take it as read that this works if other seqnum functionality works
 *  * ingress packet discard based on lns_mode, send_seq, recv_seq
 *     - on early receipt of packets, l2tp_core performs initial checks based on session config
 *     - validate that packets are sent with seq if lns_mode != true and lns sends seq
 *     - validate that packets are discarded if lns_mode == true and lac sends no seq
 *     - validate that packets w/o seq are discarded if recv_seq == true
 *  * rx window check
 *     - prior to queueing a packet for recipt, l2tp_core checks the packet's ns value
 *       falls inside the session's current rx window
 *     - depends on L2TP protocol version (v2 has 16 bit namespace, v3 has 24 bit)
 *     - validate that packets with ns outside window are discarded (l2tpv2 and l2tpv3)
 *  * packet queuing for reordering, including stale packet discard and max_oos tracking
 *     - once queued, packets may be held for later handling if they are out of sequence
 *       and the session configuration has queuing enabled via. reorder_timeout
 *     - validate that oos packets are reordered if reorder_timeout != 0
 *     - validate that oos expiry works if reorder_timeout != 0
 *     - validate that oos packets are discarded if reorder_timeout == 0
 *     - validate that recv recovers after oos if reorder_timeout == 0
 *  * dataplane statistics tracking
 *     - packet discards based on seqnum errors are reflected in session stats
 *     - validate rx_seq_discards, rx_oos_packets are updated correctly
 *  * session nr updates
 *     - difficult to directly test
 *     - we can probably take it as read that this works if other seqnum functionality works
 */
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <regex.h>

#include "l2tp_netlink.h"
#include "util.h"
#include "util_ppp.h"

static bool g_have_l2tp_trace_events;

#define L2TP_HDRFLAG_SEQ    0x0800
#define L2TP_HDR_VER_2      0x0002

#define L2TP_TRACE_EVENT_ENABLE_PATH "/sys/kernel/debug/tracing/events/l2tp/enable"
#define TRACE_LOG_PATH "/sys/kernel/debug/tracing/trace"

#define err_dump_session_stats(_prefix, _ss) do { \
    err(_prefix); \
    err("  tx: %" PRIu64 "/%" PRIu64 "/%" PRIu64 " (pkt/bytes/errors)\n", \
            (_ss)->data_tx_packets, \
            (_ss)->data_tx_bytes, \
            (_ss)->data_tx_errors); \
    err("  rx: %" PRIu64 "/%" PRIu64 "/%" PRIu64 " (pkt/bytes/errors)\n", \
            (_ss)->data_rx_packets, \
            (_ss)->data_rx_bytes, \
            (_ss)->data_rx_errors); \
    err("  rx: %" PRIu64 "/%" PRIu64 " (seq_discard/oos_packets)\n", \
            (_ss)->data_rx_oos_discards, \
            (_ss)->data_rx_oos_packets); \
} while(0)


static void clear_trace(void)
{
    if (g_have_l2tp_trace_events) {
        FILE *f = fopen(TRACE_LOG_PATH, "w");
        if (f) fclose(f);
    }
}

static void enable_trace(void)
{
    if (g_have_l2tp_trace_events) {
        FILE *f = fopen(L2TP_TRACE_EVENT_ENABLE_PATH, "w");
        if (f) {
            char enable = '1';
            fwrite(&enable, 1, 1, f);
            fclose(f);
        }
    }
}

static char *get_trace(void)
{
    static char buf[8192];
    memset(buf, 0, sizeof(buf));
    if (g_have_l2tp_trace_events) {
        FILE *f = fopen(TRACE_LOG_PATH, "r");
        if (f) {
            size_t n = fread(buf, 1, sizeof(buf)-1, f);
            buf[n+1] = '\0';
            fclose(f);
            dbg("%s\n", buf);
        }
    }
    return buf;
}

static bool trace_regex_find(char *regex)
{
    char *trace = get_trace();
    regex_t re;
    int ret;

    ret = regcomp(&re, regex, 0);
    if (ret) {
        err("failed to compile regex '%s'\n", regex);
        return false;
    }

    ret = regexec(&re, trace, 0, NULL, 0);
    regfree(&re);
    return ret == 0;
}

static int get_session_stats(uint32_t tid, uint32_t sid, struct l2tp_session_stats *out)
{
    assert(tid);
    assert(sid);
    assert(out);
    struct l2tp_session_data sd = {};
    if (0 == l2tp_nl_session_get(tid, sid, &sd)) {
        *out = sd.stats;
        return 0;
    }
    return -1;
}

static size_t build_v2_hdr(uint16_t flags,
                           uint16_t ns, uint16_t nr,
                           uint16_t tid, uint16_t sid,
                           void *out)
{
    assert(out);

    uint16_t *pout = out;

    *pout++ = htons(flags|L2TP_HDR_VER_2);
    *pout++ = htons(tid);
    *pout++ = htons(sid);
    if (flags & L2TP_HDRFLAG_SEQ) {
        *pout++ = htons(ns);
        *pout++ = htons(nr);
    }
    return (char *)pout - (char *)out;
}

static int do_validate_ingress(int local_tfd, int peer_tfd, struct l2tp_options *options)
{
#define pktlen 64
#define regex_count_max 4
    struct ingress_testcases {
        int hdr_flags;
        int lns_mode;
        int recv_seq;
        int send_seq;
        struct l2tp_session_stats expected_stats;
        char *trace_regex[regex_count_max];
    } c[] = {
        // No seq in packet, recv_seq in session config
        {
            .hdr_flags = 0,
            .recv_seq = 1,
            .expected_stats = {
                .data_rx_errors = 1,
                .data_rx_oos_discards = 1
            },
        },
        {
            .hdr_flags = 0,
            .recv_seq = 1,
            .lns_mode = 1,
            .expected_stats = {
                .data_rx_errors = 1,
                .data_rx_oos_discards = 1
            },
        },
        // Seq in packet, recv_seq in session config
        {
            .hdr_flags = L2TP_HDRFLAG_SEQ,
            .recv_seq = 1,
            .expected_stats = {
                .data_rx_packets = 1,
                .data_rx_bytes = pktlen,
            },
            // seqnum in packet triggers send_seq in LAC mode,
            // successful recv should update seqnum in session
            .trace_regex = {
                "^.*session_seqnum_lns_enable",
                "^.*session_seqnum_reset",
                "^.*session_seqnum_update",
            },
        },
        {
            .hdr_flags = L2TP_HDRFLAG_SEQ,
            .recv_seq = 1,
            .lns_mode = 1,
            .expected_stats = {
                .data_rx_packets = 1,
                .data_rx_bytes = pktlen,
            },
            // successful recv should update seqnum in session
            .trace_regex = {
                "^.*session_seqnum_reset",
                "^.*session_seqnum_update",
            },
        },
        // Seq in packet, lns_mode in session config
        /* FIXME?  Logically I think this ought to fail: the LNS things it isn't
         * sending sequence numbers, but the LAC is sending them anyway.   However
         * that's OK by the kernel currently.
        {
            .hdr_flags = L2TP_HDRFLAG_SEQ,
            .send_seq = 0,
            .lns_mode = 1,
            .expected_stats = {
                .data_rx_errors = 1,
                .data_rx_oos_discards = 1,
            },
        },
        */
        {
            .hdr_flags = 0,
            .send_seq = 1,
            .lns_mode = 1,
            .expected_stats = {
                .data_rx_errors = 1,
                .data_rx_oos_discards = 1,
            },
        },
        // TODO: need to test lac mode, which will toggle config
    };
    struct sockaddr_storage addr = {};
    socklen_t addrlen = 0;
    int i;

    assert(0 == tunnel_sk_addr_init(options->family,
                                    options->protocol,
                                    options->local_addr.ip,
                                    options->local_addr.port,
                                    options->tid,
                                    &addr,
                                    &addrlen));

    for (i = 0; i < sizeof(c)/sizeof(c[0]); i++) {
        struct l2tp_session_nl_config cfg = {
            .debug = opt_debug ? 0xff : 0,
            .mtu = -1,
            .pw_type = options->pseudowire,
            .lns_mode = c[i].lns_mode,
            .recv_seq = c[i].recv_seq,
            .send_seq = c[i].send_seq,
        };
        struct l2tp_session_stats ss = {};
        char pkt[pktlen] = {};
        int ret;

        log("%s: pkt header 0x%x, session lns_mode=%u, recv_seq=%u, send_seq=%u\n",
                __func__,
                c[i].hdr_flags,
                c[i].lns_mode,
                c[i].recv_seq,
                c[i].send_seq);

        clear_trace();

        ret = l2tp_nl_session_create(options->tid, options->ptid, options->sid, options->psid, &cfg);
        if (ret != 0) {
            err("%s: failed to create session instance: %s\n", __func__, strerror(ret));
            return ret;
        }

        // FIXME: handle l2tpv3 as well!
        memset(pkt, 0xae, sizeof(pkt));
        (void)build_v2_hdr(c[i].hdr_flags, 0, 0, options->tid, options->sid, &pkt);
        if (sendto(peer_tfd, pkt, sizeof(pkt), 0, (void *)&addr, addrlen) <= 0) {
            err("sendto: %s\n", strerror(errno));
            return -errno;
        }

        if (0 != get_session_stats(options->tid, options->sid, &ss)) {
            err("failed to get session stats\n");
            return -1;
        }

        if (0 != memcmp(&ss, &c[i].expected_stats, sizeof(ss))) {
            err("statistics mismatch\n");
            err_dump_session_stats("expected:\n", &c[i].expected_stats);
            err_dump_session_stats("actual:\n", &ss);
            return -1;
        }

        if (g_have_l2tp_trace_events) {
            int j;
            for (j = 0; c[i].trace_regex[j]; j++) {
                if (!trace_regex_find(c[i].trace_regex[j])) {
                    err("expected pattern '%s' in event trace not found\n", c[i].trace_regex[j]);
                    return -1;
                }
            }
        }

        l2tp_nl_session_delete(options->tid, options->sid);
        usleep(250*1000);

        log("OK\n");
    }
    return 0;
#undef pktlen
#undef regex_count_max
}

static int do_validate_rxwindow(int local_tfd, int peer_tfd, struct l2tp_options *options)
{
    printf("%s\n", __func__);
    return -ENOSYS;
}

static int do_validate_queue(int local_tfd, int peer_tfd, struct l2tp_options *options)
{
    printf("%s\n", __func__);
    return -ENOSYS;
}

static int do_validate_noqueue(int local_tfd, int peer_tfd, struct l2tp_options *options)
{
    printf("%s\n", __func__);
    return -ENOSYS;
}

void show_usage(const char *myname)
{
    printf("Name:     %s\n", myname);
    printf("Desc:     validate kernel dataplane sequence number handling\n");
    printf("Usage:    %s [options] <mode>\n", myname);
    printf("\n");
    printf("          -h    print this usage information\n");
    printf("\n");
    printf("          L2TP protocol control options:\n");
    printf("\n");
    printf("          -v    specify L2TP version (2 or 3: default is 2)\n");
    printf("\n");
    printf("          Validation modes:\n");
    printf("\n");
    printf("          ingress       validates packet rx handling depending on lns_mode," \
                                    " send_seq, and recv_seq session settings.\n");
    printf("          rxwindow      validates that packets with an ns value outside the" \
                                    " rx window are discarded correctly.\n");
    printf("          queue         validates oos packet handling with reorder_timeout != 0.\n");
    printf("          noqueue       validates oos packet handling with reorder_timeout == 0.\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    struct test_modes {
        const char *name;
        int (*handler)(int local_tfd, int peer_tfd, struct l2tp_options *);
    } modes[] = {
        { "ingress", do_validate_ingress },
        { "rxwindow", do_validate_rxwindow },
        { "queue", do_validate_queue },
        { "noqueue", do_validate_noqueue },
    };

    struct l2tp_options lo = {
        .l2tp_version   = 2,
        .create_api = L2TP_NETLINK_API,
        .delete_api = L2TP_NETLINK_API,
        .family     = AF_INET,
        .protocol   = IPPROTO_UDP,
        .pseudowire = L2TP_API_SESSION_PW_TYPE_PPP,
        .mtu = 1400,
        .peer_addr = *gen_dflt_address(AF_INET, false),
        .local_addr = *gen_dflt_address(AF_INET, true),
        .tid = 111,
        .ptid = 222,
        .sid = 1,
        .psid = 2,
    };

    int opt, i, local_tfd, peer_tfd;

    /* Parse commandline, doing basic sanity checking as we go */
    while ((opt = getopt(argc, argv, "hv:")) != -1) {
        switch(opt) {
        case 'h':
            show_usage(argv[0]);
            exit(EXIT_SUCCESS);
        case 'v':
            lo.l2tp_version = atoi(optarg);
            if (lo.l2tp_version != 3 && lo.l2tp_version != 2)
                die("Invalid l2tp version %s\n", optarg);
            break;
        default:
            die("failed to parse command line args\n");
        }
    }

    if (optind >= argc) {
        show_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Do we have l2tp subsystem trace events? */
    if (0 == access(L2TP_TRACE_EVENT_ENABLE_PATH, F_OK)) {
        g_have_l2tp_trace_events = true;
        log("have L2TP subsytem trace events\n");
        enable_trace();
    } else {
        log("do not have L2TP subsytem trace events\n");
    }

    local_tfd = tunnel_socket(lo.family, lo.protocol, lo.tid, &lo.local_addr, &lo.peer_addr);
    if (local_tfd < 0) {
        die("failed to open local tunnel socket\n");
    }

    peer_tfd = tunnel_socket(lo.family, lo.protocol, lo.tid, &lo.peer_addr, &lo.local_addr);
    if (peer_tfd < 0) {
        die("failed to open peer tunnel socket\n");
    }

    if (0 != kernel_tunnel_create(local_tfd, &lo, NULL)) {
        die("failed to create local tunnel instance\n");
    }

    for (i = 0; i < sizeof(modes)/sizeof(modes[0]); i++) {
        if (0 == strcmp(argv[optind], modes[i].name)) {
            return modes[i].handler(local_tfd, peer_tfd, &lo) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }
    die("Unrecognised mode \"%s\"\n", argv[optind]);
}

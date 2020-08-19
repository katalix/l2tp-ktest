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

#define L2TPv2_HDR_FLAG_SEQ             0x0800
#define L2TPv3_HDR_FLAG_SEQ             0x40000000
#define L2TP_HDR_VER_2                  0x0002
#define L2TP_HDR_VER_3                  0x0003

#define L2TP_TRACE_EVENT_ENABLE_PATH    "/sys/kernel/debug/tracing/events/l2tp/enable"
#define TRACE_LOG_PATH                  "/sys/kernel/debug/tracing/trace"

/* Seqnum sequences include flags to control the send/check function:
 * this is possible because L2TPv2 uses a 16 bit seq, and L2TPv3 a 24 bit
 * one, so we can take eight bytes from a uint32_t for signalling purposes.
 */
#define SEQSET                          0x80000000
#define PAUSE_AFTER                     0x40000000
#define SEQNUM_MASK                     0x00ffffff
#define VALIDATE_QUEUE_TIMEOUT          100 /* milliseconds */

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

static size_t build_v2_hdr(bool send_seq,
                           uint16_t ns, uint16_t nr,
                           uint16_t tid, uint16_t sid,
                           void *out)
{
    assert(out);

    uint16_t *pout = out;
    uint16_t flags = L2TP_HDR_VER_2;

    if (send_seq)
        flags |= L2TPv2_HDR_FLAG_SEQ;

    *pout++ = htons(flags);
    *pout++ = htons(tid);
    *pout++ = htons(sid);
    if (send_seq) {
        *pout++ = htons(ns);
        *pout++ = htons(nr);
    }
    return (char *)pout - (char *)out;
}

static size_t build_v3_udp_hdr(bool send_seq,
                               uint32_t seqnum,
                               uint32_t sid,
                               void *out)
{
    assert(out);
    assert(seqnum <= 0xffffff);

    uint32_t *pout = out;

    {
        uint16_t *pout_u16 = out;
        *pout_u16++ = htons(L2TP_HDR_VER_3);
        *pout_u16++ = 0;
    }
    pout++;

    *pout++ = htonl(sid);

    if (send_seq)
        *pout++ = htonl(L2TPv3_HDR_FLAG_SEQ|seqnum);
    else
        *pout++ = 0;

    return (char *)pout - (char *)out;
}

static int send_and_check(int peer_tfd,
                          bool send_seq,
                          uint32_t *seqnum,
                          size_t pktlen,
                          struct l2tp_session_stats *expected_stats,
                          char *expected_trace_regex[],
                          struct l2tp_options *opt)
{
    uint32_t dflt_seqnum[2] = {SEQSET|0};
    struct sockaddr_storage addr = {};
    struct l2tp_session_stats ss = {};
    socklen_t addrlen = 0;
    char pkt[1024];
    int i;

    assert(pktlen <= sizeof(pkt));

    assert(0 == tunnel_sk_addr_init(opt->family,
                                    opt->protocol,
                                    opt->local_addr.ip,
                                    opt->local_addr.port,
                                    opt->tid,
                                    &addr,
                                    &addrlen));

    if (!seqnum) seqnum = dflt_seqnum;

    clear_trace();

    /* Send packet(s) */
    for (i = 0; seqnum[i]&SEQSET; i++) {

        uint32_t ns = seqnum[i]&SEQNUM_MASK;
        memset(pkt, 0xae, pktlen);

        if (opt->l2tp_version == L2TP_API_PROTOCOL_VERSION_2) {
            (void)build_v2_hdr(send_seq, ns, 0, opt->tid, opt->sid, &pkt);
        } else {
            (void)build_v3_udp_hdr(send_seq, ns, opt->sid, &pkt);
        }

        if (sendto(peer_tfd, pkt, pktlen, 0, (void *)&addr, addrlen) <= 0) {
            err("sendto: %s\n", strerror(errno));
            return -errno;
        }

        if (seqnum[i]&PAUSE_AFTER) {
            usleep((10+VALIDATE_QUEUE_TIMEOUT) * 1000);
        }
    }

    /* Validate expectations */
    if (expected_stats) {
        if (0 != get_session_stats(opt->tid, opt->sid, &ss)) {
            err("failed to get session stats\n");
            return -1;
        }

        if (0 != memcmp(&ss, expected_stats, sizeof(ss))) {
            err("statistics mismatch\n");
            err_dump_session_stats("expected:\n", expected_stats);
            err_dump_session_stats("actual:\n", &ss);
            return -1;
        }
    }

    if (g_have_l2tp_trace_events && expected_trace_regex) {
        for (i = 0; expected_trace_regex[i]; i++) {
            if (!trace_regex_find(expected_trace_regex[i])) {
                err("expected pattern '%s' in event trace not found\n", expected_trace_regex[i]);
                return -1;
            }
        }
    }
    return 0;
}

static int create_session(struct l2tp_options *opt, struct l2tp_session_nl_config *scfg, int *ctlsk, int *pppsk)
{
    int ret;

    ret = l2tp_nl_session_create(opt->tid, opt->ptid, opt->sid, opt->psid, scfg);
    if (ret != 0) {
        err("%s: failed to create session instance: %s\n", __func__, strerror(ret));
        return ret;
    }

    ret = kernel_session_create_pppox(opt, ctlsk, pppsk);
    if (ret != 0) {
        err("%s: failed to create pppol2tp context: %s\n", __func__, strerror(ret));
        return ret;
    }

    return 0;
}

static void destroy_session(struct l2tp_options *opt, int ctlsk, int pppsk)
{
    l2tp_nl_session_delete(opt->tid, opt->sid);
    close(pppsk);
    close(ctlsk);
    /* Ugh: avoid racing with kernel async shutdown process */
    usleep(250*1000);
}

static int do_validate_ingress(int local_tfd, int peer_tfd, struct l2tp_options *options)
{
#define pktlen 64
#define regex_count_max 4
    struct ingress_testcases {
        bool pkt_seq;
        int lns_mode;
        int recv_seq;
        int send_seq;
        struct l2tp_session_stats expected_stats;
        char *trace_regex[regex_count_max];
    } c[] = {
        /* No seq in packet, recv_seq in session config */
        {
            .pkt_seq = false,
            .recv_seq = 1,
            .expected_stats = {
                .data_rx_errors = 1,
                .data_rx_oos_discards = 1
            },
        },
        {
            .pkt_seq = false,
            .recv_seq = 1,
            .lns_mode = 1,
            .expected_stats = {
                .data_rx_errors = 1,
                .data_rx_oos_discards = 1
            },
        },
        /* Seq in packet, recv_seq in session config */
        {
            .pkt_seq = true,
            .recv_seq = 1,
            .expected_stats = {
                .data_rx_packets = 1,
                .data_rx_bytes = pktlen,
            },
            /* seqnum in packet triggers send_seq in LAC mode,
             * successful recv should update seqnum in session
             */
            .trace_regex = {
                "^.*session_seqnum_lns_enable",
                "^.*session_seqnum_reset",
                "^.*session_seqnum_update",
            },
        },
        {
            .pkt_seq = true,
            .recv_seq = 1,
            .lns_mode = 1,
            .expected_stats = {
                .data_rx_packets = 1,
                .data_rx_bytes = pktlen,
            },
            /* successful recv should update seqnum in session */
            .trace_regex = {
                "^.*session_seqnum_reset",
                "^.*session_seqnum_update",
            },
        },
        /* No seq in packet, send_seq and lns_mode in session config */
        {
            .pkt_seq = false,
            .send_seq = 1,
            .lns_mode = 1,
            .expected_stats = {
                .data_rx_errors = 1,
                .data_rx_oos_discards = 1,
            },
        },
        {
            .pkt_seq = false,
            .send_seq = 1,
            .expected_stats = {
                .data_rx_packets = 1,
                .data_rx_bytes = pktlen,
            },
            /* No seq in packet should disable send_seq.
             * Since there's no packet seq we don't expect seqnum updates in session.
             */
            .trace_regex = {
                "^.*session_seqnum_lns_disable",
            },
        },
    };
    int i;

    for (i = 0; i < sizeof(c)/sizeof(c[0]); i++) {
        struct l2tp_session_nl_config cfg = {
            .debug = opt_debug ? 0xff : 0,
            .mtu = -1,
            .pw_type = options->pseudowire,
            .l2spec_type = L2TP_API_SESSION_L2SPECTYPE_DEFAULT,
            .lns_mode = c[i].lns_mode,
            .recv_seq = c[i].recv_seq,
            .send_seq = c[i].send_seq,
        };
        int ret, ctlsk, pppsk;

        log("%s: pkt_seq=%u, session lns_mode=%u, recv_seq=%u, send_seq=%u\n",
                __func__,
                c[i].pkt_seq ? 1 : 0,
                c[i].lns_mode,
                c[i].recv_seq,
                c[i].send_seq);


        ret = create_session(options, &cfg, &ctlsk, &pppsk);
        if (ret != 0) {
            err("%s: failed to create session instance: %s\n", __func__, strerror(ret));
            return ret;
        }

        ret = send_and_check(peer_tfd, c[i].pkt_seq, NULL, pktlen, &c[i].expected_stats, c[i].trace_regex, options);
        if (ret != 0)
            return ret;

        destroy_session(options, ctlsk, pppsk);

        log("OK\n");
    }
    return 0;
#undef pktlen
#undef regex_count_max
}

static int do_validate_rxwindow(int local_tfd, int peer_tfd, struct l2tp_options *options)
{
#define pktlen 64
#define regex_count_max 4
#define seqnum_count_max 6
    struct rxwindow_testcases {
        uint32_t seqnum[seqnum_count_max];
        struct l2tp_session_stats expected_stats;
        char *trace_regex[regex_count_max];
    };

    struct rxwindow_testcases v2c[] = {
        /* RFC2661 is a bit vague on the rules for dataplane sequence number comparisons,
         * so the kernel copies the rules for the control plane (ref: RFC2661 section 5.8).
         * At the start of time the session nr is zero, so:
         *      0 -> 32766 inclusive is in sequence and should be accepted
         *      32767 -> 65535 is out of sequence and should be rejected
         */
        { .seqnum = {SEQSET|0}, .expected_stats = { .data_rx_packets = 1, .data_rx_bytes = pktlen } },
        { .seqnum = {SEQSET|1}, .expected_stats = { .data_rx_packets = 1, .data_rx_bytes = pktlen } },
        { .seqnum = {SEQSET|32766}, .expected_stats = { .data_rx_packets = 1, .data_rx_bytes = pktlen } },
        {
            .seqnum = {SEQSET|32767},
            .expected_stats = { .data_rx_errors = 1 },
            .trace_regex = { "^.*session_pkt_outside_rx_window" },
        },
        {
            .seqnum = {SEQSET|65535},
            .expected_stats = { .data_rx_errors = 1 },
            .trace_regex = { "^.*session_pkt_outside_rx_window" },
        },
    };

    struct rxwindow_testcases v3c[] = {
        /* RFC3931 section 4.6 deals with the default L2-specific sublayer, which implements
         * a 24-bit sequence number.
         * At the start of time the session nr is zero, so:
         *      0 -> 8388606 inclusive is in sequence and should be accepted
         *      8388607 -> 16777215 is out of sequence and should be rejected
         */
        { .seqnum = {SEQSET|0}, .expected_stats = { .data_rx_packets = 1, .data_rx_bytes = pktlen } },
        { .seqnum = {SEQSET|1}, .expected_stats = { .data_rx_packets = 1, .data_rx_bytes = pktlen } },
        { .seqnum = {SEQSET|8388606}, .expected_stats = { .data_rx_packets = 1, .data_rx_bytes = pktlen } },
        {
            .seqnum = {SEQSET|8388607},
            .expected_stats = { .data_rx_errors = 1 },
            .trace_regex = { "^.*session_pkt_outside_rx_window" },
        },
        {
            .seqnum = {SEQSET|16777215},
            .expected_stats = { .data_rx_errors = 1 },
            .trace_regex = { "^.*session_pkt_outside_rx_window" },
        },
    };

    struct rxwindow_testcases *c;
    size_t nc;
    int i;

    if (options->l2tp_version == L2TP_API_PROTOCOL_VERSION_2) {
        c = v2c;
        nc = sizeof(v2c)/sizeof(v2c[0]);
    } else {
        c = v3c;
        nc = sizeof(v3c)/sizeof(v3c[0]);
    }

    for (i = 0; i < nc; i++) {

        struct l2tp_session_nl_config cfg = {
            .debug = opt_debug ? 0xff : 0,
            .mtu = -1,
            .pw_type = options->pseudowire,
            .l2spec_type = L2TP_API_SESSION_L2SPECTYPE_DEFAULT,
            .send_seq = 1,
        };
        int ret, ctlsk, pppsk;

        {
            int j;
            log("%s: seqnum ", __func__);
            for (j = 0; c[i].seqnum[j]&SEQSET; j++) {
                log_raw("%u ", c[i].seqnum[j]&SEQNUM_MASK);
            }
            log_raw("\n");
        }

        ret = create_session(options, &cfg, &ctlsk, &pppsk);
        if (ret != 0) {
            err("%s: failed to create session instance: %s\n", __func__, strerror(ret));
            return ret;
        }

        ret = send_and_check(peer_tfd, true, c[i].seqnum, pktlen, &c[i].expected_stats, c[i].trace_regex, options);
        if (ret)
            return ret;

        destroy_session(options, ctlsk, pppsk);

        log("OK\n");
    }

    return 0;
#undef pktlen
#undef regex_count_max
#undef seqnum_count_max
}

static int do_validate_queue(int local_tfd, int peer_tfd, struct l2tp_options *options)
{
#define pktlen 64
#define regex_count_max 4
#define seqnum_count_max 10
    struct queue_testcases {
        uint32_t seqnum[seqnum_count_max];
        struct l2tp_session_stats expected_stats;
        char *trace_regex[regex_count_max];
    } c[] = {
        /* oos packets should be reordered */
        {
            .seqnum = {SEQSET|0, SEQSET|2, SEQSET|1},
            .expected_stats = {
                .data_rx_packets = 3,
                .data_rx_bytes = 3*pktlen,
                .data_rx_oos_packets = 1,
            },
        },
        /* packet loss should be recovered from */
        {
            .seqnum = {SEQSET|0, SEQSET|PAUSE_AFTER|2, SEQSET|3},
            .expected_stats = {
                .data_rx_errors = 1,
                .data_rx_packets = 2,
                .data_rx_bytes = 2*pktlen,
                .data_rx_oos_discards = 1,
            },
            .trace_regex = {
                "^.*session_pkt_expired",
                "^.*session_seqnum_reset",
                "^.*session_seqnum_update",
            },
        },
    };
    int i;

    for (i = 0; i < sizeof(c)/sizeof(c[0]); i++) {
        struct l2tp_session_nl_config cfg = {
            .debug = opt_debug ? 0xff : 0,
            .mtu = -1,
            .pw_type = options->pseudowire,
            .l2spec_type = L2TP_API_SESSION_L2SPECTYPE_DEFAULT,
            .send_seq = 1,
            .reorder_timeout = VALIDATE_QUEUE_TIMEOUT,
        };
        int ret, ctlsk, pppsk;

        {
            int j;
            log("%s: seqnum ", __func__);
            for (j = 0; c[i].seqnum[j]&SEQSET; j++) {
                log_raw("%u ", c[i].seqnum[j]&SEQNUM_MASK);
            }
            log_raw("\n");
        }

        ret = create_session(options, &cfg, &ctlsk, &pppsk);
        if (ret != 0) {
            err("%s: failed to create session instance: %s\n", __func__, strerror(ret));
            return ret;
        }

        ret = send_and_check(peer_tfd, true, c[i].seqnum, pktlen, &c[i].expected_stats, c[i].trace_regex, options);
        if (ret != 0)
            return ret;

        destroy_session(options, ctlsk, pppsk);

        log("OK\n");
    }

    return 0;
#undef pktlen
#undef regex_count_max
#undef seqnum_count_max
}

static int do_validate_noqueue(int local_tfd, int peer_tfd, struct l2tp_options *options)
{
#define pktlen 64
#define regex_count_max 4
#define seqnum_count_max 10
    struct noqueue_testcases {
        uint32_t seqnum[seqnum_count_max];
        struct l2tp_session_stats expected_stats;
        char *trace_regex[regex_count_max];
    } c[] = {
        /* oos packets should be discarded */
        {
            .seqnum = {SEQSET|0, SEQSET|2, SEQSET|1},
            .expected_stats = {
                .data_rx_errors = 1,
                .data_rx_packets = 2,
                .data_rx_bytes = 2*pktlen,
                .data_rx_oos_discards = 1,
            },
            .trace_regex = {
                "^.*session_pkt_oos",
            },
        },
        /* packet loss should be recovered from */
        {
            .seqnum = {SEQSET|0, SEQSET|2, SEQSET|3, SEQSET|4, SEQSET|5, SEQSET|6, SEQSET|7, SEQSET|8},
            .expected_stats = {
                .data_rx_errors = 5,
                .data_rx_packets = 3,
                .data_rx_bytes = 3*pktlen,
                .data_rx_oos_discards = 5,
            },
            .trace_regex = {
                "^.*session_pkt_oos",
                "^.*session_seqnum_reset",
                "^.*session_seqnum_update",
            },
        },
    };
    int i;

    for (i = 0; i < sizeof(c)/sizeof(c[0]); i++) {
        struct l2tp_session_nl_config cfg = {
            .debug = opt_debug ? 0xff : 0,
            .mtu = -1,
            .pw_type = options->pseudowire,
            .l2spec_type = L2TP_API_SESSION_L2SPECTYPE_DEFAULT,
            .send_seq = 1,
            .reorder_timeout = 0,
        };
        int ret, ctlsk, pppsk;

        {
            int j;
            log("%s: seqnum ", __func__);
            for (j = 0; c[i].seqnum[j]&SEQSET; j++) {
                log_raw("%u ", c[i].seqnum[j]&SEQNUM_MASK);
            }
            log_raw("\n");
        }

        ret = create_session(options, &cfg, &ctlsk, &pppsk);
        if (ret != 0) {
            err("%s: failed to create session instance: %s\n", __func__, strerror(ret));
            return ret;
        }

        ret = send_and_check(peer_tfd, true, c[i].seqnum, pktlen, &c[i].expected_stats, c[i].trace_regex, options);
        if (ret != 0)
            return ret;

        destroy_session(options, ctlsk, pppsk);

        log("OK\n");
    }

    return 0;
#undef pktlen
#undef regex_count_max
#undef seqnum_count_max
}

static int run_tests(struct l2tp_options *opt, char *mode)
{
    assert(opt);

    struct test_modes {
        const char *name;
        int (*handler)(int local_tfd, int peer_tfd, struct l2tp_options *);
    } modes[] = {
        { "ingress", do_validate_ingress },
        { "rxwindow", do_validate_rxwindow },
        { "queue", do_validate_queue },
        { "noqueue", do_validate_noqueue },
    };
    int local_tfd, peer_tfd, i, ret = -ENOENT;

    log("%s: L2TPv%d, mode %s\n", __func__, opt->l2tp_version, mode ? mode : "all");

    local_tfd = tunnel_socket(opt->family, opt->protocol, opt->tid, &opt->local_addr, &opt->peer_addr);
    if (local_tfd < 0) {
        die("failed to open local tunnel socket\n");
    }

    peer_tfd = tunnel_socket(opt->family, opt->protocol, opt->tid, &opt->peer_addr, &opt->local_addr);
    if (peer_tfd < 0) {
        die("failed to open peer tunnel socket\n");
    }

    if (0 != kernel_tunnel_create(local_tfd, opt, NULL)) {
        die("failed to create local tunnel instance\n");
    }

    for (i = 0; i < sizeof(modes)/sizeof(modes[0]); i++) {
        if (mode) {
            if (0 != strcmp(mode, modes[i].name))
                continue;
        }
        ret = modes[i].handler(local_tfd, peer_tfd, opt);
        if (ret)
            break;
    }

    close(local_tfd);
    close(peer_tfd);

    return ret;
}

static void show_usage(const char *myname)
{
    printf("Name:     %s\n", myname);
    printf("Desc:     validate kernel dataplane sequence number handling\n");
    printf("Usage:    %s [options] [mode]\n", myname);
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
    printf("          If no validation mode is specified, all modes will be run for both L2TPv2 and v3.\n");
    printf("\n");
}

int main(int argc, char **argv)
{
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

    char *user_specified_mode = NULL;
    enum l2tp_api_protocol_version versions[] = {
        L2TP_API_PROTOCOL_VERSION_2,
        L2TP_API_PROTOCOL_VERSION_3,
    };
    int opt, i;

    /* Parse commandline, doing basic sanity checking as we go */
    while ((opt = getopt(argc, argv, "hv:")) != -1) {
        switch(opt) {
        case 'h':
            show_usage(argv[0]);
            exit(EXIT_SUCCESS);
        case 'v':
            if (!parse_l2tp_version(optarg, (int*)&versions[0])) {
                die("Invalid l2tp version %s\n", optarg);
            }
            versions[1] = 0;
            break;
        default:
            die("failed to parse command line args\n");
        }
    }

    if (optind < argc) {
        user_specified_mode = argv[optind];
    }

    /* Do we have l2tp subsystem trace events? */
    if (0 == access(L2TP_TRACE_EVENT_ENABLE_PATH, F_OK)) {
        g_have_l2tp_trace_events = true;
        log("have L2TP subsytem trace events\n");
        enable_trace();
    } else {
        log("do not have L2TP subsytem trace events\n");
    }

    for (i = 0; i < sizeof(versions)/sizeof(versions[0]) && versions[i]; i++) {
        int ret;

        lo.l2tp_version = versions[i];
        ret = run_tests(&lo, user_specified_mode);
        if (ret) return EXIT_FAILURE;

        /* avoid possible races with tunnel async shutdown */
        lo.tid++;
        lo.ptid++;
    }

    return EXIT_SUCCESS;
}

/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * @getstats.c
 *
 * Utility to look up tunnel or session dataplane stats using netlink.
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "l2tp_netlink.h"

int main (int argc, char **argv)
{
    uint32_t tid = 0, sid = 0;
    int ret;

    if (argc > 1)
        tid = atoi(argv[1]);
    if (argc > 2)
        sid = atoi(argv[2]);

    if (!tid && !sid) {
        printf("Usage: %s <tid> [<sid>]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (tid && sid) {
        struct l2tp_session_data d = {};
        ret = l2tp_nl_session_get(tid, sid, &d);
        if (ret == 0) {
            printf("tx %" PRIu64 "/%" PRIu64 "/%" PRIu64 " pkts/bytes/errors\n",
                    d.stats.data_tx_packets,
                    d.stats.data_tx_bytes,
                    d.stats.data_tx_errors);
            printf("rx %" PRIu64 "/%" PRIu64 "/%" PRIu64 " pkts/bytes/errors\n",
                    d.stats.data_rx_packets,
                    d.stats.data_rx_bytes,
                    d.stats.data_rx_errors);
            printf("rx %" PRIu64 "/%" PRIu64 " oos pkts/discards\n",
                    d.stats.data_rx_oos_packets,
                    d.stats.data_rx_oos_discards);
        }
    } else {
        struct l2tp_tunnel_stats s = {};
        ret = l2tp_nl_tunnel_get(tid, &s);
        if (ret == 0) {
            printf("tx %" PRIu64 "/%" PRIu64 "/%" PRIu64 " pkts/bytes/errors\n",
                    s.data_tx_packets,
                    s.data_tx_bytes,
                    s.data_tx_errors);
            printf("rx %" PRIu64 "/%" PRIu64 "/%" PRIu64 " pkts/bytes/errors\n",
                    s.data_rx_packets,
                    s.data_rx_bytes,
                    s.data_rx_errors);
            printf("rx %" PRIu64 "/%" PRIu64 " oos pkts/discards\n",
                    s.data_rx_oos_packets,
                    s.data_rx_oos_discards);
        }
    }
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * @file l2tp_netlink.h
 *
 * Netlink wrappers for L2TP genl commands.
 */
#ifndef L2TP_NETLINK_H
#define L2TP_NETLINK_H

#include <sys/socket.h>

#include "l2tp_kapi.h"

/**
 * Configuration for a kernel tunnel context.
 */
struct l2tp_tunnel_nl_config {
    uint32_t debug;                                 /** Bitmask of enum l2tp_debug_flags */
    enum l2tp_api_tunnel_encap_type encap_type;
    enum l2tp_api_protocol_version proto_version;
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
};

/**
 * Configuration for a kernel session context.
 */
struct l2tp_session_nl_config {
    uint32_t debug;                                 /** Bitmask of enum l2tp_debug_flags */
    enum l2tp_api_session_seqmode seqmode;
    uint8_t cookie_len;
    uint8_t cookie[8];
    uint8_t peer_cookie_len;
    uint8_t peer_cookie[8];
    enum l2tp_api_session_pw_type pw_type;
    uint16_t vlan_id;
    uint16_t mtu;
    uint16_t lns_mode:1;
    uint16_t recv_seq:1;
    uint16_t send_seq:1;
    int reorder_timeout;
    char *ifname;
    enum l2tp_api_session_l2spec_type l2spec_type;
    enum l2tp_api_session_l2spec_type peer_l2spec_type;
};


/**
 * Initialise the netlink module.
 * @return                  0 on success, negative number otherwise
 */
int l2tp_nl_init(void);

/**
 * Clean up resources allocated by l2tp_nl_init.
 */
void l2tp_nl_cleanup(void);

/**
 * Create a tunnel instance in the kernel.
 *  @param  tunnel_id       local L2TP tunnel ID
 *  @param  peer_tunnel_id  peer L2TP tunnel ID
 *  @param  fd              tunnel socket (may be < 0 for unmanaged tunnel)
 *  @param  cfg             tunnel configuration
 *  @return                 0 on success, negative number otherwise
 */
int l2tp_nl_tunnel_create(uint32_t tunnel_id,
        uint32_t peer_tunnel_id,
        int fd,
        struct l2tp_tunnel_nl_config *cfg);

/**
 * Delete a tunnel instance in the kernel.
 *  @param  tunnel_id       local L2TP tunnel ID to delete
 *  @return                 0 on success, negative number otherwise
 */
int l2tp_nl_tunnel_delete(uint32_t tunnel_id);

/**
 * Change kernel tunnel context debug mask.
 *  @param  tunnel_id       local L2TP tunnel ID to be modified
 *  @param  debug           new debug flags for the tunnel
 *  @return                 0 on success, negative number otherwise
 */
int l2tp_nl_tunnel_modify(uint32_t tunnel_id, uint32_t debug);

/**
 * Obtain tunnel stats from the kernel.
 *  @param  tunnel_id       local L2TP tunnel ID to query
 *  @param  stats           pointer to stats structure to fill out on successful return
 *  @return                 0 on success, negative number otherwise
 */
int l2tp_nl_tunnel_get(uint32_t tunnel_id, struct l2tp_tunnel_stats *stats);

/**
 * Create a session instance in the kernel.
 *  @param  tunnel_id       local L2TP tunnel ID of the parent tunnel
 *  @param  peer_tunnel_id  peer L2TP tunnel ID of the parent tunnel
 *  @param  session_id      local L2TP session ID
 *  @param  peer_session_id peer L2TP session ID
 *  @param  cfg             session configuration
 *  @return                 0 on success, negative number otherwise
 */
int l2tp_nl_session_create(uint32_t tunnel_id,
        uint32_t peer_tunnel_id,
        uint32_t session_id,
        uint32_t peer_session_id,
        struct l2tp_session_nl_config *cfg);

/**
 * Delete a session instance in the kernel.
 *  @param  tunnel id       local L2TP tunnel ID of the parent tunnel
 *  @param  session_id      local L2TP session ID of the session to delete
 *  @return                 0 on success, negative number otherwise
 */
int l2tp_nl_session_delete(uint32_t tunnel_id, uint32_t session_id);

/**
 * Change kernel session context debug mask.
 *  @param  tunnel id       local L2TP tunnel ID of the parent tunnel
 *  @param  session_id      local L2TP session ID of the session to modify
 *  @return                 0 on success, negative number otherwise
 */
int l2tp_nl_session_modify(uint32_t tunnel_id, uint32_t session_id, uint32_t debug);

/**
 * Delete a session instance in the kernel.
 *  @param  tunnel id       local L2TP tunnel ID of the parent tunnel
 *  @param  session_id      local L2TP session ID of the session to query
 *  @param  data            pointer to session data structure to fill out on successful return
 *  @return                 0 on success, negative number otherwise
 */
int l2tp_nl_session_get(uint32_t tunnel_id, uint32_t session_id, struct l2tp_session_data *data);

#endif

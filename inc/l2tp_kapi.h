/**
 * @file l2tp_kapi.h
 *
 * A minimal set of Linux kernel API types.
 */
#ifndef L2TP_KAPI_H
#define L2TP_KAPI_H

#include <stdint.h>
#include <linux/l2tp.h>

#if (__BYTE_ORDER == __BIG_ENDIAN)
#define X(a,b)  b,a
#elif (__BYTE_ORDER == __LITTLE_ENDIAN)
#define X(a,b)  a,b
#else
#error  "Adjust your <endian.h> defines"
#endif

/**
 * Packet header for an L2TP v2 packet.
 * Ref: RFC2661
 */
struct l2tp_control_hdr_v2 {
    union {
        struct {
            uint8_t X(X(X(X(X(X(p_bit:1, o_bit:1), rsvd_2:1), s_bit:1), rsvd_1:2), l_bit:1), t_bit:1);
            uint8_t X(ver:4, rsvd_3:4);
        };
        uint16_t flags_ver;
    };
    uint16_t    length;
    uint16_t    tunnel_id;
    uint16_t    session_id;
    uint16_t    ns;
    uint16_t    nr;
    uint8_t     data[0];
};

/**
 * Packet header for an L2TP v3 packet.
 * Ref: RFC3931
 */
struct l2tp_control_hdr_v3 {
    union {
        struct {
            uint8_t X(X(X(X(rsvd_2:3, s_bit:1), rsvd_1:2), l_bit:1), t_bit:1);
            uint8_t X(ver:4, rsvd_3:4);
        };
        uint16_t flags_ver;
    };
    uint16_t    length;
    uint32_t    tunnel_id;
    uint16_t    ns;
    uint16_t    nr;
    uint8_t     data[0];
};

#undef X

/**
 * Tunnel data plane statistics as reported by the
 * kernel L2TP subsystem.
 */
struct l2tp_tunnel_stats {
    uint64_t        data_rx_packets;
    uint64_t        data_rx_bytes;
    uint64_t        data_rx_errors;
    uint64_t        data_rx_oos_packets;
    uint64_t        data_rx_oos_discards;
    uint64_t        data_tx_packets;
    uint64_t        data_tx_bytes;
    uint64_t        data_tx_errors;
};

/**
 * Session data plane statistics as reported by the
 * kernel L2TP subsystem.
 */
struct l2tp_session_stats {
    uint64_t    data_rx_packets;
    uint64_t    data_rx_bytes;
    uint64_t    data_rx_errors;
    uint64_t    data_rx_oos_packets;
    uint64_t    data_rx_oos_discards;
    uint64_t    data_tx_packets;
    uint64_t    data_tx_bytes;
    uint64_t    data_tx_errors;
};

/**
 * Session information as reported by the kernel
 * L2TP subsystem.
 */
struct l2tp_session_data {
    struct l2tp_session_stats   stats;
    char                        *ifname;
};

/**
 * Tunnel encapsulation type.
 */
enum l2tp_api_tunnel_encap_type {
    L2TP_API_TUNNEL_ENCAPTYPE_UDP = L2TP_ENCAPTYPE_UDP,
    L2TP_API_TUNNEL_ENCAPTYPE_IP = L2TP_ENCAPTYPE_IP,
};

/**
 * Tunnel protocol version.
 */
enum l2tp_api_protocol_version {
    L2TP_API_PROTOCOL_VERSION_2 = 2,        /** L2TPv2 */
    L2TP_API_PROTOCOL_VERSION_3 = 3,        /** L2TPv3 */
};

/**
 * Session pseudowire types.
 * L2TPv2 sessions are always PPP.
 * Pseudowire values correspond to IANA assigned numbers.
 */
enum l2tp_api_session_pw_type {
    L2TP_API_SESSION_PW_TYPEUNSPECIFIED = L2TP_PWTYPE_NONE,
    L2TP_API_SESSION_PW_TYPE_ETH_VLAN   = L2TP_PWTYPE_ETH_VLAN,
    L2TP_API_SESSION_PW_TYPE_ETH        = L2TP_PWTYPE_ETH,
    L2TP_API_SESSION_PW_TYPE_PPP        = L2TP_PWTYPE_PPP,
    L2TP_API_SESSION_PW_TYPE_PPP_AC     = L2TP_PWTYPE_PPP_AC,
    L2TP_API_SESSION_PW_TYPE_IP         = L2TP_PWTYPE_IP,
};

/**
 * Session data sequencing mode.
 * Ref: RFC2931 section 5.4.4, Data Sequencing AVP.
 */
enum l2tp_api_session_seqmode {
    L2TP_API_SESSION_SEQ_NONE   = L2TP_SEQ_NONE,
    L2TP_API_SESSION_SEQ_IP     = L2TP_SEQ_IP,
    L2TP_API_SESSION_SEQ_ALL    = L2TP_SEQ_ALL,
};

/**
 * Session L2-specific sublayer type
 * Ref: RFC2931 section 5.4.4, L2-Specific Sublayer AVP.
 */
enum l2tp_api_session_l2spec_type {
    L2TP_API_SESSION_L2SPECTYPE_NONE        = L2TP_L2SPECTYPE_NONE,
    L2TP_API_SESSION_L2SPECTYPE_DEFAULT     = L2TP_L2SPECTYPE_DEFAULT,
};

#endif /* L2TP_KAPI_H */

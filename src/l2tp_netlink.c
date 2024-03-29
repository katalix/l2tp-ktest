/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * file: l2tp_netlink.c
 *
 * L2TP-specific netlink wrappers using libnl.
 */
#include <inttypes.h>
#include <sys/types.h>

#include <libmnl/libmnl.h>
#include <linux/l2tp.h>
#include <linux/genetlink.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <string.h>

#include "l2tp_netlink.h"
#include "util.h"

static pthread_mutex_t l2tp_nl_lock = PTHREAD_MUTEX_INITIALIZER;
static struct mnl_socket *l2tp_nl_sock;
static uint16_t l2tp_nl_family = 0;
static int l2tp_nl_seq;
static unsigned int l2tp_nl_portid;

static int do_nl_send(struct mnl_socket *sk, struct nlmsghdr *nlh)
{
    int ret;
    char buf[1024];

    if (!sk || !nlh) return -EINVAL;

    pthread_mutex_lock(&l2tp_nl_lock);
    if (opt_debug) mnl_nlmsg_fprintf(stdout, nlh, nlh->nlmsg_len, 0);
    if (mnl_socket_sendto(sk, nlh, nlh->nlmsg_len) < 0) {
        ret = -errno;
        goto out;
    }
    ret = mnl_socket_recvfrom(sk, buf, sizeof(buf));
    if (ret > 0) {
        struct nlmsghdr *rnlh = (void *)&buf[0];
        if (opt_debug) mnl_nlmsg_fprintf(stdout, rnlh, ret, 0);
        ret = mnl_cb_run(rnlh, ret, rnlh->nlmsg_seq, 0, NULL, NULL);
        if (ret < 0 && errno) {
            ret = -errno;
        }
    }
  out:
    pthread_mutex_unlock(&l2tp_nl_lock);
    if (ret > 0) ret = 0;
    return ret;
}

static int do_nl_send_recv(struct mnl_socket *sk, struct nlmsghdr *nlh, mnl_cb_t cb, void *cb_data)
{
    char buf[1024] = {};
    int ret;

    if (!sk || !nlh || !cb) return -EINVAL;

    pthread_mutex_lock(&l2tp_nl_lock);
    if (opt_debug) mnl_nlmsg_fprintf(stdout, nlh, nlh->nlmsg_len, 0);
    if (mnl_socket_sendto(sk, nlh, nlh->nlmsg_len) < 0) {
        ret = -errno;
        goto out;
    }

    ret = mnl_socket_recvfrom(sk, buf, sizeof(buf));
    if (ret > 0) {
        struct nlmsghdr *rnlh = (void *)&buf[0];
        int nl_len = ret;
        while (mnl_nlmsg_ok(rnlh, nl_len)) {
            if (opt_debug) mnl_nlmsg_fprintf(stdout, rnlh, rnlh->nlmsg_len, 0);
            if (rnlh->nlmsg_type == l2tp_nl_family) {
                /* We can't use mnl_cb_run with GENL, so call the user's callback directly. */
                if (nlh->nlmsg_seq == rnlh->nlmsg_seq && rnlh->nlmsg_pid == l2tp_nl_portid) {
                    ret = cb(rnlh, cb_data);
                    if (ret < 0 && errno) {
                        ret = -errno;
                    }
                } else {
                    ret = -EPROTO;
                }
            } else {
                /* in case NLF_F_ACK is requested with a Get request */
                ret = mnl_cb_run(rnlh, ret, rnlh->nlmsg_seq, 0, NULL, NULL);
                if (ret < 0 && errno) {
                    ret = -errno;
                }
            }
            if (ret <= MNL_CB_STOP) {
                goto out;
            }
            rnlh = mnl_nlmsg_next(rnlh, &nl_len);
        }
    }

  out:
    pthread_mutex_unlock(&l2tp_nl_lock);
    if (ret > 0) ret = 0;
    return ret;
}

int l2tp_nl_tunnel_create(uint32_t tunnel_id, uint32_t peer_tunnel_id, int fd, struct l2tp_tunnel_nl_config *cfg)
{
    int ret;
    struct nlmsghdr *nlh;
    struct genlmsghdr *gnlh;
    char buf[1024];

    if (!cfg) return -EINVAL;

    if (l2tp_nl_family == 0) return -EPROTONOSUPPORT;

    dbg("%s: tid %" PRIu32 ", ptid %" PRIu32 "\n", __func__, tunnel_id, peer_tunnel_id);

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = l2tp_nl_family;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = l2tp_nl_seq++;
    nlh->nlmsg_pid = l2tp_nl_portid;

    gnlh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gnlh));
    gnlh->cmd = L2TP_CMD_TUNNEL_CREATE;
    gnlh->version = L2TP_GENL_VERSION;
    gnlh->reserved = 0;

    /* An fd < 0 implies creation of an unmanaged tunnel: omit the L2TP_ATTR_FD
     * attribute in this case so that the kernel creates its own socket.
     */
    dbg("%s: fd %d, tid %u, ptid %u, ver %d, encap %d, dbg 0x%x\n",
            __func__,
            fd,
            tunnel_id,
            peer_tunnel_id,
            cfg->proto_version,
            cfg->encap_type,
            cfg->debug);
    if (fd >= 0) {
        mnl_attr_put_u32(nlh, L2TP_ATTR_FD, fd);
    } else {
        {
            int ipattr = cfg->local_addr.ss_family == AF_INET ? L2TP_ATTR_IP_SADDR : L2TP_ATTR_IP6_SADDR;
            size_t addrlen;
            void *addr = ss_get_addr(&cfg->local_addr, &addrlen);
            mnl_attr_put(nlh, ipattr, addrlen, addr);
            mnl_attr_put_u16(nlh, L2TP_ATTR_UDP_SPORT, ss_get_port(&cfg->local_addr));
        }
        {
            int ipattr = cfg->peer_addr.ss_family == AF_INET ? L2TP_ATTR_IP_DADDR : L2TP_ATTR_IP6_DADDR;
            size_t addrlen;
            void *addr = ss_get_addr(&cfg->peer_addr, &addrlen);
            mnl_attr_put(nlh, ipattr, addrlen, addr);
            mnl_attr_put_u16(nlh, L2TP_ATTR_UDP_DPORT, ss_get_port(&cfg->peer_addr));
        }
    }
    mnl_attr_put_u32(nlh, L2TP_ATTR_CONN_ID, tunnel_id);
    mnl_attr_put_u32(nlh, L2TP_ATTR_PEER_CONN_ID, peer_tunnel_id);
    mnl_attr_put_u8(nlh, L2TP_ATTR_PROTO_VERSION, cfg->proto_version);
    mnl_attr_put_u16(nlh, L2TP_ATTR_ENCAP_TYPE, cfg->encap_type);
    mnl_attr_put_u32(nlh, L2TP_ATTR_DEBUG, cfg->debug);
    ret = do_nl_send(l2tp_nl_sock, nlh);

    dbg("%s: ret %d\n", __func__, ret);

    return ret;
}

int l2tp_nl_tunnel_delete(uint32_t tunnel_id)
{
    struct nlmsghdr *nlh;
    struct genlmsghdr *gnlh;
    char buf[1024] = {};
    int ret;

    if (l2tp_nl_family == 0) return -EPROTONOSUPPORT;

    dbg("%s: tid %" PRIu32 "\n", __func__, tunnel_id);

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = l2tp_nl_family;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = l2tp_nl_seq++;
    nlh->nlmsg_pid = l2tp_nl_portid;

    gnlh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gnlh));
    gnlh->cmd = L2TP_CMD_TUNNEL_DELETE;
    gnlh->version = L2TP_GENL_VERSION;
    gnlh->reserved = 0;

    mnl_attr_put_u32(nlh, L2TP_ATTR_CONN_ID, tunnel_id);

    ret = do_nl_send(l2tp_nl_sock, nlh);

    dbg("%s: ret %d\n", __func__, ret);

    return ret;
}

int l2tp_nl_tunnel_modify(uint32_t tunnel_id, uint32_t debug)
{
    struct nlmsghdr *nlh;
    struct genlmsghdr *gnlh;
    char buf[1024] = {};
    int ret;

    if (l2tp_nl_family == 0) return -EPROTONOSUPPORT;

    dbg("%s: tid %" PRIu32 "\n", __func__, tunnel_id);

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = l2tp_nl_family;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = l2tp_nl_seq++;
    nlh->nlmsg_pid = l2tp_nl_portid;

    gnlh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gnlh));
    gnlh->cmd = L2TP_CMD_TUNNEL_MODIFY;
    gnlh->version = L2TP_GENL_VERSION;
    gnlh->reserved = 0;

    mnl_attr_put_u32(nlh, L2TP_ATTR_CONN_ID, tunnel_id);
    mnl_attr_put_u32(nlh, L2TP_ATTR_DEBUG, debug);

    ret = do_nl_send(l2tp_nl_sock, nlh);

    dbg("%s: ret %d\n", __func__, ret);

    return ret;
}

static int nl_tunl_get_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, L2TP_ATTR_MAX) < 0)
        return MNL_CB_OK;

    tb[type] = attr;
    return MNL_CB_OK;
}

static int nl_tunl_get_stats_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, L2TP_ATTR_STATS_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case L2TP_ATTR_TX_PACKETS:
    case L2TP_ATTR_TX_BYTES:
    case L2TP_ATTR_TX_ERRORS:
    case L2TP_ATTR_RX_PACKETS:
    case L2TP_ATTR_RX_BYTES:
    case L2TP_ATTR_RX_ERRORS:
    case L2TP_ATTR_RX_SEQ_DISCARDS:
    case L2TP_ATTR_RX_OOS_PACKETS:
        if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) return MNL_CB_ERROR;
        break;
    default:
        return MNL_CB_OK;
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

int nl_tunl_get_cb(const struct nlmsghdr *nlh, void *data)
{
    assert(nlh);
    assert(data);

    struct nlattr *tb[L2TP_ATTR_MAX + 1] = {};
    struct l2tp_tunnel_stats *stats = data;

    if (MNL_CB_ERROR == mnl_attr_parse(nlh, sizeof(struct genlmsghdr), nl_tunl_get_attr_cb, tb)) {
        return MNL_CB_ERROR;
    }

    if (tb[L2TP_ATTR_STATS]) {
        struct nlattr *tbs[L2TP_ATTR_STATS_MAX + 1] = {};

        if (MNL_CB_ERROR == mnl_attr_parse_nested(tb[L2TP_ATTR_STATS], nl_tunl_get_stats_attr_cb, tbs)) {
            return MNL_CB_ERROR;
        }

        if (tbs[L2TP_ATTR_TX_PACKETS])
            stats->data_tx_packets = mnl_attr_get_u64(tbs[L2TP_ATTR_TX_PACKETS]);
        if (tbs[L2TP_ATTR_TX_BYTES])
            stats->data_tx_bytes = mnl_attr_get_u64(tbs[L2TP_ATTR_TX_BYTES]);
        if (tbs[L2TP_ATTR_TX_ERRORS])
            stats->data_tx_errors = mnl_attr_get_u64(tbs[L2TP_ATTR_TX_ERRORS]);
        if (tbs[L2TP_ATTR_RX_PACKETS])
            stats->data_rx_packets = mnl_attr_get_u64(tbs[L2TP_ATTR_RX_PACKETS]);
        if (tbs[L2TP_ATTR_RX_BYTES])
            stats->data_rx_bytes = mnl_attr_get_u64(tbs[L2TP_ATTR_RX_BYTES]);
        if (tbs[L2TP_ATTR_RX_ERRORS])
            stats->data_rx_errors = mnl_attr_get_u64(tbs[L2TP_ATTR_RX_ERRORS]);
        if (tbs[L2TP_ATTR_RX_SEQ_DISCARDS])
            stats->data_rx_oos_discards = mnl_attr_get_u64(tbs[L2TP_ATTR_RX_SEQ_DISCARDS]);
        if (tbs[L2TP_ATTR_RX_OOS_PACKETS])
            stats->data_rx_oos_packets = mnl_attr_get_u64(tbs[L2TP_ATTR_RX_OOS_PACKETS]);
    }
    return MNL_CB_OK;
}

int l2tp_nl_tunnel_get(uint32_t tunnel_id, struct l2tp_tunnel_stats *stats)
{
    struct nlmsghdr *nlh;
    struct genlmsghdr *gnlh;
    char buf[1024] = {};
    int ret;

    if (l2tp_nl_family == 0) return -EPROTONOSUPPORT;

    if (!stats) return -EINVAL;

    dbg("%s: tid %" PRIu32 "\n", __func__, tunnel_id);

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = l2tp_nl_family;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = l2tp_nl_seq++;
    nlh->nlmsg_pid = l2tp_nl_portid;

    gnlh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gnlh));
    gnlh->cmd = L2TP_CMD_TUNNEL_GET;
    gnlh->version = L2TP_GENL_VERSION;
    gnlh->reserved = 0;

    mnl_attr_put_u32(nlh, L2TP_ATTR_CONN_ID, tunnel_id);

    ret = do_nl_send_recv(l2tp_nl_sock, nlh, nl_tunl_get_cb, stats);

    dbg("%s: ret %d\n", __func__, ret);

    return ret;
}

/* FIXME: keep in sync with upstream, retire once available upstream! */
#define L2TP_ATTR_PPPOE_SESSION_ID L2TP_ATTR_PAD+1
#define L2TP_ATTR_PPPOE_PEER_MAC_ADDR L2TP_ATTR_PAD+2

int l2tp_nl_session_create(uint32_t tunnel_id, uint32_t peer_tunnel_id, uint32_t session_id,
        uint32_t peer_session_id, struct l2tp_session_nl_config *cfg)
{
    struct nlmsghdr *nlh;
    struct genlmsghdr *gnlh;
    char buf[1024] = {};
    int ret;

    if (l2tp_nl_family == 0) return -EPROTONOSUPPORT;

    if (!cfg) return -EINVAL;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = l2tp_nl_family;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = l2tp_nl_seq++;
    nlh->nlmsg_pid = l2tp_nl_portid;

    gnlh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gnlh));
    gnlh->cmd = L2TP_CMD_SESSION_CREATE;
    gnlh->version = L2TP_GENL_VERSION;
    gnlh->reserved = 0;

    dbg("%s: tid %" PRIu32 ", ptid %" PRIu32 ", sid %" PRIu32 ", psid %" PRIu32 "\n",
            __func__,
            tunnel_id,
            peer_tunnel_id,
            session_id,
            peer_session_id);

    mnl_attr_put_u32(nlh, L2TP_ATTR_CONN_ID, tunnel_id);
    mnl_attr_put_u32(nlh, L2TP_ATTR_PEER_CONN_ID, peer_tunnel_id);
    mnl_attr_put_u32(nlh, L2TP_ATTR_SESSION_ID, session_id);
    mnl_attr_put_u32(nlh, L2TP_ATTR_PEER_SESSION_ID, peer_session_id);
    mnl_attr_put_u32(nlh, L2TP_ATTR_DEBUG, cfg->debug);
    mnl_attr_put_u16(nlh, L2TP_ATTR_PW_TYPE, cfg->pw_type);
    if (cfg->pw_type == L2TP_API_SESSION_PW_TYPE_ETH_VLAN) {
        mnl_attr_put_u16(nlh, L2TP_ATTR_VLAN_ID, cfg->vlan_id);
    }
    mnl_attr_put_u16(nlh, L2TP_ATTR_MTU, cfg->mtu);
    if (cfg->recv_seq) {
        mnl_attr_put_u8(nlh, L2TP_ATTR_RECV_SEQ, cfg->recv_seq);
    }
    if (cfg->send_seq) {
        mnl_attr_put_u8(nlh, L2TP_ATTR_SEND_SEQ, cfg->send_seq);
    }
    if (cfg->lns_mode) {
        mnl_attr_put_u8(nlh, L2TP_ATTR_LNS_MODE, cfg->lns_mode);
    }
    if (cfg->seqmode) {
        mnl_attr_put_u8(nlh, L2TP_ATTR_DATA_SEQ, cfg->seqmode);
    }
    if (cfg->reorder_timeout) {
        mnl_attr_put_u64(nlh, L2TP_ATTR_RECV_TIMEOUT, cfg->reorder_timeout);
    }
    if (cfg->cookie_len) {
        mnl_attr_put(nlh, L2TP_ATTR_COOKIE, cfg->cookie_len, &cfg->cookie);
    }
    if (cfg->peer_cookie_len) {
        mnl_attr_put(nlh, L2TP_ATTR_PEER_COOKIE, cfg->peer_cookie_len, &cfg->peer_cookie);
    }
    if (cfg->vlan_id) {
        mnl_attr_put_u16(nlh, L2TP_ATTR_VLAN_ID, cfg->vlan_id);
    }
    if (cfg->ifname && cfg->ifname[0]) {
        mnl_attr_put_strz(nlh, L2TP_ATTR_IFNAME, cfg->ifname);
    }
    mnl_attr_put_u8(nlh, L2TP_ATTR_L2SPEC_TYPE, cfg->l2spec_type);
    if (cfg->l2spec_type == L2TP_API_SESSION_L2SPECTYPE_NONE) {
        mnl_attr_put_u8(nlh, L2TP_ATTR_L2SPEC_LEN, 0);
    } else if (cfg->l2spec_type == L2TP_API_SESSION_L2SPECTYPE_DEFAULT) {
        mnl_attr_put_u8(nlh, L2TP_ATTR_L2SPEC_LEN, 4);
    }
    if (cfg->pppoe_session_id) {
        mnl_attr_put_u16(nlh, L2TP_ATTR_PPPOE_SESSION_ID, cfg->pppoe_session_id);
        mnl_attr_put(nlh, L2TP_ATTR_PPPOE_PEER_MAC_ADDR, 6, cfg->pppoe_peer_mac);
    }
    /* FIXME - configure l2spec_type tx/rx values separately here
     * when support is available in the kernel.
     */

    ret = do_nl_send(l2tp_nl_sock, nlh);

    dbg("%s: ret %d\n", __func__, ret);

    return ret;
}

int l2tp_nl_session_delete(uint32_t tunnel_id, uint32_t session_id)
{
    struct nlmsghdr *nlh;
    struct genlmsghdr *gnlh;
    char buf[1024] = {};
    int ret;

    if (l2tp_nl_family == 0) return -EPROTONOSUPPORT;

    dbg("%s: tid %" PRIu32 ", sid %" PRIu32 "\n", __func__, tunnel_id, session_id);

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = l2tp_nl_family;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = l2tp_nl_seq++;
    nlh->nlmsg_pid = l2tp_nl_portid;

    gnlh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gnlh));
    gnlh->cmd = L2TP_CMD_SESSION_DELETE;
    gnlh->version = L2TP_GENL_VERSION;
    gnlh->reserved = 0;

    mnl_attr_put_u32(nlh, L2TP_ATTR_CONN_ID, tunnel_id);
    mnl_attr_put_u32(nlh, L2TP_ATTR_SESSION_ID, session_id);

    ret = do_nl_send(l2tp_nl_sock, nlh);

    dbg("%s: ret %d\n", __func__, ret);

    return ret;
}

int l2tp_nl_session_modify(uint32_t tunnel_id, uint32_t session_id, uint32_t debug)
{
    struct nlmsghdr *nlh;
    struct genlmsghdr *gnlh;
    char buf[1024] = {};
    int ret;

    if (l2tp_nl_family == 0) return -EPROTONOSUPPORT;

    dbg("%s: tid %" PRIu32 ", sid %" PRIu32 "\n", __func__, tunnel_id, session_id);

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = l2tp_nl_family;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = l2tp_nl_seq++;
    nlh->nlmsg_pid = l2tp_nl_portid;

    gnlh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gnlh));
    gnlh->cmd = L2TP_CMD_SESSION_MODIFY;
    gnlh->version = L2TP_GENL_VERSION;
    gnlh->reserved = 0;

    mnl_attr_put_u32(nlh, L2TP_ATTR_CONN_ID, tunnel_id);
    mnl_attr_put_u32(nlh, L2TP_ATTR_SESSION_ID, session_id);
    mnl_attr_put_u32(nlh, L2TP_ATTR_DEBUG, debug);

    ret = do_nl_send(l2tp_nl_sock, nlh);

    dbg("%s: ret %d\n", __func__, ret);

    return ret;
}

static int nl_sess_get_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, L2TP_ATTR_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case L2TP_ATTR_IFNAME:
        if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
            return MNL_CB_ERROR;
        }
        break;
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

static int nl_sess_get_stats_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, L2TP_ATTR_STATS_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case L2TP_ATTR_TX_PACKETS:
    case L2TP_ATTR_TX_BYTES:
    case L2TP_ATTR_TX_ERRORS:
    case L2TP_ATTR_RX_PACKETS:
    case L2TP_ATTR_RX_BYTES:
    case L2TP_ATTR_RX_ERRORS:
    case L2TP_ATTR_RX_SEQ_DISCARDS:
    case L2TP_ATTR_RX_OOS_PACKETS:
        if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) return MNL_CB_ERROR;
        break;
    default:
        return MNL_CB_OK;
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

static int nl_sess_get_cb(const struct nlmsghdr *nlh, void *dptr)
{
    assert(nlh);
    assert(dptr);

    struct nlattr *tb[L2TP_ATTR_MAX + 1] = {};
    struct l2tp_session_data *data = dptr;
    int ret;

    ret = mnl_attr_parse(nlh, sizeof(struct genlmsghdr), nl_sess_get_attr_cb, tb);
    if (ret < 0) {
        return MNL_CB_ERROR;
    }

    if (tb[L2TP_ATTR_IFNAME]) {
        data->ifname = strdup(mnl_attr_get_str(tb[L2TP_ATTR_IFNAME]));
    }
    if (tb[L2TP_ATTR_STATS]) {
        struct nlattr *tbs[L2TP_ATTR_STATS_MAX + 1] = {};
        struct l2tp_session_stats *stats = &data->stats;

        ret = mnl_attr_parse_nested(tb[L2TP_ATTR_STATS], nl_sess_get_stats_attr_cb, tbs);
        if (ret < 0) {
            return MNL_CB_ERROR;
        }
        if (tbs[L2TP_ATTR_TX_PACKETS])
            stats->data_tx_packets = mnl_attr_get_u64(tbs[L2TP_ATTR_TX_PACKETS]);
        if (tbs[L2TP_ATTR_TX_BYTES])
            stats->data_tx_bytes = mnl_attr_get_u64(tbs[L2TP_ATTR_TX_BYTES]);
        if (tbs[L2TP_ATTR_TX_ERRORS])
            stats->data_tx_errors = mnl_attr_get_u64(tbs[L2TP_ATTR_TX_ERRORS]);
        if (tbs[L2TP_ATTR_RX_PACKETS])
            stats->data_rx_packets = mnl_attr_get_u64(tbs[L2TP_ATTR_RX_PACKETS]);
        if (tbs[L2TP_ATTR_RX_BYTES])
            stats->data_rx_bytes = mnl_attr_get_u64(tbs[L2TP_ATTR_RX_BYTES]);
        if (tbs[L2TP_ATTR_RX_ERRORS])
            stats->data_rx_errors = mnl_attr_get_u64(tbs[L2TP_ATTR_RX_ERRORS]);
        if (tbs[L2TP_ATTR_RX_SEQ_DISCARDS])
            stats->data_rx_oos_discards = mnl_attr_get_u64(tbs[L2TP_ATTR_RX_SEQ_DISCARDS]);
        if (tbs[L2TP_ATTR_RX_OOS_PACKETS])
            stats->data_rx_oos_packets = mnl_attr_get_u64(tbs[L2TP_ATTR_RX_OOS_PACKETS]);
    }
    return MNL_CB_OK;
}

int l2tp_nl_session_get(uint32_t tunnel_id, uint32_t session_id, struct l2tp_session_data *data)
{
    struct nlmsghdr *nlh;
    struct genlmsghdr *gnlh;
    char buf[1024] = {};
    int ret;

    if (l2tp_nl_family == 0) return -EPROTONOSUPPORT;

    if (!data) return -EINVAL;

    dbg("%s: tid %" PRIu32 ", sid %" PRIu32 "\n", __func__, tunnel_id, session_id);

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = l2tp_nl_family;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = l2tp_nl_seq++;
    nlh->nlmsg_pid = l2tp_nl_portid;

    gnlh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gnlh));
    gnlh->cmd = L2TP_CMD_SESSION_GET;
    gnlh->version = L2TP_GENL_VERSION;
    gnlh->reserved = 0;

    mnl_attr_put_u32(nlh, L2TP_ATTR_CONN_ID, tunnel_id);
    mnl_attr_put_u32(nlh, L2TP_ATTR_SESSION_ID, session_id);

    ret = do_nl_send_recv(l2tp_nl_sock, nlh, nl_sess_get_cb, data);
    if (ret == 0) {
        dbg("%s: ifname %s\n", __func__, data->ifname ? data->ifname : "unset");
        dbg("%s: stats: tx: %" PRIu64 "/%" PRIu64 "/%" PRIu64" pkt/bytes/err\n",
                __func__, data->stats.data_tx_packets, data->stats.data_tx_bytes, data->stats.data_tx_errors);
        dbg("%s: stats: rx: %" PRIu64 "/%" PRIu64 "/%" PRIu64" pkt/bytes/err\n",
                __func__, data->stats.data_rx_packets, data->stats.data_rx_bytes, data->stats.data_rx_errors);
        dbg("%s: stats: rx: %" PRIu64 "/%" PRIu64 " seq_discard/oos\n",
                __func__, data->stats.data_rx_oos_discards, data->stats.data_rx_oos_packets);
    }
    dbg("%s: ret %d\n", __func__, ret);

    return ret;
}

static int genl_skt_data_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
    case CTRL_ATTR_FAMILY_NAME:
        if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
            return MNL_CB_ERROR;
        }
        break;
    case CTRL_ATTR_FAMILY_ID:
        if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
            return MNL_CB_ERROR;
        }
        break;
    case CTRL_ATTR_VERSION:
    case CTRL_ATTR_HDRSIZE:
    case CTRL_ATTR_MAXATTR:
        if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
            return MNL_CB_ERROR;
        }
        break;
    case CTRL_ATTR_OPS:
    case CTRL_ATTR_MCAST_GROUPS:
        if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
            return MNL_CB_ERROR;
        }
        break;
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

static int genl_skt_data_cb(const struct nlmsghdr *nlh, void *data)
{
    struct nlattr *tb[CTRL_ATTR_MAX+1] = {};
    uint16_t *id = data;

    mnl_attr_parse(nlh, sizeof(struct genlmsghdr), genl_skt_data_attr_cb, tb);
    if (tb[CTRL_ATTR_FAMILY_ID]) {
        *id = mnl_attr_get_u16(tb[CTRL_ATTR_FAMILY_ID]);
    }
    return MNL_CB_OK;
}

static int genl_get_skt_id(struct mnl_socket *sock,
                           int version,
                           const char *family_name,
                           uint16_t *id)
{
    assert(sock);
    assert(version);
    assert(family_name);
    assert(id);

    struct genlmsghdr *genl;
    uint8_t msg[1024] = {};
    uint8_t hdr[128] = {};
    struct nlmsghdr *nlh;
    int ret;

    nlh = mnl_nlmsg_put_header(hdr);
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = l2tp_nl_portid;

    genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
    genl->cmd = CTRL_CMD_GETFAMILY;
    genl->version = version;

    mnl_attr_put_u16(nlh, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL);
    mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, family_name);

    if (opt_debug) mnl_nlmsg_fprintf(stdout, nlh, nlh->nlmsg_len, 0);
    if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) return -errno;
    ret = mnl_socket_recvfrom(sock, msg, sizeof(msg));
    if (ret > 0) {
        nlh = (void *) &msg[0];
        if (opt_debug) mnl_nlmsg_fprintf(stdout, nlh, ret, 0);
        ret = mnl_cb_run(nlh, ret, nlh->nlmsg_seq, 0, genl_skt_data_cb, id);
    }
    if (ret == -1) return -errno;
    return 0;
}


int l2tp_nl_init(void)
{
    int ret = 0;
    uint16_t id = 0;

    if (l2tp_nl_sock) return -EALREADY;

    l2tp_nl_sock = mnl_socket_open(NETLINK_GENERIC);
    if (!l2tp_nl_sock)
        return -errno;

    ret = mnl_socket_bind(l2tp_nl_sock, 0, MNL_SOCKET_AUTOPID);
    if (ret) {
        mnl_socket_close(l2tp_nl_sock);
        return -errno;
    }

    l2tp_nl_portid = mnl_socket_get_portid(l2tp_nl_sock);

    /* Send command to get the socket's id */
    ret = genl_get_skt_id(l2tp_nl_sock, L2TP_GENL_VERSION, L2TP_GENL_NAME, &id);
    if (ret || !id) {
        mnl_socket_close(l2tp_nl_sock);
        return -EPROTONOSUPPORT;
    }

    /* Just used ID 1 for obtaining the socket ID */
    l2tp_nl_seq = 2;
    l2tp_nl_family = id;

    if (ret) l2tp_nl_cleanup();
    return ret;
}

void l2tp_nl_cleanup(void)
{
    if (l2tp_nl_sock) {
        mnl_socket_close(l2tp_nl_sock);
        l2tp_nl_sock = NULL;
    }
    if (l2tp_nl_family > 0) l2tp_nl_family = -1;
}

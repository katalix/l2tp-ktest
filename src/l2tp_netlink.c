/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * file: l2tp_netlink.c
 *
 * L2TP-specific netlink wrappers using libnl.
 */
#include <inttypes.h>
#include <sys/types.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/route/link.h>
#include <libmnl/libmnl.h>
#include <linux/l2tp.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

#include "l2tp_netlink.h"
#include "util.h"

/* Temporary define to be removed when mnl port is complete */
#ifndef MNL_PORT
#define MNL_PORT 1
#endif

#ifdef MNL_PORT
/* Timeout for netlink operations.
 * It's possible in some circumstances for a netlink request to receive
 * no response from the kernel.  Rather than having callers hang forever
 * if this occurs, we have a timeout for waiting from responses from the
 * kernel.
 */
#define GENL_TIMEOUT_DFLT 2000
#endif

static pthread_mutex_t l2tp_nl_lock = PTHREAD_MUTEX_INITIALIZER;
#ifdef MNL_PORT
static struct nl_sock *l2tp_nl_sock;
static int l2tp_nl_family = -1;
#endif
static struct mnl_socket *l2tp_nl_sock2;
static uint16_t l2tp_nl_family2 = 0;
static int l2tp_nl_seq;
static unsigned int l2tp_nl_portid;

static int nlerr_to_errno(int e)
{
    e = abs(e);
    switch (e) {
        case NLE_BAD_SOCK:      return EBADF;
        case NLE_EXIST:         return EEXIST;
        case NLE_NOADDR:        return EADDRNOTAVAIL;
        case NLE_OBJ_NOTFOUND:  return ENOENT;
        case NLE_INTR:          return EINTR;
        case NLE_AGAIN:         return EAGAIN;
        case NLE_NOACCESS:      return EACCES;
        case NLE_NOMEM:         return ENOMEM;
        case NLE_AF_NOSUPPORT:  return EAFNOSUPPORT;
        case NLE_PROTO_MISMATCH: return EPROTONOSUPPORT;
        case NLE_OPNOTSUPP:     return EOPNOTSUPP;
        case NLE_PERM:          return EPERM;
        case NLE_BUSY:          return EBUSY;
        case NLE_RANGE:         return ERANGE;
        case NLE_NODEV:         return ENODEV;
        case NLE_INVAL: /* fall through */
        default:                return EINVAL;
    }
    return EINVAL;
}

#define my_nl_exit_log(_ret) do { \
    if (_ret) { \
        err("%s: ret %d %s\n", __func__, ret, nl_geterror(_ret)); \
        _ret = -nlerr_to_errno(_ret); \
    } else dbg("%s: ret 0\n", __func__); \
} while(0)

#ifdef MNL_PORT
static int do_nl_send(struct nl_sock *sk, struct nl_msg *msg)
{
    int ret;

    if (!sk || !msg) return -EINVAL;

    pthread_mutex_lock(&l2tp_nl_lock);
    ret = nl_send_auto_complete(sk, msg);
    if (ret > 0) {
        ret = nl_wait_for_ack(sk);
        if (ret > 0) ret = 0; // success
    }
    pthread_mutex_unlock(&l2tp_nl_lock);

    return ret;
}
#endif

__attribute__((unused))
static int do_nl_send2(struct mnl_socket *sk, struct nlmsghdr *nlh)
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

#ifdef MNL_PORT
static int do_nl_send_recv(struct nl_sock *sk, struct nl_msg *msg, struct nl_cb *cb)
{
    int ret;

    if (!sk || !msg || !cb) return -EINVAL;

    pthread_mutex_lock(&l2tp_nl_lock);
    ret = nl_send_auto_complete(sk, msg);
    if (ret > 0) {
        /* Wait for a response for a bounded time.  If no response arrives
         * in that time, return early.
         * This approach doesn't account for the possibiliy of the usleep()
         * call being interrupted.
         */
        int nsleep = 0, tsleep = 100;
again:
        ret = nl_recvmsgs(sk, cb);
        if (ret == -NLE_AGAIN) {
            if (nsleep*tsleep > GENL_TIMEOUT_DFLT) {
                ret = -ETIMEDOUT;
            } else {
                usleep(tsleep);
                nsleep++;
                goto again;
            }
        }
    }
    if (ret >= 0) {
        ret = nl_wait_for_ack(sk);
        if (ret > 0) ret = 0; // success
    }
    pthread_mutex_unlock(&l2tp_nl_lock);

    return ret;
}
#endif

__attribute__((unused))
static int do_nl_send_recv2(struct mnl_socket *sk, struct nlmsghdr *nlh, mnl_cb_t cb, void *cb_data)
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

    if (l2tp_nl_family2 == 0) return -EPROTONOSUPPORT;

    dbg("%s: tid %" PRIu32 ", ptid %" PRIu32 "\n", __func__, tunnel_id, peer_tunnel_id);

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = l2tp_nl_family2;
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
    ret = do_nl_send2(l2tp_nl_sock2, nlh);

    my_nl_exit_log(ret);

    return ret;
}

int l2tp_nl_tunnel_delete(uint32_t tunnel_id)
{
    struct nlmsghdr *nlh;
    struct genlmsghdr *gnlh;
    char buf[1024] = {};
    int ret;

    if (l2tp_nl_family2 == 0) return -EPROTONOSUPPORT;

    dbg("%s: tid %" PRIu32 "\n", __func__, tunnel_id);

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = l2tp_nl_family2;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = l2tp_nl_seq++;
    nlh->nlmsg_pid = l2tp_nl_portid;

    gnlh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gnlh));
    gnlh->cmd = L2TP_CMD_TUNNEL_DELETE;
    gnlh->version = L2TP_GENL_VERSION;
    gnlh->reserved = 0;

    mnl_attr_put_u32(nlh, L2TP_ATTR_CONN_ID, tunnel_id);

    ret = do_nl_send2(l2tp_nl_sock2, nlh);

    my_nl_exit_log(ret);

    return ret;
}

int l2tp_nl_tunnel_modify(uint32_t tunnel_id, uint32_t debug)
{
    struct nl_msg *msg;
    int ret;

    if (l2tp_nl_family <= 0) return -EPROTONOSUPPORT;

    msg = nlmsg_alloc();
    if (!msg) return -ENOMEM;

    dbg("%s: tid %" PRIu32 "\n", __func__, tunnel_id);

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, l2tp_nl_family, 0, NLM_F_REQUEST,
            L2TP_CMD_TUNNEL_MODIFY, L2TP_GENL_VERSION);

    nla_put_u32(msg, L2TP_ATTR_CONN_ID, tunnel_id);
    nla_put_u32(msg, L2TP_ATTR_DEBUG, debug);

    ret = do_nl_send(l2tp_nl_sock, msg);
    nlmsg_free(msg);

    my_nl_exit_log(ret);

    return ret;
}

static int l2tp_nl_tunnel_get_response(struct nl_msg *msg, void *arg)
{
    struct l2tp_tunnel_stats *stats = arg;
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct nlattr *attrs[L2TP_ATTR_MAX + 1];
    struct nlattr *nla_stats;

    /* Validate message and parse attributes */
    genlmsg_parse(hdr, 0, attrs, L2TP_ATTR_MAX, NULL);
    if (hdr->nlmsg_type == NLMSG_ERROR) return -EBADMSG;

    nla_stats = attrs[L2TP_ATTR_STATS];
    if (nla_stats) {
        struct nlattr *tb[L2TP_ATTR_STATS_MAX + 1];
        int ret;

        ret = nla_parse_nested(tb, L2TP_ATTR_STATS_MAX, nla_stats, NULL);
        if (ret < 0) return ret;

        if (tb[L2TP_ATTR_TX_PACKETS])
            stats->data_tx_packets = nla_get_u64(tb[L2TP_ATTR_TX_PACKETS]);
        if (tb[L2TP_ATTR_TX_BYTES])
            stats->data_tx_bytes = nla_get_u64(tb[L2TP_ATTR_TX_BYTES]);
        if (tb[L2TP_ATTR_TX_ERRORS])
            stats->data_tx_errors = nla_get_u64(tb[L2TP_ATTR_TX_ERRORS]);
        if (tb[L2TP_ATTR_RX_PACKETS])
            stats->data_rx_packets = nla_get_u64(tb[L2TP_ATTR_RX_PACKETS]);
        if (tb[L2TP_ATTR_RX_BYTES])
            stats->data_rx_bytes = nla_get_u64(tb[L2TP_ATTR_RX_BYTES]);
        if (tb[L2TP_ATTR_RX_ERRORS])
            stats->data_rx_errors = nla_get_u64(tb[L2TP_ATTR_RX_ERRORS]);
        if (tb[L2TP_ATTR_RX_SEQ_DISCARDS])
            stats->data_rx_oos_discards = nla_get_u64(tb[L2TP_ATTR_RX_SEQ_DISCARDS]);
        if (tb[L2TP_ATTR_RX_OOS_PACKETS])
            stats->data_rx_oos_packets = nla_get_u64(tb[L2TP_ATTR_RX_OOS_PACKETS]);
    }

    return 0;
}

int l2tp_nl_tunnel_get(uint32_t tunnel_id, struct l2tp_tunnel_stats *stats)
{
    struct nl_msg *msg;
    struct nl_cb *cb;
    int ret;

    if (!stats) return -EINVAL;

    if (l2tp_nl_family <= 0) return -EPROTONOSUPPORT;

    dbg("%s: tid %" PRIu32 "\n", __func__, tunnel_id);

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) return -ENOMEM;
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, l2tp_nl_tunnel_get_response, stats);

    msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM;
        goto out_put_cb;
    }

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, l2tp_nl_family, 0, NLM_F_REQUEST,
            L2TP_CMD_TUNNEL_GET, L2TP_GENL_VERSION);

    nla_put_u32(msg, L2TP_ATTR_CONN_ID, tunnel_id);

    ret = do_nl_send_recv(l2tp_nl_sock, msg, cb);
    nlmsg_free(msg);
out_put_cb:
    nl_cb_put(cb);
    my_nl_exit_log(ret);
    return ret;
}

/* FIXME: keep in sync with upstream, retire once available upstream! */
#define L2TP_ATTR_PPPOE_SESSION_ID L2TP_ATTR_PAD+1
#define L2TP_ATTR_PPPOE_PEER_MAC_ADDR L2TP_ATTR_PAD+2

int l2tp_nl_session_create(uint32_t tunnel_id, uint32_t peer_tunnel_id, uint32_t session_id,
        uint32_t peer_session_id, struct l2tp_session_nl_config *cfg)
{
    struct nl_msg *msg;
    int ret;

    if (!cfg) return -EINVAL;

    if (l2tp_nl_family <= 0) return -EPROTONOSUPPORT;

    msg = nlmsg_alloc();
    if (!msg) return -ENOMEM;

    dbg("%s: tid %" PRIu32 ", ptid %" PRIu32 ", sid %" PRIu32 ", psid %" PRIu32 "\n",
            __func__,
            tunnel_id,
            peer_tunnel_id,
            session_id,
            peer_session_id);

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, l2tp_nl_family, 0, NLM_F_REQUEST,
            L2TP_CMD_SESSION_CREATE, L2TP_GENL_VERSION);

    nla_put_u32(msg, L2TP_ATTR_CONN_ID, tunnel_id);
    nla_put_u32(msg, L2TP_ATTR_PEER_CONN_ID, peer_tunnel_id);
    nla_put_u32(msg, L2TP_ATTR_SESSION_ID, session_id);
    nla_put_u32(msg, L2TP_ATTR_PEER_SESSION_ID, peer_session_id);
    nla_put_u32(msg, L2TP_ATTR_DEBUG, cfg->debug);
    nla_put_u16(msg, L2TP_ATTR_PW_TYPE, cfg->pw_type);
    if (cfg->pw_type == L2TP_API_SESSION_PW_TYPE_ETH_VLAN) {
        nla_put_u16(msg, L2TP_ATTR_VLAN_ID, cfg->vlan_id);
    }
    nla_put_u16(msg, L2TP_ATTR_MTU, cfg->mtu);
    if (cfg->recv_seq) {
        nla_put_u8(msg, L2TP_ATTR_RECV_SEQ, cfg->recv_seq);
    }
    if (cfg->send_seq) {
        nla_put_u8(msg, L2TP_ATTR_SEND_SEQ, cfg->send_seq);
    }
    if (cfg->lns_mode) {
        nla_put_u8(msg, L2TP_ATTR_LNS_MODE, cfg->lns_mode);
    }
    if (cfg->seqmode) {
        nla_put_u8(msg, L2TP_ATTR_DATA_SEQ, cfg->seqmode);
    }
    if (cfg->reorder_timeout) {
        nla_put_msecs(msg, L2TP_ATTR_RECV_TIMEOUT, cfg->reorder_timeout);
    }
    if (cfg->cookie_len) {
        nla_put(msg, L2TP_ATTR_COOKIE, cfg->cookie_len, &cfg->cookie);
    }
    if (cfg->peer_cookie_len) {
        nla_put(msg, L2TP_ATTR_PEER_COOKIE, cfg->peer_cookie_len, &cfg->peer_cookie);
    }
    if (cfg->vlan_id) {
        nla_put_u16(msg, L2TP_ATTR_VLAN_ID, cfg->vlan_id);
    }
    if (cfg->ifname && cfg->ifname[0]) {
        nla_put_string(msg, L2TP_ATTR_IFNAME, cfg->ifname);
    }
    nla_put_u8(msg, L2TP_ATTR_L2SPEC_TYPE, cfg->l2spec_type);
    if (cfg->l2spec_type == L2TP_API_SESSION_L2SPECTYPE_NONE) {
        nla_put_u8(msg, L2TP_ATTR_L2SPEC_LEN, 0);
    } else if (cfg->l2spec_type == L2TP_API_SESSION_L2SPECTYPE_DEFAULT) {
        nla_put_u8(msg, L2TP_ATTR_L2SPEC_LEN, 4);
    }
    if (cfg->pppoe_session_id) {
        nla_put_u16(msg, L2TP_ATTR_PPPOE_SESSION_ID, cfg->pppoe_session_id);
        nla_put(msg, L2TP_ATTR_PPPOE_PEER_MAC_ADDR, 6, cfg->pppoe_peer_mac);
    }
    /* FIXME - configure l2spec_type tx/rx values separately here
     * when support is available in the kernel.
     */

    ret = do_nl_send(l2tp_nl_sock, msg);
    nlmsg_free(msg);

    my_nl_exit_log(ret);

    return ret;
}

int l2tp_nl_session_delete(uint32_t tunnel_id, uint32_t session_id)
{
    struct nl_msg *msg;
    int ret;

    if (l2tp_nl_family <= 0) return -EPROTONOSUPPORT;

    msg = nlmsg_alloc();
    if (!msg) return -ENOMEM;

    dbg("%s: tid %" PRIu32 ", sid %" PRIu32 "\n", __func__, tunnel_id, session_id);

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, l2tp_nl_family, 0, NLM_F_REQUEST,
            L2TP_CMD_SESSION_DELETE, L2TP_GENL_VERSION);

    nla_put_u32(msg, L2TP_ATTR_CONN_ID, tunnel_id);
    nla_put_u32(msg, L2TP_ATTR_SESSION_ID, session_id);

    ret = do_nl_send(l2tp_nl_sock, msg);
    nlmsg_free(msg);

    my_nl_exit_log(ret);

    return ret;
}

int l2tp_nl_session_modify(uint32_t tunnel_id, uint32_t session_id, uint32_t debug)
{
    struct nl_msg *msg;
    int ret;

    if (l2tp_nl_family <= 0) return -EPROTONOSUPPORT;

    msg = nlmsg_alloc();
    if (!msg) return -ENOMEM;

    dbg("%s: tid %" PRIu32 ", sid %" PRIu32 "\n", __func__, tunnel_id, session_id);

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, l2tp_nl_family, 0, NLM_F_REQUEST,
            L2TP_CMD_SESSION_MODIFY, L2TP_GENL_VERSION);

    nla_put_u32(msg, L2TP_ATTR_CONN_ID, tunnel_id);
    nla_put_u32(msg, L2TP_ATTR_SESSION_ID, session_id);
    nla_put_u32(msg, L2TP_ATTR_DEBUG, debug);

    ret = do_nl_send(l2tp_nl_sock, msg);
    nlmsg_free(msg);

    my_nl_exit_log(ret);

    return ret;
}

static int l2tp_nl_session_get_response(struct nl_msg *msg, void *arg)
{
    struct l2tp_session_data *data = arg;
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct nlattr *attrs[L2TP_ATTR_MAX + 1];
    struct nlattr *nla_stats;

    /* Validate message and parse attributes */
    genlmsg_parse(hdr, 0, attrs, L2TP_ATTR_MAX, NULL);
    if (hdr->nlmsg_type == NLMSG_ERROR) return -EBADMSG;

    if (attrs[L2TP_ATTR_IFNAME]) {
        data->ifname = strdup(nla_get_string(attrs[L2TP_ATTR_IFNAME]));
    }
    nla_stats = attrs[L2TP_ATTR_STATS];
    if (nla_stats) {
        struct nlattr *tb[L2TP_ATTR_STATS_MAX + 1];
        int ret;

        ret = nla_parse_nested(tb, L2TP_ATTR_STATS_MAX, nla_stats, NULL);
        if (ret < 0) return ret;

        if (tb[L2TP_ATTR_TX_PACKETS])
            data->stats.data_tx_packets = nla_get_u64(tb[L2TP_ATTR_TX_PACKETS]);
        if (tb[L2TP_ATTR_TX_BYTES])
            data->stats.data_tx_bytes = nla_get_u64(tb[L2TP_ATTR_TX_BYTES]);
        if (tb[L2TP_ATTR_TX_ERRORS])
            data->stats.data_tx_errors = nla_get_u64(tb[L2TP_ATTR_TX_ERRORS]);
        if (tb[L2TP_ATTR_RX_PACKETS])
            data->stats.data_rx_packets = nla_get_u64(tb[L2TP_ATTR_RX_PACKETS]);
        if (tb[L2TP_ATTR_RX_BYTES])
            data->stats.data_rx_bytes = nla_get_u64(tb[L2TP_ATTR_RX_BYTES]);
        if (tb[L2TP_ATTR_RX_ERRORS])
            data->stats.data_rx_errors = nla_get_u64(tb[L2TP_ATTR_RX_ERRORS]);
        if (tb[L2TP_ATTR_RX_SEQ_DISCARDS])
            data->stats.data_rx_oos_discards = nla_get_u64(tb[L2TP_ATTR_RX_SEQ_DISCARDS]);
        if (tb[L2TP_ATTR_RX_OOS_PACKETS])
            data->stats.data_rx_oos_packets = nla_get_u64(tb[L2TP_ATTR_RX_OOS_PACKETS]);
    }

    return 0;
}

int l2tp_nl_session_get(uint32_t tunnel_id, uint32_t session_id, struct l2tp_session_data *data)
{
    struct nl_msg *msg;
    struct nl_cb *cb;
    int ret;

    if (!data) return -EINVAL;

    if (l2tp_nl_family <= 0) return -EPROTONOSUPPORT;

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) return -ENOMEM;
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, l2tp_nl_session_get_response, data);

    msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM;
        goto out_put_cb;
    }

    dbg("%s: tid %" PRIu32 ", sid %" PRIu32 "\n", __func__, tunnel_id, session_id);

    genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, l2tp_nl_family, 0, NLM_F_REQUEST,
            L2TP_CMD_SESSION_GET, L2TP_GENL_VERSION);

    nla_put_u32(msg, L2TP_ATTR_CONN_ID, tunnel_id);
    nla_put_u32(msg, L2TP_ATTR_SESSION_ID, session_id);

    ret = do_nl_send_recv(l2tp_nl_sock, msg, cb);
    nlmsg_free(msg);
out_put_cb:
    nl_cb_put(cb);
    if (ret == 0) {
        dbg("%s: ifname %s\n", __func__, data->ifname ? data->ifname : "unset");
        dbg("%s: stats: tx: %" PRIu64 "/%" PRIu64 "/%" PRIu64" pkt/bytes/err\n",
                __func__, data->stats.data_tx_packets, data->stats.data_tx_bytes, data->stats.data_tx_errors);
        dbg("%s: stats: rx: %" PRIu64 "/%" PRIu64 "/%" PRIu64" pkt/bytes/err\n",
                __func__, data->stats.data_rx_packets, data->stats.data_rx_bytes, data->stats.data_rx_errors);
        dbg("%s: stats: rx: %" PRIu64 "/%" PRIu64 " seq_discard/oos\n",
                __func__, data->stats.data_rx_oos_discards, data->stats.data_rx_oos_packets);
    }
    my_nl_exit_log(ret);
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

#ifdef MNL_PORT
    if (l2tp_nl_sock) return -EALREADY;

    l2tp_nl_sock = nl_socket_alloc();
    if (!l2tp_nl_sock) {
        err("nl_socket_alloc() failed\n");
        ret = -ENOSYS;
        goto out;
    }

    ret = genl_connect(l2tp_nl_sock);
    if (ret) {
        err("genl_connect() failed: %s\n", nl_geterror(ret));
        goto out;
    }

    l2tp_nl_family = genl_ctrl_resolve(l2tp_nl_sock, L2TP_GENL_NAME);
    if (l2tp_nl_family < 0) {
        err("genl_ctrl_resolve() failed");
        ret = -EPROTONOSUPPORT;
        goto out;
    }

    ret = nl_socket_set_nonblocking(l2tp_nl_sock);
    if (ret) {
        err("nl_socket_set_nonblocking() failed: %s\n", nl_geterror(ret));
        goto out;
    }
#endif

    if (l2tp_nl_sock2) return -EALREADY;

    l2tp_nl_sock2 = mnl_socket_open(NETLINK_GENERIC);
    if (!l2tp_nl_sock2)
        return -errno;

    ret = mnl_socket_bind(l2tp_nl_sock2, 0, MNL_SOCKET_AUTOPID);
    if (ret) {
        mnl_socket_close(l2tp_nl_sock2);
        return -errno;
    }

    l2tp_nl_portid = mnl_socket_get_portid(l2tp_nl_sock2);

    /* Send command to get the socket's id */
    ret = genl_get_skt_id(l2tp_nl_sock2, L2TP_GENL_VERSION, L2TP_GENL_NAME, &id);
    if (ret || !id) {
        mnl_socket_close(l2tp_nl_sock2);
        return -EPROTONOSUPPORT;
    }

    l2tp_nl_portid = mnl_socket_get_portid(l2tp_nl_sock2);

    /* Just used ID 1 for obtaining the socket ID */
    l2tp_nl_seq = 2;
    l2tp_nl_family2 = id;

#ifdef MNL_PORT
out:
#endif
    if (ret) l2tp_nl_cleanup();
    return ret;
}

void l2tp_nl_cleanup(void)
{
#ifdef MNL_PORT
    if (l2tp_nl_sock) {
        nl_close(l2tp_nl_sock);
        nl_socket_free(l2tp_nl_sock);
        l2tp_nl_sock = NULL;
    }
    if (l2tp_nl_family > 0) l2tp_nl_family = -1;
#endif
    if (l2tp_nl_sock2) {
        mnl_socket_close(l2tp_nl_sock2);
        l2tp_nl_sock2 = NULL;
    }
    if (l2tp_nl_family2 > 0) l2tp_nl_family2 = -1;
}

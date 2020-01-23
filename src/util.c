/**
 * file: util.c
 *
 * Shared utility functions used by test applications.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <ctype.h>
#include <unistd.h>
#include <netdb.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define aligned_u64 __aligned_u64
#include <linux/l2tp.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_pppol2tp.h>
#include <linux/ppp_defs.h>
#include <linux/if_pppox.h>
#include <linux/if_ppp.h>

#include "l2tp_netlink.h"
#include "usl_list.h"
#include "util.h"

bool opt_debug = false;
bool opt_quiet = false;
bool opt_silent = false;

static void seedprng(void)
{
    struct timeval tv;
    if (0 == gettimeofday(&tv, NULL)) {
        srandom(tv.tv_usec);
    }
}

static void __attribute__((constructor)) _test_init(void)
{
    opt_debug = getenv("OPT_DEBUG") ? true : false;
    opt_quiet = getenv("OPT_QUIET") ? true : false;
    opt_silent = getenv("OPT_SILENT") ? true : false;

    if (opt_silent) opt_quiet = true;

    if (opt_debug && (opt_quiet || opt_silent)) {
        die("OPT_DEBUG environment variable is set as well as one of OPT_QUIET or OPT_SILENT\n");
    }

    if (getenv("OPT_RNG_SEED")) {
        int seed = atoi(getenv("OPT_RNG_SEED"));
        srandom(seed);
    } else seedprng();

    l2tp_nl_init();
}

static void __attribute__((destructor)) _test_cleanup(void)
{
    l2tp_nl_cleanup();
}

/* Note this function is not thread-safe since it uses a static buffer for output */
static char *ss_to_str(struct sockaddr_storage *ss)
{
    assert(ss);
    assert(ss->ss_family == AF_INET || ss->ss_family == AF_INET6);

    static char addr_str[INET6_ADDRSTRLEN + 5 + 3 + 1];
    char tmp[INET6_ADDRSTRLEN] = {0};
    size_t nbytes;
    uint16_t port;

    memset(addr_str, 0, sizeof(addr_str));
    port = ss_get_port(ss);
    inet_ntop(ss->ss_family, ss_get_addr(ss, &nbytes), tmp, sizeof(tmp));
    if (port) {
        if (ss->ss_family == AF_INET) snprintf(addr_str, sizeof(addr_str), "%s:%" PRIu16, tmp, port);
        else snprintf(addr_str, sizeof(addr_str), "[%s]:%" PRIu16, tmp, port);
    } else snprintf(addr_str, sizeof(addr_str), "%s", tmp);

    return addr_str;
}

uint16_t ss_get_port(struct sockaddr_storage *ss)
{
    assert(ss);
    if (ss->ss_family == AF_INET) return ((struct sockaddr_in*)ss)->sin_port;
    else if (ss->ss_family == AF_INET6) return ((struct sockaddr_in6*)ss)->sin6_port;
    else assert(!"Unhandled socket family");
}

void *ss_get_addr(struct sockaddr_storage *ss, size_t *nbytes)
{
    assert(ss);
    assert(nbytes);
    if (ss->ss_family == AF_INET) {
        *nbytes = sizeof(struct in_addr);
        return &((struct sockaddr_in*)ss)->sin_addr;
    } else if (ss->ss_family == AF_INET6) {
        *nbytes = sizeof(struct in6_addr);
        return &((struct sockaddr_in6*)ss)->sin6_addr;
    }
    else assert(!"Unhandled socket family");
}

void *scalloc(size_t nmemb, size_t size)
{
    void *p = calloc(nmemb, size);
    if (!p) die("failed to allocate %zu blocks of %zu bytes", nmemb, size);
    return p;
}

int ssocket(int domain, int type, int protocol)
{
    int sfd = socket(domain, type, protocol);
    if (sfd < 0) die("failed to create socket: %s\n", strerror(errno));
    return sfd;
}

int tunnel_sk_addr_init(int family,
                        int protocol,
                        const char *addr,
                        uint16_t port,
                        uint32_t tid,
                        struct sockaddr_storage *ss,
                        socklen_t *sslen)
{
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_flags = AI_NUMERICSERV | AI_PASSIVE,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP,
    };
    struct addrinfo *res = NULL, *addrs = NULL;
    char port_str[16] = {0};
    char *service = NULL;
    bool found = false;

    assert(family == AF_INET || family == AF_INET6);
    assert(protocol == IPPROTO_L2TP || protocol == IPPROTO_UDP);
    assert(addr);
    assert(ss);
    assert(sslen);

    if (port) {
        sprintf(port_str, "%hu", port);
        service = port_str;
    }

    if (0 != getaddrinfo(addr, service, &hints, &addrs)) return -EINVAL;

    for (res = addrs; res; res = res->ai_next) {
        if (res->ai_family != family) continue;
        memcpy(ss, res->ai_addr, res->ai_addrlen);
        if (protocol == IPPROTO_L2TP) {
            if (res->ai_family == AF_INET) {
                struct sockaddr_l2tpip *in4 = (void*)ss;
                in4->l2tp_conn_id = tid;
                *sslen = sizeof(*in4);
                found = true;
            } else if (res->ai_family == AF_INET6) {
                struct sockaddr_l2tpip6 *in6 = (void*)ss;
                in6->l2tp_conn_id = tid;
                *sslen = sizeof(*in6);
                found = true;
            }
        } else {
            *sslen = res->ai_addrlen;
        }
        found = true;
        break;
    }

    if (!found) {
        err("%s: getaddrinfo returned no results for %s %s %s/%d\n",
                __func__,
                family == AF_INET ? "AF_INET" : "AF_INET6",
                protocol == IPPROTO_UDP ? "IPPROTO_UDP" : "IPPROTO_L2TP",
                addr,
                port);
    }

    freeaddrinfo(addrs);
    return found ? 0 : -ENXIO;
}

static void pppol2tp_addr_init(int family,
        enum l2tp_api_protocol_version version,
        uint32_t tid,
        uint32_t ptid,
        uint32_t sid,
        uint32_t psid,
        int sk,
        struct sockaddr_storage *ss,
        socklen_t *sslen)
{
    assert(family == AF_INET || family == AF_INET6);
    assert(version == L2TP_API_PROTOCOL_VERSION_2 || version == L2TP_API_PROTOCOL_VERSION_3);
    assert(tid != 0);
    assert(ptid != 0);
    assert(ss != NULL);
    assert(sslen != NULL);

#define SA_PPPOL2TP_INIT \
    .sa_family = AF_PPPOX, \
    .sa_protocol = PX_PROTO_OL2TP, \
    .pppol2tp.fd = sk, \
    .pppol2tp.s_tunnel = tid, \
    .pppol2tp.d_tunnel = ptid, \
    .pppol2tp.s_session = sid, \
    .pppol2tp.d_session = psid,

    dbg("%s: L2TPv%d %s: tid %" PRIu32 ", ptid %" PRIu32 ", sid %" PRIu32 ", psid %" PRIu32 "\n",
            __func__,
            version,
            family == AF_INET ? "AF_INET" : "AF_INET6",
            tid,
            ptid,
            sid,
            psid);

    switch (version) {
        case L2TP_API_PROTOCOL_VERSION_2:
            switch (family) {
                case AF_INET: {
                    struct sockaddr_pppol2tp sax = { SA_PPPOL2TP_INIT };
                    memcpy(ss, &sax, sizeof(sax));
                    *sslen = sizeof(sax);
                } break;
                case AF_INET6: {
                    struct sockaddr_pppol2tpin6 saxi6 = { SA_PPPOL2TP_INIT };
                    memcpy(ss, &saxi6, sizeof(saxi6));
                    *sslen = sizeof(saxi6);
                } break;
            }
            break;
        case L2TP_API_PROTOCOL_VERSION_3:
            switch (family) {
                case AF_INET: {
                    struct sockaddr_pppol2tpv3 sax3 = { SA_PPPOL2TP_INIT };
                    memcpy(ss, &sax3, sizeof(sax3));
                    *sslen = sizeof(sax3);
                } break;
                case AF_INET6: {
                    struct sockaddr_pppol2tpv3in6 sax3i6 = { SA_PPPOL2TP_INIT };
                    memcpy(ss, &sax3i6, sizeof(sax3i6));
                    *sslen = sizeof(sax3i6);
                } break;
            }
            break;
    }
#undef SA_PPPOL2TP_INIT
}

void pppol2tp_tunnel_ctrl_addr_init(int family,
        enum l2tp_api_protocol_version version,
        uint32_t tid,
        uint32_t ptid,
        int sk,
        struct sockaddr_storage *ss,
        socklen_t *sslen)
{
    assert(sk >= 0);
    pppol2tp_addr_init(family, version, tid, ptid, 0, 0, sk, ss, sslen);
}

void pppol2tp_session_ctrl_addr_init(int family,
        enum l2tp_api_protocol_version version,
        uint32_t tid,
        uint32_t ptid,
        uint32_t sid,
        uint32_t psid,
        struct sockaddr_storage *ss,
        socklen_t *sslen)
{
    assert(sid != 0);
    assert(psid != 0);
    pppol2tp_addr_init(family, version, tid, ptid, sid, psid, -1, ss, sslen);
}

static int pppol2tp_ctrl_create(struct sockaddr_storage *addr, socklen_t addrlen)
{
    assert(addr);
    assert(addrlen > 0);
    int fd, ret;

    fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
    if (fd < 0) {
        err("failed to create AF_PPPOX socket: %s\n", strerror(errno));
        return fd;
    }

    ret = connect(fd, (struct sockaddr*)addr, addrlen);
    if (ret) {
        err("failed to connect AF_PPPOX socket: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    if (opt_debug) {
        int debug = 0xff;
        setsockopt(fd, SOL_PPPOL2TP, PPPOL2TP_SO_DEBUG, &debug, sizeof(debug));
    }

    return fd;
}

int pppol2tp_tunnel_ctrl_socket(int family,
        enum l2tp_api_protocol_version version,
        uint32_t tid,
        uint32_t ptid,
        int sk)
{
    struct sockaddr_storage ss = {0};
    socklen_t sslen = 0;
    int ctlfd;
    dbg("%s: tid %" PRIu32 ", ptid %" PRIu32 "\n", __func__, tid, ptid);
    pppol2tp_tunnel_ctrl_addr_init(family, version, tid, ptid, sk, &ss, &sslen);
    ctlfd = pppol2tp_ctrl_create(&ss, sslen);
    return ctlfd;
}

int pppol2tp_session_ctrl_socket(int family,
        enum l2tp_api_protocol_version version,
        uint32_t tid,
        uint32_t ptid,
        uint32_t sid,
        uint32_t psid)
{
    struct sockaddr_storage ss = {0};
    socklen_t sslen = 0;
    int ctlfd;
    dbg("%s: tid %" PRIu32 ", ptid %" PRIu32 ", sid %" PRIu32 ", psid %" PRIu32 "\n",
            __func__, tid, ptid, sid, psid);
    pppol2tp_session_ctrl_addr_init(family, version, tid, ptid, sid, psid, &ss, &sslen);
    ctlfd = pppol2tp_ctrl_create(&ss, sslen);
    return ctlfd;
}

int tunnel_socket(int family, int protocol, uint32_t tid, struct addr *local, struct addr *peer)
{
    assert(family == AF_INET || family == AF_INET6);
    assert(protocol == IPPROTO_UDP || protocol == IPPROTO_L2TP);
    if (protocol == IPPROTO_L2TP && local) assert(tid);

    int fd = -1, ret = 0;

    dbg("%s: managed %s %s tunnel socket local %s/%d -> peer %s/%d\n",
            __func__,
            family == AF_INET ? "AF_INET" : "AF_INET6",
            protocol == IPPROTO_UDP ? "IPPROTO_UDP" : "IPPROTO_L2TP",
            local && local->ip ? local->ip : "???",
            local && local->ip ? local->port : 0,
            peer && peer->ip ? peer->ip : "???",
            peer && peer->ip ? peer->port : 0);

    fd = socket(family, SOCK_DGRAM, protocol);
    if (fd < 0) {
        ret = -errno;
        err("%s: failed to create %s %s socket: %s\n",
                __func__,
                family == AF_INET ? "AF_INET" : "AF_INET6",
                protocol == IPPROTO_UDP ? "IPPROTO_UDP" : "IPPROTO_L2TP",
                strerror(-ret));
        goto out;
    }

    if (local && local->ip) {
        struct sockaddr_storage ss = {0};
        int on = 1;
        socklen_t sslen;
        ret = tunnel_sk_addr_init(family, protocol, local->ip, local->port, tid, &ss, &sslen);
        if (ret) goto out;
        ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (ret) goto out;
        ret = bind(fd, (struct sockaddr *)&ss, sslen);
        if (ret) {
            ret = -errno;
            err("%s: failed to bind tunnel socket to %s: %s\n",
                    __func__,
                    ss_to_str(&ss),
                    strerror(-ret));
            goto out;
        }
    }

    if (peer && peer->ip) {
        struct sockaddr_storage ss = {0};
        socklen_t sslen;
        ret = tunnel_sk_addr_init(family, protocol, peer->ip, peer->port, 0, &ss, &sslen);
        if (ret) goto out;
        ret = connect(fd, (struct sockaddr *)&ss, sslen);
        if (ret) {
            ret = -errno;
            err("%s: failed to connect tunnel socket to %s: %s\n",
                    __func__,
                    ss_to_str(&ss),
                    strerror(-ret));
            goto out;
        }
    }

out:
    if (ret) {
        if (fd >= 0) close(fd);
        fd = -1;
    } else {
        dbg("%s: allocated socket fd %d\n", __func__, fd);
    }
    return fd;
}

int kernel_tunnel_create(int tfd, struct l2tp_options *options, int *ctlsk)
{
    assert(options);
    assert(options->create_api == L2TP_SOCKET_API || options->create_api == L2TP_NETLINK_API);
    assert(options->create_api == L2TP_NETLINK_API || ctlsk); // need output pointer if using socket API

    int ret;

    switch (options->create_api) {
        case L2TP_SOCKET_API:
            ret = pppol2tp_tunnel_ctrl_socket(options->family, options->l2tp_version, options->tid, options->ptid, tfd);
            if (ret >= 0) {
                if (ctlsk) *ctlsk = ret;
                ret = 0;
            }
        break;
        case L2TP_NETLINK_API: {
            struct l2tp_tunnel_nl_config tcfg = {
                .debug = opt_debug ? 0xff : 0,
                .proto_version = options->l2tp_version,
                .encap_type = options->protocol == IPPROTO_UDP ?
                    L2TP_API_TUNNEL_ENCAPTYPE_UDP :
                    L2TP_API_TUNNEL_ENCAPTYPE_IP,
            };

            /* if we don't have a managed tunnel socket we need to tell the
             * kernel the addresses and ports to use
             */
            if (tfd < 0) {
                assert(options->local_addr.ip != NULL);
                assert(options->peer_addr.ip != NULL);

                ret = tunnel_sk_addr_init(options->family,
                        options->protocol,
                        options->local_addr.ip,
                        options->local_addr.port ? options->local_addr.port : 1701,
                        options->tid,
                        &tcfg.local_addr,
                        &tcfg.local_addr_len);
                if (ret) return ret;

                ret = tunnel_sk_addr_init(options->family,
                        options->protocol,
                        options->peer_addr.ip,
                        options->peer_addr.port ? options->peer_addr.port : 1701,
                        options->ptid,
                        &tcfg.peer_addr,
                        &tcfg.peer_addr_len);
                if (ret) return ret;
            }

            ret = l2tp_nl_tunnel_create(options->tid, options->ptid, tfd, &tcfg);
        } break;
        case L2TP_UNDEFINED_API:
            assert(!"Unhandled switch case");
            ret = -ENOSYS;
        break;
    }

    return ret;
}

int kernel_session_create(struct l2tp_options *options, int *ctlsk)
{
    assert(options);
    assert(options->create_api == L2TP_SOCKET_API || options->create_api == L2TP_NETLINK_API);
    assert(options->create_api == L2TP_NETLINK_API || ctlsk); // need output pointer if using socket API

    int ret;

    switch (options->create_api) {
        case L2TP_SOCKET_API:
do_pppox_connect:
            ret = pppol2tp_session_ctrl_socket(options->family, options->l2tp_version, options->tid, options->ptid, options->sid, options->psid);
            if (ret >= 0) {
                if (ctlsk) *ctlsk = ret;
                ret = 0;
            }
        break;
        case L2TP_NETLINK_API: {
            struct l2tp_session_nl_config scfg = {
                .debug = opt_debug ? 0xff : 0,
                .mtu = 1300,
                .pw_type = options->pseudowire,
                /* leave everything else as default */
            };
            ret = l2tp_nl_session_create(options->tid, options->ptid, options->sid, options->psid, &scfg);
            if (ret) return ret;

            /* To actually bind the pppox session we still need to
             * call connect on a pppox socket :-/
             */
            if (options->pseudowire == L2TP_API_SESSION_PW_TYPE_PPP) goto do_pppox_connect;
        } break;
        case L2TP_UNDEFINED_API:
            assert(!"Unhandled switch case");
            ret = -ENOSYS;
        break;
    }
    return ret;
}

int brandom(int lower, int upper)
{
    return random() % (upper - lower + 1) + lower;
}

void mem_dump(void *data, size_t data_len)
{
    int x, y;
    unsigned char *bytep;
    char cbuf[80];
    char nbuf[80];
    char *p;

    bytep = data;
    for (y = 0; y < data_len; y += 16) {
        memset(&cbuf[0], 0, sizeof(cbuf));
        memset(&nbuf[0], 0, sizeof(nbuf));
        p = &nbuf[0];

        for (x = 0; x < 16; x++, bytep++) {
            if ((x + y) >= data_len) {
                break;
            }
            cbuf[x] = isprint(*bytep) ? *bytep : '.';
            p += sprintf(p, "%02x ", *bytep);
        }
        log("%8d: %-48s  %s\n", y, nbuf, cbuf);
    }
}

struct addr *gen_dflt_address(int family, bool is_local)
{
    static struct addr dflt_local_addr_inet = {
        .ip = "127.0.0.1",
        .port = 5000,
    };

    static struct addr dflt_peer_addr_inet = {
        .ip = "127.0.0.1",
        .port = 10000,
    };

    static struct addr dflt_local_addr_inet6 = {
        .ip = "::1",
        .port = 5000,
    };

    static struct addr dflt_peer_addr_inet6 = {
        .ip = "::1",
        .port = 10000,
    };

    if (family == AF_INET)
        return is_local ? &dflt_local_addr_inet : &dflt_peer_addr_inet;
    else if (family == AF_INET6)
        return is_local ? &dflt_local_addr_inet6 : &dflt_peer_addr_inet6;

    assert(!"Unsupported family type");
    return NULL;
}

bool parse_l2tp_version(const char *str, int *version)
{
    if (!str || !version) return false;
    *version = atoi(str);
    return (*version == 2) || (*version == 3);
}

bool parse_socket_family(const char *str, int *family)
{
    if (!str || !family) return false;
    if (0 == strcmp("inet", str)) *family = AF_INET;
    else if (0 == strcmp("inet6", str)) *family = AF_INET6;
    else return false;
    return true;
}

bool parse_encap(const char *str, int *proto)
{
    if (!str || !proto) return false;
    if (0 == strcmp("udp", str)) *proto = IPPROTO_UDP;
    else if (0 == strcmp("ip", str)) *proto = IPPROTO_L2TP;
    else return false;
    return true;
}

bool parse_api(const char *str, api_flavour *flv)
{
    if (!str || !flv) return false;
    if (0 == strcmp(str, "socket"))
        *flv = L2TP_SOCKET_API;
    else if (0 == strcmp(str, "netlink"))
        *flv = L2TP_NETLINK_API;
    else {
        *flv = L2TP_UNDEFINED_API;
        return false;
    }
    return true;
}

bool parse_address(char *str, struct addr *addr)
{
    char *p;
    if (!str || !addr) return false;
    p = strchr(str, '/');
    if (!p) return false;
    addr->port = atoi(p+1);
    if ((addr->port <= 0 || addr->port > 63335)) return false;
    *p = '\0';
    addr->ip = str;
    if (!strlen(addr->ip)) return false;
    return true;
}

struct racing_thread {
    struct thread_data {
        pthread_t thread;
        racing_threads_cb_fn_t cb;
        void *dptr;
    } t1, t2;
    size_t id;
    pthread_mutex_t lock;
    int tfd, ppptctl;
    struct l2tp_options opt;
    struct usl_list_head list;
};

static void *tunl_racing_threads__thread_wrapper(void *dptr)
{
    struct racing_thread *rt = dptr;
    struct racing_threads_tunnel_info ti = {
        .tid = rt->opt.tid,
        .tunnel_socket_fd = rt->tfd,
        .pppctl_socket_fd = rt->ppptctl,
    };
    racing_threads_cb_fn_t cb = NULL;
    void *cb_dptr = NULL;

    if (pthread_equal(rt->t1.thread, pthread_self())) {
        cb = rt->t1.cb;
        cb_dptr = rt->t1.dptr;
    } else if (pthread_equal(rt->t2.thread, pthread_self())) {
        cb = rt->t2.cb;
        cb_dptr = rt->t2.dptr;
    } else assert(!"Failed to determine thread resources");

    pthread_mutex_lock(&rt->lock);
    pthread_mutex_unlock(&rt->lock);

    return cb(rt->id, &ti, cb_dptr);
}

static struct racing_thread *tunl_racing_threads__alloc_thread_pair(
        struct l2tp_options *options,
        racing_threads_cb_fn_t cb1, void *dptr1,
        racing_threads_cb_fn_t cb2, void *dptr2)
{
    assert(cb1);
    assert(cb2);

    struct racing_thread *rt = scalloc(1, sizeof(*rt));
    int ret;

    /* pthread_mutex_init(3) states that pthread_mutex_init always returns 0 */
    (void)pthread_mutex_init(&rt->lock, NULL);

    USL_LIST_HEAD_INIT(&rt->list);
    rt->opt = *options;

    ret = pthread_mutex_lock(&rt->lock);
    assert(ret == 0);

    rt->ppptctl = rt->tfd = -1;

    rt->tfd = tunnel_socket(rt->opt.family,
            rt->opt.protocol,
            rt->opt.tid,
            &rt->opt.local_addr,
            &rt->opt.peer_addr);
    assert(rt->tfd >= 0);

    ret = kernel_tunnel_create(rt->tfd, &rt->opt, &rt->ppptctl);
    assert(ret == 0);

    rt->t1.cb = cb1;
    rt->t1.dptr = dptr1;
    ret = pthread_create(&rt->t1.thread, NULL, tunl_racing_threads__thread_wrapper, rt);
    assert(ret == 0);

    rt->t2.cb = cb2;
    rt->t2.dptr = dptr2;
    ret = pthread_create(&rt->t2.thread, NULL, tunl_racing_threads__thread_wrapper, rt);
    assert(ret == 0);

    return rt;
}

static void tunl_racing_threads__free(struct racing_thread *rt)
{
    assert(rt);
    if (rt->tfd >= 0) close(rt->tfd);
    if (rt->ppptctl >= 0) close(rt->ppptctl);
    free(rt);
}

void tunl_racing_threads(size_t ntunnels,
        struct l2tp_options *options,
        size_t noptions,
        racing_threads_cb_fn_t t1,
        void *t1_dptr,
        racing_threads_cb_fn_t t2,
        void *t2_dptr)
{
    assert(noptions == ntunnels || noptions == 1 || noptions == 0);
    struct l2tp_options dflt_options = {
        .l2tp_version = L2TP_API_PROTOCOL_VERSION_3,
        .create_api = L2TP_NETLINK_API,
        .delete_api = L2TP_NETLINK_API,
        .family = AF_INET,
        .protocol = IPPROTO_UDP,
        .pseudowire = L2TP_API_SESSION_PW_TYPE_ETH,
        .peer_addr = { .ip = "127.0.0.1", .port = 10000 },
        .local_addr = { .ip = "127.0.0.1", .port = 20000 },
        .tid = 1,
        .ptid = 1,
    };
    USL_LIST_HEAD(racing_threads);
    struct usl_list_head *c, *t;
    size_t i;

    /* Create tunnels and threads */
    for (i = 0; i < ntunnels; i++) {
        struct l2tp_options opt = {};
        struct racing_thread *rt;

        if (noptions == ntunnels) opt = options[i];
        else if (noptions == 1) opt = *options;
        else opt = dflt_options;

        if (noptions != ntunnels) {
            opt.peer_addr.port += i;
            opt.local_addr.port += i;
            opt.tid += i;
            opt.ptid += i;
        }

        rt = tunl_racing_threads__alloc_thread_pair(&opt, t1, t1_dptr, t2, t2_dptr);
        assert(rt != NULL);
        usl_list_add_tail(&rt->list, &racing_threads);
    }

    /* Unlock the thread locks to allow racing to commence */
    usl_list_for_each(c, t, &racing_threads) {
        struct racing_thread *rt = usl_list_entry(c, struct racing_thread, list);
        pthread_mutex_unlock(&rt->lock);
    }

    /* Wait for all the thread to complete */
    usl_list_for_each(c, t, &racing_threads) {
        struct racing_thread *rt = usl_list_entry(c, struct racing_thread, list);
        pthread_join(rt->t1.thread, NULL);
        pthread_join(rt->t2.thread, NULL);
    }

    /* Clean up */
    usl_list_for_each(c, t, &racing_threads) {
        struct racing_thread *rt = usl_list_entry(c, struct racing_thread, list);
        usl_list_del(&rt->list);
        tunl_racing_threads__free(rt);
    }
}

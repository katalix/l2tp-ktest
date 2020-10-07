/**
 * @file util.h
 *
 * Shared utility functions for test programs.
 */
#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include "usl_list.h"

#include "l2tp_kapi.h"
#include "util_ppp.h"

typedef enum {
    L2TP_UNDEFINED_API,
    L2TP_SOCKET_API,
    L2TP_NETLINK_API,
} api_flavour;

struct addr {
    char *ip;
    int port;
};

struct l2tp_options {
    enum l2tp_api_protocol_version l2tp_version;
    api_flavour create_api;
    api_flavour delete_api;
    int family;
    int protocol;
    enum l2tp_api_session_pw_type pseudowire;
    uint16_t mtu;
    uint8_t cookie_len;
    uint8_t cookie[8];
    uint8_t peer_cookie_len;
    uint8_t peer_cookie[8];
    struct addr peer_addr;
    struct addr local_addr;
    uint32_t tid;
    uint32_t ptid;
    uint32_t sid;
    uint32_t psid;
    char ifname[16];
    union {
        struct {
            uint8_t peer_mac[6];
            uint16_t id;
        } pppac;
    } pw;
};

struct l2tp_pw {
    char ifname[16];
    union {
        struct ppp ppp;
    } typ;
};

#define INIT_L2TP_PW { \
    .ifname[0] = 0, \
    .typ.ppp = INIT_PPP, \
}

#define l2tp_pw_init(_pw) do { \
    struct l2tp_pw _init = INIT_L2TP_PW; \
    *(_pw) = _init; \
} while(0)

/*
 * Logging wrapper macros: dbg() generates output if opt_debug
 * is set true, log() and err() generate output on stdout/err
 * respectively, and die() terminates the program.
 */

extern bool opt_debug;  /* enable dbg() logging */
extern bool opt_quiet;  /* disable log() logging */
extern bool opt_silent; /* disable err() logging */

/**
 * Logging macro for debug-level output to stderr.
 * Nothing is printed if opt_debug is false.
 *  @param  fmt         printf(3)-style format string
 *  @param  ...         vaargs for format string
 */
#define dbg(fmt, ...) do { \
    if (opt_debug) { \
        struct timeval ct = {0}; \
        gettimeofday(&ct, NULL); \
        fprintf(stderr, "%ld.%09ld : %ld : DEBUG %s:%d : " fmt, \
            ct.tv_sec, \
            ct.tv_usec, \
            syscall(SYS_gettid), \
            __FILE__, \
            __LINE__, \
            ##__VA_ARGS__); \
    } \
} while(0)

/**
 * Logging macro, rendered string is printed on stdout.
 *  @param  fmt         printf(3)-style format string
 *  @param  ...         vaargs for format string
 */
#define log(fmt, ...) do { \
    if (!opt_quiet) { \
        struct timeval ct = {0}; \
        gettimeofday(&ct, NULL); \
        fprintf(stdout, "%ld.%09ld : %ld : " fmt, \
            ct.tv_sec, \
            ct.tv_usec, \
            syscall(SYS_gettid), \
            ##__VA_ARGS__); \
    } \
} while(0)

/**
 * Logging macro, rendered string is printed on stdout
 * with no preamble.
 *  @param  fmt         printf(3)-style format string
 *  @param  ...         vaargs for format string
 */
#define log_raw(fmt, ...) do { \
    if (!opt_quiet) { \
        fprintf(stdout, fmt, ##__VA_ARGS__); \
    } \
} while(0)

/**
 * Logging macro, rendered string is printed on stderr.
 *  @param  fmt         printf(3)-style format string
 *  @param  ...         vaargs for format string
 */
#define err(fmt, ...) do { \
    if (!opt_silent) { \
        struct timeval ct = {0}; \
        gettimeofday(&ct, NULL); \
        fprintf(stderr, "%ld.%09ld : %ld : ERROR %s:%d : " fmt, \
            ct.tv_sec, \
            ct.tv_usec, \
            syscall(SYS_gettid), \
            __FILE__, \
            __LINE__, \
            ##__VA_ARGS__); \
    } \
} while(0)

/**
 * Print an error message to stderr and terminate the process with EXIT_FAILURE.
 *  @param  fmt         printf(3)-style format string
 *  @param  ...         vaargs for format string
 */
#define die(fmt, ...) do { \
    struct timeval ct = {0}; \
    gettimeofday(&ct, NULL); \
    fprintf(stderr, "%ld.%09ld : %ld : FATAL %s:%d : " fmt, \
        ct.tv_sec, \
        ct.tv_usec, \
        syscall(SYS_gettid), \
        __FILE__, \
        __LINE__, \
        ##__VA_ARGS__); \
    exit(EXIT_FAILURE); \
} while(0)

/**
 * Obtain port from a sockaddr_storage structure.
 * Structure must be initialised with either an AF_INET or AF_INET6 address.
 *  @param  ss          pointer to sockaddr
 *  @return             port
 */
uint16_t ss_get_port(struct sockaddr_storage *ss);

/**
 * Obtain IP address structure from a sockaddr_storage structure.
 * Structure must be initialised with either an AF_INET or AF_INET6 address.
 *  @param  ss          pointer to sockaddr
 *  @param  nbytes      pointer to variable to accept address struct size
 *  @return             pointer to address struct
 */
void *ss_get_addr(struct sockaddr_storage *ss, size_t *nbytes);

/**
 * "Safe" wrapper for calloc(3).
 * On failure the process is terminated.
 *  @param  nmemb       number of members to allocate
 *  @param  size        size of each member
 *  @return             pointer to allocated memory
 */
void *scalloc(size_t nmemb, size_t size);

/**
 * "Safe" wrapper for socket(2).
 * On failure the process is terminated.
 *  @param  domain      communication domain
 *  @param  type        socket type
 *  @param  protocol    socket protocol
 *  @return             file descriptor
 */
int ssocket(int domain, int type, int protocol);

/**
 * Initialise a sockaddr structure using getaddrinfo(3).
 * Suitable for use with a managed tunnel socket.
 *  @param  family      address family (AF_INET or AF_INET6)
 *  @param  protocol    IPPROTO_L2TP or IPPROTO_UDP
 *  @param  address     address string
 *  @param  port        port
 *  @param  tid         tunnel ID
 *  @param  ss          pointer to a socket address struct to fill out on return
 *  @param  sslen       pointer to a socket address length to fill out on return
 *  @return             0 on success, negative errno otherwise
 */
int tunnel_sk_addr_init(int family,
                        int protocol,
                        const char *addr,
                        uint16_t port,
                        uint32_t tid,
                        struct sockaddr_storage *ss,
                        socklen_t *sslen);

/**
 * Initialise a sockaddr structure for a pppol2tp tunnel control socket.
 *  @param  family      address family (AF_INET or AF_INET6)
 *  @param  version     L2TP version
 *  @param  tid         local tunnel ID
 *  @param  ptid        peer tunnel ID
 *  @param  sk          tunnel socket file descriptor
 *  @param  ss          pointer to a socket address struct to fill out on return
 *  @param  sslen       pointer to a socket address length to fill out on return
 */
void pppol2tp_tunnel_ctrl_addr_init(int family,
        enum l2tp_api_protocol_version version,
        uint32_t tid,
        uint32_t ptid,
        int sk,
        struct sockaddr_storage *ss,
        socklen_t *sslen);

/**
 * Initialise a sockaddr structure for a pppol2tp session control socket.
 *  @param  family      address family (AF_INET or AF_INET6)
 *  @param  version     L2TP version
 *  @param  tid         local tunnel ID
 *  @param  ptid        peer tunnel ID
 *  @param  sid         local session ID
 *  @param  psid        peer session ID
 *  @param  ss          pointer to a socket address struct to fill out on return
 *  @param  sslen       pointer to a socket address length to fill out on return
 */
void pppol2tp_session_ctrl_addr_init(int family,
        enum l2tp_api_protocol_version version,
        uint32_t tid,
        uint32_t ptid,
        uint32_t sid,
        uint32_t psid,
        struct sockaddr_storage *ss,
        socklen_t *sslen);

/**
 * Create a tunnel control socket using the pppol2tp API.
 *  @param  family      address family (AF_INET or AF_INET6)
 *  @param  version     L2TP version
 *  @param  tid         local tunnel ID
 *  @param  ptid        peer tunnel ID
 *  @param  sk          tunnel socket file descriptor
 *  @return             control socket on success, negative errno otherwise
 */
int pppol2tp_tunnel_ctrl_socket(int family,
        enum l2tp_api_protocol_version version,
        uint32_t tid,
        uint32_t ptid,
        int sk);

/**
 * Create a session control socket using the pppol2tp API.
 *  @param  family      address family (AF_INET or AF_INET6)
 *  @param  version     L2TP version
 *  @param  tid         local tunnel ID
 *  @param  ptid        peer tunnel ID
 *  @param  sid         local session ID
 *  @param  psid        peer session ID
 *  @return             control socket on success, negative errno otherwise
 */
int pppol2tp_session_ctrl_socket(int family,
        enum l2tp_api_protocol_version version,
        uint32_t tid,
        uint32_t ptid,
        uint32_t sid,
        uint32_t psid);

/**
 * Create a managed tunnel socket.
 *  @param  family      address family (AF_INET or AF_INET6)
 *  @param  protocol    protocol (IPPROTO_UDP or IPPROTO_L2TP)
 *  @param  tid         tunnel ID (only necessary for binding IPPROTO_L2TP sockets)
 *  @param  local       optional local address.  If set socket is bound to this address.
 *  @param  peer        optional peer address.  If set socket is connected to this address.
 *  @return             tunnel socket fd on success, negative errno otherwise
 */
int tunnel_socket(int family, int protocol, uint32_t tid, struct addr *local, struct addr *peer);

/**
 * Create kernel tunnel data plane context.
 * This helper function creates a kernel context using either the
 * socket API or the netlink API as requested by the supplied options.
 *  @param  tfd         tunnel socket file descriptor if the tunnel is managed
 *  @param  options     options governing tunnel creation
 *  @param  ctlsk       variable to receive control socket for pppol2tp/socket API
 *  @return             0 on success, negative errno otherwise
 */
int kernel_tunnel_create(int tfd, struct l2tp_options *options, int *ctlsk);

/**
 * Create kernel session data plane context.
 * This helper function creates a kernel context using either the
 * socket API or the netlink API as requested by the supplied options.
 *  @param  options     options governing session creation
 *  @param  pw          output variable for pseudowire data
 *  @return             0 on success, negative errno otherwise
 */
int kernel_session_create(struct l2tp_options *options, struct l2tp_pw *pw);

/**
 * Create kernel session pppox socket(s).
 * This helper function creates pppol2tp control and ppp sockets.
 * Most code will be able to use kernel_session_create which wraps this function,
 * however code wanting to control the netlink options passed to the kernel can
 * use l2tp_nl_session_create to create the core kernel context, and then use this
 * function to create the pppol2tp context.
 *  @param  options     options governing session creation
 *  @param  pw          output variable for pseudowire data
 *  @return             0 on success, negative errno otherwise
 */
int kernel_session_create_pppox(struct l2tp_options *options, struct l2tp_pw *pw);

/**
 * Generate a bounded random number using random(3).
 *  @param  lower           lower limit
 *  @param  upper           upper limit
 *  @return                 random number in the range lower >= x <= upper
 */
int brandom(int lower, int upper);

/**
 * Log an array of binary data as a hex dump to stdout.
 *  @param  data            pointer to data buffer
 *  @param  data_len        number of bytes in data buffer
 */
void mem_dump(void *data, size_t data_len);

/**
 * Generate default loopback address.
 * Returned structure is statically allocated and should not
 * be modified or freed.
 *  @param  family          AF_INET or AF_INET6
 *  @param  is_local        true if address is local, false for peer address
 *  @return                 address structure pointer
 */
struct addr *gen_dflt_address(int family, bool is_local);

/**
 * Parse L2TP version from NULL terminated string.
 *  @param  str             pointer to string
 *  @param  version         pointer to variable to set with version
 *  @return                 true on success, false otherwise.
 */
bool parse_l2tp_version(const char *str, int *version);

/**
 * Parse socket family from NULL terminated string.
 *  @param  str             pointer to string
 *  @param  family          pointer to variable to set with socket family
 *  @return                 true on success, false otherwise.
 */
bool parse_socket_family(const char *str, int *family);

/**
 * Parse encapsulation type from NULL terminated string.
 *  @param  str             pointer to string
 *  @param  encap           pointer to variable to set with encap type
 *  @return                 true on success, false otherwise.
 */
bool parse_encap(const char *str, int *encap);

/**
 * Parse API flavour from NULL terminated string.
 *  @param  str             pointer to string
 *  @param  flv             pointer to variable to set with API flavour
 *  @return                 true on success, false otherwise.
 */
bool parse_api(const char *str, api_flavour *flv);

/**
 * Parse address/port pair from NULL terminated string.
 *  @param  str             pointer to string
 *  @param  addr            pointer to variable to set with address
 *  @return                 true on success, false otherwise.
 */
bool parse_address(char *str, struct addr *addr);

/**
 * Parse pseudowire type from NULL terminated string.
 *  @param  str             pointer to string
 *  @param  pwtype          pointer to variable to set with pseudowire type.
 *  @return                 true on success, false otherwise.
 */
bool parse_pseudowire_type(char *str, enum l2tp_api_session_pw_type *pwtype);

/**
 * Racing threads info for thread callbacks.
 */
struct racing_threads_tunnel_info {
    uint32_t tid;           /* tunnel ID associated with the thread */
    int tunnel_socket_fd;   /* tunnel socket fd (may be -1) */
    int pppctl_socket_fd;   /* ppp tunnel control socket fd (may be -1) */
};

/**
 * "Racing threads" callback.
 *  @param  id              index of the thread
 *  @param  ti              pointer to a thread info structure
 *  @param  dptr            opaque data pointer
 */
typedef void * (*racing_threads_cb_fn_t)(size_t id, struct racing_threads_tunnel_info *ti, void *dptr);

/**
 * Create a pair of threads per tunnel, and call an arbitrary callback in each.
 * This allows multi-threaded stressing of the kernel code to probe for race
 * conditions.
 *  @param  ntunnels        number of tunnels to create
 *  @param  options         optional pointer to an array of options structures;
 *                          if unset default options will be used
 *  @param  noptions        number of options structures pointed to by the options pointer
 *  @param  t1              callback for thread 1
 *  @param  t1_dptr         opaque data pointer for thread 1, passed as callback dptr argument
 *  @param  t2              callback for thread 2
 *  @param  t2_dptr         opaque data pointer for thread 2, passed as callback dptr argument
 */
void tunl_racing_threads(size_t ntunnels,
        struct l2tp_options *options,
        size_t noptions,
        racing_threads_cb_fn_t t1,
        void *t1_dptr,
        racing_threads_cb_fn_t t2,
        void *t2_dptr);

#endif /* UTIL_H */

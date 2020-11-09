/**
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * @pppoe_sess_pkt.c
 *
 * In send mode, wrap stdin data in a PPPoE session header and fire it off.
 * In receive mode, listen for a PPPoE session packet.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "util.h"

struct app_options {
    bool        send_mode;
    char        *ifname;
    uint16_t    session_id;
    uint8_t     peer_mac[6];
    bool        peer_mac_set;
};

#define PPPOE_VER                       0x1
#define PPPOE_TYPE                      0x1

#define PPPOE_HEADER_LEN                6 /* octets */
#define PPPOE_PAYLOAD_LEN               ( ETH_DATA_LEN - PPPOE_HEADER_LEN )
#define PPPOE_PACKET_LEN                ( ETH_HLEN + PPPOE_HEADER_LEN + PPPOE_PAYLOAD_LEN )

struct pppoe_pkt {
    struct ethhdr   ehdr;
    unsigned int    version:4;
    unsigned int    type:4;
    unsigned int    code:8;
    unsigned int    session_id:16;
    unsigned int    payload_len:16;
    uint8_t         payload[PPPOE_PAYLOAD_LEN];
};

static int socket_raw(const char *ifname, int *sfd)
{
    assert(ifname);
    assert(sfd);
    assert(strlen(ifname) <= IFNAMSIZ);

    int protocol = htons(ETH_P_PPP_SES);
    struct sockaddr_ll sa = {
        .sll_family = AF_PACKET,
        .sll_protocol = protocol,
    };
    struct ifreq ifr = {};
    int fd, ret;

    fd = socket(PF_PACKET, SOCK_RAW, protocol);
    if (fd < 0) {
        perror("socket");
        return errno;
    }

    /* enable broadcast */
    {
        int val = 1;
        ret = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val));
        if (ret) {
            perror("setsockopt(SO_BROADCAST)");
            return errno;
        }
    }

    /* bind to the specified interface */
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(fd, SIOCGIFINDEX, &ifr);
    if (ret) {
        perror("ioctl(SIOCGIFINDEX)");
        close(fd);
        return errno;
    }

    sa.sll_ifindex = ifr.ifr_ifindex;
    ret = bind(fd, (struct sockaddr*)&sa, sizeof(sa));
    if (ret) {
        perror("bind");
        close(fd);
        return errno;
    }

    *sfd = fd;
    return 0;
}

static int get_hwaddr(const char *ifname, uint8_t *mac)
{
    assert(ifname);
    assert(mac);
    assert(strlen(ifname) <= IFNAMSIZ);

    struct ifreq ifr = {};
    int fd, ret;

    fd = socket(PF_PACKET, SOCK_RAW, 0);
    if (fd < 0) {
        perror("socket");
        return errno;
    }

    memcpy(ifr.ifr_name, ifname, strlen(ifname));

    ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
    if (ret) {
        perror("ioctl(SIOCGIFHWADDR)");
        ret = errno;
    } else {
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    }
    close(fd);
    return ret;
}

static int send_pppoe_pkt(int sfd, uint16_t id, uint8_t *h_source, uint8_t *h_dest, uint8_t *data, size_t nbytes)
{
    assert(id);
    assert(h_source);
    assert(h_dest);
    assert(data);
    assert(nbytes);
    assert(nbytes <= PPPOE_PAYLOAD_LEN);

    size_t pkt_len = ETH_HLEN + PPPOE_HEADER_LEN + nbytes;
    struct pppoe_pkt pkt = {
        .version = PPPOE_VER,
        .type = PPPOE_TYPE,
        .code = 0,
        .session_id = htons(id),
        .payload_len = htons(nbytes),
    };
    void *ppkt = &pkt;
    size_t sent = 0;

    pkt.ehdr.h_proto = htons(ETH_P_PPP_SES);
    memcpy(pkt.ehdr.h_source, h_source, ETH_ALEN);
    memcpy(pkt.ehdr.h_dest, h_dest, ETH_ALEN);
    memcpy(pkt.payload, data, nbytes);

    while (sent < pkt_len) {
        ssize_t nb = send(sfd, ppkt + sent, pkt_len - sent, 0);
        if (nb < 0) {
            if (errno == EINTR)
                continue;
            perror("send");
            return errno;
        }
        sent += nb;
    }
    return 0;
}

static int pppoe_sess_pkt_send(struct app_options *opt, uint8_t *mac, int sfd)
{
    assert(opt);
    assert(mac);
    assert(sfd >= 0);

    uint8_t buf[PPPOE_PAYLOAD_LEN];
    int ret = 0;
    size_t nb;

    for (;;) {
        nb = fread(buf, 1, sizeof(buf), stdin);

        if (nb == 0 && feof(stdin))
            break;

        if (nb == 0 && ferror(stdin)) {
            /* TODO: possible to get actual error code? */
            ret = -EINVAL;
            break;
        }

        assert(nb > 0);

        ret = send_pppoe_pkt(sfd, opt->session_id, mac, opt->peer_mac, buf, nb);
        if (ret)
            break;
    }

    return ret;
}

static int pppoe_sess_pkt_recv(struct app_options *opt, int sfd)
{
    assert(opt);
    assert(sfd >= 0);
    /* TODO */
    return -ENOSYS;
}

static int pppoe_sess_pkt(struct app_options *opt)
{
    assert(opt);
    uint8_t my_mac[6];
    int fd = -1, ret;

    ret = socket_raw(opt->ifname, &fd);
    if (ret)
        return ret;
    assert(fd >= 0);

    ret = get_hwaddr(opt->ifname, my_mac);
    if (ret)
        goto out;

    ret = opt->send_mode ? pppoe_sess_pkt_send(opt, my_mac, fd) : pppoe_sess_pkt_recv(opt, fd);

out:
    if (fd >= 0) close(fd);
    return ret;
}

static void show_usage(const char *myname)
{
    printf("Name:     %s\n", myname);
    printf("Desc:     send and receive PPPoE session packets\n");
    printf("Usage:    %s [options] <ifname>\n", myname);
    printf("\n");
    printf("          -h    print this usage information\n");
    printf("          -R    recv mode (default is to send)\n");
    printf("          -m    peer MAC address\n");
    printf("          -i    PPPoE session ID\n");
    printf("\n");
    printf("          Operation modes:\n");
    printf("\n");
    printf("          In send mode, data is read from stdin, wrapped in a PPPoE session header,\n");
    printf("          and transmitted to the specified peer over the specified network interface.\n");
    printf("          The caller MUST provide peer MAC address and PPPoE session ID.\n");
    printf("          If the data on stdin exceeds the size of a PPPoE session packet payload, it is\n");
    printf("          automatically segmented into multiple packets.\n");
    printf("          The exit code is zero if the input data was successfully transmitted.\n");
    printf("\n");
    printf("          In recv mode, data is read from PPPoE session packets received on the specified\n");
    printf("          network interface, and the data payload written to stdout\n");
    printf("          The caller MAY provide peer MAC address and PPPoE session ID, in which case any\n");
    printf("          PPPoE session packets received from other peers or with other session IDs are ignored.\n");
    printf("          In recv mode the program must be signalled to cause it to exit.  The exit code is zero\n");
    printf("          unless setup or recv errors cause the program to exit early.\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    struct app_options options = {
        .send_mode = true,
    };
    int opt;

    while ((opt = getopt(argc, argv, "hRm:i:")) != -1) {
        switch(opt) {
        case 'h':
            show_usage(argv[0]);
            exit(EXIT_SUCCESS);
        case 'R':
            options.send_mode = false;
            break;
        case 'm':
            if (6 != sscanf(optarg,
                        "%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8,
                        &options.peer_mac[0], &options.peer_mac[1],
                        &options.peer_mac[2], &options.peer_mac[3],
                        &options.peer_mac[4], &options.peer_mac[5]))
                die("Failed to parse peer MAC address \"%s\"\n", optarg);
            options.peer_mac_set = true;
            break;
        case 'i':
            options.session_id = atoi(optarg);
            break;
        }
    }

    /* We need interface name in all cases */
    if (optind < argc)
        options.ifname = argv[optind];
    else
        die("No interface name specified\n");

    if (strlen(options.ifname) > IFNAMSIZ)
        die("Interface name is invalid (too long)\n");

    /* Sanity check send options: recv mode only needs ifname */
    if (options.send_mode) {
        if (!options.peer_mac_set)
            die("Must specify a peer MAC address in send mode\n");
        if (options.session_id == 0)
            die("Must specify a non-zero PPPoE ID in send mode\n");
    }

    return pppoe_sess_pkt(&options) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

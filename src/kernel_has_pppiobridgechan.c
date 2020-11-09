#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#include "util.h"

static void show_usage(const char *myname)
{
    printf("Name:     %s\n", myname);
    printf("Desc:     check whether kernel supports PPPIOCBRIDGECHAN\n");
    printf("Usage:    %s [options]\n", myname);
    printf("\n");
    printf("          -N    specify session interface name\n");
    printf("          -i    specify PPPoE session ID\n");
    printf("          -M    specify PPPoE peer MAC address\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    struct l2tp_options opt = {
        .l2tp_version   = 2,
        .create_api = L2TP_SOCKET_API,
        .delete_api = L2TP_SOCKET_API,
        .family     = AF_INET,
        .protocol   = IPPROTO_UDP,
        .pseudowire = L2TP_API_SESSION_PW_TYPE_PPP_AC,
        .tid = brandom(1,65535),
        .ptid = brandom(1,65535),
        .sid = brandom(1,65535),
        .psid = brandom(1,65535),
        .peer_addr = *gen_dflt_address(AF_INET, false),
        .local_addr = *gen_dflt_address(AF_INET, true),
    };
    struct l2tp_pw pw = INIT_L2TP_PW;
    int o, tfd, pppsk;

    while ((o = getopt(argc, argv, "hN:i:M:")) != -1) {
        switch(o) {
            case 'h':
                show_usage(argv[0]);
                exit(EXIT_SUCCESS);
            case 'N':
                if (strlen(optarg) > sizeof(opt.ifname)-1)
                    die("Interface name \"%s\" is too long\n", optarg);
                memcpy(opt.ifname, optarg, strlen(optarg));
                break;
            case 'i':
                opt.pw.pppac.id = atoi(optarg);
                break;
            case 'M':
                if (6 != sscanf(optarg,
                            "%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8":%2"SCNx8,
                            &opt.pw.pppac.peer_mac[0],
                            &opt.pw.pppac.peer_mac[1],
                            &opt.pw.pppac.peer_mac[2],
                            &opt.pw.pppac.peer_mac[3],
                            &opt.pw.pppac.peer_mac[4],
                            &opt.pw.pppac.peer_mac[5]))
                    die("Failed to parse MAC address \"%s\"\n", optarg);
                break;
            default:
                die("failed to parse command line args\n");
        }
    }

    if (!strlen(opt.ifname) || !opt.pw.pppac.id) {
        die("must specify interface name, session ID, and peer MAC\n");
    }

    tfd = tunnel_socket(opt.family, opt.protocol, opt.tid, &opt.local_addr, &opt.peer_addr);
    if (tfd < 0) {
        die("failed to open tunnel socket\n");
    }

    if (0 != kernel_tunnel_create(tfd, &opt, &pppsk)) {
        die("failed to create tunnel instance\n");
    }

    if (0 != kernel_session_create(&opt, &pw)) {
        die("failed to create session instance\n");
    }

    return 0;
}

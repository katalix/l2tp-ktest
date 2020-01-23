/**
 * @file tunl_delete_race.c
 *
 * Race netlink tunnel delete requests with tunnel socket close(2).
 */
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>

#include "l2tp_netlink.h"
#include "util.h"

static void *t_nl_close(size_t id, struct racing_threads_tunnel_info *ti, void *dptr)
{
    assert(ti);
    dbg("%s: nl delete tid %" PRIu32 "\n", __func__, ti->tid);
    l2tp_nl_tunnel_delete(ti->tid);
    return NULL;
}

static void *t_sk_close(size_t id, struct racing_threads_tunnel_info *ti, void *dptr)
{
    assert(ti);
    /* netlink requests are more time consuming than close(2), so sleep a little
     * to give the other thread a chance to get in first in some cases.
     */
    usleep(brandom(0,10000));
    dbg("%s: close fd %d\n", __func__, ti->tunnel_socket_fd);
    close(ti->tunnel_socket_fd);
    return NULL;
}

static void show_usage(const char *myname)
{
   printf("Name:     %s\n", myname);
   printf("Desc:     stresses tunnel deletion with racing threads\n");
   printf("Usage:    %s [options]\n", myname);
   printf("          -h    print this usage information\n");
   printf("          -c    number of tunnels to create per testcase\n");
}

int main(int argc, char **argv)
{
    int tunnel_count = 100;
    int opt;

    while ((opt = getopt(argc, argv, "hc:")) != -1) {
        switch(opt) {
        case 'h':
            show_usage(argv[0]);
            exit(EXIT_SUCCESS);
        case 'c':
            tunnel_count = atoi(optarg);
            break;
        default:
            die("failed to parse command line args\n");
        }
    }

    if (tunnel_count < 0)
        die("command line error: invalid specification for tunnel count or iterations\n");

    log("Running %i racing tunnels: expect to see netlink errors...\n", tunnel_count);
    tunl_racing_threads(tunnel_count, NULL, 0, t_nl_close, NULL, t_sk_close, NULL);
    log("OK\n");

    return 0;
}

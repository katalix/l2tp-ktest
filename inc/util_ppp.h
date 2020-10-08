/**
 * @file util_ppp.h
 *
 * Shared ppp utility functions for test programs.
 */
#ifndef UTIL_PPP_H
#define UTIL_PPP_H

/**
 * Sockets and indices associated with the ppp subsystem.
 */
struct ppp {
    struct {
        int pppox;      /** convenience storage of the AF_PPPOX socket, not directly set here */
        int ppp;        /** fd of the /dev/ppp instance attached to the channel */
        int unit;       /** fd of the /dev/ppp instance for the unit (netdev) */
    } fd;
    struct {
        int channel;    /** channel index */
        int unit;       /** unit index */
    } idx;
};

#define INIT_PPP { \
    .fd = { \
        .pppox = -1, \
        .ppp = -1, \
        .unit = -1, \
    }, \
    .idx = {0}, \
}
#define ppp_init(_p) do { \
    struct ppp _init = INIT_PPP; \
    *(_p) = _init; \
} while(0)

/**
 * Open /dev/ppp, and call PPPIOCATTCHAN to associate
 * the input channel socket with the /dev/ppp instance.
 * struct ppp @fd.ppp and @idx.channel are set on success.
 *  @param  pppox_fd        AF_PPPOX socket for the channel
 *  @param  ppp             ppp instance
 *  @return                 0 on success, negative errno otherwise
 */
int ppp_associate_channel(int pppox_fd, struct ppp *ppp);

/**
 * Open /dev/ppp, and call PPPIOCNEWUNIT to create a new
 * ppp unit (netdev) instance.
 * struct ppp @fd.unit and @idx.unit are set on success.
 *  @param  ppp             ppp instance
 *  @return                 0 on success, negative errno otherwise
 */
int ppp_new_unit(struct ppp *ppp);

/**
 * Connect a channel to a ppp unit using PPPIOCCONNECT.
 * struct ppp @fd.ppp and @idx.unit must be set.
 *  @param  ppp             ppp instance
 *  @return                 0 on success, negative errno otherwise
 */
int ppp_connect_channel(struct ppp *ppp);

/**
 * Calls ppp_associate_channel, ppp_new_unit, and ppp_connect_channel
 * to create a new ppp netdev connected to the input channel socket.
 * The channl socket should be any AF_PPPOX socket.
 *  @param  pppox_fd        AF_PPPOX socket for the channel
 *  @param  ppp             ppp instance
 *  @return                 0 on success, negative errno otherwise
 */
int ppp_establish_pppox(int pppox_fd, struct ppp *ppp);

/**
 * Bridge one ppp channel to another using PPPIOCBRIDGECHAN.
 * struct ppp @fd.ppp must be set in both instances.
 *  @param  ppp1            ppp channel to bridge
 *  @param  ppp2            ppp channel to bridge
 *  @return                 0 on success, negative errno otherwise
 */
int ppp_bridge_channels(struct ppp *ppp1, struct ppp *ppp2);

/**
 * Close all resources associated with a ppp instance.
 *  @param  ppp             ppp instance
 */
void ppp_close(struct ppp *ppp);

#endif /* UTIL_PPP_H */

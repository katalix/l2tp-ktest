/*
 * SPDX-License-Identifier: BSD
 *
 * PPP support code. Derived from pppd's sys-linux.c:
 *
 * Copyright (c) 1994-2004 Paul Mackerras. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 3. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Paul Mackerras
 *     <paulus@samba.org>".
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Derived from main.c and pppd.h, which are:
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>

#include "util.h"
#include "util_ppp.h"

/*
 * make_ppp_unit - make a new ppp unit.
 */
#if 0
static int make_ppp_unit()
{
    int ifunit = -1;
    int flags, fd;

    fd = open("/dev/ppp", O_RDWR);
    if (fd < 0) {
        err("Couldn't open /dev/ppp: %m\n");
        return -errno;
    }

    flags = fcntl(fd, F_GETFL);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        err("Couldn't set /dev/ppp to nonblock: %m\n");
        return -errno;
    }

    if (ioctl(fd, PPPIOCNEWUNIT, &ifunit) < 0) {
        err("Couldn't create new ppp unit: %m\n");
        return -errno;
    }

    return ifunit;
}
#endif

/********************************************************************
 *
 * generic_establish_ppp - Turn the fd into a ppp interface.
 */
#if 0
int ppp_generic_establish_ppp(int fd, int *unit)
{
    int flags, ifunit;
    int chindex = 0;

    /* Open an instance of /dev/ppp and connect the channel to it */
    if (ioctl(fd, PPPIOCGCHAN, &chindex) == -1) {
        err("Couldn't get channel number: %m\n");
        goto err;
    }
    dbg("using channel %d\n", chindex);

    fd = open("/dev/ppp", O_RDWR);
    if (fd < 0) {
        err("Couldn't reopen /dev/ppp: %m\n");
        goto err;
    }

    if (ioctl(fd, PPPIOCATTCHAN, &chindex) < 0) {
        err("Couldn't attach to channel %d: %m", chindex);
        goto err_close;
    }

    flags = fcntl(fd, F_GETFL);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        err("Couldn't set /dev/ppp (channel) to nonblock: %m");

    /*
     * Create a new PPP unit.
     */
    ifunit = make_ppp_unit();
    if (ifunit < 0)
        goto err_close;

    if (ioctl(fd, PPPIOCCONNECT, &ifunit) < 0) {
        err("Couldn't attach to PPP unit %d: %m", ifunit);
        goto err_close;
    }

    if (unit) {
        *unit = ifunit;
    }

    return fd;

err_close:
    close(fd);
err:
    return -1;
}
#endif

/********************************************************************
 *
 * output_packet - Output PPP packet.
 */

void ppp_output_packet(int fd, unsigned char *p, int len)
{
    if (len < PPP_HDRLEN)
        return;

    p += 2;
    len -= 2;

    if (write(fd, p, len) < 0) {
        if (!(errno == EWOULDBLOCK ||
                errno == EAGAIN ||
                errno == ENOBUFS ||
                errno == ENXIO ||
                errno == EIO ||
                errno == EINTR)) {
            err("write: %m (%d)\n", errno);
        }
    }
}

/********************************************************************
 *
 * read_packet - get a PPP packet from the serial device.
 */

int ppp_read_packet(int fd, unsigned char *buf)
{
    int len, nr;

    len = PPP_MRU + PPP_HDRLEN;
    *buf++ = PPP_ALLSTATIONS;
    *buf++ = PPP_UI;
    len -= 2;

    nr = read(fd, buf, len);
    if (nr < 0 && errno != EWOULDBLOCK && errno != EAGAIN
            && errno != EIO && errno != EINTR)
        err("read: %m\n");
    if (nr < 0 && errno == ENXIO)
        return 0;

    return (nr > 0)? nr+2: nr;
}

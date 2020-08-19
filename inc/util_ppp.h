/**
 * @file util_ppp.h
 *
 * Shared ppp utility functions for test programs.
 */
#ifndef UTIL_PPP_H
#define UTIL_PPP_H

int ppp_generic_establish_ppp(int fd, int *unit);
void ppp_output_packet(int fd, unsigned char *p, int len);
int ppp_read_packet(int fd, unsigned char *buf);

#endif /* UTIL_PPP_H */

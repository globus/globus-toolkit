
#ifndef __RADIX_H__
#define __RADIX_H__

int radix_encode(unsigned char inbuf[],
                 unsigned char outbuf[],
                 int *len, int decode);

char * radix_error(int e);

#endif

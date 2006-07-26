/*	$OpenBSD: buffer.h,v 1.13 2005/03/14 11:46:56 markus Exp $	*/

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Code for manipulating FIFO buffers.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef BUFFER_H
#define BUFFER_H

typedef struct {
	u_char	*buf;		/* Buffer for data. */
	u_int	 alloc;		/* Number of bytes allocated for data. */
	u_int	 offset;	/* Offset of first byte containing data. */
	u_int	 end;		/* Offset of last byte containing data. */
}       Buffer;

#define	BUFFER_MAX_CHUNK	0x100000  /*1MB*/
#define	BUFFER_MAX_LEN		0xa00000  /*10MB*/

/* this value for BUFFER_MAX_HPN_LEN is */
/* still undersized for the faster networks */
/* it might make sense to have yet another */
/* MAX_LEN for 10+GB networks. Something closer to */
/* 128MB or 192MB -cjr*/
#define	BUFFER_MAX_HPN_LEN	0x2000000 /*32MB*/

void	 buffer_init(Buffer *);
void	 buffer_clear(Buffer *);
void	 buffer_free(Buffer *);

u_int	 buffer_len(Buffer *);
void	*buffer_ptr(Buffer *);

void	 buffer_append(Buffer *, const void *, u_int);
void	*buffer_append_space(Buffer *, u_int);

void	 buffer_get(Buffer *, void *, u_int);

void	 buffer_consume(Buffer *, u_int);
void	 buffer_consume_end(Buffer *, u_int);

void     buffer_dump(Buffer *);

int	 buffer_get_ret(Buffer *, void *, u_int);
int	 buffer_consume_ret(Buffer *, u_int);
int	 buffer_consume_end_ret(Buffer *, u_int);

#endif				/* BUFFER_H */

/*
 * AFS support routines for wuftpd
 */

#include "config.h"

#ifdef AFS

/*
 * Most of this code taken from krb5/appl/bsd/login.c patched
 * with Ken Hornstein's monster patch.
 */

/* Set to 1 if we got a pagsh */
static int pagflag = 0;

/* These routines are Transarc or libkrbafs specific */
static int setpag_internal();
static int unlog_internal();


int
afs_pagsh()
{
    pagflag = setpag_internal();
    
    return 0;
}

int
afs_logout()
{
    return unlog_internal();
}

#ifdef HAVE_LIBKRBAFS
/* libkrb5afs library */

static int setpag_internal()
{
    int retval = 0;

    if (k_hasafs()) {
 	k_setpag();
 	k_unlog();
	retval = 1;
    }
    
    return retval;
}
 
static int unlog_internal()
{
    k_unlog();
    return(0);
}

#else /* !HAVE_LIBKRBAFS */

#include <signal.h>

/* XXX Do we always want this or just if we have POSIX_SETJMP? */
#include <setjmp.h>

/* Transarc AFS libraries */
#ifndef POSIX_SETJMP

#undef sigjmp_buf
#undef sigsetjmp
#undef siglongjmp
#define sigjmp_buf	jmp_buf
#define sigsetjmp(j,s)	setjmp(j)
#define siglongjmp	longjmp

#endif /* !POSIX_SETJMP */

#if !defined(SIGSYS) && defined(__linux__)
/* Linux doesn't seem to have SIGSYS */
#define SIGSYS	SIGUNUSED
#endif

#ifdef POSIX_SIGNALS

typedef struct sigaction handler;
#define handler_init(H,F)		(sigemptyset(&(H).sa_mask), \
					 (H).sa_flags=0, \
					 (H).sa_handler=(F))
#define handler_swap(S,NEW,OLD)		sigaction(S, &NEW, &OLD)
#define handler_set(S,OLD)		sigaction(S, &OLD, NULL)

#else /* !POSIX_SIGNALS */

/* XXX - I think this code is broken VW 4/21/00 */

typedef RETSIGTYPE (*handler)();
#define handler_init(H,F)		((H) = (F))
#define handler_swap(S,NEW,OLD)		((OLD) = signal ((S), (NEW)))
#define handler_set(S,OLD)		(signal ((S), (OLD)))

#endif /* !POSIX_SIGNALS */

extern setpag(), ktc_ForgetAllTokens();

static sigjmp_buf setpag_buf;

static RETSIGTYPE sigsys ()
{
    siglongjmp(setpag_buf, 1);
}

static int try_afscall(scall)
	int (*scall)();
{
	handler sa, osa;
	volatile int retval = 0;

	(void) &retval;
	handler_init(sa, sigsys);
	handler_swap(SIGSYS, sa, osa);
	if (sigsetjmp(setpag_buf, 1) == 0) {
	    (*scall)();
	    retval = 1;
	}
	handler_set(SIGSYS, osa);
	return retval;
}

static int setpag_internal()
{
    return try_afscall(setpag);
}

static int unlog_internal()
{
    return try_afscall(ktc_ForgetAllTokens);
}

#endif  /* !HAVE_LIBKRBAFS */

#endif /* AFS */
 

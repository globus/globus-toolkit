/* syshdrs.h
 * 
 * Copyright (c) 1992-1999 by Mike Gleason, NCEMRSoft.
 * All rights reserved.
 * 
 */

#ifdef HAVE_CONFIG_H
#	include <config.h>
#endif

#if defined(AIX) || defined(_AIX)
#	define _ALL_SOURCE 1
#endif

#if defined(HPUX) || defined(_HPUX_SOURCE)
#	ifndef _XOPEN_SOURCE_EXTENDED
#		define _XOPEN_SOURCE_EXTENDED 1
#	endif
#endif

#ifdef HAVE_UNISTD_H
#	include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>

#ifdef CAN_USE_SYS_SELECT_H
#	include <sys/select.h>
#endif

#if defined(HAVE_SYS_UTSNAME_H) && defined(HAVE_UNAME)
#	include <sys/utsname.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#	include <strings.h>
#endif
#include <stddef.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <setjmp.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <pwd.h>
#include <fcntl.h>

#ifdef HAVE_LOCALE_H
#	include <locale.h>
#endif

#ifdef HAVE_NCURSES_H
#	include <ncurses.h>
#else
#	ifdef HAVE_CURSES_H
#		include <curses.h>
#	endif
#endif

/* These next two sections are mostly for HP-UX. */
#if defined(HAVE___GETMAXX) && !defined(HAVE_GETMAXX) && !defined(getmaxx)
#	define HAVE_GETMAXX 1
#	define getmaxx __getmaxx
#endif
#if defined(HAVE___GETMAXY) && !defined(HAVE_GETMAXY) && !defined(getmaxy)
#	define HAVE_GETMAXY 1
#	define getmaxy __getmaxy
#endif
#if defined(HAVE___GETMAXY) && defined(HAVE___GETMAXX) && !defined(HAVE_GETMAXYX) && !defined(getmaxyx)
#	define HAVE_GETMAXYX 1
#	define getmaxyx(__win,__y,__x) { WINDOW *__wi; __wi = __win; ((__y) = __getmaxy(__wi), (__x) = __getmaxx(__wi)); }
#endif

#if defined(HAVE___GETBEGX) && !defined(HAVE_GETBEGX) && !defined(getbegx)
#	define HAVE_GETBEGX 1
#	define getbegx __getbegx
#endif
#if defined(HAVE___GETBEGY) && !defined(HAVE_GETBEGY) && !defined(getbegy)
#	define HAVE_GETBEGY 1
#	define getbegy __getbegy
#endif
#if defined(HAVE___GETBEGY) && defined(HAVE___GETBEGX) && !defined(HAVE_GETBEGYX) && !defined(getbegyx)
#	define HAVE_GETBEGYX 1
#	define getbegyx(__win,__y,__x) { WINDOW *__wi; __wi = __win; ((__y) = __getbegy(__wi), (__x) = __getbegx(__wi)); }
#endif

/* Otherwise, try accessing the structure directly. */
#ifndef HAVE_GETMAXYX
#	ifdef HAVE__MAXX
#		ifndef getmaxyx
#			define getmaxyx(w,y,x) y = w->_maxy;  x = w->_maxx;
#		endif
#		ifndef getbegyx
#			define getbegyx(w,y,x) y = w->_begy;  x = w->_begx;
#		endif
#	else
#		ifndef getmaxyx
#			define getmaxyx(w,y,x) y = w->maxy;  x = w->maxx;
#		endif
#		ifndef getbegyx
#			define getbegyx(w,y,x) y = w->begy;  x = w->begx;
#		endif
#	endif
#endif

#ifndef HAVE_GETMAXX
#	ifdef HAVE__MAXX
#		ifndef getmaxy
#			define getmaxy(win) ((win)->_maxy)
#		endif
#		ifndef getmaxx
#			define getmaxx(win) ((win)->_maxx)
#		endif
#	else
#		ifndef getmaxy
#			define getmaxy(win) ((win)->maxy)
#		endif
#		ifndef getmaxx
#			define getmaxx(win) ((win)->maxx)
#		endif
#	endif
#endif

#ifndef HAVE_GETBEGX
#	ifdef HAVE__MAXX
#		ifndef getbegy
#			define getbegy(win) ((win)->_begy)
#		endif
#		ifndef getbegx
#			define getbegx(win) ((win)->_begx)
#		endif
#	else
#		ifndef getbegy
#			define getbegy(win) ((win)->begy)
#		endif
#		ifndef getbegx
#			define getbegx(win) ((win)->begx)
#		endif
#	endif
#endif

#ifndef HAVE_TOUCHWIN
#	ifdef HAVE__MAXX
#		ifndef touchwin
#			define touchwin(win) wtouchln((win), 0, (win)->_maxy, 1)
#		endif
#	else
#		ifndef touchwin
#			define touchwin(win) wtouchln((win), 0, (win)->maxy, 1)
#		endif
#	endif
#endif

#ifndef HAVE_CURS_SET
#	ifndef curs_set
#		define curs_set(a)
#	endif
#endif

#ifdef HAVE_DOUPDATE
#	define DOUPDATE(a) doupdate()
#else
#	define DOUPDATE(a)
#endif

#ifndef HAVE_NODELAY
#	ifndef nodelay
#		define nodelay(win,boolval)
#	endif
#endif

#ifndef HAVE_WNOUTREFRESH
#	ifndef wnoutrefresh
#		define wnoutrefresh wrefresh
#	endif
#endif

#ifndef HAVE_KEYPAD
#	ifndef keypad
#		define keypad(win,boolval)
#	endif
#endif

#ifdef HAVE_BEEP
#	define BEEP(a)	beep()
#else
#	define BEEP(a)
#endif

#define NDEBUG 1			/* For assertions. */

#if defined(HAVE_LONG_LONG) && defined(HAVE_OPEN64)
#	define Open open64
#else
#	define Open open
#endif

#if defined(HAVE_LONG_LONG) && defined(HAVE_STAT64) && defined(HAVE_STRUCT_STAT64)
#	define Stat stat64
#	ifdef HAVE_FSTAT64
#		define Fstat fstat64
#	else
#		define Fstat fstat
#	endif
#	ifdef HAVE_LSTAT64
#		define Lstat lstat64
#	else
#		define Lstat lstat
#	endif
#else
#	define Stat stat
#	define Fstat fstat
#	define Lstat lstat
#endif

#if defined(HAVE_LONG_LONG) && defined(HAVE_LSEEK64)
#	define Lseek(a,b,c) lseek64(a, (longest_int) b, c)
#elif defined(HAVE_LONG_LONG) && defined(HAVE_LLSEEK)
#	if 1
#		if defined(LINUX) && (LINUX <= 23000)
#			define Lseek(a,b,c) lseek(a, (off_t) b, c)
#		else
#			define Lseek(a,b,c) llseek(a, (longest_int) b, c)
#		endif
#	else
#		define Lseek(a,b,c) lseek(a, (off_t) b, c)
#	endif
#else
#	define Lseek(a,b,c) lseek(a, (off_t) b, c)
#endif

#include <Strn.h>			/* Library header. */
#include <ncftp.h>			/* Mostly for utility routines it has. */

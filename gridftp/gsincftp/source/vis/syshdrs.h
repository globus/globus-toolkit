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

#include <Strn.h>			/* Library header. */
#include <ncftp.h>			/* Mostly for utility routines it has. */

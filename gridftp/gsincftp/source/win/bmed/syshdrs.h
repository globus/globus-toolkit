/* syshdrs.h
 *
 * Copyright (c) 1992-1999 by Mike Gleason.
 * All rights reserved.
 * 
 */

#if defined(HAVE_CONFIG_H)
#	include <config.h>
#endif

#if defined(WIN32) || defined(_WINDOWS)
#	include <windows.h>
#	include <stdio.h>
#	include <string.h>
#	include <stddef.h>
#	include <stdlib.h>
#	include <ctype.h>
#	include <stdarg.h>
#	include <time.h>
#	include <io.h>
#	include <sys/types.h>
#	include <sys/stat.h>
#	include <fcntl.h>
#	include <errno.h>
#	define strcasecmp stricmp
#	define strncasecmp strnicmp
#	define sleep(a) Sleep(a * 1000)
#	ifndef FOPEN_READ_TEXT
#		define FOPEN_READ_TEXT "rt"
#		define FOPEN_WRITE_TEXT "wt"
#		define FOPEN_APPEND_TEXT "at"
#	ifndef S_ISREG
#		define S_ISREG(m)      (((m) & _S_IFMT) == _S_IFREG)
#		define S_ISDIR(m)      (((m) & _S_IFMT) == _S_IFDIR)
#	endif
#	define uid_t int
#	endif
#else	/* UNIX */
#	error "This version is for Windows only."
#endif	/* UNIX */

#include <Strn.h>			/* Library header. */

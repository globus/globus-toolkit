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
#	define SELECT_TYPE_ARG1 int
#	define SELECT_TYPE_ARG234 (fd_set *)
#	define SELECT_TYPE_ARG5 (struct timeval *)
#	define STDC_HEADERS 1
#	define HAVE_GETHOSTNAME 1
#	define HAVE_MKTIME 1
#	define HAVE_SOCKET 1
#	define HAVE_STRSTR 1
#	define HAVE_MEMMOVE 1
#	define HAVE_LONG_FILE_NAMES 1
#	pragma warning( push, 3 )
#	include <winsock2.h>	/* Includes <windows.h> */
#	include <shlobj.h>
#	include <tchar.h>
#	include <process.h>
#	define _WIN32_IE 0x0400
#	include <commctrl.h>
#	ifdef HAVE_UNISTD_H
#		include <unistd.h>
#	endif
#	include <errno.h>
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
#	include <signal.h>
#	include <assert.h>
#	define strcasecmp stricmp
#	define strncasecmp strnicmp
#	define sleep WinSleep
#	ifndef S_ISREG
#		define S_ISREG(m)      (((m) & _S_IFMT) == _S_IFREG)
#		define S_ISDIR(m)      (((m) & _S_IFMT) == _S_IFDIR)
#	endif
#	ifndef open
#		define open _open
#		define write _write
#		define read _read
#		define close _close
#		define lseek _lseek
#		define stat _stat
#		define lstat _stat
#		define fstat _fstat
#		define dup _dup
#		define utime _utime
#		define utimbuf _utimbuf
#		define chdir _chdir
#	endif
#	ifndef unlink
#		define unlink remove
#	endif
#	define uid_t int
#	define NO_SIGNALS 1
#	define USE_SIO 1
#	ifndef FOPEN_READ_TEXT
#		define FOPEN_READ_TEXT "rt"
#		define FOPEN_WRITE_TEXT "wt"
#		define FOPEN_APPEND_TEXT "at"
#	endif
#	pragma warning( pop )
#else	/* UNIX */
#	if defined(AIX) || defined(_AIX)
#		define _ALL_SOURCE 1
#	endif
#	ifdef HAVE_UNISTD_H
#		include <unistd.h>
#	endif
#	include <sys/types.h>
#	include <sys/stat.h>
#	include <sys/socket.h>
#	include <sys/wait.h>
#	ifdef CAN_USE_SYS_SELECT_H
#		include <sys/select.h>
#	endif
#	if defined(HAVE_SYS_UTSNAME_H) && defined(HAVE_UNAME)
#		include <sys/utsname.h>
#	endif
#	include <netinet/in.h>
#	include <arpa/inet.h>
#	include <netdb.h>
#	include <errno.h>
#	include <stdio.h>
#	include <string.h>
#	include <stddef.h>
#	include <stdlib.h>
#	include <ctype.h>
#	include <signal.h>
#	include <setjmp.h>
#	include <stdarg.h>
#	include <assert.h>
#	include <time.h>
#	include <pwd.h>
#	include <fcntl.h>
#	include <dirent.h>
#	ifdef HAVE_LOCALE_H
#		include <locale.h>
#	endif
#	ifdef HAVE_GETCWD
#		ifndef HAVE_UNISTD_H
			extern char *getcwd();
#		endif
#	else
#		ifdef HAVE_GETWD
#			include <sys/param.h>
#			ifndef MAXPATHLEN
#				define MAXPATHLEN 1024
#			endif
			extern char *getwd(char *);
#		endif
#	endif
#	ifndef FOPEN_READ_TEXT
#		define FOPEN_READ_TEXT "r"
#		define FOPEN_WRITE_TEXT "w"
#		define FOPEN_APPEND_TEXT "a"
#	endif
#	define DisposeWinsock(a) sleep(1)
#endif	/* UNIX */

#ifndef STDIN_FILENO
#	define STDIN_FILENO    0
#	define STDOUT_FILENO   1
#	define STDERR_FILENO   2
#endif

#define NDEBUG 1			/* For assertions. */


#include <Strn.h>			/* Library header. */
#include <ncftp.h>			/* Library header. */

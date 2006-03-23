/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

/**
 *  Defines the macros and typedefs common to all globus
 *  components.
 */
#if !defined(GLOBUS_CONFIG_H)
#define GLOBUS_CONFIG_H 1

/*
 * flavor dependent macros
 */

/* THREADING MODEL
 *
 * The following #define determines whether the Globus libraries use
 * a non-threaded approach or a threaded approach. This approach
 * affects data structures and function call mappings as well as
 * internal implementation.
 *
 * If you want to build a non-threaded application, uncomment out the
 * BUILD_LITE #define and comment out the HAVE_WINDOWS_THREADS #define.
 * Conversely, threaded applications require that HAVE_WINDOWS_THREADS
 * be defined and BUILD_LITE be commented out.
 * 
 * WARNING: The behavior of the Globus libraries is undefined if
 * neither BUILD_LITE nor HAVE_WINDOWS_THREADS is defined, or if
 * both are defined.
 */
//#define BUILD_LITE                  1
#define HAVE_WINDOWS_THREADS

/*
 * configure macros
 */
#define TARGET_ARCH_WIN32           1
#define _WIN32_WINNT                0x0500

#define HAVE_MEMMOVE                1
#define HAVE_STDARG_H               1
#define HAVE_SYS_TYPES_H            1
#define HAVE_SYS_STAT_H
#define HAVE_STRERROR

#define MAXPATHLEN                  128
#define MAXHOSTNAMELEN              128


/* windows does not have iovec */
#undef HAVE_STRUCT_IOVEC
#define IOV_MAX 1

/* Define as the return type of signal handlers (int or void).  */

#define RETSIGTYPE void
#define HAVE_SYS_WAIT_H 1
#define RETSIGTYPE void
#define STDC_HEADERS 1

#define GLOBUS_HAVE_DIRENT_OFF 1
#define GLOBUS_HAVE_DIRENT_TYPE 1
#define GLOBUS_HAVE_DIRENT_RECLEN 1

#define HAVE_ATEXIT 1

#define HAVE_WINSOCK_H     1
//#define GLOBUS_OFF_T DWORDLONG
#define GLOBUS_OFF_T LONGLONG
#define GLOBUS_OFF_T_FORMAT "I64d"
#define SIZEOF_OFF_T 8

#define SIZEOF_INT 4
#define SIZEOF_LONG 4
#define SIZEOF_SHORT 2

#define HAVE_CTIME 1

#define HAVE_INET_ADDR     1
#define HAVE_GETADDRINFO   1
#define HAVE_FREEADDRINFO  1
#define HAVE_GAI_STRERROR  1
#define HAVE_GETNAMEINFO   1

#define HAVE_GETHOSTBYADDR 1
#define HAVE_GETHOSTBYNAME 1

#define HAVE_GETHOSTNAME        1
#define HAVE_GETSERVBYNAME      1
#define HAVE_GETPROTOBYNUMBER   1
#define HAVE_INET_NTOA          1
#define HAVE_MKTIME             1

#define HAVE_MEMMOVE 1
#define HAVE_CTYPE_H 1

#define HAVE_FCNTL_H 1
#define HAVE_LIMITS_H 1

#define HAVE_SIGNAL_H 1
#define HAVE_STRING_H 1

#define HAVE_DIRECT_H 1

#define _FILE_OFFSET_BITS 64

#define GLOBUS_TRUE	    1
#define GLOBUS_FALSE	0
#define GLOBUS_NULL  	0
#define GLOBUS_FAILURE  -1
#define GLOBUS_SUCCESS  0

#endif /*GLOBUS_CONFIG_H*/


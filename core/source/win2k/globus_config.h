/**
 *  Defines the macros and typedefs common to all globus
 *  components.
 */
#if !defined(GLOBUS_CONFIG_H)
#define GLOBUS_CONFIG_H 1

/*
 * flavor dependent macros
 */
//#define BUILD_LITE                  1
#define HAVE_WINDOWS_THREADS

/*
 * configure macros
 */
#define TARGET_ARCH_WIN32           1

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
#define HAVE_NETINET_TCP_H 1#define HAVE_WINSOCK_H     1

#define GLOBUS_OFF_T DWORDLONG
#define GLOBUS_OFF_T_FORMAT "ld"
#define SIZEOF_OFF_T 8
#define SIZEOF_INT 4
#define SIZEOF_LONG 4
#define SIZEOF_SHORT 2
#define HAVE_CTIME 1
#define HAVE_GETHOSTBYADDR 1
#define HAVE_GETHOSTBYNAME 1
#define HAVE_MEMMOVE 1
#define HAVE_CTYPE_H 1

#define HAVE_FCNTL_H 1
#define HAVE_LIMITS_H 1
#define HAVE_SIGNAL_H 1
#define HAVE_STRING_H 1

#define _FILE_OFFSET_BITS 64
#define GLOBUS_TRUE	    1
#define GLOBUS_FALSE	0
#define GLOBUS_NULL  	0
#define GLOBUS_FAILURE  1
#define GLOBUS_SUCCESS  0

// POSIX error code remapping
// FOR NOW- leave it here
// TODO- MOVE THIS DEFINITION TO AN APPROPRIATE PLACE
#define EWOULDBLOCK EAGAIN

#endif /*GLOBUS_CONFIG_H*/

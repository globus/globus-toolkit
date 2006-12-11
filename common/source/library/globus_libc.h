/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/******************************************************************************
globus_libc.h

Description:
   Thread-safe libc macros, function prototypes

******************************************************************************/
#ifndef GLOBUS_INCLUDE_GLOBUS_LIBC_H_
#define GLOBUS_INCLUDE_GLOBUS_LIBC_H_ 1

#include "globus_common_include.h"
#include GLOBUS_THREAD_INCLUDE
#ifdef WIN32
/* For addrinfo struct */
#include <ws2tcpip.h>
#define EAI_SYSTEM 11
#define snprintf _snprintf
#endif

EXTERN_C_BEGIN

/*
 * Reentrant lock
 */
#ifdef BUILD_LITE

#define globus_macro_libc_lock() (0)
#define globus_macro_libc_unlock() (0)

#else  /* BUILD_LITE */

extern globus_mutex_t globus_libc_mutex;

#define globus_macro_libc_lock() \
    globus_mutex_lock(&globus_libc_mutex)
#define globus_macro_libc_unlock() \
    globus_mutex_unlock(&globus_libc_mutex)

#endif /* BUILD_LITE */

#ifdef USE_MACROS
#define globus_libc_lock()   globus_macro_libc_lock()
#define globus_libc_unlock() globus_macro_libc_unlock()
#else  /* USE_MACROS */
extern int globus_libc_lock(void);
extern int globus_libc_unlock(void);
#endif /* USE_MACROS */

#if defined(va_copy)
#   define globus_libc_va_copy(dest,src) \
        va_copy(dest,src)
#elif defined(__va_copy)
#   define globus_libc_va_copy(dest,src) \
        __va_copy(dest,src)
#else
#   define globus_libc_va_copy(dest,src) \
        memcpy(&dest, &src, sizeof(va_list))
#endif


#if !defined(HAVE_THREAD_SAFE_STDIO) && !defined(BUILD_LITE)
#   define globus_stdio_lock globus_libc_lock
#   define globus_stdio_unlock globus_libc_unlock
    extern int globus_libc_printf(const char *format, ...);
    extern int globus_libc_fprintf(FILE *strm, const char *format, ...);
    extern int globus_libc_sprintf(char *s, const char *format, ...);
    extern int globus_libc_vprintf(const char *format, va_list ap);
    extern int globus_libc_vfprintf(FILE *strm, const char *format,va_list ap);
    extern int globus_libc_vsprintf(char *s, const char *format,va_list ap);
#else
#   define globus_stdio_lock()
#   define globus_stdio_unlock()
#   define globus_libc_printf   printf
#   define globus_libc_fprintf  fprintf
#   define globus_libc_sprintf  sprintf
#   define globus_libc_vprintf  vprintf
#   define globus_libc_vfprintf vfprintf
#   define globus_libc_vsprintf vsprintf
#endif

#if ((!defined(HAVE_THREAD_SAFE_STDIO) && !defined(BUILD_LITE)) || (!defined(HAVE_SNPRINTF)))
    extern int globus_libc_snprintf(char *s, size_t n, const char *format,
				    ...);
#else
#   define globus_libc_snprintf snprintf
#endif

#if ((!defined(HAVE_THREAD_SAFE_STDIO) && !defined(BUILD_LITE)) || \
    (!defined(HAVE_VSNPRINTF)))
    extern int globus_libc_vsnprintf(char *s, size_t n, const char *format,
				     va_list ap);
#else
#   define globus_libc_vsnprintf vsnprintf
#endif

/*
 * File I/O routines
 *  These functions are not supported on the windwos platform
 */
#if !defined(TARGET_ARCH_WIN32)
#   if !defined(HAVE_THREAD_SAFE_SELECT) && !defined(BUILD_LITE)

extern int globus_libc_open(char *path, int flags, ... /*int mode*/);
extern int globus_libc_close(int fd);
extern int globus_libc_read(int fd, char *buf, int nbytes);
extern int globus_libc_write(int fd, char *buf, int nbytes);
extern int globus_libc_writev(int fd, struct iovec *iov, int iovcnt);
extern int globus_libc_fstat(int fd, struct stat *buf);
extern int globus_libc_umask(mode_t mask);

extern DIR *globus_libc_opendir(char *filename);
extern long globus_libc_telldir(DIR *dirp);
extern void globus_libc_seekdir(DIR *dirp, long loc);
extern void globus_libc_rewinddir(DIR *dirp);
extern void globus_libc_closedir(DIR *dirp);

#else  /* HAVE_THREAD_SAFE_SELECT */

#define globus_libc_open open
#define globus_libc_close close
#define globus_libc_read read
#define globus_libc_write write
#define globus_libc_umask umask
#if defined(HAVE_WRITEV)
#define globus_libc_writev writev
#else
#define globus_libc_writev(fd,iov,iovcnt) \
	    write(fd,iov[0].iov_base,iov[0].iov_len)
#endif
#define globus_libc_fstat fstat

#define globus_libc_opendir opendir
#define globus_libc_telldir telldir
#define globus_libc_seekdir seekdir
#define globus_libc_rewinddir rewinddir
#define globus_libc_closedir closedir

#endif /* HAVE_THREAD_SAFE_SELECT */

     int
     globus_libc_getpwuid_r(
        uid_t                           uid,
        struct passwd *                 pwd,
	    char *                          buffer,
	    int                             bufsize,
	    struct passwd **                result);

    int
    globus_libc_readdir_r(
        DIR *                           dirp,
        struct dirent **                result);

#else /* TARGET_ARCH_WIN32 */

extern
mode_t
globus_libc_umask_win32(
    mode_t                          mask); 

#    define globus_libc_open            _open
#    define globus_libc_close           _close
#    define globus_libc_read            _read
#    define globus_libc_write           _write
#    define globus_libc_umask           globus_libc_umask_win32
#           define globus_libc_writev(fd,iov,iovcnt) \
	            write(fd,iov[0].iov_base,iov[0].iov_len)
#   define uid_t int

/*
 * these are only on windows for now
 */
int
globus_libc_system_memory(
    globus_off_t *                  mem);

int
globus_libc_free_memory(
    globus_off_t *                  mem);

#endif /* TARGET_ARCH_WIN32 */

/*
 * Memory allocation routines
 */
#define globus_malloc(bytes) globus_libc_malloc(bytes)
#define globus_realloc(ptr,bytes) globus_libc_realloc(ptr,bytes)
#define globus_calloc(nobjs,bytes) globus_libc_calloc(nobjs,bytes)
#define globus_free(ptr) globus_libc_free(ptr)

#if !defined(BUILD_LITE)

extern void *globus_libc_malloc(size_t bytes);
extern void *globus_libc_realloc(void *ptr,
				 size_t bytes);
extern void *globus_libc_calloc(size_t nobj,
				size_t bytes);
extern void globus_libc_free(void *ptr);

extern void *globus_libc_alloca(size_t bytes);

#else  /* BUILD_LITE */

#define globus_libc_malloc	malloc
#define globus_libc_realloc	realloc
#define globus_libc_calloc	calloc
#define globus_libc_free	free

#define globus_libc_alloca	alloca

#endif /* BUILD_LITE */

#ifdef TARGET_ARCH_CRAYT3E
extern void *alloca(size_t bytes);
#endif /* TARGET_ARCH_CRAYT3E */

globus_byte_t *
globus_libc_memrchr(
    globus_byte_t *                         s,
    globus_byte_t                           c,
    globus_size_t                           n);

globus_byte_t *
globus_libc_memmem(
    globus_byte_t *                         haystack,
    globus_size_t                           h_len,
    globus_byte_t *                         needle,
    globus_size_t                           n_len);

/* Never a macro because globus_off_t must match largefile definition */
extern int globus_libc_lseek(int fd, globus_off_t offset, int whence);

/* Miscellaneous libc functions (formerly md_unix.c) */
int globus_libc_gethostname(char *name, int len);
int globus_libc_getpid(void);
int globus_libc_fork(void);
int globus_libc_usleep(long usec);
double globus_libc_wallclock(void);

/* returns # of characters printed to s */
extern int globus_libc_sprint_off_t(char * s, globus_off_t off);
/* returns 1 if scanned succeeded */
extern int globus_libc_scan_off_t(char *s, globus_off_t *off, int *consumed);

/* single interface to reentrant libc functions we use*/
struct hostent *globus_libc_gethostbyname_r(char *name,
					    struct hostent *result,
					    char *buffer,
					    int buflen,
					    int *h_errnop);
struct hostent *globus_libc_gethostbyaddr_r(char *addr,
					    int length,
					    int type,
					    struct hostent *result,
					    char *buffer,
					    int buflen,
					    int *h_errnop);

char *globus_libc_ctime_r(time_t *clock,
			  char *buf,
			  int buflen);

struct tm *
globus_libc_localtime_r(
    const time_t *timep, 
    struct tm *result);

struct tm *
globus_libc_gmtime_r(
    const time_t *timep, 
    struct tm *result);

int globus_libc_getpwnam_r(char *name,
			   struct passwd *pwd,
			   char *buffer,
			   int bufsize,
			   struct passwd **result);

int
globus_libc_strncasecmp(
    const char *                            s1,
    const char *                            s2,
    globus_size_t                           n);

int globus_libc_setenv(register const char *name,
		       register const char *value,
		       int rewrite);
void globus_libc_unsetenv(register const char *name);
char *globus_libc_getenv(register const char *name);

char *globus_libc_system_error_string(int the_error);

char *
globus_libc_strdup(const char * source);

char *
globus_libc_strndup(const char * string, globus_size_t length);

char *
globus_libc_strtok(
    char *                                  s, 
    const char *                            delim);

#define globus_libc_strcmp strcmp
#define globus_libc_strlen strlen

char *
globus_libc_join(
    const char **                       array,
    int                                 count);
    
int
globus_libc_vprintf_length(const char * fmt, va_list ap);

int
globus_libc_printf_length(const char * fmt, ...);

/* not really 'libc'... but a convenient place to put it in */
int globus_libc_gethomedir(char *result, int bufsize);

char *
globus_common_create_string(
    const char *                        format,
    ...);

char *
globus_common_create_nstring(
    int                                 length,
    const char *                        format,
    ...);

char *
globus_common_v_create_string(
    const char *                        format,
    va_list                             ap);

char *
globus_common_v_create_nstring(
    int                                 length,
    const char *                        format,
    va_list                             ap);

/* for backwards compatibility */
#define globus_libc_memmove(d, s, n) memmove((d), (s), (n)) 

#ifdef TARGET_ARCH_HPUX
#   define   globus_libc_setegid(a)  setresgid(-1,a,-1)
#   define   globus_libc_seteuid(a)  setresuid(-1,a,-1)
#else
#   define   globus_libc_setegid(a)  setegid(a)
#   define   globus_libc_seteuid(a)  seteuid(a)
#endif

#ifndef HAVE_GETADDRINFO
#ifndef AI_PASSIVE
# define AI_PASSIVE     0x0001
# define AI_CANONNAME   0x0002
# define AI_NUMERICHOST 0x0004

struct addrinfo
{
    int                                 ai_flags;
    int                                 ai_family;
    int                                 ai_socktype;
    int                                 ai_protocol;
    size_t                              ai_addrlen;
    struct sockaddr *                   ai_addr;
    char *                              ai_canonname;
    struct addrinfo *                   ai_next;
};
#endif

#define GLOBUS_IMPLEMENT_GETADDRINFO 1
#define HAVE_GETADDRINFO
int
getaddrinfo(
    const char *                        node,
    const char *                        service,
    const struct addrinfo *             hints,
    struct addrinfo **                  res);
#endif

#ifndef HAVE_FREEADDRINFO
#define HAVE_FREEADDRINFO 1
#define GLOBUS_IMPLEMENT_FREEADDRINFO 1
void
freeaddrinfo(struct addrinfo * res);
#endif

#ifndef HAVE_GAI_STRERROR
#define GLOBUS_IMPLEMENT_GAI_STRERROR 1
#define HAVE_GAI_STRERROR
const char * gai_strerror(int errorcode);
#endif

#ifndef HAVE_GETNAMEINFO
#define GLOBUS_IMPLEMENT_GETNAMEINFO 1
#define HAVE_GETNAMEINFO
int
getnameinfo(
    const struct sockaddr *             sa,
    globus_socklen_t                    sa_len,
    char *                              host,
    size_t                              hostlen,
    char *                              serv,
    size_t                              servlen,
    int                                 flags);

#define NI_NUMERICHOST 1
#define NI_NUMERICSERV 2
#define NI_NOFQDN      4
#define NI_NAMEREQD    8
#define NI_DGRAM       16
#endif


/* IPv6 compatible utils */
#if defined(TARGET_ARCH_CYGWIN)
typedef struct sockaddr                 globus_sockaddr_t;
#else
typedef struct sockaddr_storage         globus_sockaddr_t;
#endif
typedef struct addrinfo                 globus_addrinfo_t;

#ifdef AF_INET6
#define GlobusLibcProtocolFamilyIsIP(family)                                \
    ((family == AF_INET ? 1 : (family == AF_INET6 ? 1 : 0)))
#else
#define GlobusLibcProtocolFamilyIsIP(family)                                \
    (family == AF_INET ? 1 : 0)
#endif

#ifndef PF_INET
#define PF_INET AF_INET
#endif

#ifndef PF_UNSPEC
#define PF_UNSPEC AF_UNSPEC
#endif

#define GlobusLibcSockaddrSetFamily(_addr, fam)  ((struct sockaddr *) &(_addr))->sa_family = fam
#define GlobusLibcSockaddrGetFamily(_addr)  ((struct sockaddr *) &(_addr))->sa_family

#ifdef AF_INET6
#define GlobusLibcSockaddrGetPort(addr, port)                               \
    do                                                                      \
    {                                                                       \
        const struct sockaddr *         _addr = (struct sockaddr *) &(addr);\
                                                                            \
        switch(_addr->sa_family)                                            \
        {                                                                   \
          case AF_INET:                                                     \
            (port) = ntohs(((struct sockaddr_in *) _addr)->sin_port);       \
            break;                                                          \
                                                                            \
          case AF_INET6:                                                    \
            (port) = ntohs(((struct sockaddr_in6 *) _addr)->sin6_port);     \
            break;                                                          \
                                                                            \
          default:                                                          \
            globus_assert(0 &&                                              \
                "Unknown family in GlobusLibcSockaddrGetPort");             \
            (port) = -1;                                                    \
            break;                                                          \
        }                                                                   \
    } while(0)
#else
#define GlobusLibcSockaddrGetPort(addr, port)                               \
    do                                                                      \
    {                                                                       \
        const struct sockaddr *         _addr = (struct sockaddr *) &(addr);\
                                                                            \
        switch(_addr->sa_family)                                            \
        {                                                                   \
          case AF_INET:                                                     \
            (port) = ntohs(((struct sockaddr_in *) _addr)->sin_port);       \
            break;                                                          \
                                                                            \
          default:                                                          \
            globus_assert(0 &&                                              \
                "Unknown family in GlobusLibcSockaddrGetPort");             \
            (port) = -1;                                                    \
            break;                                                          \
        }                                                                   \
    } while(0)
#endif

#ifdef AF_INET6
#define GlobusLibcSockaddrSetPort(addr, port)                               \
    do                                                                      \
    {                                                                       \
        struct sockaddr *               _addr = (struct sockaddr *) &(addr);\
                                                                            \
        switch(_addr->sa_family)                                            \
        {                                                                   \
          case AF_INET:                                                     \
            ((struct sockaddr_in *) _addr)->sin_port = htons((port));       \
            break;                                                          \
                                                                            \
          case AF_INET6:                                                    \
            ((struct sockaddr_in6 *) _addr)->sin6_port = htons((port));     \
            break;                                                          \
                                                                            \
          default:                                                          \
            globus_assert(0 &&                                              \
                "Unknown family in GlobusLibcSockaddrSetPort");             \
            break;                                                          \
        }                                                                   \
    } while(0)
#else
#define GlobusLibcSockaddrSetPort(addr, port)                               \
    do                                                                      \
    {                                                                       \
        struct sockaddr *               _addr = (struct sockaddr *) &(addr);\
                                                                            \
        switch(_addr->sa_family)                                            \
        {                                                                   \
          case AF_INET:                                                     \
            ((struct sockaddr_in *) _addr)->sin_port = htons((port));       \
            break;                                                          \
                                                                            \
          default:                                                          \
            globus_assert(0 &&                                              \
                "Unknown family in GlobusLibcSockaddrSetPort");             \
            break;                                                          \
        }                                                                   \
    } while(0)
#endif

/* only use this on systems with the sin_len field (AIX) */
#define GlobusLibcSockaddrSetLen(addr, len)                                 \
    do                                                                      \
    {                                                                       \
        struct sockaddr *               _addr = (struct sockaddr *) &(addr);\
                                                                            \
        switch(_addr->sa_family)                                            \
        {                                                                   \
          case AF_INET:                                                     \
            ((struct sockaddr_in *) _addr)->sin_len = (len);                \
            break;                                                          \
                                                                            \
          case AF_INET6:                                                    \
            ((struct sockaddr_in6 *) _addr)->sin6_len = (len);              \
            break;                                                          \
                                                                            \
          default:                                                          \
            globus_assert(0 &&                                              \
                "Unknown family in GlobusLibcSockaddrSetLen");              \
            break;                                                          \
        }                                                                   \
    } while(0)

#define GlobusLibcSockaddrCopy(dest_addr, source_addr, source_len)          \
    (memcpy(&(dest_addr), &(source_addr), (source_len)))

#if 0
#define GlobusLibcSockaddrLen(addr, len)                                    \
    do                                                                      \
    {                                                                       \
        const struct sockaddr *         _addr = &(addr);                    \
                                                                            \
        switch(_addr->sa_family)                                            \
        {                                                                   \
          case AF_INET:                                                     \
            (len) = sizeof(struct sockaddr_in);                             \
            break;                                                          \
                                                                            \
          case AF_INET6:                                                    \
            (len) = sizeof(struct sockaddr_in6);                            \
            break;                                                          \
                                                                            \
          default:                                                          \
            globus_assert(0 &&                                              \
                "Unknown family in GlobusLibcSizeofSockaddr");              \
            (len) = 0;                                                      \
            break;                                                          \
        }                                                                   \
    } while(0)
#endif

#ifdef HAVE_SOCKAPI_H
/* Net+OS only has sockaddr_in */
#define GlobusLibcSockaddrLen(addr)                                         \
    (((struct sockaddr *) (addr))->sin_family == AF_INET                    \
        ? sizeof(struct sockaddr_in) : 1)
#else
#define GlobusLibcSockaddrLen(addr)                                         \
    (((struct sockaddr *) (addr))->sa_family == AF_INET                     \
        ? sizeof(struct sockaddr_in) :                                      \
            (((struct sockaddr *) (addr))->sa_family == AF_INET6            \
        ? sizeof(struct sockaddr_in6) : -1))
#endif

#define GLOBUS_AI_PASSIVE               AI_PASSIVE
#define GLOBUS_AI_NUMERICHOST           AI_NUMERICHOST
#define GLOBUS_AI_CANONNAME             AI_CANONNAME

#define GLOBUS_NI_MAXHOST               NI_MAXHOST
#define GLOBUS_NI_NOFQDN                NI_NOFQDN
#define GLOBUS_NI_NAMEREQD              NI_NAMEREQD
#define GLOBUS_NI_DGRAM                 NI_DGRAM
#define GLOBUS_NI_NUMERICSERV           NI_NUMERICSERV
#define GLOBUS_NI_NUMERICHOST           NI_NUMERICHOST

#define GLOBUS_EAI_ERROR_OFFSET         2048

#define GLOBUS_EAI_FAMILY            (EAI_FAMILY     + GLOBUS_EAI_ERROR_OFFSET)
#define GLOBUS_EAI_SOCKTYPE          (EAI_SOCKTYPE   + GLOBUS_EAI_ERROR_OFFSET)
#define GLOBUS_EAI_BADFLAGS          (EAI_BADFLAGS   + GLOBUS_EAI_ERROR_OFFSET)
#define GLOBUS_EAI_NONAME            (EAI_NONAME     + GLOBUS_EAI_ERROR_OFFSET)
#define GLOBUS_EAI_SERVICE           (EAI_SERVICE    + GLOBUS_EAI_ERROR_OFFSET)
#define GLOBUS_EAI_ADDRFAMILY        (EAI_ADDRFAMILY + GLOBUS_EAI_ERROR_OFFSET)
#define GLOBUS_EAI_NODATA            (EAI_NODATA     + GLOBUS_EAI_ERROR_OFFSET)
#define GLOBUS_EAI_MEMORY            (EAI_MEMORY     + GLOBUS_EAI_ERROR_OFFSET)
#define GLOBUS_EAI_FAIL              (EAI_FAIL       + GLOBUS_EAI_ERROR_OFFSET)
#define GLOBUS_EAI_AGAIN             (EAI_AGAIN      + GLOBUS_EAI_ERROR_OFFSET)
#define GLOBUS_EAI_SYSTEM            (EAI_SYSTEM     + GLOBUS_EAI_ERROR_OFFSET)
       
globus_result_t
globus_libc_getaddrinfo(
    const char *                        node,
    const char *                        service,
    const globus_addrinfo_t *           hints,
    globus_addrinfo_t **                res);

void
globus_libc_freeaddrinfo(
    globus_addrinfo_t *                 res);

globus_result_t
globus_libc_getnameinfo(
    const globus_sockaddr_t *           addr,
    char *                              hostbuf,
    globus_size_t                       hostbuf_len,
    char *                              servbuf,
    globus_size_t                       servbuf_len,
    int                                 flags);

globus_bool_t
globus_libc_addr_is_loopback(
    const globus_sockaddr_t *           addr);

globus_bool_t
globus_libc_addr_is_wildcard(
    const globus_sockaddr_t *           addr);
    
/* use this to get a numeric contact string (ip addr.. default is hostname) */
#define GLOBUS_LIBC_ADDR_NUMERIC        1
/* use this if this is a local addr; will use GLOBUS_HOSTNAME if avail */
#define GLOBUS_LIBC_ADDR_LOCAL          2
/* force IPV6 host addresses */
#define GLOBUS_LIBC_ADDR_IPV6           4
/* force IPV4 host addresses */
#define GLOBUS_LIBC_ADDR_IPV4           8

/* creates a contact string of the form <host>:<port>
 * user needs to free contact string
 */
globus_result_t
globus_libc_addr_to_contact_string(
    const globus_sockaddr_t *           addr,
    int                                 opts_mask,
    char **                             contact_string);

globus_result_t
globus_libc_contact_string_to_ints(
    const char *                        contact_string,
    int *                               host,
    int *                               count,
    unsigned short *                    port);

/* create a contact string... if port == 0, it will be omitted
 * returned string must be freed
 * 
 * count should be 4 for ipv4 or 16 for ipv6
 */
char *
globus_libc_ints_to_contact_string(
    int *                               host,
    int                                 count,
    unsigned short                      port);

int
globus_libc_gethostaddr(
    globus_sockaddr_t *                 addr);

int
globus_libc_gethostaddr_by_family(
    globus_sockaddr_t *                 addr,
    int                                 family);

EXTERN_C_END

#endif

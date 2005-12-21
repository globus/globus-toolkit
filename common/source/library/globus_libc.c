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

/*****************************************************************************
globus_libc.c

Description:
   Thread-safe libc macros, function prototypes

CVS Information:
   $Source$
   $Date$
   $Revision$
   $State$
   $Author$
******************************************************************************/

/******************************************************************************
			     Include header files
******************************************************************************/
#include "config.h"
#include "globus_common.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if !defined(MAXPATHLEN)
#   include <sys/param.h>
#   define MAXPATHLEN PATH_MAX
#endif

/* HPUX 10.20 headers do not define this */
#if defined(TARGET_ARCH_HPUX)
extern int h_errno;
#endif

#ifdef TARGET_ARCH_NETOS
#include "appconf_api.h"
#endif

#ifndef HAVE_GETEUID
#define geteuid() 0
#endif

extern globus_bool_t globus_i_module_initialized;
/******************************************************************************
		       Define module specific variables
******************************************************************************/
/* mutex to make globus_libc reentrant */
globus_mutex_t globus_libc_mutex;

/******************************************************************************
		      Module specific function prototypes
******************************************************************************/
static int
globus_l_libc_copy_hostent_data_to_buffer(
    struct hostent *                    h,
    char *                              buffer,
    size_t                              buflen);

static void
globus_l_libc_copy_pwd_data_to_buffer(
    struct passwd *                     pwd,
    char *                              buffer,
    size_t                              buflen);

/******************************************************************************
Function: globus_libc_lock()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_lock
int
globus_libc_lock(void)
{
    if(globus_i_module_initialized==GLOBUS_TRUE)
    {
        return globus_macro_libc_lock();
    }
    return GLOBUS_FAILURE;
} /* globus_libc_lock() */

/******************************************************************************
Function: globus_libc_unlock()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_unlock
int
globus_libc_unlock(void)
{
    if(globus_i_module_initialized==GLOBUS_TRUE)
    {
        return globus_macro_libc_unlock();
    }
    return GLOBUS_FAILURE;
} /* globus_libc_unlock() */



/******************************************************************************
Function: globus_libc_strncasecmp

Description:

Parameters:

Returns:
 ******************************************************************************/
int
globus_libc_strncasecmp(
	const char *                            s1,
	const char *                            s2,
	globus_size_t                           n)
{
    int                                     rc;
    int                                     save_errno;

    globus_libc_lock();

#   if HAVE_STRNCASECMP
    {
        rc = strncasecmp(s1, s2, n);
    }
#   else
    {
        char ch1;
        char ch2;
        int  ctr;

        for(ctr = 0; ctr < n; ctr++)
        {
	        if(s2[ctr] == '\0' && s1[ctr] == '\0')
	        {
	            rc = 0;
	            goto exit;
	        }
        	else if(s2[ctr] == '\0')
	        {
	            rc = -1;
	            goto exit;
	        }
	        else if(s1[ctr] == '\0')
	        {
	            rc = 1;
	            goto exit;
	        }
            else
	        {
                ch1 = toupper(s2[ctr]);
                ch2 = toupper(s1[ctr]);
                if(ch2 > ch1)
		        {
                    rc = 1;
                    goto exit;
		        }
                else if(ch2 < ch1)
		        {
                    rc = -1;
                    goto exit;
		        }
            }
        }
        rc = 0;
    }
#   endif

  exit:
    save_errno = errno;

    globus_libc_unlock();
    errno = save_errno;

    return(rc);
}

int
globus_libc_setuid(
    uid_t                                   uid)
{
    return -1;
}


#if !defined(HAVE_THREAD_SAFE_SELECT) && !defined(BUILD_LITE)

/******************************************************************************
Function: globus_libc_open()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_open
int
globus_libc_open(char *path,
		 int flags,
		 ... /*int mode*/)
{
    va_list ap;
    int rc;
    int save_errno;
    int mode=0;

    globus_libc_lock();


    if(flags & O_CREAT)
    {
#       ifdef HAVE_STDARG_H
        {
            va_start(ap, flags);
	    }
#       else
	    {
            va_start(ap);
	    }
#       endif
        mode = va_arg(ap, int);
        va_end(ap);
    }

    rc = open(path, flags, mode);
    save_errno = errno;
    /* Should set the fd to non-blocking here */
    globus_libc_unlock();
    errno = save_errno;
    return(rc);
} /* globus_libc_open() */

/******************************************************************************
Function: globus_libc_close()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_close
int
globus_libc_close(int fd)
{
    int rc;
    int save_errno;
    globus_libc_lock();
    rc = close(fd);
    save_errno = errno;
    /* Should convert EWOULDBLOCK to EINTR */
    globus_libc_unlock();
    errno = save_errno;
    return(rc);
} /* globus_libc_close() */


/******************************************************************************
Function: globus_libc_read()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_read
int
globus_libc_read(int fd,
		 char *buf,
		 int nbytes)
{
    int rc;
    int save_errno;
    globus_libc_lock();
    rc = read(fd, buf, nbytes);
    save_errno = errno;
    /* Should convert EWOULDBLOCK to EINTR */
    globus_libc_unlock();
    errno = save_errno;
    return(rc);
} /* globus_libc_read() */

/******************************************************************************
Function: globus_libc_writev()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_writev
int
globus_libc_writev(
    int					fd,
    struct iovec *			iov,
    int					iovcnt)
{
    int					rc;
    int					save_errno;

#if defined(HAVE_WRITEV)
    globus_libc_lock();
    rc = writev(fd, iov, iovcnt);
    save_errno = errno;


    globus_libc_unlock();

    errno = save_errno;

    return rc;
#else
    return globus_libc_write(fd,
		             iov[0].iov_base,
		             iov[0].iov_len);
#endif
} /* globus_libc_writev() */

/******************************************************************************
Function: globus_libc_write()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_write
int
globus_libc_write(int fd,
		  char *buf,
		  int nbytes)
{
    int rc;
    int save_errno;
    globus_libc_lock();
    rc = write(fd, buf, nbytes);
    save_errno = errno;
    /* Should convert EWOULDBLOCK to EINTR */
    globus_libc_unlock();
    errno = save_errno;
    return(rc);
} /* globus_libc_write() */

/******************************************************************************
Function: globus_libc_fstat()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_fstat
int
globus_libc_fstat(int fd,
		  struct stat *buf)
{
    int rc;
    int save_errno;
    globus_libc_lock();
    rc = fstat(fd, buf);
    save_errno = errno;
    /* Should convert EWOULDBLOCK to EINTR */
    globus_libc_unlock();
    errno = save_errno;
    return(rc);
} /* globus_libc_fstat() */

#endif /* !defined(HAVE_THREAD_SAFE_SELECT) && !defined(BUILD_LITE) */


#if !defined(BUILD_LITE)
/******************************************************************************
Function: globus_libc_malloc()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_malloc
void *
globus_libc_malloc(
    size_t					bytes)
{
    globus_bool_t				done;
    int						save_errno;
    void *					ptr;

    do
    {
		globus_libc_lock();
		{
			ptr = (void *) malloc(bytes);
			save_errno = errno;
		}
		globus_libc_unlock();

		if (ptr == GLOBUS_NULL &&
			(save_errno == EINTR ||
			save_errno == EAGAIN ||
			save_errno == EWOULDBLOCK))
		{
			done = GLOBUS_FALSE;
			globus_thread_yield();
		}
		else
		{
			done = GLOBUS_TRUE;
		}
    }
	while (!done);

    errno = save_errno;
    return(ptr);
}
/* globus_libc_malloc() */

/******************************************************************************
Function: globus_libc_realloc()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_realloc
void *
globus_libc_realloc(void *ptr,
		    size_t bytes)
{
    int save_errno;

    globus_libc_lock();
    ptr = (void *) realloc(ptr, bytes);
    save_errno = errno;

    /* Should convert EWOULDBLOCK to EINTR */
    globus_libc_unlock();
    errno = save_errno;
    return(ptr);
} /* globus_libc_realloc() */

/******************************************************************************
Function: globus_libc_calloc()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_calloc
void *
globus_libc_calloc(size_t nelem,
		   size_t elsize)
{
    int save_errno;
    void *ptr;

    globus_libc_lock();
    ptr = (void *) calloc(nelem, elsize);
    save_errno = errno;

    /* Should convert EWOULDBLOCK to EINTR */
    globus_libc_unlock();
    errno = save_errno;
    return(ptr);
} /* globus_libc_calloc() */

/******************************************************************************
Function: globus_libc_free()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_free
void
globus_libc_free(void *ptr)
{
    int save_errno;

    globus_libc_lock();
    free (ptr);
    save_errno = errno;

    /* Should convert EWOULDBLOCK to EINTR */
    globus_libc_unlock();
    errno = save_errno;

    return;
} /* globus_libc_free() */

/******************************************************************************
Function: globus_libc_alloca()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_alloca
void *
globus_libc_alloca(size_t bytes)
{
    int save_errno;
    void *ptr;

    globus_libc_lock();
    ptr = (void *) alloca(bytes);
    save_errno = errno;
    /* Should convert EWOULDBLOCK to EINTR */
    globus_libc_unlock();
    errno = save_errno;
    return(ptr);
} /* globus_libc_alloca() */

/******************************************************************************
Function: globus_libc_printf()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_printf
int
globus_libc_printf(const char *format, ...)
{
    va_list ap;
    int rc;
    int save_errno;

    globus_libc_lock();
#ifdef HAVE_STDARG_H
    va_start(ap, format);
#else
    va_start(ap);
#endif

    rc = vprintf(format, ap);
    save_errno=errno;

    globus_libc_unlock();

    errno=save_errno;
    return rc;
} /* globus_libc_printf() */

/******************************************************************************
Function: globus_libc_fprintf()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_fprintf
int
globus_libc_fprintf(FILE *strm, const char *format, ...)
{
    va_list ap;
    int rc;
    int save_errno;

    if(strm == GLOBUS_NULL)
    {
	return -1;
    }
    globus_libc_lock();

#ifdef HAVE_STDARG_H
    va_start(ap, format);
#else
    va_start(ap);
#endif

    rc = vfprintf(strm, format, ap);
    save_errno=errno;

    globus_libc_unlock();

    errno=save_errno;
    return rc;
} /* globus_libc_fprintf() */

/******************************************************************************
Function: globus_libc_sprintf()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_sprintf
int
globus_libc_sprintf(char *s, const char *format, ...)
{
    va_list ap;
    int rc;
    int save_errno;

    globus_libc_lock();

#ifdef HAVE_STDARG_H
    va_start(ap, format);
#else
    va_start(ap);
#endif

    rc = vsprintf(s, format, ap);
    save_errno=errno;

    globus_libc_unlock();

    errno=save_errno;
    return rc;
} /* globus_libc_sprintf() */

/******************************************************************************
Function: globus_libc_vprintf()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_vprintf
int
globus_libc_vprintf(const char *format, va_list ap)
{
    int rc;
    int save_errno;

    globus_libc_lock();

    rc = vprintf(format, ap);
    save_errno=errno;

    globus_libc_unlock();

    errno=save_errno;
    return rc;
} /* globus_libc_vprintf() */

/******************************************************************************
Function: globus_libc_vfprintf()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_vfprintf
extern int
globus_libc_vfprintf(FILE *strm, const char *format, va_list ap)
{
    int rc;
    int save_errno;

    if(strm == GLOBUS_NULL)
    {
	return -1;
    }
    globus_libc_lock();

    rc = vfprintf(strm, format, ap);
    save_errno=errno;

    globus_libc_unlock();

    errno=save_errno;
    return rc;
} /* globus_libc_vfprintf() */

/******************************************************************************
Function: globus_libc_vsprintf()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_vsprintf
int
globus_libc_vsprintf(char *s, const char *format, va_list ap)
{
    int rc;
    int save_errno;

    globus_libc_lock();

    rc = vsprintf(s, format, ap);
    save_errno=errno;

    globus_libc_unlock();

    errno=save_errno;
    return rc;
} /* globus_libc_vsprintf() */

#endif /* !defined(BUILD_LITE)*/

static
int
globus_l_libc_vsnprintf(char *s, size_t n, const char *format, va_list ap)
{
    int rc;
    int save_errno;
    va_list ap_copy;

    globus_libc_va_copy(ap_copy,ap);

    globus_libc_unlock();
    rc = globus_libc_vprintf_length( format, ap_copy);
    globus_libc_lock();

    va_end(ap_copy);

    if ( rc < 0 )
    {
	return rc;
    }
    else if ( rc < n )
    {
	return vsprintf( s, format, ap );
    }
    else
    {
	char *buf = malloc( rc + 1 );
	if (buf == NULL)
	{
	    return -1;
	}
	rc = vsprintf( buf, format, ap );
	save_errno = errno;
	strncpy( s, buf, n - 1 );
	s[n - 1] = '\0';
	free( buf );
	errno = save_errno;
	return rc;
    }
}

/******************************************************************************
Function: globus_libc_snprintf()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_snprintf
int
globus_libc_snprintf(char *s, size_t n, const char *format, ...)
{
    va_list ap;
    int rc;
    int save_errno;

    globus_libc_lock();

#ifdef HAVE_STDARG_H
    va_start(ap, format);
#else
    va_start(ap);
#endif

#if defined(HAVE_VSNPRINTF)
    rc = vsnprintf(s, n, format, ap);
#else
    rc = globus_l_libc_vsnprintf(s, n, format, ap);
#endif
    save_errno=errno;

    globus_libc_unlock();

    errno=save_errno;
    return rc;
} /* globus_libc_snprintf() */

/******************************************************************************
Function: globus_libc_vsnprintf()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_vsnprintf
int
globus_libc_vsnprintf(char *s, size_t n, const char *format, va_list ap)
{
    int rc;
    int save_errno;

    globus_libc_lock();

#if defined(HAVE_VSNPRINTF)
    rc = vsnprintf(s, n, format, ap);
#else
    rc = globus_l_libc_vsnprintf(s, n, format, ap);
#endif
    save_errno=errno;

    globus_libc_unlock();

    errno=save_errno;
    return rc;
} /* globus_libc_vsnprintf() */

/*
 * Print a globus_off_t to a string. The format for the off_t depends
 * on the size of the data type, which may vary with flavor and
 * architecture.
 */
int
globus_libc_sprint_off_t(char * s, globus_off_t off)
{
    return globus_libc_sprintf(s, "%" GLOBUS_OFF_T_FORMAT, off);
}

/*
 * Scan a globus_off_t from a string. Equivalent to
 * sscanf("%d%n", off, consumed) (with %d replaced with the
 * appropriately-sized integer type.
 */
int
globus_libc_scan_off_t(char * s, globus_off_t * off, int * consumed)
{
    int rc;
    int dummy;

    if(consumed == GLOBUS_NULL)
    {
	consumed = &dummy;
    }
    globus_libc_lock();

    rc = sscanf(s, "%" GLOBUS_OFF_T_FORMAT "%n", off, consumed);
    globus_libc_unlock();
    return rc;
}

/******************************************************************************
Function: globus_libc_gethostname()

Description:  XXX this needs to be changed to use globus_libc_getnameinfo()

Parameters:

Returns:
******************************************************************************/
int
globus_libc_gethostname(char *name, int len)
{
#if HAVE_GETHOSTNAME
    static char                         hostname[MAXHOSTNAMELEN];
    static size_t                       hostname_length = 0;
    static globus_mutex_t               gethostname_mutex;
    static int                          initialized = GLOBUS_FALSE;
    char *                              env;
    
    globus_libc_lock();
    if(initialized == GLOBUS_FALSE)
    {
        globus_mutex_init(&gethostname_mutex,
                          (globus_mutexattr_t *) GLOBUS_NULL);
        initialized = GLOBUS_TRUE;
    }
    globus_libc_unlock();
    
    globus_mutex_lock(&gethostname_mutex);

    /* ToDo: This change should perhaps be applied to unix side as well?
     */
#ifdef WIN32
        /*
     * If the environment variable is set, always return that.
     * Otherwise, we can drop through to the caching code.
     */
    if ((env = globus_libc_getenv("GLOBUS_HOSTNAME")) != GLOBUS_NULL)
    {
        size_t hlen = strlen(env);
    	if (hlen < (size_t) len)
    	{
    	    size_t i;
    	    strcpy(name, env);
    	    for (i=0; i < hlen; i++)
    		name[i] = tolower(name[i]);
    	    globus_mutex_unlock(&gethostname_mutex);
    	    return 0;
    	}
    	else
    	{
    	    globus_mutex_unlock(&gethostname_mutex);
    	    errno=EFAULT;
    	    return(-1);
    	}
    }
    #else    
    if (hostname_length == 0U &&
        (env = globus_libc_getenv("GLOBUS_HOSTNAME")) != GLOBUS_NULL)
    {
        strncpy(hostname, env, MAXHOSTNAMELEN);
        hostname_length = strlen(hostname);
    }
#endif
    if (hostname_length == 0U)
    {
        globus_addrinfo_t               hints;
        globus_addrinfo_t *             addrinfo;
        globus_result_t                 result;

        if (gethostname(hostname, MAXHOSTNAMELEN) < 0)
        {
            globus_mutex_unlock(&gethostname_mutex);
            return(-1);
        }
        
        hostname_length = strlen(hostname);
        if(strchr(hostname, '.') != GLOBUS_NULL)
        {
            unsigned int                i = 0;
            for (i=0; i<hostname_length; i++)
            {
                hostname[i] = tolower(hostname[i]);
            }
            strncpy(name, hostname, len);
            globus_mutex_unlock(&gethostname_mutex);
            return 0;
        }
        
        memset(&hints, 0, sizeof(globus_addrinfo_t));
        hints.ai_flags = GLOBUS_AI_CANONNAME;
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = 0;
        
        result = globus_libc_getaddrinfo(hostname, NULL, &hints, &addrinfo);
        if(result == GLOBUS_SUCCESS)
        {
            if(addrinfo && addrinfo->ai_canonname)
            {
                strncpy(hostname, addrinfo->ai_canonname, sizeof(hostname));
                hostname[sizeof(hostname) - 1] = 0;
            }
            
            globus_libc_freeaddrinfo(addrinfo);
        }
    }

    if(strchr(hostname, '.') == GLOBUS_NULL &&
       (env = globus_libc_getenv("GLOBUS_DOMAIN_NAME")) != GLOBUS_NULL)
    {
        if(strlen(hostname) +
           strlen(env) + 2 < MAXHOSTNAMELEN)
        {
            strcat(hostname, ".");
            strcat(hostname,
                   globus_libc_getenv("GLOBUS_DOMAIN_NAME"));
        }
    }

    hostname_length = strlen(hostname);
    if (hostname_length < (size_t) len)
    {
        size_t i;
        for (i=0; i<hostname_length; i++)
           hostname[i] = tolower(hostname[i]);
        strcpy(name, hostname);
    }
    else
    {
        globus_mutex_unlock(&gethostname_mutex);
        errno=EFAULT;
        return(-1);
    }

    globus_mutex_unlock(&gethostname_mutex);
    return(0);
#elif defined(TARGET_ARCH_NETOS)
    char * env;
    if ((env = globus_libc_getenv("GLOBUS_HOSTNAME")) != GLOBUS_NULL)
    {
        size_t hlen = strlen(env);
    	if (hlen < (size_t) len)
    	{
    	    size_t i;
    	    strcpy(name, env);
    	    for (i=0; i < hlen; i++)
    		name[i] = tolower(name[i]);
    	    return 0;
    	}
    	else
    	{
    	    errno=EFAULT;
    	    return(-1);
    	}
    }
    else if (NAGetAppUseStaticIP())
    {
        char * tmp = NAGetAppIpAddress();

        if (tmp != NULL)
        {
            strcpy(name, tmp);

            return 0;
        }
    }
    else if (len < 5)
    {
        errno = EFAULT;
        return -1;
    }
    else
    {
        strncpy(name, "netos", 5);
    }
    return 0;
#else
    errno=EINVAL;
    return -1;
#endif
} /* globus_libc_gethostname() */

int
globus_libc_gethostaddr_by_family(
    globus_sockaddr_t *                 addr,
    int                                 family)
{
    int                                 rc;
    char                                hostname[MAXHOSTNAMELEN];
    globus_addrinfo_t                   hints;
    globus_addrinfo_t *                 save_addrinfo;
    globus_addrinfo_t *                 addrinfo;
    globus_result_t                     result;
    
    rc = globus_libc_gethostname(hostname, sizeof(hostname));
    if(rc < 0)
    {
        return rc;
    }
    
    memset(&hints, 0, sizeof(globus_addrinfo_t));
    hints.ai_flags = 0;
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    
    result = globus_libc_getaddrinfo(
        hostname, GLOBUS_NULL, &hints, &save_addrinfo);
    if(result != GLOBUS_SUCCESS)
    {
        return -1;
    }

    for(addrinfo = save_addrinfo; addrinfo; addrinfo = addrinfo->ai_next)
    {
        if(GlobusLibcProtocolFamilyIsIP(addrinfo->ai_family))
        {
            memcpy(addr, addrinfo->ai_addr, addrinfo->ai_addrlen);
            
            break;
        }
    }
    
    globus_libc_freeaddrinfo(save_addrinfo);
    
    return 0;
}

int
globus_libc_gethostaddr(
    globus_sockaddr_t *                 addr)
{
#ifdef AF_UNSPEC
    return globus_libc_gethostaddr_by_family(addr, AF_UNSPEC);
#else
    errno = EINVAL;
    return -1;
#endif
}

/*
 *  The windows definition of the following funtions differs
 */
#if defined(TARGET_ARCH_WIN32)

int
globus_libc_system_memory(
    globus_off_t *                  mem)
{
    MEMORYSTATUSEX                      statex;

    if(mem == GLOBUS_NULL)
    {
        return -1;
    }

    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);

    *mem = statex.ullTotalPhys;

    return 0;
}

int
globus_libc_free_memory(
    globus_off_t *                  mem)
{
    MEMORYSTATUSEX                      statex;

    if(mem == GLOBUS_NULL)
    {
        return -1;
    }

    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);

    *mem = statex.ullAvailPhys;

    return 0;
}

int
globus_libc_usleep(long usec)
{
	globus_libc_lock();
	Sleep(usec/1000);
	globus_libc_unlock();

	return 0;
}

int
globus_libc_getpid(void)
{
    int pid;

    globus_libc_lock();

    pid = (int) _getpid();

    globus_libc_unlock();

    return(pid);
} /* globus_libc_getpid() */

int
globus_libc_fork(void)
{
    return -1;
}

#else /* TARGET_ARCH_WIN32 */

int
globus_libc_system_memory(
    globus_size_t *                  mem)
{
    return -1;
}

int
globus_libc_free_memory(
    globus_size_t *                  mem)
{
    return -1;
}

/******************************************************************************
Function: globus_libc_getpid()

Description:

Parameters:

Returns:
******************************************************************************/
int
globus_libc_getpid(void)
{
    int pid;

    globus_libc_lock();

    pid = (int) getpid();

    globus_libc_unlock();

    return(pid);
} /* globus_libc_getpid() */

/******************************************************************************
Function: globus_libc_fork()

Description:

Parameters:

Returns:
******************************************************************************/
int
globus_libc_fork(void)
{
#if HAVE_FORK
    int child;

    globus_thread_prefork();

#   if defined(HAVE_FORK1)
    {
	child = fork1();
    }
#   else
    {
	child = fork();
    }
#   endif

    globus_thread_postfork();

    return child;
#else
    errno = ENOMEM;
    return -1;
#endif
} /* globus_libc_fork() */

/******************************************************************************
Function: globus_libc_usleep()

Description:

Parameters:

Returns:
******************************************************************************/
int
globus_libc_usleep(long usec)
{
    struct timeval timeout;

    timeout.tv_sec = usec/1000000;
    timeout.tv_usec = usec%1000000;

#   if !defined(HAVE_THREAD_SAFE_SELECT)
    {
	    globus_libc_lock();
    }
#   endif

    select(0, NULL, NULL, NULL, &timeout);

#   if !defined(HAVE_THREAD_SAFE_SELECT)
    {
	     globus_libc_unlock();
    }
#   endif

    return GLOBUS_SUCCESS;
} /* globus_libc_usleep() */
#endif /* TARGET_ARCH_WIN32 */

/******************************************************************************
Function: globus_libc_wallclock()

Description:

Parameters:

Returns:
******************************************************************************/
double
globus_libc_wallclock(void)
{
    globus_abstime_t now;
    long sec;
    long usec;

    GlobusTimeAbstimeGetCurrent(now);
    GlobusTimeAbstimeGet(now, sec, usec);
    return (((double) sec) + ((double) usec) / 1000000.0);
} /* globus_libc_wallclock() */


/******************************************************************************
Function: globus_libc_getbyhostname_r()

Description:

Parameters:

Returns:
******************************************************************************/
struct hostent *
globus_libc_gethostbyname_r(
    char *                              hostname,
    struct hostent *                    result,
    char *                              buffer,
    int                                 buflen,
    int *                               h_errnop)
{
    struct hostent *                    hp = GLOBUS_NULL;
    int                                 test[4];
#   if defined(GLOBUS_HAVE_GETHOSTBYNAME_R_3)
    struct hostent_data                 hp_data;
    int                                 rc;
#   endif
#   if defined(GLOBUS_HAVE_GETHOSTBYNAME_R_6)
    int                                 rc;
#   endif

    globus_libc_lock();

#   if !defined(HAVE_GETHOSTBYNAME_R)
    {

        hp = gethostbyname(hostname);
	if(hp != GLOBUS_NULL)
	{
            memcpy(result, hp, sizeof(struct hostent));
            if(globus_l_libc_copy_hostent_data_to_buffer(
                   result,
                   buffer,
                   (size_t) buflen) == -1)
            {
                hp = GLOBUS_NULL;
            }
            else
            { 
                hp = result;
            }
            
	    if (h_errnop != GLOBUS_NULL)
	    {
		*h_errnop = 0;
	    }
	}
	else
	{
	    if (h_errnop != GLOBUS_NULL)
	    {
	        *h_errnop = h_errno;
	    }
	}
    }
#   elif defined(GLOBUS_HAVE_GETHOSTBYNAME_R_3)
    {
	    rc = gethostbyname_r(hostname,
                                 result,
                                 &hp_data);
        if(rc == 0)
        {
            if(globus_l_libc_copy_hostent_data_to_buffer(
                   result, buffer, (size_t) buflen) == -1)
            {
                hp = GLOBUS_NULL;
            }
            else
            { 
                hp = result;
            }
            if(h_errnop != GLOBUS_NULL)
            {
                *h_errnop = h_errno;
            }
        }
        else
        {
            hp = GLOBUS_NULL;
            if(h_errnop != GLOBUS_NULL)
            {
                *h_errnop = h_errno;
            }
        }
    }
#   elif defined(GLOBUS_HAVE_GETHOSTBYNAME_R_5)
    {
        hp = gethostbyname_r(hostname,
			     result,
			     buffer,
			     buflen,
			     h_errnop);
    }
#   elif defined(GLOBUS_HAVE_GETHOSTBYNAME_R_6)
    {
        rc = gethostbyname_r(hostname,
			     result,
			     buffer,
			     buflen,
			     &hp,
			     h_errnop);
    }
#   else
    {
	    GLOBUS_HAVE_GETHOSTBYNAME symbol must be defined!!!;
    }
#   endif

    globus_libc_unlock();

    /*
     * gethostbyname() on many machines does the right thing for IP addresses
     * (e.g., "140.221.7.13").  But on some machines (e.g., SunOS 4.1.x) it
     * doesn't.  So hack it in this case.
     */
    if (hp == GLOBUS_NULL)
    {
	    if(isdigit(hostname[0]))
	    {
	        struct in_addr			addr;

	        addr.s_addr = inet_addr(hostname);
	        if ((int) addr.s_addr != -1)
	        {
		        hp = globus_libc_gethostbyaddr_r(
		        (void *) &addr,
		        sizeof(addr),
		        AF_INET,
		        result,
		        buffer,
		        buflen,
		        h_errnop);
	        }
	    }
    }

    return hp;
} /* globus_libc_gethostbyname_r() */


/******************************************************************************
Function: globus_libc_gethostbyaddr_r()

Description:

Parameters:

Returns:
******************************************************************************/
struct hostent *
globus_libc_gethostbyaddr_r(char *addr,
			    int length,
			    int type,
			    struct hostent *result,
			    char *buffer,
			    int buflen,
			    int *h_errnop)
{
    struct hostent *hp=GLOBUS_NULL;
#   if defined(GLOBUS_HAVE_GETHOSTBYADDR_R_5)
        struct hostent_data hp_data;
	int rc;
#   endif

#   if defined(GLOBUS_HAVE_GETHOSTBYADDR_R_8)
	int rc;
#   endif
#   if defined(GLOBUS_HAVE_GETHOSTBYADDR_R_7)
	int rc;
#   endif


    globus_libc_lock();

#   if !defined(HAVE_GETHOSTBYADDR_R)
    {
        hp = gethostbyaddr(addr, length, type);
	if(hp != GLOBUS_NULL)
	{
            memcpy(result, hp, sizeof(struct hostent));
            if(globus_l_libc_copy_hostent_data_to_buffer(
                   result, buffer, buflen) == -1)
            {
                hp = GLOBUS_NULL;
            }
            else
            { 
                hp = result;
            }
	    if (h_errnop != GLOBUS_NULL)
	    {
		*h_errnop = h_errno;
	    }
	}
	else
	{
	    if (h_errnop != GLOBUS_NULL)
	    {
		*h_errnop = h_errno;
	    }
	}
    }
#   elif defined(GLOBUS_HAVE_GETHOSTBYADDR_R_5)
    {
	rc = gethostbyaddr_r(addr,
			     length,
			     type,
			     result,
			     &hp_data);
        if(rc == 0)
	{
            if(globus_l_libc_copy_hostent_data_to_buffer(
                   result, buffer, buflen) == -1)
            {
                hp = GLOBUS_NULL;
            }
            else
            {
                hp = result;
            }
            
	    if (h_errnop != GLOBUS_NULL)
	    {
		*h_errnop = h_errno;
	    }
        }
	else
	{
	    hp = GLOBUS_NULL;
	    if (h_errnop != GLOBUS_NULL)
	    {
		*h_errnop = h_errno;
	    }
        }
    }
#   elif defined(GLOBUS_HAVE_GETHOSTBYADDR_R_7)
    {
        hp = gethostbyaddr_r(addr,
			     length,
			     type,
			     result,
			     buffer,
			     buflen,
			     h_errnop);
    }
#   elif defined(GLOBUS_HAVE_GETHOSTBYADDR_R_8)
    {
        rc = gethostbyaddr_r(addr,
			     length,
			     type,
			     result,
			     buffer,
			     buflen,
			     &hp,
			     h_errnop);
    }
#   else
    {
	GLOBUS_HAVE_GETHOSTBYADDR symbol must be defined!!!;
    }
#   endif

    globus_libc_unlock();

    return hp;
} /* globus_libc_gethostbyaddr_r() */

/******************************************************************************
Function: globus_libc_ctime_r()

Description:

Parameters:

Returns:
******************************************************************************/
char *
globus_libc_ctime_r(time_t *clock,
		    char *buf,
		    int buflen)
{
    char *tmp_buf;

#   if !defined(HAVE_CTIME_R)
    {
	globus_libc_lock();
	tmp_buf = ctime(clock);

	if(tmp_buf != GLOBUS_NULL)
	{
	    strncpy(buf,tmp_buf,buflen);
	}
	globus_libc_unlock();

	tmp_buf = buf;
    }
#   endif

#   if defined(GLOBUS_HAVE_CTIME_R_2)
    {
	tmp_buf = ctime_r(clock, buf);
    }
#   endif

#   if defined(GLOBUS_HAVE_CTIME_R_3)
    {
	tmp_buf = ctime_r(clock, buf, buflen);
    }
#   endif

    return tmp_buf;
} /* globus_libc_ctime_r() */

/******************************************************************************
Function: globus_libc_localtime_r()

Description:

Parameters:

Returns:
******************************************************************************/
struct tm *
globus_libc_localtime_r(
    const time_t *timep, 
    struct tm *result)
{
        struct tm * tmp_tm;
        
#   if !defined(HAVE_LOCALTIME_R)
    {
	globus_libc_lock();
	tmp_tm = localtime(timep);

	if(tmp_tm != GLOBUS_NULL)
	{
	    memcpy(result, tmp_tm, sizeof(struct tm));
	}
	globus_libc_unlock();

	tmp_tm = result;
    }
#   else
    {
        tmp_tm = localtime_r(timep, result);
    }
#   endif

    return tmp_tm;
} /* globus_libc_localtime_r() */

/******************************************************************************
Function: globus_libc_gmtime_r()

Description:

Parameters:

Returns:
******************************************************************************/
struct tm *
globus_libc_gmtime_r(
    const time_t *timep, 
    struct tm *result)
{
        struct tm * tmp_tm;
        
#   if !defined(HAVE_GMTIME_R)
    {
	globus_libc_lock();
	tmp_tm = gmtime(timep);

	if(tmp_tm != GLOBUS_NULL)
	{
	    memcpy(result, tmp_tm, sizeof(struct tm));
	}
	globus_libc_unlock();

	tmp_tm = result;
    }
#   else
    {
        tmp_tm = gmtime_r(timep, result);
    }
#   endif

    return tmp_tm;
} /* globus_libc_gmtime_r() */

/*
 * These functions are not defined on win32
 */
#if !defined(TARGET_ARCH_WIN32)
/******************************************************************************
Function: globus_libc_getpwnam_r()

Description:

Parameters:

Returns:
******************************************************************************/
int
globus_libc_getpwnam_r(char *name,
		       struct passwd *pwd,
		       char *buffer,
		       int buflen,
		       struct passwd **result)
{
    int rc=GLOBUS_SUCCESS;

#   if !defined(HAVE_GETPWNAM_R)
    {
#ifdef HAVE_GETPWNAM
	struct passwd *tmp_pwd;

	globus_libc_lock();
	tmp_pwd = getpwnam(name);
	if(tmp_pwd != GLOBUS_NULL)
	{
	    memcpy(pwd, tmp_pwd, sizeof(struct passwd));

	    globus_l_libc_copy_pwd_data_to_buffer(pwd,
						  buffer,
						  (size_t) buflen);
	    (*result) = pwd;
	}
	else
	{
	    rc = -1;
	}
	globus_libc_unlock();
#else
        rc = -1;
#endif
    }
#   elif defined(GLOBUS_HAVE_GETPWNAM_R_4)
    {
#       if defined(TARGET_ARCH_AIX)
        {
            rc = getpwnam_r(name,
                            pwd,
                            buffer,
			    buflen);
	    if(rc == 0)
	    {
		(*result) = pwd;
	    }
	    else
	    {
		(*result) = GLOBUS_NULL;
	    }
	}
#       else
        {
	    (*result) = getpwnam_r(name,
			           pwd,
			           buffer,
			           buflen);
	    if((*result) == GLOBUS_NULL)
	    {
	        rc = -1;
	    }
        }
#       endif
    }
#   elif defined(GLOBUS_HAVE_GETPWNAM_R_5)
    {
	rc = getpwnam_r(name,
			pwd,
			buffer,
			(size_t) buflen,
			result);
    }
#   endif

    return rc;
} /* globus_libc_getpwnam_r */

/******************************************************************************
Function: globus_libc_getpwuid_r()

Description:

Parameters:

Returns:
******************************************************************************/
int
globus_libc_getpwuid_r(uid_t uid,
		       struct passwd *pwd,
		       char *buffer,
		       int buflen,
		       struct passwd **result)
{
    int rc=GLOBUS_SUCCESS;

#   if !defined(HAVE_GETPWUID_R)
    {
#ifdef HAVE_GETPWUID
	struct passwd *tmp_pwd;

	globus_libc_lock();

	tmp_pwd = getpwuid(uid);
	if(tmp_pwd != GLOBUS_NULL)
	{
	    memcpy(pwd, tmp_pwd, sizeof(struct passwd));

	    globus_l_libc_copy_pwd_data_to_buffer(pwd,
						  buffer,
						  (size_t) buflen);
	    *result = pwd;
	}
	else
	{
	    rc = -1;
	}


	globus_libc_unlock();
#else
        rc = -1;
#endif
    }
#   elif defined(GLOBUS_HAVE_GETPWUID_R_4)
    {
#       if defined(TARGET_ARCH_AIX)
        {
            rc = getpwuid_r(uid,
			    pwd,
			    buffer,
			    buflen);
	    if(rc == 0)
	    {
		(*result) = pwd;
	    }
        }
#       else
        {
	    (*result) = getpwuid_r(uid,
			           pwd,
			           buffer,
			           buflen);
	    if((*result) == GLOBUS_NULL)
	    {
	        rc = -1;
	    }
        }
#       endif
    }
#   elif defined(GLOBUS_HAVE_GETPWUID_R_5)
    {
	rc = getpwuid_r(uid,
			pwd,
			buffer,
			(size_t) buflen,
			result);
    }
#   endif

    return rc;
} /* globus_libc_getpwuid_r */

#endif /* TARGET_ARCH_WIN32 */

/******************************************************************************
Function: globus_l_libc_copy_hostent_data_to_buffer()

Description:

Parameters:

Returns:
******************************************************************************/
static int
globus_l_libc_copy_hostent_data_to_buffer(
    struct hostent *                    h,
    char *                              buffer,
    size_t                              buflen)
{
    size_t                              offset=0U;
    char **                             ptr;
    char **                             ptr_buffer = (char **) buffer;
    int                                 num_ptrs=0;
    
   /* list of addresses from name server */
    if(h->h_addr_list != GLOBUS_NULL)
    {
	for(ptr = h->h_addr_list; (*ptr) != GLOBUS_NULL; ptr++)
	{
	    num_ptrs++;
	}
	num_ptrs++;
    }

    if(h->h_aliases != GLOBUS_NULL)
    {
	/* host aliases */
	for(ptr = h->h_aliases; *ptr != GLOBUS_NULL; ptr++)
	{
	    num_ptrs++;
	}
	num_ptrs++;
    }

    offset += num_ptrs * sizeof(char *);

    if(offset > buflen)
    {
        return -1;
    }
    
    /* official hostname of host */
    if(h->h_name != NULL)
    { 
	size_t     name_len;

	name_len = strlen(h->h_name);
	if(name_len + 1 + offset > buflen)
	{
            return -1;
	}

        strncpy(&buffer[offset], h->h_name, name_len);
	buffer[offset + name_len] = '\0';
	h->h_name = &buffer[offset];
        offset += name_len + 1;
    }

    /* list of addresses from name server */
    if(h->h_addr_list != GLOBUS_NULL)
    {
	size_t addrsize = h->h_length;

	ptr = h->h_addr_list;
	h->h_addr_list = ptr_buffer;

	for(; (*ptr) != GLOBUS_NULL; ptr++)
	{
	    if(offset + addrsize > buflen)
	    {
                return -1;
	    }

            memcpy(&buffer[offset], *ptr, addrsize);
            *ptr_buffer = &buffer[offset];
            ptr_buffer++;
            offset += addrsize;
	}
	*ptr_buffer = GLOBUS_NULL;
	ptr_buffer++;
    } 

    if(h->h_aliases != GLOBUS_NULL)
    {
	ptr = h->h_aliases;
	h->h_aliases = ptr_buffer;

	/* host aliases */
	for(; *ptr != GLOBUS_NULL; ptr++)
	{
	    if(strlen(*ptr) + offset + 1 > buflen)
	    {
                return -1;
	    }
            
            strcpy(&buffer[offset], *ptr);
            *ptr_buffer = &buffer[offset];
            ptr_buffer++;
            offset += strlen(*ptr) + 1;
	}
	*ptr_buffer = GLOBUS_NULL;
	ptr_buffer++;
    }
    return 0;
} /* globus_l_libc_copy_hostent_data_to_buffer() */


/*
 * globus_libc_system_error_string()
 *
 * Return the string for the current errno.
 */
char *
globus_libc_system_error_string(int the_error)
{
#if !defined HAVE_STRERROR
#if ! defined(TARGET_ARCH_LINUX) & ! defined(TARGET_ARCH_FREEBSD) & \
    ! defined(TARGET_ARCH_DARWIN)
    extern char *sys_errlist[];
#endif
    return ((char *)sys_errlist[the_error]);
#else
    return strerror(the_error);
#endif
} /* globus_libc_system_error_string() */


/*
 *  these functions are not defined on win32
 */
#if !defined(TARGET_ARCH_WIN32)
/******************************************************************************
Function: globus_l_libc_copy_pwd_data_to_buffer()

Description:

Parameters:

Returns:
******************************************************************************/
static void
globus_l_libc_copy_pwd_data_to_buffer(struct passwd *pwd,
				      char *buffer,
				      size_t buflen)
{
    size_t offset = 0;

    /* all platforms do not make use of all the fields in the passwd
       struct, so check whether null or not before we copy */

    /* pw_name */
    if (pwd->pw_name)
    {
	if(strlen(pwd->pw_name) > buflen-offset)
	{
	    pwd->pw_name[buflen-offset-1] = '\0';
	}
	if(offset < buflen)
	{
	    strcpy(&buffer[offset], pwd->pw_name);
	    pwd->pw_name = &buffer[offset];
	    offset += strlen(pwd->pw_name) + 1;
	}
    }
    /* pw_passwd */
    if (pwd->pw_passwd)
    {
	if(strlen(pwd->pw_passwd) > buflen-offset)
	{
	    pwd->pw_passwd[buflen-offset-1] = '\0';
	}
	if(offset < buflen)
	{
	    strcpy(&buffer[offset], pwd->pw_passwd);
	    pwd->pw_passwd = &buffer[offset];
	    offset += strlen(pwd->pw_passwd) + 1;
	}
    }

#   if defined(GLOBUS_HAVE_PW_AGE)
    {
	/* pw_age */
	if (pwd->pw_age)
	{
	    if(strlen(pwd->pw_age) > buflen-offset)
	    {
		pwd->pw_age[buflen-offset-1] = '\0';
	    }
	    if(offset < buflen)
	    {
		strcpy(&buffer[offset], pwd->pw_age);
		pwd->pw_age = &buffer[offset];
		offset += strlen(pwd->pw_age) + 1;
	    }
	}
    }
#   endif

#   if defined(GLOBUS_HAVE_PW_COMMENT)
    {
	/* pw_comment */
	if (pwd->pw_comment)
	{
	    if(strlen(pwd->pw_comment) > buflen-offset)
	    {
		pwd->pw_comment[buflen-offset-1] = '\0';
	    }
	    if(offset < buflen)
	    {
		strcpy(&buffer[offset], pwd->pw_comment);
		pwd->pw_comment = &buffer[offset];
		offset += strlen(pwd->pw_comment) + 1;
	    }
	}
    }
#   endif

    /* pw_gecos */
    if (pwd->pw_gecos)
    {
	if(strlen(pwd->pw_gecos) > buflen-offset)
	{
	    pwd->pw_gecos[buflen-offset-1] = '\0';
	}
	if(offset < buflen)
	{
	    strcpy(&buffer[offset], pwd->pw_gecos);
	    pwd->pw_gecos = &buffer[offset];
	    offset += strlen(pwd->pw_gecos) + 1;
	}
    }
    /* pw_dir */
    if (pwd->pw_dir)
    {
	if(strlen(pwd->pw_dir) > buflen-offset)
	{
	    pwd->pw_dir[buflen-offset-1] = '\0';
	}
	if(offset < buflen)
	{
	    strcpy(&buffer[offset], pwd->pw_dir);
	    pwd->pw_dir = &buffer[offset];
	    offset += strlen(pwd->pw_dir) + 1;
	}
    }
    /* pw_shell */
    if (pwd->pw_shell)
    {
	if(strlen(pwd->pw_shell) > buflen-offset)
	{
	    pwd->pw_shell[buflen-offset-1] = '\0';
	}
	if(offset < buflen)
	{
	    strcpy(&buffer[offset], pwd->pw_shell);
	    pwd->pw_shell = &buffer[offset];
	    offset += strlen(pwd->pw_shell) + 1;
	}
    }
} /* globus_l_libc_copy_pwd_data_to_buffer() */




/******************************************************************************
Function: globus_libc_gethomedir()

Description: wrapper around globus_libc_getpwuid_r(getuid()).

Parameters:

Returns:
******************************************************************************/
int
globus_libc_gethomedir(char *result, int bufsize)
{
    static globus_mutex_t   gethomedir_mutex;
    static int              initialized = GLOBUS_FALSE;
    static struct passwd    pw;
    static char             homedir[MAXPATHLEN];
    static int              homedir_len = 0;
    static char             buf[1024];
    int                     rc;
    int                     len;
    char *                  p;
    struct passwd *         pwres;

    globus_libc_lock();
    if (!initialized)
    {
	globus_mutex_init(&gethomedir_mutex,
			  (globus_mutexattr_t *) GLOBUS_NULL);
	initialized = GLOBUS_TRUE;
    }
    globus_libc_unlock();

    globus_mutex_lock(&gethomedir_mutex);
    {
	rc = 0;

	if (homedir_len == 0)
	{
	    p = globus_libc_getenv("HOME");
	    if (!p || strlen(p)==0)
	    {
		p = GLOBUS_NULL;
		rc = globus_libc_getpwuid_r(geteuid(),
					    &pw,
					    buf,
					    1024,
					    &pwres);

		if (!rc && pwres && pwres->pw_dir)
		    p = pwres->pw_dir;
	    }

	    if (!rc && p)
	    {
		len = strlen(p);
		if (len+1 < MAXPATHLEN)
		{
		    memcpy(homedir, p, len);
		    homedir[len] = '\0';
		    homedir_len = strlen(homedir);
		}
		else
		    rc = -1;
	    }
	}

	if (homedir_len > bufsize)
	    rc = -1;

	if (!rc)
	{
	    memcpy(result, homedir, homedir_len);
	    result[homedir_len] = '\0';
	}
    }
    globus_mutex_unlock(&gethomedir_mutex);

    return rc;
} /* globus_libc_gethomedir() */

#endif /* TARGET_ARCH_WIN32 */

globus_byte_t *
globus_libc_memmem(
    globus_byte_t *                         haystack,
    globus_size_t                           h_len,
    globus_byte_t *                         needle,
    globus_size_t                           n_len)
{
    globus_byte_t *                         tmp_ptr;
    globus_size_t                           left;

    tmp_ptr = memchr(haystack, needle[0], h_len);
    while(tmp_ptr != NULL)
    {
        /* figure out how many bytes remain, if not enough return NULL */
        left = h_len - (tmp_ptr - haystack);
        if(left < n_len)
        {
            return NULL;
        }
        if(memcmp(tmp_ptr, needle, n_len) == 0)
        {
            return tmp_ptr;
        }
        tmp_ptr++;
        tmp_ptr = memchr(tmp_ptr, needle[0], left - 1);
    }

    return NULL;
}

globus_byte_t *
globus_libc_memrchr(
    globus_byte_t *                         s,
    globus_byte_t                           c,
    globus_size_t                           n)
{
    globus_byte_t *                         tmp_ptr;

    tmp_ptr = &s[n - 1];
    while(tmp_ptr != s)
    {
        if(*tmp_ptr == c)
        {
            return tmp_ptr;
        }
        tmp_ptr--;
    }

    return NULL;
}

char *
globus_libc_strtok(
    char *                                  s,
    const char *                            delim)
{
    return strtok(s, delim);
}

char *
globus_libc_strdup(const char * string)
{
    char *                  ns;
    int                     l;

    ns = GLOBUS_NULL;

    if(string)
    {
	l = strlen(string);

	ns = globus_malloc(sizeof(char) * (l + 1));
	if(ns)
	{
	    memcpy(ns, string, l + 1);
	}
    }

    return ns;
}
/* globus_libc_strdup */

char *
globus_libc_strndup(const char * string, globus_size_t length)
{
    char *                  ns;
    int                     i;

    ns = GLOBUS_NULL;

    if(string)
    {
        ns = globus_malloc(sizeof(char *) * (length + 1));
        if(ns)
        {
            for(i = 0; i < length && string[i] != '\0'; i++)
                ns[i] = string[i];
                                                                                
            ns[i] = '\0';
        }
    }

    return ns;
}
/* globus_libc_strndup */


/*
 * not defined on win32
 */
#if !defined(TARGET_ARCH_WIN32)

/******************************************************************************
Function: globus_libc_lseek()

Description:

Parameters:

Returns:
******************************************************************************/
#undef globus_libc_lseek

int
globus_libc_lseek(int fd,
		  globus_off_t offset,
		  int whence)
{
    int rc;
    int save_errno;
    globus_libc_lock();
    rc = lseek(fd, offset, whence);
    save_errno = errno;
    /* Should convert EWOULDBLOCK to EINTR */
    globus_libc_unlock();
    errno = save_errno;
    return(rc);
} /* globus_libc_lseek() */

#undef globus_libc_opendir
extern DIR *
globus_libc_opendir(char *filename)
{
#if HAVE_DIR
    DIR *dirp;
    int save_errno;

    globus_libc_lock();

    dirp = opendir(filename);
    save_errno=errno;

    globus_libc_unlock();

    errno=save_errno;
    return dirp;
#else
    errno = EINVAL;
    return NULL;
#endif
}

#if defined(HAVE_TELLDIR)
#undef globus_libc_telldir
extern long
globus_libc_telldir(DIR *dirp)
{
    long pos=-1;
    int save_errno;


    if(dirp != GLOBUS_NULL)
    {
	globus_libc_lock();

	pos = telldir(dirp);
	save_errno=errno;

	globus_libc_unlock();
	errno = save_errno;

	return pos;
    }
    else
    {
	return pos;
    }
}
#endif /* defined(HAVE_TELLDIR) */

#if defined(HAVE_SEEKDIR)
#undef globus_libc_seekdir
extern void
globus_libc_seekdir(DIR *dirp,
		    long loc)
{
    int save_errno;

    if(dirp != GLOBUS_NULL)
    {
	globus_libc_lock();

	seekdir(dirp, loc);

	save_errno = errno;

	globus_libc_unlock();
	errno = save_errno;
	return;
    }
}
#endif /* defined(HAVE_SEEKDIR) */

#undef globus_libc_rewinddir
extern void
globus_libc_rewinddir(DIR *dirp)
{
#if HAVE_DIR
    int save_errno;

    if(dirp != GLOBUS_NULL)
    {
	globus_libc_lock();

	rewinddir(dirp);

	save_errno = errno;

	globus_libc_unlock();
	errno = save_errno;
	return;
    }
#else
    errno = EINVAL;
#endif
}

#undef globus_libc_closedir
extern void
globus_libc_closedir(DIR *dirp)
{
#if HAVE_DIR
    int save_errno;

    if(dirp != GLOBUS_NULL)
    {
        globus_libc_lock();

        closedir(dirp);
        save_errno = errno;

        globus_libc_unlock();
        errno = save_errno;
        return;
    }
#else
    errno = EINVAL;
#endif
}

#undef globus_libc_readdir_r
extern int
globus_libc_readdir_r(DIR *dirp,
		      struct dirent **result)
{
#if HAVE_DIR
#if !defined(HAVE_READDIR_R)
    {
	struct dirent *tmpdir, *entry;
	int save_errno;

	entry = (struct dirent *) globus_malloc(sizeof(struct dirent)
						+ MAXPATHLEN
						+ 1);
	globus_libc_lock();

	tmpdir = readdir(dirp);
	save_errno = errno;

	if(tmpdir == GLOBUS_NULL)
	{
	    *result = GLOBUS_NULL;

	    globus_libc_unlock();

            globus_free(entry);

	    errno = save_errno;

	    return -1;
	}

	/* copy returned buffer into data structure */
	entry->d_ino = tmpdir->d_ino;
#       if defined(GLOBUS_HAVE_DIRENT_OFF)
	{
	    entry->d_off = tmpdir->d_off;
	}
#       endif
#       if defined(GLOBUS_HAVE_DIRENT_OFFSET)
	{
	    entry->d_offset = tmpdir->d_offset;
	}
#       endif
#       if defined(GLOBUS_HAVE_DIRENT_TYPE)
	{
	    entry->d_type = tmpdir->d_type;
	}
#       endif
#	if defined(GLOBUS_HAVE_DIRENT_RECLEN)
	{
	    entry->d_reclen = tmpdir->d_reclen;
	}
#       endif
	strcpy(&entry->d_name[0], &tmpdir->d_name[0]);

#       if defined(HAVE_DIRENT_NAMELEN)
	{
	    entry->d_namlen = tmpdir->d_namlen;
	}
#       endif

	*result = entry;
	globus_libc_unlock();
	errno = save_errno;
	return 0;
    }
#   else
    {
	int errno;

#       if defined(GLOBUS_HAVE_READDIR_R_3)
	{
	    int rc = 0;
	    struct dirent *entry = globus_malloc(sizeof(struct dirent)
						 + MAXPATHLEN
						 + 1);

	    rc = readdir_r(dirp, entry, result);

            if(rc != 0 || *result == NULL)
            {
		globus_free(entry);
		*result = GLOBUS_NULL;
            }
            return rc;
	}
#       elif defined(GLOBUS_HAVE_READDIR_R_2)
	{
	    struct dirent *entry = globus_malloc(sizeof(struct dirent)
						 + MAXPATHLEN
						 + 1);
	    int rc=0;

#           if defined(TARGET_ARCH_SOLARIS)
	    {
		*result = readdir_r(dirp, entry);
		if(*result == GLOBUS_NULL)
		{
		    rc = -1;
		}
	    }
#           elif defined(TARGET_ARCH_HPUX)
	    {
		rc = readdir_r(dirp, entry);
		*result = entry;
	    }
#           endif

	    if(rc != GLOBUS_SUCCESS)
	    {
		globus_free(entry);
		*result = GLOBUS_NULL;
		return rc;
	    }
	    else
	    {
		return 0;
	    }
	}
#       endif
    }
#   endif
#else
    globus_assert_string(0, "readdir not implemented on this system\n");
    errno = EINVAL;
    return -1;
#endif
}

#endif /* TARGET_ARCH_WIN32 */

int
globus_libc_vprintf_length(const char * fmt, va_list ap)
{
#ifdef TARGET_ARCH_NETOS
    return vsprintf(NULL, fmt, ap);
#else
    static FILE *			devnull = GLOBUS_NULL;
    int save_errno;

    globus_libc_lock();
    if(devnull == GLOBUS_NULL)
    {
#ifndef TARGET_ARCH_WIN32
	devnull = fopen("/dev/null", "w");

        if(devnull == GLOBUS_NULL)
        {
            save_errno = errno;
            globus_libc_unlock();
            errno = save_errno;
            return -1;
        }
        fcntl(fileno(devnull), F_SETFD, FD_CLOEXEC);
#else
	devnull = fopen("NUL", "w");
        if(devnull == GLOBUS_NULL)
        {
            save_errno = errno;
            globus_libc_unlock();
            errno = save_errno;
            return -1;
        }
#endif
    }
    globus_libc_unlock();

    return globus_libc_vfprintf(devnull, fmt, ap);
#endif
}

int
globus_libc_printf_length(const char * fmt, ...)
{
    int                                 length;
    va_list                             ap;

    va_start(ap,fmt);

    length = globus_libc_vprintf_length(fmt,ap);

    va_end(ap);

    return length;
}


char *
globus_common_create_string(
    const char *                        format,
    ...)
{
    va_list                             ap;
    char *                              new_string;

    va_start(ap, format);

    new_string = globus_common_v_create_string(format, ap);

    va_end(ap);

    return new_string;
}

char *
globus_common_create_nstring(
    int                                 length,
    const char *                        format,
    ...)
{
    va_list                             ap;
    char *                              new_string;

    va_start(ap, format);

    new_string = globus_common_v_create_nstring(length, format, ap);

    va_end(ap);

    return new_string;
}

char *
globus_common_v_create_string(
    const char *                        format,
    va_list                             ap)
{
    int                                 len;
    char *                              new_string = NULL;
    va_list                             ap_copy;

    globus_libc_va_copy(ap_copy,ap);
    
    len = globus_libc_vprintf_length(format,ap_copy);

    va_end(ap_copy);

    if(len < 0)
    {
        return NULL;
    }
    
    len++;

    if((new_string = malloc(len)) == NULL)
    {
        return NULL;
    }
    
    globus_libc_vsnprintf(new_string,
                          len,
                          format,
                          ap);
    
    return new_string;
}

char *
globus_common_v_create_nstring(
    int                                 length,
    const char *                        format,
    va_list                             ap)
{
    char *                              new_string = NULL;

    if((new_string = malloc(length + 1)) == NULL)
    {
        return NULL;
    }

    globus_libc_vsnprintf(new_string, length + 1, format, ap);

    return new_string;
}


#ifdef TARGET_ARCH_CRAYT3E
/* for alloca on T3E */
#if !defined (__GNUC__) || __GNUC__ < 2
#if defined (CRAY) && defined (CRAY_STACKSEG_END)
    static long globus_l_libc_i00afunc ();
#   define ADDRESS_FUNCTION(arg) (char *) globus_l_libc_i00afunc (&(arg))
#else
#   define ADDRESS_FUNCTION(arg) &(arg)
#endif

/* Define STACK_DIRECTION if you know the direction of stack
   growth for your system; otherwise it will be automatically
   deduced at run-time.

   STACK_DIRECTION > 0 => grows toward higher addresses
   STACK_DIRECTION < 0 => grows toward lower addresses
   STACK_DIRECTION = 0 => direction of growth unknown  */

#ifndef STACK_DIRECTION
#define	STACK_DIRECTION	0	/* Direction unknown.  */
#endif

#if STACK_DIRECTION != 0

#define	STACK_DIR	STACK_DIRECTION	/* Known at compile-time.  */

#else /* STACK_DIRECTION == 0; need run-time code.  */

static int stack_dir=0;		/* 1 or -1 once known.  */
#define	STACK_DIR	stack_dir

static void
find_stack_direction ()
{
  static char *addr = GLOBUS_NULL;	/* Address of first `dummy', once known.  */
  auto char dummy;		/* To get stack address.  */

  if (addr == GLOBUS_NULL)
    {				/* Initial entry.  */
      addr = ADDRESS_FUNCTION (dummy);

      find_stack_direction ();	/* Recurse once.  */
    }
  else
    {
      /* Second entry.  */
      if (ADDRESS_FUNCTION (dummy) > addr)
	stack_dir = 1;		/* Stack grew upward.  */
      else
	stack_dir = -1;		/* Stack grew downward.  */
    }
}

#endif /* STACK_DIRECTION == 0 */
/* An "alloca header" is used to:
   (a) chain together all alloca'ed blocks;
   (b) keep track of stack depth.

   It is very important that sizeof(header) agree with malloc
   alignment chunk size.  The following default should work okay.  */

#ifndef	ALIGN_SIZE
#define	ALIGN_SIZE	sizeof(double)
#endif

typedef union hdr
{
  char align[ALIGN_SIZE];	/* To force sizeof(header).  */
  struct
    {
      union hdr *next;		/* For chaining headers.  */
      char *deep;		/* For stack depth measure.  */
    } h;
} header;

static header *last_alloca_header = GLOBUS_NULL;	/* -> last alloca header.  */

/* Return a pointer to at least SIZE bytes of storage,
   which will be automatically reclaimed upon exit from
   the procedure that called alloca.  Originally, this space
   was supposed to be taken from the current stack frame of the
   caller, but that method cannot be made to work for some
   implementations of C, for example under Gould's UTX/32.  */

void *
alloca (size)
     unsigned size;
{
  auto char probe;		/* Probes stack depth: */
  register char *depth = ADDRESS_FUNCTION (probe);

#if STACK_DIRECTION == 0
  if (STACK_DIR == 0)		/* Unknown growth direction.  */
    find_stack_direction ();
#endif

  /* Reclaim garbage, defined as all alloca'd storage that
     was allocated from deeper in the stack than currently.  */

  {
    register header *hp;	/* Traverses linked list.  */

#ifdef emacs
    BLOCK_INPUT;
#endif

    for (hp = last_alloca_header; hp != GLOBUS_NULL;)
      if ((STACK_DIR > 0 && hp->h.deep > depth)
	  || (STACK_DIR < 0 && hp->h.deep < depth))
	{
	  register header *np = hp->h.next;

	  free ((void *) hp);	/* Collect garbage.  */

	  hp = np;		/* -> next header.  */
	}
      else
	break;			/* Rest are not deeper.  */

    last_alloca_header = hp;	/* -> last valid storage.  */

#ifdef emacs
    UNBLOCK_INPUT;
#endif
  }

  if (size == 0)
    return GLOBUS_NULL;		/* No allocation required.  */

  /* Allocate combined header + user data storage.  */

  {
    register void * new = malloc (sizeof (header) + size);
    /* Address of header.  */

    if (new == 0)
      abort();

    ((header *) new)->h.next = last_alloca_header;
    ((header *) new)->h.deep = depth;

    last_alloca_header = (header *) new;

    /* User storage begins just after header.  */

    return (void *) ((char *) new + sizeof (header));
  }
}

#if defined (CRAY) && defined (CRAY_STACKSEG_END)
#ifndef CRAY_STACK
#define CRAY_STACK
#ifndef CRAY2
/* Stack structures for CRAY-1, CRAY X-MP, and CRAY Y-MP */
struct stack_control_header
  {
    long shgrow:32;		/* Number of times stack has grown.  */
    long shaseg:32;		/* Size of increments to stack.  */
    long shhwm:32;		/* High water mark of stack.  */
    long shsize:32;		/* Current size of stack (all segments).  */
  };

/* The stack segment linkage control information occurs at
   the high-address end of a stack segment.  (The stack
   grows from low addresses to high addresses.)  The initial
   part of the stack segment linkage control information is
   0200 (octal) words.  This provides for register storage
   for the routine which overflows the stack.  */

struct stack_segment_linkage
  {
    long ss[0200];		/* 0200 overflow words.  */
    long sssize:32;		/* Number of words in this segment.  */
    long ssbase:32;		/* Offset to stack base.  */
    long:32;
    long sspseg:32;		/* Offset to linkage control of previous
				   segment of stack.  */
    long:32;
    long sstcpt:32;		/* Pointer to task common address block.  */
    long sscsnm;		/* Private control structure number for
				   microtasking.  */
    long ssusr1;		/* Reserved for user.  */
    long ssusr2;		/* Reserved for user.  */
    long sstpid;		/* Process ID for pid based multi-tasking.  */
    long ssgvup;		/* Pointer to multitasking thread giveup.  */
    long sscray[7];		/* Reserved for Cray Research.  */
    long ssa0;
    long ssa1;
    long ssa2;
    long ssa3;
    long ssa4;
    long ssa5;
    long ssa6;
    long ssa7;
    long sss0;
    long sss1;
    long sss2;
    long sss3;
    long sss4;
    long sss5;
    long sss6;
    long sss7;
  };

#else /* CRAY2 */
/* The following structure defines the vector of words
   returned by the STKSTAT library routine.  */
struct stk_stat
  {
    long now;			/* Current total stack size.  */
    long maxc;			/* Amount of contiguous space which would
				   be required to satisfy the maximum
				   stack demand to date.  */
    long high_water;		/* Stack high-water mark.  */
    long overflows;		/* Number of stack overflow ($STKOFEN) calls.  */
    long hits;			/* Number of internal buffer hits.  */
    long extends;		/* Number of block extensions.  */
    long stko_mallocs;		/* Block allocations by $STKOFEN.  */
    long underflows;		/* Number of stack underflow calls ($STKRETN).  */
    long stko_free;		/* Number of deallocations by $STKRETN.  */
    long stkm_free;		/* Number of deallocations by $STKMRET.  */
    long segments;		/* Current number of stack segments.  */
    long maxs;			/* Maximum number of stack segments so far.  */
    long pad_size;		/* Stack pad size.  */
    long current_address;	/* Current stack segment address.  */
    long current_size;		/* Current stack segment size.  This
				   number is actually corrupted by STKSTAT to
				   include the fifteen word trailer area.  */
    long initial_address;	/* Address of initial segment.  */
    long initial_size;		/* Size of initial segment.  */
  };

/* The following structure describes the data structure which trails
   any stack segment.  I think that the description in 'asdef' is
   out of date.  I only describe the parts that I am sure about.  */

struct stk_trailer
  {
    long this_address;		/* Address of this block.  */
    long this_size;		/* Size of this block (does not include
				   this trailer).  */
    long unknown2;
    long unknown3;
    long link;			/* Address of trailer block of previous
				   segment.  */
    long unknown5;
    long unknown6;
    long unknown7;
    long unknown8;
    long unknown9;
    long unknown10;
    long unknown11;
    long unknown12;
    long unknown13;
    long unknown14;
  };

#endif /* CRAY2 */
#endif /* not CRAY_STACK */

#ifdef CRAY2
/* Determine a "stack measure" for an arbitrary ADDRESS.
   I doubt that "lint" will like this much.  */

static long
globus_l_libc_i00afunc (long *address)
{
  struct stk_stat status;
  struct stk_trailer *trailer;
  long *block, size;
  long result = 0;

  /* We want to iterate through all of the segments.  The first
     step is to get the stack status structure.  We could do this
     more quickly and more directly, perhaps, by referencing the
     $LM00 common block, but I know that this works.  */

  STKSTAT (&status);

  /* Set up the iteration.  */

  trailer = (struct stk_trailer *) (status.current_address
				    + status.current_size
				    - 15);

  /* There must be at least one stack segment.  Therefore it is
     a fatal error if "trailer" is null.  */

  if (trailer == 0)
    abort ();

  /* Discard segments that do not contain our argument address.  */

  while (trailer != 0)
    {
      block = (long *) trailer->this_address;
      size = trailer->this_size;
      if (block == 0 || size == 0)
	abort ();
      trailer = (struct stk_trailer *) trailer->link;
      if ((block <= address) && (address < (block + size)))
	break;
    }

  /* Set the result to the offset in this segment and add the sizes
     of all predecessor segments.  */

  result = address - block;

  if (trailer == 0)
    {
      return result;
    }

  do
    {
      if (trailer->this_size <= 0)
	abort ();
      result += trailer->this_size;
      trailer = (struct stk_trailer *) trailer->link;
    }
  while (trailer != 0);

  /* We are done.  Note that if you present a bogus address (one
     not in any segment), you will get a different number back, formed
     from subtracting the address of the first block.  This is probably
     not what you want.  */

  return (result);
}

#else /* not CRAY2 */
/* Stack address function for a CRAY-1, CRAY X-MP, or CRAY Y-MP.
   Determine the number of the cell within the stack,
   given the address of the cell.  The purpose of this
   routine is to linearize, in some sense, stack addresses
   for alloca.  */

static long
globus_l_libc_i00afunc (long address)
{
  long stkl = 0;

  long size, pseg, this_segment, stack;
  long result = 0;

  struct stack_segment_linkage *ssptr;

  /* Register B67 contains the address of the end of the
     current stack segment.  If you (as a subprogram) store
     your registers on the stack and find that you are past
     the contents of B67, you have overflowed the segment.

     B67 also points to the stack segment linkage control
     area, which is what we are really interested in.  */

  stkl = CRAY_STACKSEG_END ();
  ssptr = (struct stack_segment_linkage *) stkl;

  /* If one subtracts 'size' from the end of the segment,
     one has the address of the first word of the segment.

     If this is not the first segment, 'pseg' will be
     nonzero.  */

  pseg = ssptr->sspseg;
  size = ssptr->sssize;

  this_segment = stkl - size;

  /* It is possible that calling this routine itself caused
     a stack overflow.  Discard stack segments which do not
     contain the target address.  */

  while (!(this_segment <= address && address <= stkl))
    {
#ifdef DEBUG_I00AFUNC
      fprintf (stderr, "%011o %011o %011o\n", this_segment, address, stkl);
#endif
      if (pseg == 0)
	break;
      stkl = stkl - pseg;
      ssptr = (struct stack_segment_linkage *) stkl;
      size = ssptr->sssize;
      pseg = ssptr->sspseg;
      this_segment = stkl - size;
    }

  result = address - this_segment;

  /* If you subtract pseg from the current end of the stack,
     you get the address of the previous stack segment's end.
     This seems a little convoluted to me, but I'll bet you save
     a cycle somewhere.  */

  while (pseg != 0)
    {
#ifdef DEBUG_I00AFUNC
      fprintf (stderr, "%011o %011o\n", pseg, size);
#endif
      stkl = stkl - pseg;
      ssptr = (struct stack_segment_linkage *) stkl;
      size = ssptr->sssize;
      pseg = ssptr->sspseg;
      result += size;
    }
  return (result);
}

#endif /* not CRAY2 */
#endif /* CRAY */
#endif /* !defined (__GNUC__) || __GNUC__ < 2 */
#endif /* TARGET_ARCH_CRAYT3E */

/* IPv6 utils */

#if 0
static
int
globus_l_libc_copy_addrinfo(
    globus_addrinfo_t **                out_addrinfo,
    globus_addrinfo_t *                 in_addrinfo)
{
    globus_addrinfo_t *                 new_addrinfo;
    globus_addrinfo_t *                 addrinfo;
    char *                              canonname = NULL;
    
    addrinfo = in_addrinfo;
    if(addrinfo)
    {
        new_addrinfo = (globus_addrinfo_t *) 
            globus_malloc(sizeof(globus_addrinfo_t));
        memcpy(new_addrinfo, addrinfo, sizeof(globus_addrinfo_t));
        new_addrinfo->ai_addr = (struct sockaddr *)
            globus_malloc(addrinfo->ai_addrlen);
        memcpy(new_addrinfo->ai_addr, addrinfo->ai_addr, addrinfo->ai_addrlen);
        if(addrinfo->ai_canonname)
        {
            canonname = globus_libc_strdup(addrinfo->ai_canonname);
            new_addrinfo->ai_canonname = canonname;
        }
        *out_addrinfo = new_addrinfo;
        for(addrinfo = addrinfo->ai_next;
            addrinfo;
            addrinfo = addrinfo->ai_next)
        {
            new_addrinfo->ai_next = (globus_addrinfo_t *) 
                globus_malloc(sizeof(globus_addrinfo_t));
            new_addrinfo = new_addrinfo->ai_next;
            memcpy(new_addrinfo, addrinfo, sizeof(globus_addrinfo_t));
            new_addrinfo->ai_addr = (struct sockaddr *)
                globus_malloc(addrinfo->ai_addrlen);
            memcpy(new_addrinfo->ai_addr, addrinfo->ai_addr, 
                addrinfo->ai_addrlen);
            new_addrinfo->ai_canonname = canonname;
        }
    }
    
    return 0;       
}
#endif

globus_result_t
globus_libc_getaddrinfo(
    const char *                        node,
    const char *                        service,
    const globus_addrinfo_t *           hints,
    globus_addrinfo_t **                res)
{
    int                                 rc;
    globus_result_t                     result;
    const char *                        port_str = service;
    
#ifdef TARGET_ARCH_AIX5
    if(port_str && port_str[0] == '0' && port_str[1] == '\0')
    {
        /* aix's getaddrinfo is broken with literal zeros
         * change it to an arbitrary number and update the results after
         * the getaddrinfo call
         */
        port_str = "56789";
    }
#endif
    
    result = GLOBUS_SUCCESS;

    rc = getaddrinfo(node, port_str, hints, res);
    if(rc != 0)
    {
#   ifdef EAI_SYSTEM
        if(rc == EAI_SYSTEM)
        {
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_COMMON_MODULE,
                    errno,
                    rc + GLOBUS_EAI_ERROR_OFFSET,
                    __FILE__,
                    "globus_libc_getaddrinfo",
                    __LINE__,
                    "%s",
                    gai_strerror(rc)));
        }
        else
#   endif /* EAI_SYSTEM */
        {
            result = globus_error_put(
                globus_error_construct_error(
                    GLOBUS_COMMON_MODULE,
                    GLOBUS_NULL,
                    rc + GLOBUS_EAI_ERROR_OFFSET,
                    __FILE__,
                    "globus_libc_getaddrinfo",
                    __LINE__,
                    "%s",
                    gai_strerror(rc)));
        }
        goto error;
    }

#ifdef TARGET_ARCH_AIX5
    {
        globus_addrinfo_t *             addrinfo;
        
        /* aix's getaddrinfo also doesnt fill in the family and len fields of
         * the sockaddrs
         */
        for(addrinfo = *res;
            addrinfo;
            addrinfo = addrinfo->ai_next)
        {
            if(GlobusLibcProtocolFamilyIsIP(addrinfo->ai_family))
            {
                GlobusLibcSockaddrSetFamily(
                    *addrinfo->ai_addr, addrinfo->ai_family);
                GlobusLibcSockaddrSetLen(
                   *addrinfo->ai_addr, addrinfo->ai_addrlen);
                if(port_str != service)
                {
                    GlobusLibcSockaddrSetPort(*addrinfo->ai_addr, 0);
                }
            }
        }
    }
#endif

    return result;

error:
    return result;
}

void
globus_libc_freeaddrinfo(
    globus_addrinfo_t *                 res)
{
    freeaddrinfo(res);
}

globus_result_t
globus_libc_getnameinfo(
    const globus_sockaddr_t *           addr,
    char *                              hostbuf,
    globus_size_t                       hostbuf_len,
    char *                              servbuf,
    globus_size_t                       servbuf_len,
    int                                 flags)
{
    int                                 rc;
    globus_result_t                     result;

    result = GLOBUS_SUCCESS;
    *hostbuf = 0;
    rc = getnameinfo(
        (const struct sockaddr *) addr,
        GlobusLibcSockaddrLen(addr),
        hostbuf,
        hostbuf_len,
        servbuf,
        servbuf_len,
        flags);

    /* some getnameinfo (darwin) return success but leave the hostbuf empty.
     * in this case we'll just fill in hostbuf with the ip address
     */
    if(rc == 0 && !*hostbuf && !(flags & GLOBUS_NI_NUMERICHOST))
    {
        rc = getnameinfo(
            (const struct sockaddr *) addr,
            GlobusLibcSockaddrLen(addr),
            hostbuf,
            hostbuf_len,
            servbuf,
            servbuf_len,
            flags | GLOBUS_NI_NUMERICHOST);
    }

    if(rc != 0)
    {
#       ifdef EAI_SYSTEM
        if(rc == EAI_SYSTEM)
        {
            result = globus_error_put(
                globus_error_wrap_errno_error(
                    GLOBUS_COMMON_MODULE,
                    errno,
                    rc + GLOBUS_EAI_ERROR_OFFSET,
                    __FILE__,
                    "globus_libc_getnameinfo",
                    __LINE__,
                    "%s",
                    gai_strerror(rc)));
        }
        else
#       endif /* EAI_SYSTEM */
        {
            result = globus_error_put(
                globus_error_construct_error(
                    GLOBUS_COMMON_MODULE,
                    GLOBUS_NULL,
                    rc + GLOBUS_EAI_ERROR_OFFSET,
                    __FILE__,
                    "globus_libc_getnameinfo",
                    __LINE__,
                    "%s",
                    gai_strerror(rc)));
        }
    }

    return result;
}

globus_bool_t
globus_libc_addr_is_loopback(
    const globus_sockaddr_t *           addr)
{
    struct sockaddr *                   _addr = (struct sockaddr *) addr;
    globus_bool_t                       result = GLOBUS_FALSE;

    switch(_addr->sa_family)
    {
      case AF_INET:
        if(*(uint8_t *) &((struct sockaddr_in *) 
                _addr)->sin_addr.s_addr == 127)
        {
            result = GLOBUS_TRUE;
        }
        break;
#if defined(AF_INET6) && defined(IN6_IS_ADDR_LOOPBACK)
      case AF_INET6:
        if(IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *) _addr)->sin6_addr) ||
            (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *) _addr)->sin6_addr) &&
            *(uint8_t *) &((struct sockaddr_in6 *) 
                _addr)->sin6_addr.s6_addr[12] == 127))        
        {
            result = GLOBUS_TRUE;
        }
        break;
#endif
      default:
        globus_assert(0 &&
                      "Unknown family in globus_libc_addr_is_loopback");
        break;
    }

    return result;
}

globus_bool_t
globus_libc_addr_is_wildcard(
    const globus_sockaddr_t *           addr)
{
    struct sockaddr *                   _addr = (struct sockaddr *) addr;
    globus_bool_t                       result = GLOBUS_FALSE;
    
    switch(_addr->sa_family)
    {
      case AF_INET:
        if(ntohl(((struct sockaddr_in *) _addr)->sin_addr.s_addr) ==
           INADDR_ANY)
        {
            result = GLOBUS_TRUE;
        }
        break;
#if defined(AF_INET6) && defined(IN6_IS_ADDR_UNSPECIFIED)
      case AF_INET6:
        if(IN6_IS_ADDR_UNSPECIFIED(
          &((struct sockaddr_in6 *) _addr)->sin6_addr) ||
          (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *) _addr)->sin6_addr) &&
     ntohl(*(uint32_t *) &((struct sockaddr_in6 *) _addr)->sin6_addr.s6_addr[12]) ==
                INADDR_ANY))
        {
            result = GLOBUS_TRUE;
        }
        break;
#endif
      default:
        globus_assert(0 &&
                      "Unknown family in globus_libc_addr_is_wildcard");
        break;
    }

    return result;
}

globus_result_t
globus_libc_addr_to_contact_string(
    const globus_sockaddr_t *           addr,
    int                                 opts_mask,
    char **                             contact_string)
{
    globus_result_t                     result;
    globus_sockaddr_t                   myaddr;
    char                                host[MAXHOSTNAMELEN];
    char                                port[10];
    int                                 port_no;
    int                                 ni_flags = 0;
    char *                              cs;
    
    if(!GlobusLibcProtocolFamilyIsIP(GlobusLibcSockaddrGetFamily(*addr)))
    {
        result = globus_error_put(
            globus_error_construct_error(
               GLOBUS_COMMON_MODULE,
               GLOBUS_NULL,
               0,
               __FILE__,
               "globus_libc_addr_to_contact_string",
               __LINE__,
               "Invalid addr family"));
        goto error_nameinfo;
    }
        
    if(opts_mask & GLOBUS_LIBC_ADDR_LOCAL ||
        globus_libc_addr_is_wildcard(addr))
    {
        int                             family;
        
#if AF_INET6
        family = (opts_mask & GLOBUS_LIBC_ADDR_IPV6)
            ? AF_INET6 : ((opts_mask & GLOBUS_LIBC_ADDR_IPV4)
            ? AF_INET : AF_UNSPEC);
#else
        family = (opts_mask & GLOBUS_LIBC_ADDR_IPV4)
            ? AF_INET : AF_UNSPEC;
#endif
            
        if(globus_libc_gethostaddr_by_family(&myaddr, family) != 0)
        {
            result = globus_error_put(
                globus_error_construct_error(
                   GLOBUS_COMMON_MODULE,
                   GLOBUS_NULL,
                   0,
                   __FILE__,
                   "globus_libc_addr_to_contact_string",
                   __LINE__,
                    "globus_libc_gethostaddr failed"));
            goto error_nameinfo;
        }
        
        GlobusLibcSockaddrGetPort(*addr, port_no);
        GlobusLibcSockaddrSetPort(myaddr, port_no);
        addr = &myaddr;
    }
    
    ni_flags = GLOBUS_NI_NUMERICSERV;

    if(opts_mask & GLOBUS_LIBC_ADDR_NUMERIC)
    {
        ni_flags |= GLOBUS_NI_NUMERICHOST;
    }

    result = globus_libc_getnameinfo(
        addr, host, sizeof(host), port, sizeof(port), ni_flags);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_nameinfo;
    }
    
    cs = globus_malloc(strlen(host) + strlen(port) + 4);
    if(!cs)
    {
        result = globus_error_put(
            globus_error_construct_error(
                GLOBUS_COMMON_MODULE,
                GLOBUS_NULL,
                0,
                __FILE__,
                "globus_libc_addr_to_contact_string",
                __LINE__,
                "malloc failed"));
        goto error_memory;
    }
    
    if(strchr(host, ':'))
    {
        sprintf(cs, "[%s]:%s", host, port);
    }
    else
    {
        sprintf(cs, "%s:%s", host, port);
    }
    
    *contact_string = cs;
    
    return GLOBUS_SUCCESS;

error_memory:
error_nameinfo:
    return result;
}

/** convert a numeric contact string to an array of ints
 * 
 * (port is optional and may be NULL.  0 will be passed back if no port is
 * found)
 * host needs to have room for at least 16 ints
 * count will be passed back. 4 for ipv4, 16 for ipv6
 */
globus_result_t
globus_libc_contact_string_to_ints(
    const char *                        contact_string,
    int *                               host,
    int *                               count,
    unsigned short *                    port)
{
    char *                              s;
    char *                              p;
    int                                 i;
    char                                buf[256];
    struct in_addr                      addr4;
#ifdef AF_INET6
    struct in6_addr                     addr6;
#endif
    unsigned char *                     paddr;
    
    memset(host, 0, sizeof(int) * 16);
    strncpy(buf, contact_string, sizeof(buf));
    buf[255] = 0;
    s = strchr(buf, ':');
    p = strchr(buf, '.');
    if(!s || (p && p < s))
    {
        /* this must be ipv4 */
        *count = 4;
        if(s)
        {
            *(s++) = 0;
        }
        
        if(inet_pton(AF_INET, buf, &addr4) <= 0)
        {
            goto error_parse;
        }
        paddr = (unsigned char *) &addr4;
    }
    else
    {
        char *                          pbuf = buf;
        
        *count = 16;
        if(*pbuf == '[')
        {
            pbuf++;
            s = strchr(pbuf, ']');
            if(!s)
            {
                goto error_parse;
            }
            *(s++) = 0;
            if(*(s++) != ':')
            {
                s = NULL;
            } 
        }
        else
        {
            /* cant have a port without [] notation */
            s = NULL;
        }
        
#if defined(AF_INET6)
        if(inet_pton(AF_INET6, pbuf, &addr6) <= 0)
#endif
        {
            goto error_parse;
        }
#if defined(AF_INET6)
        paddr = (unsigned char *) &addr6;
#endif
    }
    
    if(port)
    {
        *port = 0;
        if(s)
        {
            sscanf(s, "%hu", port);
        }
    }
    
    for(i = 0; i < *count; i++)
    {
        host[i] = paddr[i];
    }
    
    return GLOBUS_SUCCESS;
    
error_parse:
    return globus_error_put(
        globus_error_construct_error(
            GLOBUS_COMMON_MODULE,
            GLOBUS_NULL,
            0,
            __FILE__,
            "globus_libc_contact_string_to_ints",
            __LINE__,
            "unable to parse ip"));
}

char *
globus_libc_ints_to_contact_string(
    int *                               host,
    int                                 count,
    unsigned short                      port)
{
    char *                              layout[25];
    char                                bufs[12][10];
    char                                ipv4[20];
    int                                 h = 0;
    int                                 l = 0;
    int                                 b = 0;
    globus_bool_t                       need_bracket = GLOBUS_FALSE;
    globus_bool_t                       compressed = GLOBUS_FALSE;
    
    if(count == 16)
    {
        if(port)
        {
            layout[l++] = "[";
            need_bracket = GLOBUS_TRUE;
        }
        
        /* count up leading zeros */
        while(h < 16 && host[h] == 0) h++;
        if(h == 12)
        {
            count = 4;
            layout[l++] = "::";
        }
        else if(h == 10 && host[10] == 0xff && host[11] == 0xff)
        {
            count = 4;
            h = 12;
            layout[l++] = "::FFFF:";
        }
        else if(h == 16)
        {
            layout[l++] = "0::0";
        }
        else
        {
            for(h = 0; h < 16;)
            {
                if(!compressed &&
                    host[h] == 0 && h < 11 && host[h + 1] == 0 &&
                    host[h + 2] == 0 && host[h + 3] == 0 &&
                    host[h + 4] == 0 && host[h + 5] == 0)
                {
                    /* compress 3 or more 0s into :: */
                    compressed = GLOBUS_TRUE;
                    if(h == 0)
                    {
                        layout[l++] = "::";
                    }
                    else
                    {
                        layout[l++] = ":";
                    }
                    
                    h += 6;
                    while(h < 15 && host[h] == 0 && host[h + 1] == 0) h += 2;
                }
                else
                {
                    if((host[h] & 0xff) == 0)
                    {
                        snprintf(bufs[b], 10, "%X", host[h + 1] & 0xff);
                    }
                    else
                    {
                        snprintf(bufs[b], 10, "%X%.2X",
                            host[h] & 0xff, host[h + 1] & 0xff);
                    }
                    
                    layout[l++] = bufs[b++];
                    if(h < 14)
                    {
                        layout[l++] = ":";
                    }
                    
                    h += 2;
                }
            }
        }
    }
    
    if(count == 4)
    {
        snprintf(ipv4, sizeof(ipv4),
            "%d.%d.%d.%d", host[h + 0], host[h + 1], host[h + 2], host[h + 3]);
        layout[l++] = ipv4;
    }
    
    if(need_bracket)
    {
        layout[l++] = "]";
    }
    
    if(port && l > 0)
    {
        sprintf(bufs[b], ":%d", (int) port);
        layout[l++] = bufs[b++];
    }
    
    return globus_libc_join((const char **)layout, l);
}

/**
 * create a new string from all of the strings in array
 * 
 * @param array
 *      an array of strings to concatenate (null entries are skipped)
 * @param count
 *      length of array
 */
char *
globus_libc_join(
    const char **                       array,
    int                                 count)
{
    int *                               lens;
    int                                 len;
    char *                              s;
    int                                 i;
    
    if(count <= 0)
    {
        return NULL;
    }
    
    lens = (int *) globus_malloc(sizeof(int) * count);
    if(!lens)
    {
        return NULL;
    }
    
    len = 0;
    for(i = 0; i < count; i++)
    {
        len += lens[i] = array[i] ? strlen(array[i]) : 0;
    }
    
    if(len)
    {
        s = (char *) globus_malloc(sizeof(char) * (len + 1));
        if(s)
        {
            len = 0;
            for(i = 0; i < count; i++)
            {
                if(lens[i])
                {
                    memcpy(s + len, array[i], lens[i]);
                    len += lens[i];
                }
            }
            
            s[len] = '\0';
        }
    }
    else
    {
        s = NULL;
    }
    
    globus_free(lens);
    
    return s;
}

/*****************************************************************************
globus_error.c

Description:
   Error- and status-reporting functions, extracted from nexus

CVS Information:
   $Source$
   $Date$
   $Revision$
   $State$
   $Author$
******************************************************************************/
#include "config.h"

#include "globus_common.h"

/*****************************************************************************
		      Module specific prototypes
*****************************************************************************/

static void globus_l_descriptor_string(char *fmt,
					      char *s1,
					      char *s2,
					      char *s3);

/*****************************************************************************
		      Module specific prototypes
*****************************************************************************/
#define GLOBUS_L_MAX_SESSION_STRING_LENGTH 1024


/*****************************************************************************
 * globus_silent_fatal()
 *
 * Fatal error out without printing any messages.
*****************************************************************************/
void
globus_silent_fatal(void)
{
    abort();
} /* globus_silent_fatal() */

/*
 * globus_fatal()
 */
#ifdef HAVE_STDARG_H
void
globus_fatal(char *msg, ...)
#else
void
globus_fatal(msg, va_alist)
char *msg;
va_dcl
#endif
{
    char fmt[1024];
    va_list ap;

    globus_l_descriptor_string(fmt, "Fatal error", msg, (char *) NULL);

#ifdef HAVE_STDARG_H
    va_start(ap, msg);
#else
    va_start(ap);
#endif
    globus_thread_diagnostics_vprintf(fmt, ap);
    va_end(ap);

    globus_silent_fatal();
    
} /* globus_fatal() */


/*
 * globus_l_descriptor_string()
 *
 */
static void
globus_l_descriptor_string(char *fmt, char *s1, char *s2, char *s3)
{
    globus_libc_sprintf(fmt, "t%lu:p%lu%s%s%s%s%s%s",
			(unsigned long) globus_thread_self(),
			(unsigned long) getpid(),
			(s1 ? ": " : ""),
			(s1 ? s1 : ""),
			(s2 ? ": " : ""),
			(s2 ? s2 : ""),
			(s3 ? ": " : ""),
			(s3 ? s3 : "") );
} /* globus_l_descriptor_string() */

/*
 * globus_error()
 */
#ifdef HAVE_STDARG_H
void globus_error(char *msg, ...)
#else
void globus_error(msg, va_alist)
char *msg;
va_dcl
#endif
{
    char fmt[1024];
    va_list ap;

    globus_l_descriptor_string(fmt, "Error", msg, (char *) NULL);

#ifdef HAVE_STDARG_H
    va_start(ap, msg);
#else
    va_start(ap);
#endif
    vfprintf(stdout, fmt, ap);
    fflush(stdout);
    va_end(ap);
} /* globus_error() */


/*
 * globus_warning()
 */
#ifdef HAVE_STDARG_H
void globus_warning(char *msg, ...)
#else
void globus_warning(msg, va_alist)
char *msg;
va_dcl
#endif
{
    char fmt[1024];
    va_list ap;
    
    globus_l_descriptor_string(fmt, "Warning", msg, (char *) NULL);

#ifdef HAVE_STDARG_H
    va_start(ap, msg);
#else
    va_start(ap);
#endif
    vfprintf(stdout, fmt, ap);
    fflush(stdout);
    va_end(ap);
} /* globus_warning() */


/*
 * globus_notice()
 */
#ifdef HAVE_STDARG_H
void globus_notice(char *msg, ...)
#else
void globus_notice(msg, va_alist)
char *msg;
va_dcl
#endif
{
    char fmt[1024];
    va_list ap;

    globus_l_descriptor_string(fmt, "Notice", msg, (char *) NULL);

#ifdef HAVE_STDARG_H
    va_start(ap, msg);
#else
    va_start(ap);
#endif
    globus_libc_vfprintf(stdout, fmt, ap);
    
    fflush(stdout);
    va_end(ap);
} /* globus_notice() */




/*
 * globus_perror()
 */
#ifdef HAVE_STDARG_H
void globus_perror(char *msg, ...)
#else
void globus_perror(msg, va_alist)
char *msg;
va_dcl
#endif
{
    char fmt[1024];
    va_list ap;
    int save_error;

    save_error = errno;
    globus_l_descriptor_string(fmt, "", msg, globus_libc_system_error_string(save_error));

#ifdef HAVE_STDARG_H
    va_start(ap, msg);
#else
    va_start(ap);
#endif
    globus_libc_vfprintf(stdout, fmt, ap);
    fflush(stdout);
    va_end(ap);

} /* globus_perror() */


#ifdef HAVE_STDARG_H
void globus_fatal_perror(char *msg, ...)
#else
void globus_fatal_perror(msg, va_alist)
char *msg;
va_dcl
#endif
{
    char fmt[1024];
    va_list ap;
    int save_error;

    save_error = errno;
    globus_l_descriptor_string(fmt, "Fatal error: ", msg, globus_libc_system_error_string(save_error));

#ifdef HAVE_STDARG_H
    va_start(ap, msg);
#else
    va_start(ap);
#endif
    globus_libc_vfprintf(stdout, fmt, ap);
    fflush(stdout);
    va_end(ap);

    globus_silent_fatal();
}

/*
 * globus_assert_sprintf()
 *
 * This is used by the NexusAssert2() macro...
 */
#ifdef HAVE_STDARG_H
char *globus_assert_sprintf(char *msg, ...)
#else
char *globus_assert_sprintf(msg, va_alist)
char *msg;
va_dcl
#endif
{
    static char assert_sprintf_buf[1024];
    va_list ap;
    
#ifdef HAVE_STDARG_H
    va_start(ap, msg);
#else
    va_start(ap);
#endif
    globus_libc_vsprintf(assert_sprintf_buf, msg, ap);
    va_end(ap);

    return (assert_sprintf_buf);
} /* globus_assert_sprintf() */


/*
 *
 * Return a malloced string containing a unique string.
 * This string should be unique for all time, not just within
 * this process but across all process on all machines.
 * This string is composed of my hostname, process id, and the
 * current time (seconds since 1970).
 */
char *
globus_get_unique_session_string(void)
{
    char hostname[MAXHOSTNAMELEN];
    char tmp_buf[MAXHOSTNAMELEN + 32];
    char *result;

    globus_libc_gethostname(hostname, MAXHOSTNAMELEN);

    globus_libc_sprintf(tmp_buf, "%s_%lx_%lx",
			hostname,
			(unsigned long) globus_libc_getpid(),
			(unsigned long) time(0));
    
    if (strlen(tmp_buf) >= GLOBUS_L_MAX_SESSION_STRING_LENGTH)
    {
        globus_fatal("Internal Error: GLOBUS_L_MAX_SESSION_STRING_LENGTH=%d not long enough to hold seesion string\n", GLOBUS_L_MAX_SESSION_STRING_LENGTH);
    }
    result = globus_libc_strdup(tmp_buf);

    return result;
} /* globus_get_unique_session_string() */


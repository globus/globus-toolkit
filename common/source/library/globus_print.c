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

/*****************************************************************************
globus_print.c

Description:
   Error- and status-reporting functions, extracted from nexus

CVS Information:
   $Source$
   $Date$
   $Revision$
   $State$
   $Author$
******************************************************************************/
#include "globus_common_include.h"
#include "globus_print.h"
#include "globus_libc.h"
#include "globus_error.h"
#include "globus_error_generic.h"
#include "globus_common.h"

/*****************************************************************************
		      Module specific prototypes
*****************************************************************************/

static void 
globus_l_descriptor_string(
    char *                                          fmt,
    char *                                          s1,
	char *                                          s2,
	char *                                          s3);

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

    globus_l_descriptor_string(fmt, _GCSL("Fatal error"), msg, (char *) NULL);

#ifdef HAVE_STDARG_H
    va_start(ap, msg);
#else
    va_start(ap);
#endif
    vprintf(fmt, ap);
    va_end(ap);

    GLOBUS_DUMP_STACK();

    globus_silent_fatal();
    
} /* globus_fatal() */

#if defined(TARGET_ARCH_LINUX)

/* this isnt guaranteed to work since globus_l_callback_main_thread can be set 
 * from a thread... hopefully not
 */
pid_t globus_l_callback_main_thread;
void globus_dump_stack()
{
    char s[1024];
    char filename[1024];
    int count;
    
#ifdef BUILD_LITE
    globus_l_callback_main_thread = getpid();
#endif

    sprintf(s, "/proc/%d/exe", globus_l_callback_main_thread);
    count = readlink(s, filename, 1024);
    filename[count] = 0;

#ifdef BUILD_LITE
    sprintf(s, "(echo 'set pagination off\nfile %s\nattach %d\nwhere\nquit' | gdb -n -batch -x /dev/stdin) 1>&2", filename, globus_l_callback_main_thread);
#else
    sprintf(s, "(echo 'set pagination off\nfile %s\nattach %d\nthread apply all where\nquit' | gdb -n -batch -x /dev/stdin) 1>&2", filename, globus_l_callback_main_thread);
#endif
    system(s);
}

#endif /* TARGET_ARCH_LINUX */

/*
 * globus_l_descriptor_string()
 *
 */
static void
globus_l_descriptor_string(char *fmt, char *s1, char *s2, char *s3)
{
    globus_libc_sprintf(fmt, "t%lu:p%lu%s%s%s%s%s%s",
/* The following line was changed to preserve the encapsulation of the 
 *  globus_thread_t datatype.  This change was necessary because this datatype maps
 *  to different implementations on different platforms, and the UNIX implementation 
 *  conflicted with the Windows implementation.
 *    Michael Lebman 2-8-02
 */

#ifndef TARGET_ARCH_WIN32
			(unsigned long) globus_thread_self(),
#else
			(unsigned long) globus_thread_get_threadID_as_long(),
#endif
			(unsigned long) globus_libc_getpid(),
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

    globus_l_descriptor_string(fmt, _GCSL("Error"), msg, (char *) NULL);

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
    
    globus_l_descriptor_string(fmt, _GCSL("Warning"), msg, (char *) NULL);

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

    globus_l_descriptor_string(fmt, _GCSL("Notice"), msg, (char *) NULL);

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
    globus_l_descriptor_string(fmt, _GCSL("Fatal error: "), msg, globus_libc_system_error_string(save_error));

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
        globus_fatal(_GCSL("Internal Error: GLOBUS_L_MAX_SESSION_STRING_LENGTH=%d not long enough to hold seesion string\n"), GLOBUS_L_MAX_SESSION_STRING_LENGTH);
    }
    result = globus_libc_strdup(tmp_buf);

    return result;
} /* globus_get_unique_session_string() */

void
globus_panic(
    globus_module_descriptor_t *        module,
    globus_result_t                     result,
    const char *                        message,
    ...)
{
    va_list                             ap;
    
    if(module)
    { 
        fprintf(stderr, _GCSL("PANIC in module %s\n"), module->module_name);
    }
    else
    {
        fprintf(stderr, _GCSL("PANIC\n"));
    }
    
    va_start(ap, message);
    vfprintf(stderr, message, ap);
    va_end(ap);
    
    if(result != GLOBUS_SUCCESS)
    {
        fprintf(stderr, _GCSL("Result:\n%s\n"),  
            globus_error_print_chain(globus_error_get(result)));
    }
    
    GLOBUS_DUMP_STACK();
    abort();
}

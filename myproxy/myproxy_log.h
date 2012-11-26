/*
 * myproxy_log.h
 *
 * Logging routines for myproxy server.
 */
#ifndef __MYPROXY_LOG_H
#define __MYPROXY_LOG_H

#include <stdio.h>

/* Include this for convenience */
#include <syslog.h>

/*
 * myproxy_log_use_syslog()
 *
 * Use syslog with given name and facility for logging (as used for
 * the syslog call. If facility == 0 then no logging to syslog will
 * be done. name may be NULL indicate no name be used.
 */
void myproxy_log_use_syslog(int facility,
			    const char *name);


/*
 * myproxy_log_use_stream()
 *
 * Send log messages to the given stream. stream may be NULL which
 * turns this off.
 */
void myproxy_log_use_stream(FILE *stream);

/*
 * myproxy_log()
 *
 * Log something. Takes arguments like sprintf().
 */
void myproxy_log(const char *format, ...);

/*
 * mproxy_log_verror()
 *
 * Log the error condition as indicated in the verror context.
 */
void myproxy_log_verror();

/*
 * myproxy_log_perror()
 *
 * Log the error message followed by a description of the current
 * errror in errno.
 */
void myproxy_log_perror(const char *format, ...);

/*
 * myproxy_log_close()
 *
 * Shutdown logging and deallocate any memory associated with it.
 * All further logging will be ignoe unless another myproxy_log_use_*()
 * call is made.
 */
void myproxy_log_close();

/*
 * myproxy_debug_set_level()
 *
 * Turns debugging on or off, depending on wether value is non-zero
 * or zero respectively. Returns previous value for debugging.
 */
int myproxy_debug_set_level(int value);

/*
 * myproxy_debug()
 *
 * Log a debugging message. Will only be displayed if debugging is
 * enabled.
 */
void myproxy_debug(const char *format, ...);
 
#endif /* __MYPROXY_LOG_H */


/*
 * myproxy_common.h
 *
 * Internal header file that includes all headers needed for building
 * MyProxy in one place to ease porting.
 *
 */

#ifndef __MYPROXY_COMMON_H
#define __MYPROXY_COMMON_H

#include <globus_common.h> /* need to start w/ this to avoid later trouble */

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>	/* Might be needed before <arpa/inet.h> */
#include <arpa/inet.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(HAVE_GETOPT_H)
#include <getopt.h>
#endif

#if !defined(HAVE_SOCKLEN_T)
typedef int socklen_t;
#endif

#include <globus_gss_assist.h>
#include <globus_gsi_system_config.h>
#include <gssapi.h>

#include "myproxy.h" /* public headers */
#include "myproxy_popen.h"
#include "myproxy_ocsp.h"
#include "accept_credmap.h"
#include "certauth_extensions.h"
#include "certauth_resolveuser.h"
#include "gsi_socket.h"
#include "port_getopt.h"
#include "ssl_utils.h"
#include "string_funcs.h"
#include "vparse.h"

#if defined(HAVE_LIBSASL2)
#include <sasl.h>
#include <saslutil.h>
#define SASL_BUFFER_SIZE 20480
#endif

#if defined(HAVE_LIBKRB5)
#include <krb5.h>
#endif

#if defined(HAVE_VOMS)
#include <voms_apic.h>
#endif

#if defined(HAVE_SECURITY_PAM_APPL_H)
# include <security/pam_appl.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
# include <pam/pam_appl.h>
#endif

#endif /* __MYPROXY_COMMON_H */

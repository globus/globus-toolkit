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
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <globus_gss_assist.h>
#include <gssapi.h>

#include "gnu_getopt.h"
#include "gsi_socket.h"
#include "myproxy.h"
#include "myproxy_authorization.h"
#include "myproxy_creds.h"
#include "myproxy_delegation.h"
#include "myproxy_log.h"
#include "myproxy_read_pass.h"
#include "myproxy_server.h"
#include "ssl_utils.h"
#include "string_funcs.h"
#include "verror.h"
#include "vparse.h"

#endif /* __MYPROXY_COMMON_H */

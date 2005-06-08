/*
 * myproxy.h
 *
 * Main public header for MyProxy library
 *
 */

#ifndef __MYPROXY_H
#define __MYPROXY_H

#define MYPROXY_VERSION "MYPROXYv2"	/* protocol version string */

/* software version constants */
#define MYPROXY_VERSION_MAJOR 2
#define MYPROXY_VERSION_MINOR 0
#define MYPROXY_VERSION_MICRO 0
#define MYPROXY_VERSION_DATE "v2.0 X XXX 2005"

/*
 * myproxy_version()
 *
 * Returns a static string indicating the MyProxy library version.
 * Also sets major, minor, and micro version numbers if non-NULL.
 */
char *myproxy_version(int *major, int *minor, int *micro);

/*
 * myproxy_check_version()
 *
 * Returns 0 if MyProxy library version matches this header.
 * Returns 1 if major version number differs.
 * Returns 2 if minor version number differs.
 * Returns 3 if micro version number differs.
 */
int myproxy_check_version_ex(int major, int minor, int micro);
#define myproxy_check_version() \
  myproxy_check_version_ex(MYPROXY_VERSION_MAJOR, MYPROXY_VERSION_MINOR, \
			   MYPROXY_VERSION_MICRO)

#include "myproxy_constants.h"
#include "myproxy_authorization.h"
#include "myproxy_protocol.h"
#include "myproxy_creds.h"
#include "myproxy_delegation.h"
#include "myproxy_log.h"
#include "myproxy_read_pass.h"
#include "myproxy_sasl_client.h"
#include "myproxy_sasl_server.h"
#include "myproxy_server.h"
#include "verror.h"

#endif /* __MYPROXY_H */

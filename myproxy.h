/*
 * myproxy.h
 *
 * Main header for MyProxy library
 *
 */

#ifndef __MYPROXY_H
#define __MYPROXY_H

#define MYPROXY_VERSION "MYPROXYv2"	/* protocol version string */

/* software version constants */
#define MYPROXY_VERSION_MAJOR 0
#define MYPROXY_VERSION_MINOR 6
#define MYPROXY_VERSION_MICRO 2
#define MYPROXY_VERSION_DATE "v0.6.2 21 Jun 2004"

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

/*
 * myproxy-delegation.h
 *
 * Interface for doing credential delegations with myproxy.
 */

#ifndef __MYPROXY_DELEGATION_H
#define __MYPROXY_DELEGATION_H

#include <gssapi.h>
#include "myproxy-gss-context.h"

/*
 * Values for MYPROXY_DELEGATION_init() source_credentials:
 */
#define MYPROXY_DELEGATION_CREDENTIALS_DEFAULT		NULL

/*
 * Values for MYPROXY_DELEGATION_init() flags:
 */
#define MYPROXY_DELEGATION_FLAGS_DEFAULT		0x0000

/*
 * Values for MYPROXY_DELEGATION_init() lifetime:
 */
#define MYPROXY_DELEGATION_LIFETIME_MAXIMUM		0x0000

/*
 * Valyes for MYPROXY_DELEGATION_init() restrictions:
 */
#define MYPROXY_DELEGATION_RESTRICTIONS_DEFAULT		NULL

/*
 * MYPROXY_DELEGATION_init()
 *
 * Function to be called by a process wishing to delegate
 * credentials to the remote party.
 *
 * source_credentials should be a string specifying the location
 * of the credentials to delegate. A value of
 * MYPROXY_DELEGATION_CREDENTIALS_DEFAULT indicates that the
 * default credentials for the given context be used.
 *
 * flags is reserved for future use and should currently always be
 * MYPROXY_DELEGATION_FLAGS_DEFAULT.
 *
 * lifetime should be the lifetime of the delegated credentials
 * in seconds. A value of MYPROXY_DELEGATION_LIFETIME_MAXIMUM
 * indicates that the longest possible lifetime should be delegated.
 *
 * restrictions is reserved for future use and should currently always be
 * MYPROXY_DELEGATION_RESTRICTIONS_DEFAULT.
 *
 * Returns 0 on success, -1 on error.
 */
int MYPROXY_DELEGATION_init(MYPROXY_GSS_CONTEXT *context,
			    char *source_credentials,
			    int flags,
			    int lifetime,
			    void *restrictions);

/*
 * MYPROXY_DELEGATION_accept()
 *
 * Function to be called by a proess wishing to accept delegated
 * credentials from the remote party.
 *
 * If target_credentials is NULL, it will be set to point to
 * a allocated string (to be freed by caller) indicating the
 * location of the received credentials. If target_credentials
 * is non-NULL it should point to a string indicating the
 * desired location for the credentials to be stored.
 *
 * Returns 0 on success, -1 on error.
 */
int MYPROXY_DELEGATION_accept(MYPROXY_GSS_CONTEXT *context,
			      char **target_credentials);



#endif /* !__MYPROXY_DELEGATION_H */

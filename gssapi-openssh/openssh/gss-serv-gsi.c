/*
 * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef GSSAPI
#ifdef GSI

#include "auth.h"
#include "auth-pam.h"
#include "xmalloc.h"
#include "log.h"
#include "servconf.h"

#include "ssh-gss.h"

#include <globus_gss_assist.h>

/*
 * Check if this user is OK to login under GSI. User has been authenticated
 * as identity in global 'client_name.value' and is trying to log in as passed
 * username in 'name'.
 *
 * Returns non-zero if user is authorized, 0 otherwise.
 */
static int
ssh_gssapi_gsi_userok(ssh_gssapi_client *client, char *name)
{
    int authorized = 0;
    
    /* This returns 0 on success */
    authorized = (globus_gss_assist_userok(client->name.value,
					   name) == 0);
    
    debug("GSI user %s is%s authorized as target user %s",
	  (char *) client->name.value,
	  (authorized ? "" : " not"),
	  name);
    
    return authorized;
}

/*
 * Handle setting up child environment for GSI.
 *
 * Make sure that this is called _after_ we've setuid to the user.
 */
static void
ssh_gssapi_gsi_storecreds(ssh_gssapi_client *client)
{
	OM_uint32	major_status;
	OM_uint32	minor_status;
	
	
	if (client->creds != NULL)
	{
		char *creds_env = NULL;

		/*
 		 * This is the current hack with the GSI gssapi library to
		 * export credentials to disk.
		 */

		debug("Exporting delegated credentials");
		
		minor_status = 0xdee0;	/* Magic value */
		major_status =
			gss_inquire_cred(&minor_status,
					 client->creds,
					 (gss_name_t *) &creds_env,
					 NULL,
					 NULL,
					 NULL);

		if ((major_status == GSS_S_COMPLETE) &&
		    (minor_status == 0xdee1) &&
		    (creds_env != NULL))
		{
			char		*value;
				
			/*
			 * String is of the form:
			 * X509_USER_DELEG_PROXY=filename
			 * so we parse out the filename
			 * and then set X509_USER_PROXY
			 * to point at it.
			 */
			value = strchr(creds_env, '=');
			
			if (value != NULL)
			{
				*value = '\0';
				value++;
#ifdef USE_PAM
				do_pam_putenv("X509_USER_PROXY",value);
#endif
			 	client->store.filename=NULL;
				client->store.envvar="X509_USER_PROXY";
				client->store.envval=strdup(value);

				return;
			}
			else
			{
				log("Failed to parse delegated credentials string '%s'",
				    creds_env);
			}
		}
		else
		{
			log("Failed to export delegated credentials (error %ld)",
			    major_status);
		}
	}	
}

ssh_gssapi_mech gssapi_gsi_mech_old = {
	"N3+k7/4wGxHyuP8Yxi4RhA==",
	"GSI",
	{9, "\x2B\x06\x01\x04\x01\x9B\x50\x01\x01"}
	NULL,
	&ssh_gssapi_gsi_userok,
	NULL,
	&ssh_gssapi_gsi_storecreds
};

ssh_gssapi_mech gssapi_gsi_mech = {
	"dZuIebMjgUqaxvbF7hDbAw==",
	"GSI",
	{9, "\x2B\x06\x01\x04\x01\x9B\x50\x01\x01"}
	NULL,
	&ssh_gssapi_gsi_userok,
	NULL,
	&ssh_gssapi_gsi_storecreds
};

#endif /* GSI */
#endif /* GSSAPI */

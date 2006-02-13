/*	$OpenBSD: gss-serv-krb5.c,v 1.4 2005/10/13 19:08:08 stevesk Exp $	*/

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
#ifdef KRB5

#include "auth.h"
#include "xmalloc.h"
#include "log.h"
#include "servconf.h"

#include "ssh-gss.h"

extern ServerOptions options;

#ifdef HEIMDAL
# include <krb5.h>
#elsif !defined(MECHGLUE)
# ifdef HAVE_GSSAPI_KRB5_H
#  include <gssapi_krb5.h>
# elif HAVE_GSSAPI_GSSAPI_KRB5_H
#  include <gssapi/gssapi_krb5.h>
# endif
#endif

static krb5_context krb_context = NULL;
static int ssh_gssapi_krb5_init();
static int ssh_gssapi_krb5_userok(ssh_gssapi_client *client, char *name);
static int ssh_gssapi_krb5_localname(ssh_gssapi_client *client, char **user);
static void ssh_gssapi_krb5_storecreds(ssh_gssapi_client *client);

ssh_gssapi_mech gssapi_kerberos_mech = {
	"toWM5Slw5Ew8Mqkay+al2g==",
	"Kerberos",
	{9, "\x2A\x86\x48\x86\xF7\x12\x01\x02\x02"},
	NULL,
	&ssh_gssapi_krb5_userok,
	&ssh_gssapi_krb5_localname,
	&ssh_gssapi_krb5_storecreds
};

/* Initialise the krb5 library, for the stuff that GSSAPI won't do */

static int
ssh_gssapi_krb5_init(void)
{
	krb5_error_code problem;

	if (krb_context != NULL)
		return 1;

	problem = krb5_init_context(&krb_context);
	if (problem) {
		logit("Cannot initialize krb5 context");
		return 0;
	}

	return 1;
}

/* Check if this user is OK to login. This only works with krb5 - other
 * GSSAPI mechanisms will need their own.
 * Returns true if the user is OK to log in, otherwise returns 0
 */

static int
ssh_gssapi_krb5_userok(ssh_gssapi_client *client, char *name)
{
	krb5_principal princ;
	int retval;

	if (ssh_gssapi_krb5_init() == 0)
		return 0;

	if ((retval = krb5_parse_name(krb_context, client->exportedname.value,
	    &princ))) {
		logit("krb5_parse_name(): %.100s",
		    krb5_get_err_text(krb_context, retval));
		return 0;
	}
	if (krb5_kuserok(krb_context, princ, name)) {
		retval = 1;
		logit("Authorized to %s, krb5 principal %s (krb5_kuserok)",
		    name, (char *)client->displayname.value);
	} else
		retval = 0;

	krb5_free_principal(krb_context, princ);
	return retval;
}


/* Retrieve the local username associated with a set of Kerberos 
 * credentials. Hopefully we can use this for the 'empty' username
 * logins discussed in the draft  */
static int
ssh_gssapi_krb5_localname(ssh_gssapi_client *client, char **user) {
	krb5_principal princ;
	int retval;
	
	if (ssh_gssapi_krb5_init() == 0)
		return 0;

	if ((retval=krb5_parse_name(krb_context, client->displayname.value, 
				    &princ))) {
		logit("krb5_parse_name(): %.100s", 
			krb5_get_err_text(krb_context,retval));
		return 0;
	}
	
	/* We've got to return a malloc'd string */
	*user = (char *)xmalloc(256);
	if (krb5_aname_to_localname(krb_context, princ, 256, *user)) {
		xfree(*user);
		*user = NULL;
		return(0);
	}
	
	return(1);
}
	
/* This writes out any forwarded credentials from the structure populated
 * during userauth. Called after we have setuid to the user */

static void
ssh_gssapi_krb5_storecreds(ssh_gssapi_client *client)
{
	krb5_ccache ccache;
	krb5_error_code problem;
	krb5_principal princ;
	OM_uint32 maj_status, min_status;
	gss_cred_id_t krb5_cred_handle;
	int len;

	if (client->creds == NULL) {
		debug("No credentials stored");
		return;
	}

	if (ssh_gssapi_krb5_init() == 0)
		return;

#ifdef HEIMDAL
	if ((problem = krb5_cc_gen_new(krb_context, &krb5_fcc_ops, &ccache))) {
		logit("krb5_cc_gen_new(): %.100s",
		    krb5_get_err_text(krb_context, problem));
		return;
	}
#else
	if ((problem = ssh_krb5_cc_gen(krb_context, &ccache))) {
		logit("ssh_krb5_cc_gen(): %.100s",
		    krb5_get_err_text(krb_context, problem));
		return;
	}
#endif	/* #ifdef HEIMDAL */

	if ((problem = krb5_parse_name(krb_context,
	    client->exportedname.value, &princ))) {
		logit("krb5_parse_name(): %.100s",
		    krb5_get_err_text(krb_context, problem));
		krb5_cc_destroy(krb_context, ccache);
		return;
	}

	if ((problem = krb5_cc_initialize(krb_context, ccache, princ))) {
		logit("krb5_cc_initialize(): %.100s",
		    krb5_get_err_text(krb_context, problem));
		krb5_free_principal(krb_context, princ);
		krb5_cc_destroy(krb_context, ccache);
		return;
	}

	krb5_free_principal(krb_context, princ);

#ifdef MECHGLUE
	krb5_cred_handle =
	    __gss_get_mechanism_cred(client->creds,
				     &(gssapi_kerberos_mech.oid));
#else
	krb5_cred_handle = client->creds;
#endif

	if ((maj_status = gss_krb5_copy_ccache(&min_status, 
	    krb5_cred_handle, ccache))) {
		logit("gss_krb5_copy_ccache() failed");
		krb5_cc_destroy(krb_context, ccache);
		return;
	}

	client->store.filename = xstrdup(krb5_cc_get_name(krb_context, ccache));
	client->store.envvar = "KRB5CCNAME";
	len = strlen(client->store.filename) + 6;
	client->store.envval = xmalloc(len);
	snprintf(client->store.envval, len, "FILE:%s", client->store.filename);

#ifdef USE_PAM
	if (options.use_pam)
		do_pam_putenv(client->store.envvar, client->store.envval);
#endif

	krb5_cc_close(krb_context, ccache);

	return;
}

#endif /* KRB5 */

#endif /* GSSAPI */

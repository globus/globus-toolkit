/*
 * Copyright (c) 2001,2002 Simon Wilkinson. All rights reserved.
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

#include "ssh.h"
#include "ssh1.h"
#include "ssh2.h"
#include "xmalloc.h"
#include "buffer.h"
#include "bufaux.h"
#include "packet.h"
#include "compat.h"
#include <openssl/evp.h>
#include "cipher.h"
#include "kex.h"
#include "auth.h"
#include "log.h"
#include "channels.h"
#include "session.h"
#include "dispatch.h"
#include "servconf.h"
#include "compat.h"
#include "misc.h"
#include "monitor_wrap.h"

#include "ssh-gss.h"

extern ServerOptions options;
extern u_char *session_id2;
extern int session_id2_len;

typedef struct ssh_gssapi_cred_cache {
	char *filename;
	char *envvar;
	char *envval;
	void *data;
} ssh_gssapi_cred_cache;

static struct ssh_gssapi_cred_cache gssapi_cred_store = {NULL,NULL,NULL};

/*
 * Environment variables pointing to delegated credentials
 */
static char *delegation_env[] = {
  "X509_USER_PROXY",		/* GSSAPI/SSLeay */
  "KRB5CCNAME",			/* Krb5 and possibly SSLeay */
  NULL
};

static void gssapi_unsetenv(const char *var);

#ifdef KRB5

#ifdef HEIMDAL
#include <krb5.h>
#else
#include <gssapi_krb5.h>
#define krb5_get_err_text(context,code) error_message(code)
#endif

static krb5_context krb_context = NULL;

/* Initialise the krb5 library, so we can use it for those bits that
 * GSSAPI won't do */

int ssh_gssapi_krb5_init() {
	krb5_error_code problem;
	
	if (krb_context !=NULL)
		return 1;
		
	problem = krb5_init_context(&krb_context);
	if (problem) {
		log("Cannot initialize krb5 context");
		return 0;
	}
	krb5_init_ets(krb_context);

	return 1;	
}			

/* Check if this user is OK to login. This only works with krb5 - other 
 * GSSAPI mechanisms will need their own.
 * Returns true if the user is OK to log in, otherwise returns 0
 */

int
ssh_gssapi_krb5_userok(char *name) {
	krb5_principal princ;
	int retval;

	if (ssh_gssapi_krb5_init() == 0)
		return 0;
		
	if ((retval=krb5_parse_name(krb_context, gssapi_client_name.value, 
				    &princ))) {
		log("krb5_parse_name(): %.100s", 
			krb5_get_err_text(krb_context,retval));
		return 0;
	}
	if (krb5_kuserok(krb_context, princ, name)) {
		retval = 1;
		log("Authorized to %s, krb5 principal %s (krb5_kuserok)",name,
		    (char *)gssapi_client_name.value);
	}
	else
		retval = 0;
	
	krb5_free_principal(krb_context, princ);
	return retval;
}

int
ssh_gssapi_krb5_localname(char **user)
{
    krb5_principal princ;

    if (krb5_parse_name(krb_context, gssapi_client_name.value, &princ)) {
	return(0);
    }
    *user = (char *)xmalloc(256);
    if (krb5_aname_to_localname(krb_context, princ, 256, *user)) {
	xfree(*user);
	*user = NULL;
	return(0);
    }
    return(1);
}
	
/* Make sure that this is called _after_ we've setuid to the user */

/* This writes out any forwarded credentials. Its specific to the Kerberos
 * GSSAPI mechanism
 *
 * We assume that our caller has made sure that the user has selected
 * delegated credentials, and that the client_creds structure is correctly
 * populated.
 */

void
ssh_gssapi_krb5_storecreds() {
	krb5_ccache ccache;
	krb5_error_code problem;
	krb5_principal princ;
	char ccname[35];
	static char name[40];
	int tmpfd;
	OM_uint32 maj_status,min_status;


	if (gssapi_client_creds==NULL) {
		debug("No credentials stored"); 
		return;
	}
		
	if (ssh_gssapi_krb5_init() == 0)
		return;

	if (options.gss_use_session_ccache) {
        	snprintf(ccname,sizeof(ccname),"/tmp/krb5cc_%d_XXXXXX",geteuid());
       
        	if ((tmpfd = mkstemp(ccname))==-1) {
                	log("mkstemp(): %.100s", strerror(errno));
                	return;
        	}
	        if (fchmod(tmpfd, S_IRUSR | S_IWUSR) == -1) {
	               	log("fchmod(): %.100s", strerror(errno));
	               	close(tmpfd);
	               	return;
	        }
        } else {
        	snprintf(ccname,sizeof(ccname),"/tmp/krb5cc_%d",geteuid());
        	tmpfd = open(ccname, O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
        	if (tmpfd == -1) {
        		log("open(): %.100s", strerror(errno));
        		return;
        	}
        }

       	close(tmpfd);
        snprintf(name, sizeof(name), "FILE:%s",ccname);
 
        if ((problem = krb5_cc_resolve(krb_context, name, &ccache))) {
                log("krb5_cc_default(): %.100s", 
                	krb5_get_err_text(krb_context,problem));
                return;
        }

	if ((problem = krb5_parse_name(krb_context, gssapi_client_name.value, 
				       &princ))) {
		log("krb5_parse_name(): %.100s", 
			krb5_get_err_text(krb_context,problem));
		krb5_cc_destroy(krb_context,ccache);
		return;
	}
	
	if ((problem = krb5_cc_initialize(krb_context, ccache, princ))) {
		log("krb5_cc_initialize(): %.100s", 
			krb5_get_err_text(krb_context,problem));
		krb5_free_principal(krb_context,princ);
		krb5_cc_destroy(krb_context,ccache);
		return;
	}
	
	krb5_free_principal(krb_context,princ);

	if ((maj_status = gss_krb5_copy_ccache(&min_status, 
					       gssapi_client_creds, 
					       ccache))) {
		log("gss_krb5_copy_ccache() failed");
		ssh_gssapi_error(maj_status,min_status);
		krb5_cc_destroy(krb_context,ccache);
		return;
	}
	
	krb5_cc_close(krb_context,ccache);


#ifdef USE_PAM
	do_pam_putenv("KRB5CCNAME",name);
#endif

	gssapi_cred_store.filename=strdup(ccname);
	gssapi_cred_store.envvar="KRB5CCNAME";
	gssapi_cred_store.envval=strdup(name);

	return;
}

#endif /* KRB5 */

#ifdef GSI
#include <globus_gss_assist.h>

/*
 * Check if this user is OK to login under GSI. User has been authenticated
 * as identity in global 'client_name.value' and is trying to log in as passed
 * username in 'name'.
 *
 * Returns non-zero if user is authorized, 0 otherwise.
 */
int
ssh_gssapi_gsi_userok(char *name)
{
    int authorized = 0;
    
    /* This returns 0 on success */
    authorized = (globus_gss_assist_userok(gssapi_client_name.value,
					   name) == 0);
    
    log("GSI user %s is%s authorized as target user %s",
	(char *) gssapi_client_name.value, (authorized ? "" : " not"), name);
    
    return authorized;
}

/*
 * Return the local username associated with the GSI credentials.
 */
int
ssh_gssapi_gsi_localname(char **user)
{
    return(globus_gss_assist_gridmap(gssapi_client_name.value, user) == 0);
}

/*
 * Handle setting up child environment for GSI.
 *
 * Make sure that this is called _after_ we've setuid to the user.
 */
void
ssh_gssapi_gsi_storecreds()
{
	OM_uint32	major_status;
	OM_uint32	minor_status;
	
	/* should use gss_export_cred() instead */
	
	if (gssapi_client_creds != NULL)
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
					 gssapi_client_creds,
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
			 	gssapi_cred_store.filename=NULL;
				gssapi_cred_store.envvar="X509_USER_PROXY";
				gssapi_cred_store.envval=strdup(value);

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

#endif /* GSI */

void
ssh_gssapi_cleanup_creds(void *ignored)
{
	if (gssapi_cred_store.filename!=NULL) {
		/* Unlink probably isn't sufficient */
		debug("removing gssapi cred file\"%s\"",gssapi_cred_store.filename);
		unlink(gssapi_cred_store.filename);
	}
}

void 
ssh_gssapi_storecreds()
{
	switch (gssapi_client_type) {
#ifdef KRB5
	case GSS_KERBEROS:
		ssh_gssapi_krb5_storecreds();
		break;
#endif
#ifdef GSI
	case GSS_GSI:
		ssh_gssapi_gsi_storecreds();
		break;
#endif /* GSI */
	case GSS_LAST_ENTRY:
		/* GSSAPI not used in this authentication */
		debug("No GSSAPI credentials stored");
		break;
	default:
		log("ssh_gssapi_do_child: Unknown mechanism");
	
	}
	
	if (options.gss_cleanup_creds) {
		fatal_add_cleanup(ssh_gssapi_cleanup_creds, NULL);
	}

}

/* This allows GSSAPI methods to do things to the childs environment based
 * on the passed authentication process and credentials.
 *
 * Question: If we didn't use userauth_external for some reason, should we
 * still delegate credentials?
 */
void 
ssh_gssapi_do_child(char ***envp, u_int *envsizep) 
{

	if (gssapi_cred_store.envvar!=NULL && 
	    gssapi_cred_store.envval!=NULL) {
	    
		debug("Setting %s to %s", gssapi_cred_store.envvar,
					  gssapi_cred_store.envval);				  
		child_set_env(envp, envsizep, gssapi_cred_store.envvar, 
					      gssapi_cred_store.envval);
	}

	switch(gssapi_client_type) {
#ifdef KRB5
	case GSS_KERBEROS: break;
#endif
#ifdef GSI
	case GSS_GSI: break;
#endif
	case GSS_LAST_ENTRY:
		debug("No GSSAPI credentials stored");
		break;
	default:
		log("ssh_gssapi_do_child: Unknown mechanism");
	}
}

int
ssh_gssapi_userok(char *user)
{
	if (gssapi_client_name.length==0 || 
	    gssapi_client_name.value==NULL) {
		debug("No suitable client data");
		return 0;
	}
	switch (gssapi_client_type) {
#ifdef KRB5
	case GSS_KERBEROS:
		return(ssh_gssapi_krb5_userok(user));
		break; /* Not reached */
#endif
#ifdef GSI
	case GSS_GSI:
		return(ssh_gssapi_gsi_userok(user));
		break; /* Not reached */
#endif /* GSI */
	case GSS_LAST_ENTRY:
		debug("Client not GSSAPI");
		break;
	default:
		debug("Unknown client authentication type");
	}
	return(0);
}

int
ssh_gssapi_localname(char **user)
{
    	*user = NULL;
	if (gssapi_client_name.length==0 || 
	    gssapi_client_name.value==NULL) {
		debug("No suitable client data");
		return(0);;
	}
	switch (gssapi_client_type) {
#ifdef KRB5
	case GSS_KERBEROS:
		return(ssh_gssapi_krb5_localname(user));
		break; /* Not reached */
#endif
#ifdef GSI
	case GSS_GSI:
		return(ssh_gssapi_gsi_localname(user));
		break; /* Not reached */
#endif /* GSI */
	case GSS_LAST_ENTRY:
		debug("Client not GSSAPI");
		break;
	default:
		debug("Unknown client authentication type");
	}
	return(0);
}

/*
 * Clean our environment on startup. This means removing any environment
 * strings that might inadvertantly been in root's environment and 
 * could cause serious security problems if we think we set them.
 */
void
ssh_gssapi_clean_env(void)
{
  char *envstr;
  int envstr_index;

  
   for (envstr_index = 0;
       (envstr = delegation_env[envstr_index]) != NULL;
       envstr_index++) {

     if (getenv(envstr)) {
       debug("Clearing environment variable %s", envstr);
       gssapi_unsetenv(envstr);
     }
   }
}

/*
 * Wrapper around unsetenv.
 */
static void
gssapi_unsetenv(const char *var)
{
#ifdef HAVE_UNSETENV
    unsetenv(var);

#else /* !HAVE_UNSETENV */
    extern char **environ;
    char **p1 = environ;	/* New array list */
    char **p2 = environ;	/* Current array list */
    int len = strlen(var);

    /*
     * Walk through current environ array (p2) copying each pointer
     * to new environ array (p1) unless the pointer is to the item
     * we want to delete. Copy happens in place.
     */
    while (*p2) {
	if ((strncmp(*p2, var, len) == 0) &&
	    ((*p2)[len] == '=')) {
	    /*
	     * *p2 points at item to be deleted, just skip over it
	     */
	    p2++;
	} else {
	    /*
	     * *p2 points at item we want to save, so copy it
	     */
	    *p1 = *p2;
	    p1++;
	    p2++;
	}
    }

    /* And make sure new array is NULL terminated */
    *p1 = NULL;
#endif /* HAVE_UNSETENV */
}

#endif /* GSSAPI */

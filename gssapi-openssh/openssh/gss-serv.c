/*
 * Copyright (c) 2001 Simon Wilkinson. All rights reserved.
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

#include "ssh-gss.h"

extern ServerOptions options;
extern u_char *session_id2;
extern int session_id2_len;

int 	userauth_external(Authctxt *authctxt);
int	userauth_gssapi(Authctxt *authctxt);
void    userauth_reply(Authctxt *authctxt, int authenticated);
static void gssapi_unsetenv(const char *var);

typedef struct ssh_gssapi_cred_cache {
	char *filename;
	char *envvar;
	char *envval;
	void *data;
} ssh_gssapi_cred_cache;

static struct ssh_gssapi_cred_cache gssapi_cred_store = {NULL,NULL,NULL};
unsigned char ssh1_key_digest[16]; /* used for ssh1 gssapi */

/*
 * Environment variables pointing to delegated credentials
 */
static char *delegation_env[] = {
  "X509_USER_PROXY",		/* GSSAPI/SSLeay */
  "KRB5CCNAME",			/* Krb5 and possibly SSLeay */
  NULL
};

Authmethod method_external = {
	"external-keyx",
	userauth_external,
	&options.gss_authentication
};

Authmethod method_gssapi = {
	"gssapi",
	userauth_gssapi,
	&options.gss_authentication
};

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

	#ifdef HEIMDAL
	if ((problem = krb5_cc_copy_cache(krb_context, 
					   gssapi_client_creds->ccache,
					   ccache))) {
		log("krb5_cc_copy_cache(): %.100s", 
			krb5_get_err_text(krb_context,problem));
		krb5_cc_destroy(krb_context,ccache);
		return;
	}
	#else
	if ((maj_status = gss_krb5_copy_ccache(&min_status, 
					       gssapi_client_creds, 
					       ccache))) {
		log("gss_krb5_copy_ccache() failed");
		ssh_gssapi_error(maj_status,min_status);
		krb5_cc_destroy(krb_context,ccache);
		return;
	}
	#endif
	
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
 * Handle setting up child environment for GSI.
 *
 * Make sure that this is called _after_ we've setuid to the user.
 */
void
ssh_gssapi_gsi_storecreds()
{
	OM_uint32	major_status;
	OM_uint32	minor_status;
	
	
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
userauth_external(Authctxt *authctxt)
{
	packet_check_eom();

	return(ssh_gssapi_userok(authctxt->user));
}

void input_gssapi_token(int type, u_int32_t plen, void *ctxt);
void input_gssapi_exchange_complete(int type, u_int32_t plen, void *ctxt);

/* We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like
 */
int
userauth_gssapi(Authctxt *authctxt)
{
	gss_OID_desc	oid= {0,NULL};
	Gssctxt		*ctxt;
	int		mechs;
	gss_OID_set	supported;
	int		present;
	OM_uint32	ms;
	u_int		len;
	
	if (!authctxt->valid || authctxt->user == NULL)
		return 0;
		
	if (datafellows & SSH_OLD_GSSAPI) {
		debug("Early drafts of GSSAPI userauth not supported");
		return 0;
	}
	
	mechs=packet_get_int();
	if (mechs==0) {
		debug("Mechanism negotiation is not supported");
		return 0;
	}

	ssh_gssapi_supported_oids(&supported);
	do {
		if (oid.elements)
			xfree(oid.elements);
		oid.elements = packet_get_string(&len);
		oid.length = len;
		gss_test_oid_set_member(&ms, &oid, supported, &present);
		mechs--;
	} while (mechs>0 && !present);
	
	if (!present) {
		xfree(oid.elements);
		return(0);
	}
	
	ctxt=xmalloc(sizeof(Gssctxt));
	authctxt->methoddata=(void *)ctxt;
	
	ssh_gssapi_build_ctx(ctxt);
	ssh_gssapi_set_oid(ctxt,&oid);

	if (ssh_gssapi_acquire_cred(ctxt))
		return 0;

	/* Send SSH_MSG_USERAUTH_GSSAPI_RESPONSE */

	if (!compat20)
	packet_start(SSH_SMSG_AUTH_GSSAPI_RESPONSE);
	else
	packet_start(SSH2_MSG_USERAUTH_GSSAPI_RESPONSE);
	packet_put_string(oid.elements,oid.length);
	packet_send();
	packet_write_wait();
	xfree(oid.elements);
		
 	if (!compat20)
 	dispatch_set(SSH_MSG_AUTH_GSSAPI_TOKEN,
 				&input_gssapi_token);
 	else
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, 
		     &input_gssapi_token);
	authctxt->postponed = 1;
	
	return 0;
}

void
input_gssapi_token(int type, u_int32_t plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok,recv_tok;
	OM_uint32 maj_status, min_status;
	
	if (authctxt == NULL || authctxt->methoddata == NULL)
		fatal("No authentication or GSSAPI context");
		
	gssctxt=authctxt->methoddata;

	recv_tok.value=packet_get_string(&recv_tok.length);
	
	maj_status=ssh_gssapi_accept_ctx(gssctxt, &recv_tok, &send_tok, NULL);
	packet_check_eom();
	
	if (GSS_ERROR(maj_status)) {
		/* Failure <sniff> */
		ssh_gssapi_send_error(maj_status,min_status);
		authctxt->postponed = 0;
		dispatch_set(SSH_MSG_AUTH_GSSAPI_TOKEN, NULL);
		dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
		userauth_finish(authctxt, 0, "gssapi");
	}
			
	if (send_tok.length != 0) {
		/* Send a packet back to the client */
		if (!compat20)
		packet_start(SSH_MSG_AUTH_GSSAPI_TOKEN);
		else
	        packet_start(SSH2_MSG_USERAUTH_GSSAPI_TOKEN);
                packet_put_string(send_tok.value,send_tok.length);
                packet_send();
                packet_write_wait();
                gss_release_buffer(&min_status, &send_tok);
	}
	
	if (maj_status == GSS_S_COMPLETE) {
		dispatch_set(SSH_MSG_AUTH_GSSAPI_TOKEN, NULL);
  		dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN,NULL);
		/* ssh1 does not have an extra message here */
		if (!compat20)
		input_gssapi_exchange_complete(0, 0, ctxt);
		else
  		dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
  			     &input_gssapi_exchange_complete);
	}
}

/* This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */
 
void
input_gssapi_exchange_complete(int type, u_int32_t plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt;
	int authenticated;

    	if(strcmp(authctxt->user,"") == 0) {
        	char *user;
        	char *gridmapped_name = NULL;
        	struct passwd *pw = NULL;
        	if(globus_gss_assist_gridmap(gssapi_client_name.value,
                           &gridmapped_name) == 0) {
               		user = gridmapped_name;
               		debug("I gridmapped and got %s", user);
               		pw = getpwnam(user);
               		if (pw && allowed_user(pw)) {
                     		authctxt->user = user;
                     		authctxt->pw = pwcopy(pw);
                     		authctxt->valid = 1;
               		}
        	}
    	}

	
	if (authctxt == NULL || authctxt->methoddata == NULL)
		fatal("No authentication or GSSAPI context");
		
	gssctxt=authctxt->methoddata;

	/* This should never happen, but better safe than sorry. */
	if (gssctxt->status != GSS_S_COMPLETE) {
		packet_disconnect("Context negotiation is not complete");
	}

	if (ssh_gssapi_getclient(gssctxt,&gssapi_client_type,
				 &gssapi_client_name,
				 &gssapi_client_creds)) {
		fatal("Couldn't convert client name");
	}
				     		
        authenticated = ssh_gssapi_userok(authctxt->user);

	/* ssh1 needs to exchange the hash of the keys */
	if (!compat20) {
		if (authenticated) {

			OM_uint32 maj_status, min_status;
			gss_buffer_desc gssbuf,msg_tok;

			/* ssh1 uses wrap */
			gssbuf.value=ssh1_key_digest;
			gssbuf.length=sizeof(ssh1_key_digest);
			if ((maj_status=gss_wrap(&min_status,
					gssctxt->context,
					0,
					GSS_C_QOP_DEFAULT,
					&gssbuf,
					NULL,
					&msg_tok))) {
				ssh_gssapi_error(maj_status,min_status);
				fatal("Couldn't wrap keys");
			}
			packet_start(SSH_SMSG_AUTH_GSSAPI_HASH);
			packet_put_string((char *)msg_tok.value,msg_tok.length);
			packet_send();
			packet_write_wait();
			gss_release_buffer(&min_status,&msg_tok);
		} else {
		    packet_start(SSH_MSG_AUTH_GSSAPI_ABORT);
		    packet_send();
		    packet_write_wait();
		}
	}

	authctxt->postponed = 0;
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
	userauth_finish(authctxt, authenticated, "gssapi");
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

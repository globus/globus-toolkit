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
    
    debug("GSI user %s is%s authorized as target user %s",
	  (char *) gssapi_client_name.value,
	  (authorized ? "" : " not"),
	  name);
    
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

/* Stuff to play nicely with privsep */

#if 0
extern struct monitor *pmonitor;

OM_uint32
mm_ssh_gssapi_server_ctxt(Gssctxt **ctx, gss_OID oid) {
	Buffer m;
	
	/* Client doesn't get to see the context */
 	*ctx=NULL;

	buffer_init(&m)
  	buffer_put_string(&m,oid->elements,oid->length);
  	
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSETUP, &m);

	debug3("%s: waiting for MONITOR_ANS_GSSSIGN",__func__);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_SIGN, &m);
	major=buffer_get_int(&m);

	return(major);
}
	
int
mm_answer_gss_server_ctxt(int socket, Buffer *m) {
	gss_OID_desc oid;
	OM_uint32 major;
	
	oid.elements=buffer_get_string(m,&oid.length);
		
	major=ssh_gssapi_server_ctxt(&gsscontext,&oid);

	xfree(oid.elements);
	
	buffer_clear(m);
	buffer_put_int(m,result);
	
	mm_request_send(socket,MONITOR_ANS_GSSSIGN,m);
	
	return(0);
}

OM_uint32
mm_ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_desc *in,
			 gss_buffer_desc *out, OM_uint32 *flags) {

	Buffer m;
	OM_uint32, major;
	
	buffer_init(&m);
	buffer_put_string(&m, in->value, in->length);
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSTEP, &m);
	
	debug3("%s: waiting for MONITOR_ANS_GSSSTEP", &m);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSTEP, &m);
	
	major=buffer_get_int(&m);
	*out->value=buffer->get_string(&m,&out->length);
	flags=buffer_get_int(&m);

	return(major);
}

int
mm_answer_gss_accept_ctxt(int socket, Buffer *m) {
	gss_buffer_desc	in,out;
	OM_uint32 major;
	OM_uint32 flags = 0; /* GSI needs this */
	
	in.value = buffer_get_string(m,&in.length);
	major=ssh_gssapi_accept_ctxt(gsscontext,&in,&out,&flags);
	xfree(in.value);
	
	buffer_clear(m);
	buffer_put_int(m, major);
	buffer_put_string(m, out.value, out.length);
	buffer_put_int(m, flags);
	mm_request_send(socket,MONITOR_ANS_STEP,m);
	
	gss_release_buffer(out);
	
	return(0);
}

int
mm_ssh_gssapi_userok(char *user) {
	Buffer m;
	
	buffer_init(&m);
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSUSEROK, &m);
	
	debug3("%s: waiting for MONTIOR_ANS_GSSUSEROK", __func__);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSUSEROK),
				  &m);
	
	authenticated = buffer_get_int(&m);
	
	buffer_free(&m);
	debug3("%s: user %sauthetnicated",__func__, authenticated ? "" : "not ");
	return(authenticated);
}

int
mm_answer_gss_userok(int socket, Buffer *m) {
	authenticated = authctxt->valid && ssh_gssapi_userok(authctxt->user);
	
	buffer_clear(m);
	buffer_put_int(m, authenticated);
	
	debug3("%s: sending result %d", __func__, authenticated);
	mm_request_send(socket, MONITOR_ANS_GSSUSEROK, m);
	
	/* Monitor loop will terminate if authenticated */
	return(authenticated);
}

OM_uint32
mm_ssh_gssapi_sign(Gssctxt *ctx, gss_buffer_desc *data, gss_buffer_desc *hash) {
	Buffer m;
	OM_uint32 major, minor;
	
	buffer_init(&m);
	buffer_put_string(&m, data->value, data->length);
	
	mm_request_send(pmonitor->m_recvfd, MONITOR_REQ_GSSSIGN, &m);
	
	debug3("%s: waiting for MONITOR_ANS_GSSSIGN",__func__);
	mm_request_receive_expect(pmonitor->m_recvfd, MONITOR_ANS_GSSSIGN, &m);
	major=buffer_get_int(&m);
	*hash->value = buffer_get_string(&m, &hash->length);
	
	return(major);
}
	
int
mm_answer_gss_sign(int socket, Buffer *m) {
	gss_buffer_desc data,hash;
	OM_uint32 major;
	
	data.value = buffer_get_string(m,&data.length);
	if (data.length != 20)
		fatal("%s: data length incorrect: %d", __func__, datlen);
	
	/* Save the session ID - only first time round */
	if (session_id2_len == 0) {
		session_id2_len=data.length;
		session_id2 = xmalloc(session_id2_len);
		memcpy(session_id2, data.value, session_id2_len);
	}
	major=ssh_gssapi_sign(gsscontext, &data, &hash);
	
	xfree(data.value);
	
	buffer_clear(m);
	buffer_put_int(m, major);
	buffer_put_string(m, hash.value, hash.length);

        mm_request_send(socket,MONITOR_ANS_GSSSIGN,m);
        	
	gss_release_buffer(hash);
	
	return(0);
}
#endif
#endif /* GSSAPI */

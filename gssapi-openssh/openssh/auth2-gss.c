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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AS IS'' AND ANY EXPRESS OR
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
#include "auth.h"
#include "ssh2.h"
#include "ssh1.h"
#include "xmalloc.h"
#include "log.h"
#include "dispatch.h"
#include "servconf.h"
#include "compat.h"
#include "packet.h"
#include "monitor_wrap.h"

#include "ssh-gss.h"

extern ServerOptions options;
unsigned char ssh1_key_digest[16];

static int
userauth_external(Authctxt *authctxt)
{
        packet_check_eom();

        return(PRIVSEP(ssh_gssapi_userok(authctxt->user)));
}

static void ssh_gssapi_userauth_error(Gssctxt *ctxt);
static void input_gssapi_token(int type, u_int32_t plen, void *ctxt);
static void input_gssapi_exchange_complete(int type, u_int32_t plen, void *ctxt);
static void input_gssapi_errtok(int, u_int32_t, void *);

/* We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like
 */
static int
userauth_gssapi(Authctxt *authctxt)
{
        gss_OID_desc    oid= {0,NULL};
        Gssctxt         *ctxt = NULL;
        int             mechs;
        gss_OID_set     supported;
        int             present;
        OM_uint32       ms;
        u_int           len;
        char *		doid = NULL;
        
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
                mechs--;
                
                if (doid)
                        xfree(doid);
                
                debug("Trying to get OID string");
                doid = packet_get_string(&len);
                debug("Got string");
                
               	if (doid[0]!=0x06 || doid[1]!=len-2) {
               		log("Mechanism OID received using the old encoding form");
               		oid.elements = doid;
               		oid.length = len;
               	} else {
               		oid.elements = doid + 2;
               		oid.length   = len - 2;
               	}
            	gss_test_oid_set_member(&ms, &oid, supported, &present);
        } while (mechs>0 && !present);
        
        if (!present) {
                xfree(doid);
                return(0);
        }
                
	if (GSS_ERROR(PRIVSEP(ssh_gssapi_server_ctx(&ctxt,&oid)))) {
		ssh_gssapi_userauth_error(ctxt);
		return(0);
	}
	
        authctxt->methoddata=(void *)ctxt;

        /* Send SSH_MSG_USERAUTH_GSSAPI_RESPONSE */

	if (!compat20) {

	packet_start(SSH_SMSG_AUTH_GSSAPI_RESPONSE);
	packet_put_string(oid.elements,oid.length);

	} else {

       	packet_start(SSH2_MSG_USERAUTH_GSSAPI_RESPONSE);

	/* Just return whatever they sent */
	packet_put_string(doid,len);

	} /* !compat20 */
       	
        packet_send();
        packet_write_wait();
        xfree(doid);

 	if (!compat20)
 	dispatch_set(SSH_MSG_AUTH_GSSAPI_TOKEN,
 				&input_gssapi_token);
 	else
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, 
                     &input_gssapi_token);
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK,
        	     &input_gssapi_errtok);
        authctxt->postponed = 1;
        
        return 0;
}

static void
input_gssapi_token(int type, u_int32_t plen, void *ctxt)
{
        Authctxt *authctxt = ctxt;
        Gssctxt *gssctxt;
        gss_buffer_desc send_tok,recv_tok;
        OM_uint32 maj_status, min_status;
	int len;
        
        if (authctxt == NULL || (authctxt->methoddata == NULL && !use_privsep))
                fatal("No authentication or GSSAPI context");
                
        gssctxt=authctxt->methoddata;
        recv_tok.value=packet_get_string(&len);
        recv_tok.length=len; /* int vs. size_t */
        
        maj_status=PRIVSEP(ssh_gssapi_accept_ctx(gssctxt, &recv_tok, 
        					 &send_tok, NULL));
        packet_check_eom();
                        
        if (GSS_ERROR(maj_status)) {
        	ssh_gssapi_userauth_error(gssctxt);
		if (send_tok.length != 0) {
		    if (!compat20)
			packet_start(SSH_MSG_AUTH_GSSAPI_TOKEN);
		    else
			packet_start(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK);
	                packet_put_string(send_tok.value,send_tok.length);
        	        packet_send();
               		packet_write_wait();
               	}
                authctxt->postponed = 0;
		dispatch_set(SSH_MSG_AUTH_GSSAPI_TOKEN, NULL);
                dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
                userauth_finish(authctxt, 0, "gssapi");
        } else {
               	if (send_tok.length != 0) {
		    if (!compat20)
			packet_start(SSH_MSG_AUTH_GSSAPI_TOKEN);
		    else
               		packet_start(SSH2_MSG_USERAUTH_GSSAPI_TOKEN);
               		packet_put_string(send_tok.value,send_tok.length);
               		packet_send();
               		packet_write_wait();
                }
	        if (maj_status == GSS_S_COMPLETE) {
		    	dispatch_set(SSH_MSG_AUTH_GSSAPI_TOKEN, NULL);
        	        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN,NULL);
			if (!compat20)
			input_gssapi_exchange_complete(0, 0, ctxt);
			else
                	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
                             	     &input_gssapi_exchange_complete);
                }
        }
        
        gss_release_buffer(&min_status, &send_tok);        
}

static void
input_gssapi_errtok(int type, u_int32_t plen, void *ctxt)
{
        Authctxt *authctxt = ctxt;
        Gssctxt *gssctxt;
        gss_buffer_desc send_tok,recv_tok;
        OM_uint32 maj_status;
        
        if (authctxt == NULL || (authctxt->methoddata == NULL && !use_privsep))
                fatal("No authentication or GSSAPI context");
                
        gssctxt=authctxt->methoddata;
        recv_tok.value=packet_get_string(&recv_tok.length);
        
        /* Push the error token into GSSAPI to see what it says */
        maj_status=PRIVSEP(ssh_gssapi_accept_ctx(gssctxt, &recv_tok, 
        					 &send_tok, NULL));
        packet_check_eom();

	/* We can't return anything to the client, even if we wanted to */
	dispatch_set(SSH_MSG_AUTH_GSSAPI_TOKEN, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK,NULL);

	/* The client will have already moved on to the next auth */
	
}

/* This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */
 
static void
input_gssapi_exchange_complete(int type, u_int32_t plen, void *ctxt)
{
        Authctxt *authctxt = ctxt;
        Gssctxt *gssctxt;
        int authenticated;
        
	if (authctxt == NULL || (authctxt->methoddata == NULL && !use_privsep))
                fatal("No authentication or GSSAPI context");
                
	if ((strcmp(authctxt->user, "") == 0) && (authctxt->pw == NULL)) {
	    char *lname = NULL;
	    PRIVSEP(ssh_gssapi_localname(&lname));
	    if (lname && lname[0] != '\0') {
		xfree(authctxt->user);
		authctxt->user = lname;
		debug("set username to %s from gssapi context", lname);
		authctxt->pw = PRIVSEP(getpwnamallow(authctxt->user));
	    } else {
		debug("failed to set username from gssapi context");
	    }
	}
	if (authctxt->pw) {
#ifdef USE_PAM
	    PRIVSEP(start_pam(authctxt->pw->pw_name));
#endif
	} else {
	    authctxt->valid = 0;
	    authenticated = 0;
	    goto finish;
	}

        gssctxt=authctxt->methoddata;
        
	/* ssh1 needs to exchange the hash of the keys */
	if (!compat20) {

		OM_uint32 min_status;
		gss_buffer_desc dummy, msg_tok;

		/* ssh1 wraps the keys, in the monitor */

		dummy.value=malloc(sizeof(ssh1_key_digest));
		memcpy(dummy.value,ssh1_key_digest,sizeof(ssh1_key_digest));
		dummy.length=sizeof(ssh1_key_digest);
		if (GSS_ERROR(PRIVSEP(ssh_gssapi_sign(gssctxt,&dummy,&msg_tok))))
		    fatal("Couldn't wrap keys");
 
		packet_start(SSH_SMSG_AUTH_GSSAPI_HASH);
		packet_put_string((char *)msg_tok.value,msg_tok.length);
		packet_send();
		packet_write_wait();
		gss_release_buffer(&min_status,&msg_tok);
	}

  
	/* We don't need to check the status, because the stored credentials
	 * which userok uses are only populated once the context init step
	 * has returned complete.
	 */

        authenticated = PRIVSEP(ssh_gssapi_userok(authctxt->user));

finish:
        authctxt->postponed = 0;
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
        userauth_finish(authctxt, authenticated, "gssapi");
}

static void ssh_gssapi_userauth_error(Gssctxt *ctxt) {
	char *errstr;
	OM_uint32 maj,min;
	
	errstr=PRIVSEP(ssh_gssapi_last_error(ctxt,&maj,&min));
	if (errstr) {
	    if (!compat20) {
		packet_send_debug(errstr);
	    } else {
		packet_start(SSH2_MSG_USERAUTH_GSSAPI_ERROR);
		packet_put_int(maj);
		packet_put_int(min);
		packet_put_cstring(errstr);
		packet_put_cstring("");
		packet_send();
		packet_write_wait();
		xfree(errstr);
	    }
	}
}

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

#endif /* GSSAPI */

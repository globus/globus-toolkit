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
extern unsigned char ssh1_key_digest[16];

static int
userauth_external(Authctxt *authctxt)
{
        packet_check_eom();

        return(PRIVSEP(ssh_gssapi_userok(authctxt->user)));
}

static void input_gssapi_token(int type, u_int32_t plen, void *ctxt);
static void input_gssapi_exchange_complete(int type, u_int32_t plen, void *ctxt);

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
                
	if (GSS_ERROR(PRIVSEP(ssh_gssapi_server_ctx(&ctxt,&oid))))
		return(0);
	
        authctxt->methoddata=(void *)ctxt;

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

static void
input_gssapi_token(int type, u_int32_t plen, void *ctxt)
{
        Authctxt *authctxt = ctxt;
        Gssctxt *gssctxt;
        gss_buffer_desc send_tok,recv_tok;
        OM_uint32 maj_status, min_status;
        
        if (authctxt == NULL || (authctxt->methoddata == NULL && !use_privsep))
                fatal("No authentication or GSSAPI context");
                
        gssctxt=authctxt->methoddata;
        recv_tok.value=packet_get_string(&recv_tok.length);
        
        maj_status=PRIVSEP(ssh_gssapi_accept_ctx(gssctxt, &recv_tok, 
        					 &send_tok, NULL));
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
 
static void
input_gssapi_exchange_complete(int type, u_int32_t plen, void *ctxt)
{
        Authctxt *authctxt = ctxt;
        Gssctxt *gssctxt;
        int authenticated;
        
	if (authctxt == NULL || (authctxt->methoddata == NULL && !use_privsep))
                fatal("No authentication or GSSAPI context");
                
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

        authctxt->postponed = 0;
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
        userauth_finish(authctxt, authenticated, "gssapi");
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

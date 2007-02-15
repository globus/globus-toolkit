/* $OpenBSD: auth2-gss.c,v 1.15 2006/08/03 03:34:41 deraadt Exp $ */

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

#include <sys/types.h>

#include <stdarg.h>

#include "xmalloc.h"
#include "key.h"
#include "hostfile.h"
#include "auth.h"
#include "ssh2.h"
#include "log.h"
#include "dispatch.h"
#include "buffer.h"
#include "servconf.h"
#include "packet.h"
#include "ssh-gss.h"
#include "monitor_wrap.h"

extern ServerOptions options;

static void ssh_gssapi_userauth_error(Gssctxt *ctxt);
static void input_gssapi_token(int type, u_int32_t plen, void *ctxt);
static void input_gssapi_mic(int type, u_int32_t plen, void *ctxt);
static void input_gssapi_exchange_complete(int type, u_int32_t plen, void *ctxt);
static void input_gssapi_errtok(int, u_int32_t, void *);

static int gssapi_with_mic = 1;	/* flag to toggle "gssapi-with-mic" vs.
				   "gssapi" */

static int
userauth_external(Authctxt *authctxt)
{
        packet_check_eom();

	if (authctxt->valid && authctxt->user && authctxt->user[0]) {
		return(PRIVSEP(ssh_gssapi_userok(authctxt->user)));
	}
	return 0;
}

/* 
 * The 'gssapi_keyex' userauth mechanism.
 */
static int
userauth_gsskeyex(Authctxt *authctxt)
{
	int authenticated = 0;
	Buffer b, b2;
	gss_buffer_desc mic, gssbuf, gssbuf2;
	u_int len;

	mic.value = packet_get_string(&len);
	mic.length = len;

	packet_check_eom();

	ssh_gssapi_buildmic(&b, authctxt->user, authctxt->service,
	    "gssapi-keyex");

	gssbuf.value = buffer_ptr(&b);
	gssbuf.length = buffer_len(&b);

	/* client may have used empty username to determine target
	   name from GSSAPI context */
	ssh_gssapi_buildmic(&b2, "", authctxt->service, "gssapi-keyex");

	gssbuf2.value = buffer_ptr(&b2);
	gssbuf2.length = buffer_len(&b2);

	/* gss_kex_context is NULL with privsep, so we can't check it here */
	if (!GSS_ERROR(PRIVSEP(ssh_gssapi_checkmic(gss_kex_context, 
						   &gssbuf, &mic))) ||
	    !GSS_ERROR(PRIVSEP(ssh_gssapi_checkmic(gss_kex_context, 
						   &gssbuf2, &mic)))) {
	    if (authctxt->valid && authctxt->user && authctxt->user[0]) {
		authenticated = PRIVSEP(ssh_gssapi_userok(authctxt->user));
	    }
	}
	
	buffer_free(&b);
	buffer_free(&b2);
	xfree(mic.value);

	return (authenticated);
}

/*
 * We only support those mechanisms that we know about (ie ones that we know
 * how to check local user kuserok and the like)
 */
static int
userauth_gssapi(Authctxt *authctxt)
{
	gss_OID_desc goid = {0, NULL};
	Gssctxt *ctxt = NULL;
	int mechs;
	gss_OID_set supported;
	int present;
	OM_uint32 ms;
	u_int len;
	u_char *doid = NULL;

	/* authctxt->valid may be 0 if we haven't yet determined
	   username from gssapi context. */

	if (authctxt->user == NULL)
		return (0);

	mechs = packet_get_int();
	if (mechs == 0) {
		debug("Mechanism negotiation is not supported");
		return (0);
	}

	ssh_gssapi_supported_oids(&supported);
	do {
		mechs--;

		if (doid)
			xfree(doid);

		present = 0;
		doid = packet_get_string(&len);

		if (len > 2 && doid[0] == SSH_GSS_OIDTYPE &&
		    doid[1] == len - 2) {
			goid.elements = doid + 2;
			goid.length   = len - 2;
			gss_test_oid_set_member(&ms, &goid, supported,
			    &present);
		} else {
			logit("Badly formed OID received");
		}
	} while (mechs > 0 && !present);

	gss_release_oid_set(&ms, &supported);

	if (!present) {
		xfree(doid);
		authctxt->server_caused_failure = 1;
		return (0);
	}

	if (GSS_ERROR(PRIVSEP(ssh_gssapi_server_ctx(&ctxt, &goid)))) {
		if (ctxt != NULL)
			ssh_gssapi_delete_ctx(&ctxt);
		xfree(doid);
		authctxt->server_caused_failure = 1;
		return (0);
	}

	authctxt->methoddata = (void *)ctxt;

	packet_start(SSH2_MSG_USERAUTH_GSSAPI_RESPONSE);

	/* Return the OID that we received */
	packet_put_string(doid, len);

	packet_send();
	xfree(doid);

	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, &input_gssapi_token);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, &input_gssapi_errtok);
	authctxt->postponed = 1;

	return (0);
}

static void
input_gssapi_token(int type, u_int32_t plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 maj_status, min_status, flags=0;
	u_int len;

	if (authctxt == NULL || (authctxt->methoddata == NULL && !use_privsep))
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	recv_tok.value = packet_get_string(&len);
	recv_tok.length = len; /* u_int vs. size_t */

	packet_check_eom();

	maj_status = PRIVSEP(ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, &flags));

	xfree(recv_tok.value);

	if (GSS_ERROR(maj_status)) {
        	ssh_gssapi_userauth_error(gssctxt);
		if (send_tok.length != 0) {
			packet_start(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK);
			packet_put_string(send_tok.value, send_tok.length);
			packet_send();
		}
		authctxt->postponed = 0;
		dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
		userauth_finish(authctxt, 0,
				gssapi_with_mic ? "gssapi-with-mic" :
				                  "gssapi");
	} else {
		if (send_tok.length != 0) {
			packet_start(SSH2_MSG_USERAUTH_GSSAPI_TOKEN);
			packet_put_string(send_tok.value, send_tok.length);
			packet_send();
		}
		if (maj_status == GSS_S_COMPLETE) {
			dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
			if (flags & GSS_C_INTEG_FLAG && gssapi_with_mic)
				dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_MIC,
				    &input_gssapi_mic);
			else
				dispatch_set(
				    SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
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
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 maj_status;
	u_int len;

	if (authctxt == NULL || (authctxt->methoddata == NULL && !use_privsep))
		fatal("No authentication or GSSAPI context");

	gssctxt = authctxt->methoddata;
	recv_tok.value = packet_get_string(&len);
	recv_tok.length = len;

	packet_check_eom();

	/* Push the error token into GSSAPI to see what it says */
	maj_status = PRIVSEP(ssh_gssapi_accept_ctx(gssctxt, &recv_tok,
	    &send_tok, NULL));

	xfree(recv_tok.value);

	/* We can't return anything to the client, even if we wanted to */
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);

	/* The client will have already moved on to the next auth */

	gss_release_buffer(&maj_status, &send_tok);
}

static void
gssapi_set_implicit_username(Authctxt *authctxt)
{
    if ((authctxt->user == NULL) || (authctxt->user[0] == '\0')) {
	char *lname = NULL;
	PRIVSEP(ssh_gssapi_localname(&lname));
	if (lname && lname[0] != '\0') {
	    if (authctxt->user) xfree(authctxt->user);
	    authctxt->user = lname;
	    debug("set username to %s from gssapi context", lname);
	    authctxt->pw = PRIVSEP(getpwnamallow(authctxt->user));
	    if (authctxt->pw) {
		authctxt->valid = 1;
	    }
	} else {
	    debug("failed to set username from gssapi context");
	    packet_send_debug("failed to set username from gssapi context");
	}
    }
    if (authctxt->pw) {
#ifdef USE_PAM
	if (options.use_pam)
		PRIVSEP(start_pam(authctxt));
#endif
    }
}

/*
 * This is called when the client thinks we've completed authentication.
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

	gssapi_set_implicit_username(authctxt);

	gssctxt = authctxt->methoddata;

	/*
	 * We don't need to check the status, because we're only enabled in
	 * the dispatcher once the exchange is complete
	 */

	packet_check_eom();

	/* user should be set if valid but we double-check here */
	if (authctxt->valid && authctxt->user && authctxt->user[0]) {
	    authenticated = PRIVSEP(ssh_gssapi_userok(authctxt->user));
	} else {
	    authenticated = 0;
	}

	authctxt->postponed = 0;
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_MIC, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
	userauth_finish(authctxt, authenticated,
			gssapi_with_mic ? "gssapi-with-mic" : "gssapi");
}

static int
userauth_gssapi_with_mic(Authctxt *authctxt)
{
    gssapi_with_mic = 1;
    return userauth_gssapi(authctxt);
}

static int
userauth_gssapi_without_mic(Authctxt *authctxt)
{
    gssapi_with_mic = 0;
    return userauth_gssapi(authctxt);
}

static void
input_gssapi_mic(int type, u_int32_t plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt;
	int authenticated = 0;
	Buffer b;
	gss_buffer_desc mic, gssbuf;
	u_int len;

	if (authctxt == NULL || (authctxt->methoddata == NULL && !use_privsep))
		fatal("No authentication or GSSAPI context");

	gssapi_set_implicit_username(authctxt);

	gssctxt = authctxt->methoddata;

	mic.value = packet_get_string(&len);
	mic.length = len;

	ssh_gssapi_buildmic(&b, authctxt->user, authctxt->service,
	    "gssapi-with-mic");

	gssbuf.value = buffer_ptr(&b);
	gssbuf.length = buffer_len(&b);

	if (!GSS_ERROR(PRIVSEP(ssh_gssapi_checkmic(gssctxt, &gssbuf, &mic))))
	    if (authctxt->valid && authctxt->user && authctxt->user[0]) {
		authenticated = PRIVSEP(ssh_gssapi_userok(authctxt->user));
	    } else {
		authenticated = 0;
	    }
	else
		logit("GSSAPI MIC check failed");

	buffer_free(&b);
	xfree(mic.value);

	authctxt->postponed = 0;
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_MIC, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
	userauth_finish(authctxt, authenticated, "gssapi-with-mic");
}

static void ssh_gssapi_userauth_error(Gssctxt *ctxt) {
	char *errstr;
	OM_uint32 maj,min;
	
	errstr=PRIVSEP(ssh_gssapi_last_error(ctxt,&maj,&min));
	if (errstr) {
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

Authmethod method_external = {
	"external-keyx",
	userauth_external,
	&options.gss_authentication
};
	
Authmethod method_gsskeyex = {
	"gssapi-keyex",
	userauth_gsskeyex,
	&options.gss_authentication
};

Authmethod method_gssapi = {
	"gssapi-with-mic",
	userauth_gssapi_with_mic,
	&options.gss_authentication
};

Authmethod method_gssapi_compat = {
	"gssapi",
	userauth_gssapi_without_mic,
	&options.gss_authentication
};

#endif /* GSSAPI */

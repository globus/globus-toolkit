/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Code to connect to a remote host, and to perform the client side of the
 * login (authentication) dialog.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include "includes.h"
RCSID("$OpenBSD: sshconnect1.c,v 1.56 2003/08/28 12:54:34 markus Exp $");

#include <openssl/bn.h>
#include <openssl/md5.h>

#include "ssh.h"
#include "ssh1.h"
#include "xmalloc.h"
#include "rsa.h"
#include "buffer.h"
#include "packet.h"
#include "mpaux.h"
#include "uidswap.h"
#include "log.h"
#include "readconf.h"
#include "key.h"
#include "authfd.h"
#include "sshconnect.h"
#include "authfile.h"
#include "readpass.h"
#include "cipher.h"
#include "canohost.h"
#include "auth.h"

#ifdef GSSAPI
#include "ssh-gss.h"
#include "bufaux.h"

/*
 * MD5 hash of host and session keys for verification. This is filled
 * in in ssh_login() and then checked in try_gssapi_authentication().
 */
unsigned char ssh_key_digest[16];
#endif /* GSSAPI */

/* Session id for the current session. */
u_char session_id[16];
u_int supported_authentications = 0;

extern Options options;
extern char *__progname;

/*
 * Checks if the user has an authentication agent, and if so, tries to
 * authenticate using the agent.
 */
static int
try_agent_authentication(void)
{
	int type;
	char *comment;
	AuthenticationConnection *auth;
	u_char response[16];
	u_int i;
	Key *key;
	BIGNUM *challenge;

	/* Get connection to the agent. */
	auth = ssh_get_authentication_connection();
	if (!auth)
		return 0;

	if ((challenge = BN_new()) == NULL)
		fatal("try_agent_authentication: BN_new failed");
	/* Loop through identities served by the agent. */
	for (key = ssh_get_first_identity(auth, &comment, 1);
	    key != NULL;
	    key = ssh_get_next_identity(auth, &comment, 1)) {

		/* Try this identity. */
		debug("Trying RSA authentication via agent with '%.100s'", comment);
		xfree(comment);

		/* Tell the server that we are willing to authenticate using this key. */
		packet_start(SSH_CMSG_AUTH_RSA);
		packet_put_bignum(key->rsa->n);
		packet_send();
		packet_write_wait();

		/* Wait for server's response. */
		type = packet_read();

		/* The server sends failure if it doesn\'t like our key or
		   does not support RSA authentication. */
		if (type == SSH_SMSG_FAILURE) {
			debug("Server refused our key.");
			key_free(key);
			continue;
		}
		/* Otherwise it should have sent a challenge. */
		if (type != SSH_SMSG_AUTH_RSA_CHALLENGE)
			packet_disconnect("Protocol error during RSA authentication: %d",
					  type);

		packet_get_bignum(challenge);
		packet_check_eom();

		debug("Received RSA challenge from server.");

		/* Ask the agent to decrypt the challenge. */
		if (!ssh_decrypt_challenge(auth, key, challenge, session_id, 1, response)) {
			/*
			 * The agent failed to authenticate this identifier
			 * although it advertised it supports this.  Just
			 * return a wrong value.
			 */
			logit("Authentication agent failed to decrypt challenge.");
			memset(response, 0, sizeof(response));
		}
		key_free(key);
		debug("Sending response to RSA challenge.");

		/* Send the decrypted challenge back to the server. */
		packet_start(SSH_CMSG_AUTH_RSA_RESPONSE);
		for (i = 0; i < 16; i++)
			packet_put_char(response[i]);
		packet_send();
		packet_write_wait();

		/* Wait for response from the server. */
		type = packet_read();

		/* The server returns success if it accepted the authentication. */
		if (type == SSH_SMSG_SUCCESS) {
			ssh_close_authentication_connection(auth);
			BN_clear_free(challenge);
			debug("RSA authentication accepted by server.");
			return 1;
		}
		/* Otherwise it should return failure. */
		if (type != SSH_SMSG_FAILURE)
			packet_disconnect("Protocol error waiting RSA auth response: %d",
					  type);
	}
	ssh_close_authentication_connection(auth);
	BN_clear_free(challenge);
	debug("RSA authentication using agent refused.");
	return 0;
}

/*
 * Computes the proper response to a RSA challenge, and sends the response to
 * the server.
 */
static void
respond_to_rsa_challenge(BIGNUM * challenge, RSA * prv)
{
	u_char buf[32], response[16];
	MD5_CTX md;
	int i, len;

	/* Decrypt the challenge using the private key. */
	/* XXX think about Bleichenbacher, too */
	if (rsa_private_decrypt(challenge, challenge, prv) <= 0)
		packet_disconnect(
		    "respond_to_rsa_challenge: rsa_private_decrypt failed");

	/* Compute the response. */
	/* The response is MD5 of decrypted challenge plus session id. */
	len = BN_num_bytes(challenge);
	if (len <= 0 || len > sizeof(buf))
		packet_disconnect(
		    "respond_to_rsa_challenge: bad challenge length %d", len);

	memset(buf, 0, sizeof(buf));
	BN_bn2bin(challenge, buf + sizeof(buf) - len);
	MD5_Init(&md);
	MD5_Update(&md, buf, 32);
	MD5_Update(&md, session_id, 16);
	MD5_Final(response, &md);

	debug("Sending response to host key RSA challenge.");

	/* Send the response back to the server. */
	packet_start(SSH_CMSG_AUTH_RSA_RESPONSE);
	for (i = 0; i < 16; i++)
		packet_put_char(response[i]);
	packet_send();
	packet_write_wait();

	memset(buf, 0, sizeof(buf));
	memset(response, 0, sizeof(response));
	memset(&md, 0, sizeof(md));
}

/*
 * Checks if the user has authentication file, and if so, tries to authenticate
 * the user using it.
 */
static int
try_rsa_authentication(int idx)
{
	BIGNUM *challenge;
	Key *public, *private;
	char buf[300], *passphrase, *comment, *authfile;
	int i, type, quit;

	public = options.identity_keys[idx];
	authfile = options.identity_files[idx];
	comment = xstrdup(authfile);

	debug("Trying RSA authentication with key '%.100s'", comment);

	/* Tell the server that we are willing to authenticate using this key. */
	packet_start(SSH_CMSG_AUTH_RSA);
	packet_put_bignum(public->rsa->n);
	packet_send();
	packet_write_wait();

	/* Wait for server's response. */
	type = packet_read();

	/*
	 * The server responds with failure if it doesn\'t like our key or
	 * doesn\'t support RSA authentication.
	 */
	if (type == SSH_SMSG_FAILURE) {
		debug("Server refused our key.");
		xfree(comment);
		return 0;
	}
	/* Otherwise, the server should respond with a challenge. */
	if (type != SSH_SMSG_AUTH_RSA_CHALLENGE)
		packet_disconnect("Protocol error during RSA authentication: %d", type);

	/* Get the challenge from the packet. */
	if ((challenge = BN_new()) == NULL)
		fatal("try_rsa_authentication: BN_new failed");
	packet_get_bignum(challenge);
	packet_check_eom();

	debug("Received RSA challenge from server.");

	/*
	 * If the key is not stored in external hardware, we have to
	 * load the private key.  Try first with empty passphrase; if it
	 * fails, ask for a passphrase.
	 */
	if (public->flags & KEY_FLAG_EXT)
		private = public;
	else
		private = key_load_private_type(KEY_RSA1, authfile, "", NULL);
	if (private == NULL && !options.batch_mode) {
		snprintf(buf, sizeof(buf),
		    "Enter passphrase for RSA key '%.100s': ", comment);
		for (i = 0; i < options.number_of_password_prompts; i++) {
			passphrase = read_passphrase(buf, 0);
			if (strcmp(passphrase, "") != 0) {
				private = key_load_private_type(KEY_RSA1,
				    authfile, passphrase, NULL);
				quit = 0;
			} else {
				debug2("no passphrase given, try next key");
				quit = 1;
			}
			memset(passphrase, 0, strlen(passphrase));
			xfree(passphrase);
			if (private != NULL || quit)
				break;
			debug2("bad passphrase given, try again...");
		}
	}
	/* We no longer need the comment. */
	xfree(comment);

	if (private == NULL) {
		if (!options.batch_mode)
			error("Bad passphrase.");

		/* Send a dummy response packet to avoid protocol error. */
		packet_start(SSH_CMSG_AUTH_RSA_RESPONSE);
		for (i = 0; i < 16; i++)
			packet_put_char(0);
		packet_send();
		packet_write_wait();

		/* Expect the server to reject it... */
		packet_read_expect(SSH_SMSG_FAILURE);
		BN_clear_free(challenge);
		return 0;
	}

	/* Compute and send a response to the challenge. */
	respond_to_rsa_challenge(challenge, private->rsa);

	/* Destroy the private key unless it in external hardware. */
	if (!(private->flags & KEY_FLAG_EXT))
		key_free(private);

	/* We no longer need the challenge. */
	BN_clear_free(challenge);

	/* Wait for response from the server. */
	type = packet_read();
	if (type == SSH_SMSG_SUCCESS) {
		debug("RSA authentication accepted by server.");
		return 1;
	}
	if (type != SSH_SMSG_FAILURE)
		packet_disconnect("Protocol error waiting RSA auth response: %d", type);
	debug("RSA authentication refused.");
	return 0;
}

/*
 * Tries to authenticate the user using combined rhosts or /etc/hosts.equiv
 * authentication and RSA host authentication.
 */
static int
try_rhosts_rsa_authentication(const char *local_user, Key * host_key)
{
	int type;
	BIGNUM *challenge;

	debug("Trying rhosts or /etc/hosts.equiv with RSA host authentication.");

	/* Tell the server that we are willing to authenticate using this key. */
	packet_start(SSH_CMSG_AUTH_RHOSTS_RSA);
	packet_put_cstring(local_user);
	packet_put_int(BN_num_bits(host_key->rsa->n));
	packet_put_bignum(host_key->rsa->e);
	packet_put_bignum(host_key->rsa->n);
	packet_send();
	packet_write_wait();

	/* Wait for server's response. */
	type = packet_read();

	/* The server responds with failure if it doesn't admit our
	   .rhosts authentication or doesn't know our host key. */
	if (type == SSH_SMSG_FAILURE) {
		debug("Server refused our rhosts authentication or host key.");
		return 0;
	}
	/* Otherwise, the server should respond with a challenge. */
	if (type != SSH_SMSG_AUTH_RSA_CHALLENGE)
		packet_disconnect("Protocol error during RSA authentication: %d", type);

	/* Get the challenge from the packet. */
	if ((challenge = BN_new()) == NULL)
		fatal("try_rhosts_rsa_authentication: BN_new failed");
	packet_get_bignum(challenge);
	packet_check_eom();

	debug("Received RSA challenge for host key from server.");

	/* Compute a response to the challenge. */
	respond_to_rsa_challenge(challenge, host_key->rsa);

	/* We no longer need the challenge. */
	BN_clear_free(challenge);

	/* Wait for response from the server. */
	type = packet_read();
	if (type == SSH_SMSG_SUCCESS) {
		debug("Rhosts or /etc/hosts.equiv with RSA host authentication accepted by server.");
		return 1;
	}
	if (type != SSH_SMSG_FAILURE)
		packet_disconnect("Protocol error waiting RSA auth response: %d", type);
	debug("Rhosts or /etc/hosts.equiv with RSA host authentication refused.");
	return 0;
}

/*
 * Tries to authenticate with any string-based challenge/response system.
 * Note that the client code is not tied to s/key or TIS.
 */
static int
try_challenge_response_authentication(void)
{
	int type, i;
	u_int clen;
	char prompt[1024];
	char *challenge, *response;

	debug("Doing challenge response authentication.");

	for (i = 0; i < options.number_of_password_prompts; i++) {
		/* request a challenge */
		packet_start(SSH_CMSG_AUTH_TIS);
		packet_send();
		packet_write_wait();

		type = packet_read();
		if (type != SSH_SMSG_FAILURE &&
		    type != SSH_SMSG_AUTH_TIS_CHALLENGE) {
			packet_disconnect("Protocol error: got %d in response "
			    "to SSH_CMSG_AUTH_TIS", type);
		}
		if (type != SSH_SMSG_AUTH_TIS_CHALLENGE) {
			debug("No challenge.");
			return 0;
		}
		challenge = packet_get_string(&clen);
		packet_check_eom();
		snprintf(prompt, sizeof prompt, "%s%s", challenge,
		    strchr(challenge, '\n') ? "" : "\nResponse: ");
		xfree(challenge);
		if (i != 0)
			error("Permission denied, please try again.");
		if (options.cipher == SSH_CIPHER_NONE)
			logit("WARNING: Encryption is disabled! "
			    "Response will be transmitted in clear text.");
		response = read_passphrase(prompt, 0);
		if (strcmp(response, "") == 0) {
			xfree(response);
			break;
		}
		packet_start(SSH_CMSG_AUTH_TIS_RESPONSE);
		ssh_put_password(response);
		memset(response, 0, strlen(response));
		xfree(response);
		packet_send();
		packet_write_wait();
		type = packet_read();
		if (type == SSH_SMSG_SUCCESS)
			return 1;
		if (type != SSH_SMSG_FAILURE)
			packet_disconnect("Protocol error: got %d in response "
			    "to SSH_CMSG_AUTH_TIS_RESPONSE", type);
	}
	/* failure */
	return 0;
}

/*
 * Tries to authenticate with plain passwd authentication.
 */
static int
try_password_authentication(char *prompt)
{
	int type, i;
	char *password;

	debug("Doing password authentication.");
	if (options.cipher == SSH_CIPHER_NONE)
		logit("WARNING: Encryption is disabled! Password will be transmitted in clear text.");
	for (i = 0; i < options.number_of_password_prompts; i++) {
		if (i != 0)
			error("Permission denied, please try again.");
		password = read_passphrase(prompt, 0);
		packet_start(SSH_CMSG_AUTH_PASSWORD);
		ssh_put_password(password);
		memset(password, 0, strlen(password));
		xfree(password);
		packet_send();
		packet_write_wait();

		type = packet_read();
		if (type == SSH_SMSG_SUCCESS)
			return 1;
		if (type != SSH_SMSG_FAILURE)
			packet_disconnect("Protocol error: got %d in response to passwd auth", type);
	}
	/* failure */
	return 0;
}

#ifdef GSSAPI
#ifdef GSI
static gss_OID_desc gsioid={9, "\x2B\x06\x01\x04\x01\x9B\x50\x01\x01"};
char * get_gsi_name()
{
  gss_name_t pname = GSS_C_NO_NAME;
  gss_buffer_desc tmpname;
  gss_buffer_t tmpnamed = &tmpname;
  char *retname=NULL;
  gss_OID_set oidset;
  gss_cred_id_t gss_cred = GSS_C_NO_CREDENTIAL;
  Gssctxt *ctx = NULL;

  ssh_gssapi_build_ctx(&ctx);

  gss_create_empty_oid_set(&ctx->minor,&oidset);
  gss_add_oid_set_member(&ctx->minor,&gsioid,&oidset);
  ssh_gssapi_set_oid(ctx,&gsioid);
  ctx->major = gss_acquire_cred(&ctx->minor,
				GSS_C_NO_NAME,
				GSS_C_INDEFINITE,
				oidset,
				GSS_C_INITIATE,
				&gss_cred,
				NULL,
				NULL);

  if (ctx->major != GSS_S_COMPLETE) {
      goto cleanup;
  }

  debug("calling gss_inquire_cred");
  ctx->major = gss_inquire_cred(&ctx->minor,
				gss_cred,
				&pname,
				NULL,
				NULL,
				NULL);
  if (ctx->major != GSS_S_COMPLETE) {
      goto cleanup;
  }

  ctx->major = gss_display_name(&ctx->minor,
				pname,
				tmpnamed,
				NULL);
  if (ctx->major != GSS_S_COMPLETE) {
      goto cleanup;
  }
  debug("gss_display_name finsished");
  retname = xmalloc(tmpname.length + 1);
  memcpy(retname, tmpname.value, tmpname.length);
  retname[tmpname.length] = '\0';

  gss_release_name(&ctx->minor, &pname);
  gss_release_buffer(&ctx->minor, tmpnamed);

 cleanup:
  if (!retname) {
      debug("Failed to set GSI username from credentials");
      ssh_gssapi_error(ctx);
  }
  if (ctx) ssh_gssapi_delete_ctx(&ctx);
  return retname;
}
#endif /* GSI */

int try_gssapi_authentication(char *host, Options *options)
{
  char *service_name = NULL;
  gss_buffer_desc name_tok;
  gss_buffer_desc send_tok;
  gss_buffer_desc recv_tok;
  gss_buffer_desc *token_ptr;
  gss_name_t target_name = NULL;
  gss_ctx_id_t gss_context;
  gss_OID_desc mech_oid;
  gss_OID name_type;
  gss_OID_set gss_mechs, my_mechs;
  int my_mech_num, i;
  int ret_stat = 0;                             /* 1 == success */
  OM_uint32 req_flags = 0;
  OM_uint32 ret_flags;
  int type;
  char *xhost;
  unsigned int slen;
  Gssctxt *ctx = NULL;

  ssh_gssapi_build_ctx(&ctx);

  xhost = xstrdup(get_canonical_hostname(1));
  resolve_localhost(&xhost);

  /*
   * Default flags
   */
  req_flags |= GSS_C_REPLAY_FLAG;

  /* Do mutual authentication */
  req_flags |= GSS_C_MUTUAL_FLAG;

  service_name = (char *) xmalloc(strlen("host") +
				  strlen(xhost) +
				  2 /* 1 for '@', 1 for NUL */);

  sprintf(service_name, "host@%s", xhost);

  xfree(xhost);
  xhost = NULL;

  name_type = GSS_C_NT_HOSTBASED_SERVICE;

  debug("Service name is %s", service_name);

  /* Forward credentials? */
  if(options->gss_deleg_creds) {
    debug("Delegating GSSAPI credentials");
    req_flags |= GSS_C_DELEG_FLAG;
  }

  debug("req_flags = %u", (unsigned int)req_flags);

  name_tok.value = service_name;
  name_tok.length = strlen(service_name) + 1;
  ctx->major = gss_import_name(&ctx->minor, &name_tok,
			       name_type, &target_name);

  free(service_name);
  service_name = NULL;

  if (ctx->major != GSS_S_COMPLETE) {
    ssh_gssapi_error(ctx);
    goto cleanup;
  }

  ctx->major = gss_indicate_mechs(&ctx->minor, &gss_mechs);

  if (ctx->major != GSS_S_COMPLETE) {
    ssh_gssapi_error(ctx);
    goto cleanup;
  }

  /* The GSSAPI supports the mechs in gss_mechs, but which ones do
     we have credentials for?  We only get one try, so we don't want
     to propose a mechanism we know is going to fail. */
  ctx->major = gss_create_empty_oid_set(&ctx->minor, &my_mechs);
  for (i=0; i<gss_mechs->count; i++) {
      if (ssh_gssapi_check_mechanism(&(gss_mechs->elements[i]), host)) {
	  ctx->major = gss_add_oid_set_member(&ctx->minor,
					      &(gss_mechs->elements[i]),
					      &my_mechs);
      }
  }

  if (my_mechs->count == 0) {
      debug("No GSSAPI mechanisms.");
      goto cleanup;
  }

  /*
   * Send over a packet to the daemon, letting it know we're doing
   * GSSAPI and our mech_oid(s).
   */
  debug("Sending mech oid(s) to server");
  packet_start(SSH_CMSG_AUTH_GSSAPI);
  packet_put_int(my_mechs->count); /* Number of mechs we're sending */
#ifdef GSI
  {
      int present;
      /* Send GSI before Kerberos, because if GSI fails, we can always
	 fall back and try regular Kerberos authentication with our
	 Kerberos cred. */
      ctx->major = gss_test_oid_set_member(&ctx->minor, &gsioid,
					   my_mechs, &present);
      if (present) {
	  packet_put_string(gsioid.elements,gsioid.length);
      }
  }
#endif
  for (my_mech_num = 0; my_mech_num < my_mechs->count; my_mech_num++) {
#ifdef GSI
      /* Skip GSI.  We already sent it above. */
      if ((my_mechs->elements[my_mech_num].length ==
	   gsioid.length) &&
	  memcmp(my_mechs->elements[my_mech_num].elements,
		 gsioid.elements,
		 my_mechs->elements[my_mech_num].length) == 0) {
	  continue;
      }
#endif
      packet_put_string(my_mechs->elements[my_mech_num].elements,
                        my_mechs->elements[my_mech_num].length);
  }
  packet_send();
  packet_write_wait();

  /*
   * Get reply from the daemon to see if our mech was acceptable
   */
  type = packet_read();

  switch (type) {
  case SSH_SMSG_AUTH_GSSAPI_RESPONSE:
      debug("Server accepted mechanism");
      /* Successful negotiation */
      break;

  case SSH_MSG_AUTH_GSSAPI_ABORT:
  case SSH_SMSG_FAILURE:
      debug("Unable to negotiate GSSAPI mechanism type with server");
      packet_get_all();
      goto cleanup;

  default:
      packet_disconnect("Protocol error during GSSAPI authentication:"
                        " packet type %d received",
                        type);
      /* Does not return */
  }

  /* Read the mechanism the server returned */
  mech_oid.elements = packet_get_string(&slen);
  mech_oid.length = slen;	/* safe typecast */
  packet_get_all();

  ssh_gssapi_set_oid(ctx, &mech_oid);

  /*
   * Perform the context-establishement loop.
   *
   * On each pass through the loop, token_ptr points to the token
   * to send to the server (or GSS_C_NO_BUFFER on the first pass).
   * Every generated token is stored in send_tok which is then
   * transmitted to the server; every received token is stored in
   * recv_tok, which token_ptr is then set to, to be processed by
   * the next call to gss_init_sec_context.
   *
   * GSS-API guarantees that send_tok's length will be non-zero
   * if and only if the server is expecting another token from us,
   * and that gss_init_sec_context returns GSS_S_CONTINUE_NEEDED if
   * and only if the server has another token to send us.
   */

  token_ptr = GSS_C_NO_BUFFER;
  gss_context = GSS_C_NO_CONTEXT;

  do {
    ctx->major =
      gss_init_sec_context(&ctx->minor,
                           GSS_C_NO_CREDENTIAL,
                           &gss_context,
                           target_name,
                           ctx->oid,
                           req_flags,
                           0,
                           NULL,        /* no channel bindings */
                           token_ptr,
                           NULL,        /* ignore mech type */
                           &send_tok,
                           &ret_flags,
                           NULL);       /* ignore time_rec */

    if (token_ptr != GSS_C_NO_BUFFER)
      (void) gss_release_buffer(&ctx->minor, &recv_tok);

    if (ctx->major != GSS_S_COMPLETE && ctx->major != GSS_S_CONTINUE_NEEDED) {
      ssh_gssapi_error(ctx);

      /* Send an abort message */
      packet_start(SSH_MSG_AUTH_GSSAPI_ABORT);
      packet_send();
      packet_write_wait();

      goto cleanup;
    }

    if (send_tok.length != 0) {
      debug("Sending authenticaton token...");
      packet_start(SSH_MSG_AUTH_GSSAPI_TOKEN);
      packet_put_string((char *) send_tok.value, send_tok.length);
      packet_send();
      packet_write_wait();

      (void) gss_release_buffer(&ctx->minor, &send_tok);
    }

    if (ctx->major == GSS_S_CONTINUE_NEEDED) {

      debug("Continue needed. Reading response...");

      type = packet_read();

      switch(type) {

      case SSH_MSG_AUTH_GSSAPI_TOKEN:
        /* This is what we expected */
        break;

      case SSH_MSG_AUTH_GSSAPI_ABORT:
      case SSH_SMSG_FAILURE:
        debug("Server aborted GSSAPI authentication.");
        packet_get_all();
        goto cleanup;

      default:
        packet_disconnect("Protocol error during GSSAPI authentication:"
                          " packet type %d received",
                          type);
        /* Does not return */
      }

      recv_tok.value = packet_get_string(&slen);
      recv_tok.length=slen;	/* safe typecast */
      packet_get_all();
      token_ptr = &recv_tok;
    }
  } while (ctx->major == GSS_S_CONTINUE_NEEDED);

  /* Success */
  ret_stat = 1;

  debug("GSSAPI authentication successful");

  /*
   * Read hash of host and server keys and make sure it
   * matches what we got earlier.
   */
  debug("Reading hash of server and host keys...");
  type = packet_read();

  if (type == SSH_MSG_AUTH_GSSAPI_ABORT || type == SSH_SMSG_FAILURE) {
    debug("Server aborted GSSAPI authentication.");
    packet_get_all();
    ret_stat = 0;
    goto cleanup;

  } else if (type == SSH_SMSG_AUTH_GSSAPI_HASH) {
    gss_buffer_desc wrapped_buf;
    gss_buffer_desc unwrapped_buf;
    int conf_state;
    gss_qop_t qop_state;


    wrapped_buf.value = packet_get_string(&slen);
    wrapped_buf.length=slen;	/* safe typecast */
    packet_get_all();

    ctx->major = gss_unwrap(&ctx->minor,
                          gss_context,
                          &wrapped_buf,
                          &unwrapped_buf,
                          &conf_state,
                          &qop_state);

    if (ctx->major != GSS_S_COMPLETE) {
      ssh_gssapi_error(ctx);
      packet_disconnect("Verification of SSHD keys through GSSAPI-secured channel failed: "
                        "Unwrapping of hash failed.");
    }

    if (unwrapped_buf.length != sizeof(ssh_key_digest)) {
      packet_disconnect("Verification of SSHD keys through GSSAPI-secured channel failed: "
                        "Size of key hashes do not match (%d != %d)!",
                        (int)unwrapped_buf.length,
			(int)sizeof(ssh_key_digest));
    }

    if (memcmp(ssh_key_digest, unwrapped_buf.value, sizeof(ssh_key_digest)) != 0) {
      packet_disconnect("Verification of SSHD keys through GSSAPI-secured channel failed: "
                        "Hashes don't match!");
    }

    debug("Verified SSHD keys through GSSAPI-secured channel.");

    gss_release_buffer(&ctx->minor, &unwrapped_buf);

  } else {
      packet_disconnect("Protocol error during GSSAPI authentication:"
                        "packet type %d received", type);
      /* Does not return */
  }


 cleanup:
  if (target_name != NULL)
      (void) gss_release_name(&ctx->minor, &target_name);
  if (ctx)
      ssh_gssapi_delete_ctx(&ctx);

  return ret_stat;
}

#endif /* GSSAPI */


/*
 * SSH1 key exchange
 */
void
ssh_kex(char *host, struct sockaddr *hostaddr)
{
	int i;
	BIGNUM *key;
	Key *host_key, *server_key;
	int bits, rbits;
	int ssh_cipher_default = SSH_CIPHER_3DES;
	u_char session_key[SSH_SESSION_KEY_LENGTH];
	u_char cookie[8];
	u_int supported_ciphers;
	u_int server_flags, client_flags;
	u_int32_t rand = 0;

	debug("Waiting for server public key.");

	/* Wait for a public key packet from the server. */
	packet_read_expect(SSH_SMSG_PUBLIC_KEY);

	/* Get cookie from the packet. */
	for (i = 0; i < 8; i++)
		cookie[i] = packet_get_char();

	/* Get the public key. */
	server_key = key_new(KEY_RSA1);
	bits = packet_get_int();
	packet_get_bignum(server_key->rsa->e);
	packet_get_bignum(server_key->rsa->n);

	rbits = BN_num_bits(server_key->rsa->n);
	if (bits != rbits) {
		logit("Warning: Server lies about size of server public key: "
		    "actual size is %d bits vs. announced %d.", rbits, bits);
		logit("Warning: This may be due to an old implementation of ssh.");
	}
	/* Get the host key. */
	host_key = key_new(KEY_RSA1);
	bits = packet_get_int();
	packet_get_bignum(host_key->rsa->e);
	packet_get_bignum(host_key->rsa->n);

	rbits = BN_num_bits(host_key->rsa->n);
	if (bits != rbits) {
		logit("Warning: Server lies about size of server host key: "
		    "actual size is %d bits vs. announced %d.", rbits, bits);
		logit("Warning: This may be due to an old implementation of ssh.");
	}

#ifdef GSSAPI
  {
    MD5_CTX md5context;
    Buffer buf;
    unsigned char *data;
    unsigned int data_len;

    /*
     * Hash the server and host keys. Later we will check them against
     * a hash sent over a secure channel to make sure they are legit.
     */
    debug("Calculating MD5 hash of server and host keys...");

    /* Write all the keys to a temporary buffer */
    buffer_init(&buf);

    /* Server key */
    buffer_put_bignum(&buf, server_key->rsa->e);
    buffer_put_bignum(&buf, server_key->rsa->n);

    /* Host key */
    buffer_put_bignum(&buf, host_key->rsa->e);
    buffer_put_bignum(&buf, host_key->rsa->n);

    /* Get the resulting data */
    data = (unsigned char *) buffer_ptr(&buf);
    data_len = buffer_len(&buf);

    /* And hash it */
    MD5_Init(&md5context);
    MD5_Update(&md5context, data, data_len);
    MD5_Final(ssh_key_digest, &md5context);

    /* Clean up */
    buffer_clear(&buf);
    buffer_free(&buf);
  }
#endif /* GSSAPI */

	/* Get protocol flags. */
	server_flags = packet_get_int();
	packet_set_protocol_flags(server_flags);

	supported_ciphers = packet_get_int();
	supported_authentications = packet_get_int();
	packet_check_eom();

	debug("Received server public key (%d bits) and host key (%d bits).",
	    BN_num_bits(server_key->rsa->n), BN_num_bits(host_key->rsa->n));

	if (verify_host_key(host, hostaddr, host_key) == -1)
		fatal("Host key verification failed.");

	client_flags = SSH_PROTOFLAG_SCREEN_NUMBER | SSH_PROTOFLAG_HOST_IN_FWD_OPEN;

	compute_session_id(session_id, cookie, host_key->rsa->n, server_key->rsa->n);

	/* Generate a session key. */
	arc4random_stir();

	/*
	 * Generate an encryption key for the session.   The key is a 256 bit
	 * random number, interpreted as a 32-byte key, with the least
	 * significant 8 bits being the first byte of the key.
	 */
	for (i = 0; i < 32; i++) {
		if (i % 4 == 0)
			rand = arc4random();
		session_key[i] = rand & 0xff;
		rand >>= 8;
	}

	/*
	 * According to the protocol spec, the first byte of the session key
	 * is the highest byte of the integer.  The session key is xored with
	 * the first 16 bytes of the session id.
	 */
	if ((key = BN_new()) == NULL)
		fatal("respond_to_rsa_challenge: BN_new failed");
	BN_set_word(key, 0);
	for (i = 0; i < SSH_SESSION_KEY_LENGTH; i++) {
		BN_lshift(key, key, 8);
		if (i < 16)
			BN_add_word(key, session_key[i] ^ session_id[i]);
		else
			BN_add_word(key, session_key[i]);
	}

	/*
	 * Encrypt the integer using the public key and host key of the
	 * server (key with smaller modulus first).
	 */
	if (BN_cmp(server_key->rsa->n, host_key->rsa->n) < 0) {
		/* Public key has smaller modulus. */
		if (BN_num_bits(host_key->rsa->n) <
		    BN_num_bits(server_key->rsa->n) + SSH_KEY_BITS_RESERVED) {
			fatal("respond_to_rsa_challenge: host_key %d < server_key %d + "
			    "SSH_KEY_BITS_RESERVED %d",
			    BN_num_bits(host_key->rsa->n),
			    BN_num_bits(server_key->rsa->n),
			    SSH_KEY_BITS_RESERVED);
		}
		rsa_public_encrypt(key, key, server_key->rsa);
		rsa_public_encrypt(key, key, host_key->rsa);
	} else {
		/* Host key has smaller modulus (or they are equal). */
		if (BN_num_bits(server_key->rsa->n) <
		    BN_num_bits(host_key->rsa->n) + SSH_KEY_BITS_RESERVED) {
			fatal("respond_to_rsa_challenge: server_key %d < host_key %d + "
			    "SSH_KEY_BITS_RESERVED %d",
			    BN_num_bits(server_key->rsa->n),
			    BN_num_bits(host_key->rsa->n),
			    SSH_KEY_BITS_RESERVED);
		}
		rsa_public_encrypt(key, key, host_key->rsa);
		rsa_public_encrypt(key, key, server_key->rsa);
	}

	/* Destroy the public keys since we no longer need them. */
	key_free(server_key);
	key_free(host_key);

	if (options.cipher == SSH_CIPHER_NOT_SET) {
		if (cipher_mask_ssh1(1) & supported_ciphers & (1 << ssh_cipher_default))
			options.cipher = ssh_cipher_default;
	} else if (options.cipher == SSH_CIPHER_ILLEGAL ||
	    !(cipher_mask_ssh1(1) & (1 << options.cipher))) {
		logit("No valid SSH1 cipher, using %.100s instead.",
		    cipher_name(ssh_cipher_default));
		options.cipher = ssh_cipher_default;
	}
	/* Check that the selected cipher is supported. */
	if (!(supported_ciphers & (1 << options.cipher)))
		fatal("Selected cipher type %.100s not supported by server.",
		    cipher_name(options.cipher));

	debug("Encryption type: %.100s", cipher_name(options.cipher));

	/* Send the encrypted session key to the server. */
	packet_start(SSH_CMSG_SESSION_KEY);
	packet_put_char(options.cipher);

	/* Send the cookie back to the server. */
	for (i = 0; i < 8; i++)
		packet_put_char(cookie[i]);

	/* Send and destroy the encrypted encryption key integer. */
	packet_put_bignum(key);
	BN_clear_free(key);

	/* Send protocol flags. */
	packet_put_int(client_flags);

	/* Send the packet now. */
	packet_send();
	packet_write_wait();

	debug("Sent encrypted session key.");

	/* Set the encryption key. */
	packet_set_encryption_key(session_key, SSH_SESSION_KEY_LENGTH, options.cipher);

	/* We will no longer need the session key here.  Destroy any extra copies. */
	memset(session_key, 0, sizeof(session_key));

	/*
	 * Expect a success message from the server.  Note that this message
	 * will be received in encrypted form.
	 */
	packet_read_expect(SSH_SMSG_SUCCESS);

	debug("Received encrypted confirmation.");
}

/*
 * Authenticate user
 */
void
ssh_userauth1(const char *local_user, const char *server_user, char *host,
    Sensitive *sensitive)
{
#ifdef GSSAPI
#ifdef GSI
  	const char *save_server_user = NULL;
#endif /* GSI */
#endif /* GSSAPI */

	int i, type;

	if (supported_authentications == 0)
		fatal("ssh_userauth1: server supports no auth methods");

#ifdef GSSAPI
#ifdef GSI
  /* if no user given, tack on the subject name after the server_user.
   * This will allow us to run gridmap early to get real user
   * This name will start with /C=
   */
  if ((supported_authentications & (1 << SSH_AUTH_GSSAPI)) &&
      options.gss_authentication) {
      char * retname;
      char * newname;


      save_server_user = server_user;

      retname = get_gsi_name();

      if (retname) {
        debug("passing gssapi name '%s'", retname);
        if (server_user) {
          newname = (char *) malloc(strlen(retname) + strlen(server_user) + 4);
          if (newname) {
            strcpy(newname, server_user);
            if(options.implicit) {
                strcat(newname,":i:");
	    } else {
                strcat(newname,":x:");
	    }
            strcat(newname, retname);
            server_user = newname;
            free(retname);
          }
        }
      }
      debug("server_user %s", server_user);
  }
#endif /* GSI */
#endif /* GSSAPI */

	/* Send the name of the user to log in as on the server. */
	packet_start(SSH_CMSG_USER);
	packet_put_cstring(server_user);
	packet_send();
	packet_write_wait();

#if defined(GSI)
  if(save_server_user)
    {
      server_user = save_server_user;
    }
#endif
	/*
	 * The server should respond with success if no authentication is
	 * needed (the user has no password).  Otherwise the server responds
	 * with failure.
	 */
	type = packet_read();

	/* check whether the connection was accepted without authentication. */
	if (type == SSH_SMSG_SUCCESS)
		goto success;
	if (type != SSH_SMSG_FAILURE)
		packet_disconnect("Protocol error: got %d in response to SSH_CMSG_USER", type);

#ifdef GSSAPI
  /* Try GSSAPI authentication */
  if ((supported_authentications & (1 << SSH_AUTH_GSSAPI)) &&
      options.gss_authentication)
    {
      char *canonhost;
      int gssapi_succeeded;
      debug("Trying GSSAPI authentication...");
      canonhost = xstrdup(get_canonical_hostname(1));
      resolve_localhost(&canonhost);
      gssapi_succeeded = try_gssapi_authentication(canonhost, &options);
      xfree(canonhost);
      canonhost=NULL;

      if (gssapi_succeeded) {
	  type = packet_read();
	  if (type == SSH_SMSG_SUCCESS)
	      goto success;
	  if (type != SSH_SMSG_FAILURE)
	      packet_disconnect("Protocol error: got %d in response to GSSAPI auth", type);
      }

      debug("GSSAPI authentication failed");
    }
#endif /* GSSAPI */
	
	/*
	 * Try .rhosts or /etc/hosts.equiv authentication with RSA host
	 * authentication.
	 */
	if ((supported_authentications & (1 << SSH_AUTH_RHOSTS_RSA)) &&
	    options.rhosts_rsa_authentication) {
		for (i = 0; i < sensitive->nkeys; i++) {
			if (sensitive->keys[i] != NULL &&
			    sensitive->keys[i]->type == KEY_RSA1 &&
			    try_rhosts_rsa_authentication(local_user,
			    sensitive->keys[i]))
				goto success;
		}
	}
	/* Try RSA authentication if the server supports it. */
	if ((supported_authentications & (1 << SSH_AUTH_RSA)) &&
	    options.rsa_authentication) {
		/*
		 * Try RSA authentication using the authentication agent. The
		 * agent is tried first because no passphrase is needed for
		 * it, whereas identity files may require passphrases.
		 */
		if (try_agent_authentication())
			goto success;

		/* Try RSA authentication for each identity. */
		for (i = 0; i < options.num_identity_files; i++)
			if (options.identity_keys[i] != NULL &&
			    options.identity_keys[i]->type == KEY_RSA1 &&
			    try_rsa_authentication(i))
				goto success;
	}
	/* Try challenge response authentication if the server supports it. */
	if ((supported_authentications & (1 << SSH_AUTH_TIS)) &&
	    options.challenge_response_authentication && !options.batch_mode) {
		if (try_challenge_response_authentication())
			goto success;
	}
	/* Try password authentication if the server supports it. */
	if ((supported_authentications & (1 << SSH_AUTH_PASSWORD)) &&
	    options.password_authentication && !options.batch_mode) {
		char prompt[80];

		snprintf(prompt, sizeof(prompt), "%.30s@%.128s's password: ",
		    server_user, host);
		if (try_password_authentication(prompt))
			goto success;
	}
	/* All authentication methods have failed.  Exit with an error message. */
	fatal("Permission denied.");
	/* NOTREACHED */

 success:
	return;	/* need statement after label */
}

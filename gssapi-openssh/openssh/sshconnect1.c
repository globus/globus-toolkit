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
RCSID("$OpenBSD: sshconnect1.c,v 1.51 2002/05/23 19:24:30 markus Exp $");

#include <openssl/bn.h>
#include <openssl/md5.h>

#ifdef KRB4
#include <krb.h>
#endif
#ifdef KRB5
#include <krb5.h>
#ifndef HEIMDAL
#define krb5_get_err_text(context,code) error_message(code)
#endif /* !HEIMDAL */
#endif
#ifdef AFS
#include <kafs.h>
#include "radix.h"
#endif

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
			log("Authentication agent failed to decrypt challenge.");
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
	if (public->flags && KEY_FLAG_EXT)
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

#ifdef KRB4
static int
try_krb4_authentication(void)
{
	KTEXT_ST auth;		/* Kerberos data */
	char *reply;
	char inst[INST_SZ];
	char *realm;
	CREDENTIALS cred;
	int r, type;
	socklen_t slen;
	Key_schedule schedule;
	u_long checksum, cksum;
	MSG_DAT msg_data;
	struct sockaddr_in local, foreign;
	struct stat st;

	/* Don't do anything if we don't have any tickets. */
	if (stat(tkt_string(), &st) < 0)
		return 0;

	strlcpy(inst, (char *)krb_get_phost(get_canonical_hostname(1)),
	    INST_SZ);

	realm = (char *)krb_realmofhost(get_canonical_hostname(1));
	if (!realm) {
		debug("Kerberos v4: no realm for %s", get_canonical_hostname(1));
		return 0;
	}
	/* This can really be anything. */
	checksum = (u_long)getpid();

	r = krb_mk_req(&auth, KRB4_SERVICE_NAME, inst, realm, checksum);
	if (r != KSUCCESS) {
		debug("Kerberos v4 krb_mk_req failed: %s", krb_err_txt[r]);
		return 0;
	}
	/* Get session key to decrypt the server's reply with. */
	r = krb_get_cred(KRB4_SERVICE_NAME, inst, realm, &cred);
	if (r != KSUCCESS) {
		debug("get_cred failed: %s", krb_err_txt[r]);
		return 0;
	}
	des_key_sched((des_cblock *) cred.session, schedule);

	/* Send authentication info to server. */
	packet_start(SSH_CMSG_AUTH_KERBEROS);
	packet_put_string((char *) auth.dat, auth.length);
	packet_send();
	packet_write_wait();

	/* Zero the buffer. */
	(void) memset(auth.dat, 0, MAX_KTXT_LEN);

	slen = sizeof(local);
	memset(&local, 0, sizeof(local));
	if (getsockname(packet_get_connection_in(),
	    (struct sockaddr *)&local, &slen) < 0)
		debug("getsockname failed: %s", strerror(errno));

	slen = sizeof(foreign);
	memset(&foreign, 0, sizeof(foreign));
	if (getpeername(packet_get_connection_in(),
	    (struct sockaddr *)&foreign, &slen) < 0) {
		debug("getpeername failed: %s", strerror(errno));
		fatal_cleanup();
	}
	/* Get server reply. */
	type = packet_read();
	switch (type) {
	case SSH_SMSG_FAILURE:
		/* Should really be SSH_SMSG_AUTH_KERBEROS_FAILURE */
		debug("Kerberos v4 authentication failed.");
		return 0;
		break;

	case SSH_SMSG_AUTH_KERBEROS_RESPONSE:
		/* SSH_SMSG_AUTH_KERBEROS_SUCCESS */
		debug("Kerberos v4 authentication accepted.");

		/* Get server's response. */
		reply = packet_get_string((u_int *) &auth.length);
		if (auth.length >= MAX_KTXT_LEN)
			fatal("Kerberos v4: Malformed response from server");
		memcpy(auth.dat, reply, auth.length);
		xfree(reply);

		packet_check_eom();

		/*
		 * If his response isn't properly encrypted with the session
		 * key, and the decrypted checksum fails to match, he's
		 * bogus. Bail out.
		 */
		r = krb_rd_priv(auth.dat, auth.length, schedule, &cred.session,
		    &foreign, &local, &msg_data);
		if (r != KSUCCESS) {
			debug("Kerberos v4 krb_rd_priv failed: %s",
			    krb_err_txt[r]);
			packet_disconnect("Kerberos v4 challenge failed!");
		}
		/* Fetch the (incremented) checksum that we supplied in the request. */
		memcpy((char *)&cksum, (char *)msg_data.app_data,
		    sizeof(cksum));
		cksum = ntohl(cksum);

		/* If it matches, we're golden. */
		if (cksum == checksum + 1) {
			debug("Kerberos v4 challenge successful.");
			return 1;
		} else
			packet_disconnect("Kerberos v4 challenge failed!");
		break;

	default:
		packet_disconnect("Protocol error on Kerberos v4 response: %d", type);
	}
	return 0;
}

#endif /* KRB4 */

#ifdef KRB5
static int
try_krb5_authentication(krb5_context *context, krb5_auth_context *auth_context)
{
	krb5_error_code problem;
	const char *tkfile;
	struct stat buf;
	krb5_ccache ccache = NULL;
	const char *remotehost;
	krb5_data ap;
	int type;
	krb5_ap_rep_enc_part *reply = NULL;
	int ret;

	memset(&ap, 0, sizeof(ap));

	problem = krb5_init_context(context);
	if (problem) {
		debug("Kerberos v5: krb5_init_context failed");
		ret = 0;
		goto out;
	}
	
	problem = krb5_auth_con_init(*context, auth_context);
	if (problem) {
		debug("Kerberos v5: krb5_auth_con_init failed");
		ret = 0;
		goto out;
	}

#ifndef HEIMDAL
	problem = krb5_auth_con_setflags(*context, *auth_context,
					 KRB5_AUTH_CONTEXT_RET_TIME);
	if (problem) {
		debug("Keberos v5: krb5_auth_con_setflags failed");
		ret = 0;
		goto out;
	}
#endif

	tkfile = krb5_cc_default_name(*context);
	if (strncmp(tkfile, "FILE:", 5) == 0)
		tkfile += 5;

	if (stat(tkfile, &buf) == 0 && getuid() != buf.st_uid) {
		debug("Kerberos v5: could not get default ccache (permission denied).");
		ret = 0;
		goto out;
	}

	problem = krb5_cc_default(*context, &ccache);
	if (problem) {
		debug("Kerberos v5: krb5_cc_default failed: %s",
		    krb5_get_err_text(*context, problem));
		ret = 0;
		goto out;
	}

	remotehost = get_canonical_hostname(1);

	problem = krb5_mk_req(*context, auth_context, AP_OPTS_MUTUAL_REQUIRED,
	    "host", remotehost, NULL, ccache, &ap);
	if (problem) {
		debug("Kerberos v5: krb5_mk_req failed: %s",
		    krb5_get_err_text(*context, problem));
		ret = 0;
		goto out;
	}

	packet_start(SSH_CMSG_AUTH_KERBEROS);
	packet_put_string((char *) ap.data, ap.length);
	packet_send();
	packet_write_wait();

	xfree(ap.data);
	ap.length = 0;

	type = packet_read();
	switch (type) {
	case SSH_SMSG_FAILURE:
		/* Should really be SSH_SMSG_AUTH_KERBEROS_FAILURE */
		debug("Kerberos v5 authentication failed.");
		ret = 0;
		break;

	case SSH_SMSG_AUTH_KERBEROS_RESPONSE:
		/* SSH_SMSG_AUTH_KERBEROS_SUCCESS */
		debug("Kerberos v5 authentication accepted.");

		/* Get server's response. */
		ap.data = packet_get_string((unsigned int *) &ap.length);
		packet_check_eom();
		/* XXX je to dobre? */

		problem = krb5_rd_rep(*context, *auth_context, &ap, &reply);
		if (problem) {
			ret = 0;
		}
		ret = 1;
		break;

	default:
		packet_disconnect("Protocol error on Kerberos v5 response: %d",
		    type);
		ret = 0;
		break;

	}

 out:
	if (ccache != NULL)
		krb5_cc_close(*context, ccache);
	if (reply != NULL)
		krb5_free_ap_rep_enc_part(*context, reply);
	if (ap.length > 0)
#ifdef HEIMDAL
		krb5_data_free(&ap);
#else
		krb5_free_data_contents(*context, &ap);
#endif

	return (ret);
}

static void
send_krb5_tgt(krb5_context context, krb5_auth_context auth_context)
{
	int fd, type;
	krb5_error_code problem;
	krb5_data outbuf;
	krb5_ccache ccache = NULL;
	krb5_creds creds;
#ifdef HEIMDAL
	krb5_kdc_flags flags;
#else
	int forwardable;
#endif
	const char *remotehost;

	memset(&creds, 0, sizeof(creds));
	memset(&outbuf, 0, sizeof(outbuf));

	fd = packet_get_connection_in();

#ifdef HEIMDAL
	problem = krb5_auth_con_setaddrs_from_fd(context, auth_context, &fd);
#else
	problem = krb5_auth_con_genaddrs(context, auth_context, fd,
			KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR |
			KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR);
#endif
	if (problem)
		goto out;

	problem = krb5_cc_default(context, &ccache);
	if (problem)
		goto out;

	problem = krb5_cc_get_principal(context, ccache, &creds.client);
	if (problem)
		goto out;

	remotehost = get_canonical_hostname(1);
	
#ifdef HEIMDAL
	problem = krb5_build_principal(context, &creds.server,
	    strlen(creds.client->realm), creds.client->realm,
	    "krbtgt", creds.client->realm, NULL);
#else
	problem = krb5_build_principal(context, &creds.server,
	    creds.client->realm.length, creds.client->realm.data,
	    "host", remotehost, NULL);
#endif
	if (problem)
		goto out;

	creds.times.endtime = 0;

#ifdef HEIMDAL
	flags.i = 0;
	flags.b.forwarded = 1;
	flags.b.forwardable = krb5_config_get_bool(context,  NULL,
	    "libdefaults", "forwardable", NULL);
	problem = krb5_get_forwarded_creds(context, auth_context,
	    ccache, flags.i, remotehost, &creds, &outbuf);
#else
	forwardable = 1;
	problem = krb5_fwd_tgt_creds(context, auth_context, remotehost,
	    creds.client, creds.server, ccache, forwardable, &outbuf);
#endif

	if (problem)
		goto out;

	packet_start(SSH_CMSG_HAVE_KERBEROS_TGT);
	packet_put_string((char *)outbuf.data, outbuf.length);
	packet_send();
	packet_write_wait();

	type = packet_read();

	if (type == SSH_SMSG_SUCCESS) {
		char *pname;

		krb5_unparse_name(context, creds.client, &pname);
		debug("Kerberos v5 TGT forwarded (%s).", pname);
		xfree(pname);
	} else
		debug("Kerberos v5 TGT forwarding failed.");

	return;

 out:
	if (problem)
		debug("Kerberos v5 TGT forwarding failed: %s",
		    krb5_get_err_text(context, problem));
	if (creds.client)
		krb5_free_principal(context, creds.client);
	if (creds.server)
		krb5_free_principal(context, creds.server);
	if (ccache)
		krb5_cc_close(context, ccache);
	if (outbuf.data)
		xfree(outbuf.data);
}
#endif /* KRB5 */

#ifdef AFS
static void
send_krb4_tgt(void)
{
	CREDENTIALS *creds;
	struct stat st;
	char buffer[4096], pname[ANAME_SZ], pinst[INST_SZ], prealm[REALM_SZ];
	int problem, type;

	/* Don't do anything if we don't have any tickets. */
	if (stat(tkt_string(), &st) < 0)
		return;

	creds = xmalloc(sizeof(*creds));

	problem = krb_get_tf_fullname(TKT_FILE, pname, pinst, prealm);
	if (problem)
		goto out;

	problem = krb_get_cred("krbtgt", prealm, prealm, creds);
	if (problem)
		goto out;

	if (time(0) > krb_life_to_time(creds->issue_date, creds->lifetime)) {
		problem = RD_AP_EXP;
		goto out;
	}
	creds_to_radix(creds, (u_char *)buffer, sizeof(buffer));

	packet_start(SSH_CMSG_HAVE_KERBEROS_TGT);
	packet_put_cstring(buffer);
	packet_send();
	packet_write_wait();

	type = packet_read();

	if (type == SSH_SMSG_SUCCESS)
		debug("Kerberos v4 TGT forwarded (%s%s%s@%s).",
		    creds->pname, creds->pinst[0] ? "." : "",
		    creds->pinst, creds->realm);
	else
		debug("Kerberos v4 TGT rejected.");

	xfree(creds);
	return;

 out:
	debug("Kerberos v4 TGT passing failed: %s", krb_err_txt[problem]);
	xfree(creds);
}

static void
send_afs_tokens(void)
{
	CREDENTIALS creds;
	struct ViceIoctl parms;
	struct ClearToken ct;
	int i, type, len;
	char buf[2048], *p, *server_cell;
	char buffer[8192];

	/* Move over ktc_GetToken, here's something leaner. */
	for (i = 0; i < 100; i++) {	/* just in case */
		parms.in = (char *) &i;
		parms.in_size = sizeof(i);
		parms.out = buf;
		parms.out_size = sizeof(buf);
		if (k_pioctl(0, VIOCGETTOK, &parms, 0) != 0)
			break;
		p = buf;

		/* Get secret token. */
		memcpy(&creds.ticket_st.length, p, sizeof(u_int));
		if (creds.ticket_st.length > MAX_KTXT_LEN)
			break;
		p += sizeof(u_int);
		memcpy(creds.ticket_st.dat, p, creds.ticket_st.length);
		p += creds.ticket_st.length;

		/* Get clear token. */
		memcpy(&len, p, sizeof(len));
		if (len != sizeof(struct ClearToken))
			break;
		p += sizeof(len);
		memcpy(&ct, p, len);
		p += len;
		p += sizeof(len);	/* primary flag */
		server_cell = p;

		/* Flesh out our credentials. */
		strlcpy(creds.service, "afs", sizeof(creds.service));
		creds.instance[0] = '\0';
		strlcpy(creds.realm, server_cell, REALM_SZ);
		memcpy(creds.session, ct.HandShakeKey, DES_KEY_SZ);
		creds.issue_date = ct.BeginTimestamp;
		creds.lifetime = krb_time_to_life(creds.issue_date,
		    ct.EndTimestamp);
		creds.kvno = ct.AuthHandle;
		snprintf(creds.pname, sizeof(creds.pname), "AFS ID %d", ct.ViceId);
		creds.pinst[0] = '\0';

		/* Encode token, ship it off. */
		if (creds_to_radix(&creds, (u_char *)buffer,
		    sizeof(buffer)) <= 0)
			break;
		packet_start(SSH_CMSG_HAVE_AFS_TOKEN);
		packet_put_cstring(buffer);
		packet_send();
		packet_write_wait();

		/* Roger, Roger. Clearance, Clarence. What's your vector,
		   Victor? */
		type = packet_read();

		if (type == SSH_SMSG_FAILURE)
			debug("AFS token for cell %s rejected.", server_cell);
		else if (type != SSH_SMSG_SUCCESS)
			packet_disconnect("Protocol error on AFS token response: %d", type);
	}
}

#endif /* AFS */

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
			log("WARNING: Encryption is disabled! "
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
		log("WARNING: Encryption is disabled! Password will be transmitted in clear text.");
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
/*
 * This code stolen from the gss-client.c sample program from MIT's
 * kerberos 5 distribution.
 */

gss_cred_id_t gss_cred = GSS_C_NO_CREDENTIAL;

static void display_status_1(m, code, type)
 char *m;
 OM_uint32 code;
 int type;
{
  OM_uint32 maj_stat, min_stat;
  gss_buffer_desc msg;
  OM_uint32 msg_ctx;

  msg_ctx = 0;
  while (1) {
    maj_stat = gss_display_status(&min_stat, code,
                                  type, GSS_C_NULL_OID,
                                  &msg_ctx, &msg);
    debug("GSS-API error %s: %s", m, (char *)msg.value);
    (void) gss_release_buffer(&min_stat, &msg);

    if (!msg_ctx)
      break;
  }
}

static void display_gssapi_status(msg, maj_stat, min_stat)
  char *msg;
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
{
  display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
  display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

#ifdef GSI
int get_gssapi_cred()
{
  OM_uint32 maj_stat;
  OM_uint32 min_stat;


  debug("calling gss_acquire_cred");
  maj_stat = gss_acquire_cred(&min_stat,
                              GSS_C_NO_NAME,
                              GSS_C_INDEFINITE,
                              GSS_C_NO_OID_SET,
                              GSS_C_INITIATE,
                              &gss_cred,
                              NULL,
                              NULL);

  if (maj_stat != GSS_S_COMPLETE) {
    display_gssapi_status("Failuring acquiring GSSAPI credentials",
                          maj_stat, min_stat);
    gss_cred = GSS_C_NO_CREDENTIAL; /* should not be needed */
    return 0;
  }

  return 1;     /* Success */
}

char * get_gss_our_name()
{
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  gss_name_t pname = GSS_C_NO_NAME;
  gss_buffer_desc tmpname;
  gss_buffer_t tmpnamed = &tmpname;
  char *retname;

  debug("calling gss_inquire_cred");
  maj_stat = gss_inquire_cred(&min_stat,
                              gss_cred,
                              &pname,
                              NULL,
                              NULL,
                              NULL);
  if (maj_stat != GSS_S_COMPLETE) {
    return NULL;
  }

  maj_stat = gss_export_name(&min_stat,
                             pname,
                             tmpnamed);
  if (maj_stat != GSS_S_COMPLETE) {
    return NULL;
  }
  debug("gss_export_name finsished");
  retname = (char *)malloc(tmpname.length + 1);
  if (!retname) {
    return NULL;
  }
  memcpy(retname, tmpname.value, tmpname.length);
  retname[tmpname.length] = '\0';

  gss_release_name(&min_stat, &pname);
  gss_release_buffer(&min_stat, tmpnamed);

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
  gss_OID_set my_mechs;
  int my_mech_num;
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  int ret_stat = 0;                             /* 1 == success */
  OM_uint32 req_flags = 0;
  OM_uint32 ret_flags;
  int type;
  char *gssapi_auth_type = NULL;
  struct hostent *hostinfo;
  char *addr;
  unsigned int slen;

  /*
   * host is not guarenteed to be a FQDN, so we need to make sure it is.
   */
  hostinfo = gethostbyname(host);

  /* Use local hostname when coming in on loopback interface because
     we won't have 'localhost' credentials. */
  if (hostinfo && hostinfo->h_addrtype == AF_INET) {
      struct in_addr addr;
      addr = *(struct in_addr *)(hostinfo->h_addr);
      if (ntohl(addr.s_addr) == INADDR_LOOPBACK) {
	  char buf[4096];
	  if (gethostname(buf, 4096) == 0) {
	      hostinfo = gethostbyname(buf);
	  }
      }
  }

  if ((hostinfo == NULL) || (hostinfo->h_addr == NULL)) {
      debug("GSSAPI authentication: Unable to get FQDN for \"%s\"", host);
      goto cleanup;
  }

  addr = xmalloc(hostinfo->h_length);
  memcpy(addr, hostinfo->h_addr, hostinfo->h_length);
  hostinfo = gethostbyaddr(addr, hostinfo->h_length, AF_INET);
  xfree(addr);

  /* Go to the resolver to get the official hostname for our target.
     WARNING: This makes us vulnerable to DNS spoofing. */
  if ((hostinfo == NULL) || (hostinfo->h_name == NULL)) {
      debug("GSSAPI authentication: Unable to get FQDN for \"%s\"", host);
      goto cleanup;
  }

  /*
   * Default flags
   */
  req_flags |= GSS_C_REPLAY_FLAG;

  /* Do mutual authentication */
  req_flags |= GSS_C_MUTUAL_FLAG;

#ifdef KRB5

  gssapi_auth_type = "GSSAPI/Kerberos 5";

#endif

#ifdef GSI

  gssapi_auth_type = "GSSAPI/GLOBUS";

#endif /* GSI */

  if (gssapi_auth_type == NULL) {
      debug("No GSSAPI type defined during compile");
      goto cleanup;
  }

  debug("Attempting %s authentication", gssapi_auth_type);

  service_name = (char *) malloc(strlen("host") +
                                 strlen(hostinfo->h_name) +
                                 2 /* 1 for '@', 1 for NUL */);

  if (service_name == NULL) {
    debug("malloc() failed");
    goto cleanup;
  }


  sprintf(service_name, "host@%s", hostinfo->h_name);

  name_type = GSS_C_NT_HOSTBASED_SERVICE;

  debug("Service name is %s", service_name);

  /* Forward credentials? */

#ifdef KRB5
  if (options->kerberos_tgt_passing) {
      debug("Forwarding Kerberos credentials");
      req_flags |= GSS_C_DELEG_FLAG;
  }
#endif /* KRB5 */

#ifdef GSSAPI
  if(options->gss_deleg_creds) {
    debug("Forwarding X509 proxy certificate");
    req_flags |= GSS_C_DELEG_FLAG;
  }
#ifdef GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG
  /* Forward limited credentials, overrides gss_deleg_creds */
  if(options->gss_globus_deleg_limited_proxy) {
    debug("Forwarding limited X509 proxy certificate");
    req_flags |= (GSS_C_DELEG_FLAG | GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG);
  }
#endif /* GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG */

#endif /* GSSAPI */

  debug("req_flags = %u", req_flags);

  name_tok.value = service_name;
  name_tok.length = strlen(service_name) + 1;
  maj_stat = gss_import_name(&min_stat, &name_tok,
                             name_type, &target_name);

  free(service_name);
  service_name = NULL;

  if (maj_stat != GSS_S_COMPLETE) {
    display_gssapi_status("importing service name", maj_stat, min_stat);
    goto cleanup;
  }

  maj_stat = gss_indicate_mechs(&min_stat, &my_mechs);

  if (maj_stat != GSS_S_COMPLETE) {
    display_gssapi_status("indicating mechs", maj_stat, min_stat);
    goto cleanup;
  }

  /*
   * Send over a packet to the daemon, letting it know we're doing
   * GSSAPI and our mech_oid(s).
   */
  debug("Sending mech oid to server");
  packet_start(SSH_CMSG_AUTH_GSSAPI);
  packet_put_int(my_mechs->count); /* Number of mechs we're sending */
  for (my_mech_num = 0; my_mech_num < my_mechs->count; my_mech_num++)
      packet_put_string(my_mechs->elements[my_mech_num].elements,
                        my_mechs->elements[my_mech_num].length);
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
    maj_stat =
      gss_init_sec_context(&min_stat,
                           gss_cred,
                           &gss_context,
                           target_name,
                           &mech_oid,
                           req_flags,
                           0,
                           NULL,        /* no channel bindings */
                           token_ptr,
                           NULL,        /* ignore mech type */
                           &send_tok,
                           &ret_flags,
                           NULL);       /* ignore time_rec */

    if (token_ptr != GSS_C_NO_BUFFER)
      (void) gss_release_buffer(&min_stat, &recv_tok);

    if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
      display_gssapi_status("initializing context", maj_stat, min_stat);

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

      (void) gss_release_buffer(&min_stat, &send_tok);
    }

    if (maj_stat == GSS_S_CONTINUE_NEEDED) {

      debug("Continue needed. Reading response...");

      type = packet_read();

      switch(type) {

      case SSH_MSG_AUTH_GSSAPI_TOKEN:
        /* This is what we expected */
        break;

      case SSH_MSG_AUTH_GSSAPI_ABORT:
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
  } while (maj_stat == GSS_S_CONTINUE_NEEDED);

  /* Success */
  ret_stat = 1;

  debug("%s authentication successful", gssapi_auth_type);

  /*
   * Read hash of host and server keys and make sure it
   * matches what we got earlier.
   */
  debug("Reading hash of server and host keys...");
  type = packet_read();

  if (type == SSH_MSG_AUTH_GSSAPI_ABORT) {
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

    maj_stat = gss_unwrap(&min_stat,
                          gss_context,
                          &wrapped_buf,
                          &unwrapped_buf,
                          &conf_state,
                          &qop_state);

    if (maj_stat != GSS_S_COMPLETE) {
      display_gssapi_status("unwraping SSHD key hash",
                            maj_stat, min_stat);
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

    gss_release_buffer(&min_stat, &unwrapped_buf);

  } else {
      packet_disconnect("Protocol error during GSSAPI authentication:"
                        "packet type %d received", type);
      /* Does not return */
  }


 cleanup:
  if (target_name != NULL)
      (void) gss_release_name(&min_stat, &target_name);

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
		log("Warning: Server lies about size of server public key: "
		    "actual size is %d bits vs. announced %d.", rbits, bits);
		log("Warning: This may be due to an old implementation of ssh.");
	}
	/* Get the host key. */
	host_key = key_new(KEY_RSA1);
	bits = packet_get_int();
	packet_get_bignum(host_key->rsa->e);
	packet_get_bignum(host_key->rsa->n);

	rbits = BN_num_bits(host_key->rsa->n);
	if (bits != rbits) {
		log("Warning: Server lies about size of server host key: "
		    "actual size is %d bits vs. announced %d.", rbits, bits);
		log("Warning: This may be due to an old implementation of ssh.");
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
		log("No valid SSH1 cipher, using %.100s instead.",
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

#ifdef KRB5
	krb5_context context = NULL;
	krb5_auth_context auth_context = NULL;
#endif
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
    if (get_gssapi_cred()) {
      char * retname;
      char * newname;


      save_server_user = server_user;

      retname = get_gss_our_name();

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
    } else {
      /*
       * If we couldn't successfully get our GSSAPI credentials then
       * turn off gssapi authentication
       */
      options.gss_authentication = 0;
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
      debug("Trying GSSAPI authentication...");
      try_gssapi_authentication(host, &options);

      /*
       * XXX Hmmm. Kerberos authentication only reads a packet if it thinks
       * the authentication went OK, but the server seems to always send
       * a packet back. So I'm not sure if I'm missing something or
       * the Kerberos code is broken. - vwelch 1/27/99
       */

      type = packet_read();
      if (type == SSH_SMSG_SUCCESS)
        return; /* Successful connection. */
      if (type != SSH_SMSG_FAILURE)
        packet_disconnect("Protocol error: got %d in response to Kerberos auth", type);

      debug("GSSAPI authentication failed");
    }
#endif /* GSSAPI */
	
#ifdef KRB5
	if ((supported_authentications & (1 << SSH_AUTH_KERBEROS)) &&
	    options.kerberos_authentication) {
		debug("Trying Kerberos v5 authentication.");

		if (try_krb5_authentication(&context, &auth_context)) {
			type = packet_read();
			if (type == SSH_SMSG_SUCCESS)
				goto success;
			if (type != SSH_SMSG_FAILURE)
				packet_disconnect("Protocol error: got %d in response to Kerberos v5 auth", type);
		}
	}
#endif /* KRB5 */

#ifdef KRB4
	if ((supported_authentications & (1 << SSH_AUTH_KERBEROS)) &&
	    options.kerberos_authentication) {
		debug("Trying Kerberos v4 authentication.");

		if (try_krb4_authentication()) {
			type = packet_read();
			if (type == SSH_SMSG_SUCCESS)
				goto success;
			if (type != SSH_SMSG_FAILURE)
				packet_disconnect("Protocol error: got %d in response to Kerberos v4 auth", type);
		}
	}
#endif /* KRB4 */

	/*
	 * Use rhosts authentication if running in privileged socket and we
	 * do not wish to remain anonymous.
	 */
	if ((supported_authentications & (1 << SSH_AUTH_RHOSTS)) &&
	    options.rhosts_authentication) {
		debug("Trying rhosts authentication.");
		packet_start(SSH_CMSG_AUTH_RHOSTS);
		packet_put_cstring(local_user);
		packet_send();
		packet_write_wait();

		/* The server should respond with success or failure. */
		type = packet_read();
		if (type == SSH_SMSG_SUCCESS)
			goto success;
		if (type != SSH_SMSG_FAILURE)
			packet_disconnect("Protocol error: got %d in response to rhosts auth",
					  type);
	}
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
#ifdef KRB5
	/* Try Kerberos v5 TGT passing. */
	if ((supported_authentications & (1 << SSH_PASS_KERBEROS_TGT)) &&
	    options.kerberos_tgt_passing && context && auth_context) {
		if (options.cipher == SSH_CIPHER_NONE)
			log("WARNING: Encryption is disabled! Ticket will be transmitted in the clear!");
		send_krb5_tgt(context, auth_context);
	}
	if (auth_context)
		krb5_auth_con_free(context, auth_context);
	if (context)
		krb5_free_context(context);
#endif

#ifdef AFS
	/* Try Kerberos v4 TGT passing if the server supports it. */
	if ((supported_authentications & (1 << SSH_PASS_KERBEROS_TGT)) &&
	    options.kerberos_tgt_passing) {
		if (options.cipher == SSH_CIPHER_NONE)
			log("WARNING: Encryption is disabled! Ticket will be transmitted in the clear!");
		send_krb4_tgt();
	}
	/* Try AFS token passing if the server supports it. */
	if ((supported_authentications & (1 << SSH_PASS_AFS_TOKEN)) &&
	    options.afs_token_passing && k_hasafs()) {
		if (options.cipher == SSH_CIPHER_NONE)
			log("WARNING: Encryption is disabled! Token will be transmitted in the clear!");
		send_afs_tokens();
	}
#endif /* AFS */

	return;	/* need statement after label */
}

/*
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include "includes.h"
RCSID("$OpenBSD: auth1.c,v 1.44 2002/09/26 11:38:43 markus Exp $");

#include "xmalloc.h"
#include "rsa.h"
#include "ssh1.h"
#include "dispatch.h"
#include "packet.h"
#include "buffer.h"
#include "mpaux.h"
#include "log.h"
#include "servconf.h"
#include "compat.h"
#include "auth.h"
#include "channels.h"
#include "session.h"
#include "uidswap.h"
#include "monitor_wrap.h"

/* import */
extern ServerOptions options;
extern Authmethod method_gssapi;



#ifdef GSSAPI
#ifdef GSI
#include "globus_gss_assist.h"
#endif

int     userauth_gssapi(Authctxt *authctxt);

void
auth1_gss_protocol_error(int type, u_int32_t plen, void *ctxt)
{
  Authctxt *authctxt = ctxt;
  /* Other side told us to abort, dont need to tell him */ 
  /* maybe we can us some other method. */
  if (type == SSH_MSG_AUTH_GSSAPI_ABORT) {
      log("auth1: GSSAPI aborting");
      dispatch_set(SSH_MSG_AUTH_GSSAPI_TOKEN, NULL);
      authctxt->success = 1; /* get out of loop*/
      return;
  }

  log("auth1: protocol error: type %d plen %d", type, plen);
  packet_disconnect("Protocol error during GSSAPI authentication: "
          "Unknown packet type %d", type);
}

#ifdef GSI
int
gsi_gridmap(char *subject_name, char **mapped_name)
{
    return(globus_gss_assist_gridmap(subject_name, mapped_name) == 0);
}
#endif

/*
 * SSH1 GSSAPI clients may send us a user name of the form:
 *
 *   (1) username:x:SSL Subject Name
 *     or
 *   (2) username:i:SSL Subject Name
 *     or
 *   (3) username
 *
 *  if case 1, then uname is an explicit name (ssh -l uname). Keep this
 *  name always, rewrite the user parameter to be just uname. We'll pull
 *  the GSSAPI idenity out and deal with (or skip it) later.
 *  
 *  if case 2, then uname is implicit (user didn't use the -l option), so
 *  use the default gridmap mapping and replace uname with whatever
 *  the gridmap maps to. If the gridmap mapping fails, drop down
 *  to just uname
 *  
 *  if case 3, then leave it be.
 *
 *  This function may return the original pointer to the orginal string,
 *  the original pointer to a modified string, or a completely new pointer.
 */
static char *
ssh1_gssapi_parse_userstring(char *userstring)
{
  char name_type = '\0';	/* explicit 'x' or implicit 'i' */
  char *ssl_subject_name = NULL;
  char *delim = NULL;

  debug("Looking at username '%s' for gssapi-ssleay type name", userstring);
  if((delim = strchr(userstring, ':')) != NULL) {
      /* Parse and split into components */
      ssl_subject_name = strchr(delim + 1, ':');

      if (ssl_subject_name) {
	/* Successful parse, split into components */
	*delim = '\0';
	name_type = *(delim + 1);
	*ssl_subject_name = '\0';
	ssl_subject_name++;

	debug("Name parsed. type = '%c'. ssl subject name is \"%s\"",
	      name_type, ssl_subject_name);

      } else {

	debug("Don't understand name format. Letting it pass.");
      }	
  }	

#ifdef GSI
  if(ssl_subject_name) {
    char *gridmapped_name = NULL;
    switch (name_type) {
    case 'x':
      debug("explicit name given, using %s as username", userstring);
      break;

    case 'i':
      /* gridmap check */
      debug("implicit name given. gridmapping '%s'", ssl_subject_name);

      PRIVSEP(gsi_gridmap(ssl_subject_name, &gridmapped_name));
      if (gridmapped_name && gridmapped_name[0] != '\0') {
	userstring = gridmapped_name;
	debug("I gridmapped and got %s", userstring);

      } else {
	debug("I gridmapped and got null, reverting to %s", userstring);
      }
      break;

    default:
      debug("Unknown name type '%c'. Ignoring.", name_type);
      break;
    }
  } else {
    debug("didn't find any :'s so I assume it's just a user name");
  }
#endif /* GSI */

  return userstring;
}
#endif

/*
 * convert ssh auth msg type into description
 */
static char *
get_authname(int type)
{
	static char buf[1024];
	switch (type) {
	case SSH_CMSG_AUTH_PASSWORD:
		return "password";
	case SSH_CMSG_AUTH_RSA:
		return "rsa";
	case SSH_CMSG_AUTH_RHOSTS_RSA:
		return "rhosts-rsa";
	case SSH_CMSG_AUTH_RHOSTS:
		return "rhosts";
	case SSH_CMSG_AUTH_TIS:
	case SSH_CMSG_AUTH_TIS_RESPONSE:
		return "challenge-response";
#if defined(KRB4) || defined(KRB5)
	case SSH_CMSG_AUTH_KERBEROS:
		return "kerberos";
#endif
#if defined(GSSAPI)
	case SSH_CMSG_AUTH_GSSAPI:
	    	return "gssapi";
#endif
	}
	snprintf(buf, sizeof buf, "bad-auth-msg-%d", type);
	return buf;
}

/*
 * read packets, try to authenticate the user and
 * return only if authentication is successful
 */
static void
do_authloop(Authctxt *authctxt)
{
	int authenticated = 0;
	u_int bits;
	Key *client_host_key;
	BIGNUM *n;
	char *client_user, *password;
	char info[1024];
	u_int dlen;
	u_int ulen;
	int type = 0;
	struct passwd *pw = authctxt->pw;

	debug("Attempting authentication for %s%.100s.",
	    authctxt->valid ? "" : "illegal user ", authctxt->user);

	/* If the user has no password, accept authentication immediately. */
	if (options.password_authentication &&
#if defined(KRB4) || defined(KRB5)
	    (!options.kerberos_authentication || options.kerberos_or_local_passwd) &&
#endif
	    PRIVSEP(auth_password(authctxt, ""))) {
		auth_log(authctxt, 1, "without authentication", "");
		return;
	}

	/* Indicate that authentication is needed. */
	packet_start(SSH_SMSG_FAILURE);
	packet_send();
	packet_write_wait();

	client_user = NULL;

	for (;;) {
		/* default to fail */
		authenticated = 0;

		info[0] = '\0';

		/* Get a packet from the client. */
		type = packet_read();

		/* Process the packet. */
		switch (type) {

#if defined(KRB4) || defined(KRB5)
		case SSH_CMSG_AUTH_KERBEROS:
			if (!options.kerberos_authentication) {
				verbose("Kerberos authentication disabled.");
			} else {
				char *kdata = packet_get_string(&dlen);
				packet_check_eom();

				if (kdata[0] == 4) { /* KRB_PROT_VERSION */
#ifdef KRB4
					KTEXT_ST tkt, reply;
					tkt.length = dlen;
					if (tkt.length < MAX_KTXT_LEN)
						memcpy(tkt.dat, kdata, tkt.length);

					if (PRIVSEP(auth_krb4(authctxt, &tkt,
					    &client_user, &reply))) {
						authenticated = 1;
						snprintf(info, sizeof(info),
						    " tktuser %.100s",
						    client_user);

						packet_start(
						    SSH_SMSG_AUTH_KERBEROS_RESPONSE);
						packet_put_string((char *)
						    reply.dat, reply.length);
						packet_send();
						packet_write_wait();
					}
#endif /* KRB4 */
				} else {
#ifdef KRB5
					krb5_data tkt, reply;
					tkt.length = dlen;
					tkt.data = kdata;

					if (PRIVSEP(auth_krb5(authctxt, &tkt,
					    &client_user, &reply))) {
						authenticated = 1;
						snprintf(info, sizeof(info),
						    " tktuser %.100s",
						    client_user);
 
 						/* Send response to client */
 						packet_start(
						    SSH_SMSG_AUTH_KERBEROS_RESPONSE);
 						packet_put_string((char *)
						    reply.data, reply.length);
 						packet_send();
 						packet_write_wait();

 						if (reply.length)
 							xfree(reply.data);
					}
#endif /* KRB5 */
				}
				xfree(kdata);
			}
			break;
#endif /* KRB4 || KRB5 */

#ifdef GSSAPI
		case SSH_CMSG_AUTH_GSSAPI:
			if (!options.gss_authentication) {
				verbose("GSSAPI authentication disabled.");
				break;
			}
			/*
			* GSSAPI was first added to ssh1 in ssh-1.2.27, and
			* was added to the SecurtCRT product. In order
			* to continue operating with these, we will add
			* the equivelent GSSAPI support to SSH1. 
			* Will use the gssapi routines from the ssh2 as
			* they are almost identical. But they use dispatch
			* so we need to setup the dispatch tables here 
			* auth1.c for use only by the gssapi code. 
			* Since we already have the packet, we will call
			* userauth_gssapi then start the dispatch loop.
			*/
			if (!authctxt->valid) {
			packet_disconnect("Authentication rejected for invalid user");
			}
			dispatch_init(&auth1_gss_protocol_error);
			method_gssapi.userauth(authctxt);
			dispatch_run(DISPATCH_BLOCK, &authctxt->success, authctxt);
			if (authctxt->postponed) { /* failed, try other methods */
				authctxt->success = 0;
				authctxt->postponed = 0;
				break;
			}
			authenticated = 1;
			break;
#endif /* GSSAPI */
			
#if defined(AFS) || defined(KRB5)
			/* XXX - punt on backward compatibility here. */
		case SSH_CMSG_HAVE_KERBEROS_TGT:
			packet_send_debug("Kerberos TGT passing disabled before authentication.");
			break;
#ifdef AFS
		case SSH_CMSG_HAVE_AFS_TOKEN:
			packet_send_debug("AFS token passing disabled before authentication.");
			break;
#endif /* AFS */
#endif /* AFS || KRB5 */

		case SSH_CMSG_AUTH_RHOSTS:
			if (!options.rhosts_authentication) {
				verbose("Rhosts authentication disabled.");
				break;
			}
			/*
			 * Get client user name.  Note that we just have to
			 * trust the client; this is one reason why rhosts
			 * authentication is insecure. (Another is
			 * IP-spoofing on a local network.)
			 */
			client_user = packet_get_string(&ulen);
			packet_check_eom();

			/* Try to authenticate using /etc/hosts.equiv and .rhosts. */
			authenticated = auth_rhosts(pw, client_user);

			snprintf(info, sizeof info, " ruser %.100s", client_user);
			break;

		case SSH_CMSG_AUTH_RHOSTS_RSA:
			if (!options.rhosts_rsa_authentication) {
				verbose("Rhosts with RSA authentication disabled.");
				break;
			}
			/*
			 * Get client user name.  Note that we just have to
			 * trust the client; root on the client machine can
			 * claim to be any user.
			 */
			client_user = packet_get_string(&ulen);

			/* Get the client host key. */
			client_host_key = key_new(KEY_RSA1);
			bits = packet_get_int();
			packet_get_bignum(client_host_key->rsa->e);
			packet_get_bignum(client_host_key->rsa->n);

			if (bits != BN_num_bits(client_host_key->rsa->n))
				verbose("Warning: keysize mismatch for client_host_key: "
				    "actual %d, announced %d",
				    BN_num_bits(client_host_key->rsa->n), bits);
			packet_check_eom();

			authenticated = auth_rhosts_rsa(pw, client_user,
			    client_host_key);
			key_free(client_host_key);

			snprintf(info, sizeof info, " ruser %.100s", client_user);
			break;

		case SSH_CMSG_AUTH_RSA:
			if (!options.rsa_authentication) {
				verbose("RSA authentication disabled.");
				break;
			}
			/* RSA authentication requested. */
			if ((n = BN_new()) == NULL)
				fatal("do_authloop: BN_new failed");
			packet_get_bignum(n);
			packet_check_eom();
			authenticated = auth_rsa(pw, n);
			BN_clear_free(n);
			break;

		case SSH_CMSG_AUTH_PASSWORD:
			if (!options.password_authentication) {
				verbose("Password authentication disabled.");
				break;
			}
			/*
			 * Read user password.  It is in plain text, but was
			 * transmitted over the encrypted channel so it is
			 * not visible to an outside observer.
			 */
			password = packet_get_string(&dlen);
			packet_check_eom();

			/* Try authentication with the password. */
			authenticated = PRIVSEP(auth_password(authctxt, password));

			memset(password, 0, strlen(password));
			xfree(password);
			break;

		case SSH_CMSG_AUTH_TIS:
			debug("rcvd SSH_CMSG_AUTH_TIS");
			if (options.challenge_response_authentication == 1) {
				char *challenge = get_challenge(authctxt);
				if (challenge != NULL) {
					debug("sending challenge '%s'", challenge);
					packet_start(SSH_SMSG_AUTH_TIS_CHALLENGE);
					packet_put_cstring(challenge);
					xfree(challenge);
					packet_send();
					packet_write_wait();
					continue;
				}
			}
			break;
		case SSH_CMSG_AUTH_TIS_RESPONSE:
			debug("rcvd SSH_CMSG_AUTH_TIS_RESPONSE");
			if (options.challenge_response_authentication == 1) {
				char *response = packet_get_string(&dlen);
				debug("got response '%s'", response);
				packet_check_eom();
				authenticated = verify_response(authctxt, response);
				memset(response, 'r', dlen);
				xfree(response);
			}
			break;

		default:
			/*
			 * Any unknown messages will be ignored (and failure
			 * returned) during authentication.
			 */
			log("Unknown message during authentication: type %d", type);
			break;
		}
#ifdef BSD_AUTH
		if (authctxt->as) {
			auth_close(authctxt->as);
			authctxt->as = NULL;
		}
#endif
		if (!authctxt->valid && authenticated)
			fatal("INTERNAL ERROR: authenticated invalid user %s",
			    authctxt->user);

#ifdef _UNICOS
		if (type == SSH_CMSG_AUTH_PASSWORD && !authenticated)
			cray_login_failure(authctxt->user, IA_UDBERR);
		if (authenticated && cray_access_denied(authctxt->user)) {
			authenticated = 0;
			fatal("Access denied for user %s.",authctxt->user);
		}
#endif /* _UNICOS */

#ifdef HAVE_CYGWIN
		if (authenticated &&
		    !check_nt_auth(type == SSH_CMSG_AUTH_PASSWORD, pw)) {
			packet_disconnect("Authentication rejected for uid %d.",
			pw == NULL ? -1 : pw->pw_uid);
			authenticated = 0;
		}
#else
		/* Special handling for root */
		if (!use_privsep &&
		    authenticated && authctxt->pw->pw_uid == 0 &&
		    !auth_root_allowed(get_authname(type)))
			authenticated = 0;
#endif
#ifdef USE_PAM
		if (!use_privsep && authenticated && 
		    !do_pam_account(pw->pw_name, client_user))
			authenticated = 0;
#endif

		/* Log before sending the reply */
		auth_log(authctxt, authenticated, get_authname(type), info);

		if (client_user != NULL) {
			xfree(client_user);
			client_user = NULL;
		}

		if (authenticated)
			return;

		if (authctxt->failures++ > AUTH_FAIL_MAX) {
			packet_disconnect(AUTH_FAIL_MSG, authctxt->user);
		}

		packet_start(SSH_SMSG_FAILURE);
		packet_send();
		packet_write_wait();
	}
}

/*
 * Performs authentication of an incoming connection.  Session key has already
 * been exchanged and encryption is enabled.
 */
Authctxt *
do_authentication(void)
{
	Authctxt *authctxt;
	u_int ulen;
	char *user, *style = NULL;

	/* Get the name of the user that we wish to log in as. */
	packet_read_expect(SSH_CMSG_USER);

	/* Get the user name. */
	user = packet_get_string(&ulen);
	packet_check_eom();

#ifdef GSSAPI
	/* Parse GSSAPI identity from userstring */
	user = ssh1_gssapi_parse_userstring(user);
#endif /* GSSAPI */

	if ((style = strchr(user, ':')) != NULL)
		*style++ = '\0';

#ifdef KRB5
	/* XXX - SSH.com Kerberos v5 braindeath. */
	if ((datafellows & SSH_BUG_K5USER) &&
	    options.kerberos_authentication) {
		char *p;
		if ((p = strchr(user, '@')) != NULL)
			*p = '\0';
	}
#endif

	authctxt = authctxt_new();
	authctxt->user = user;
	authctxt->style = style;

	/* Verify that the user is a valid user. */
	if ((authctxt->pw = PRIVSEP(getpwnamallow(user))) != NULL)
		authctxt->valid = 1;
	else
		debug("do_authentication: illegal user %s", user);

	setproctitle("%s%s", authctxt->pw ? user : "unknown",
	    use_privsep ? " [net]" : "");

#ifdef USE_PAM
	PRIVSEP(start_pam(authctxt->pw == NULL ? "NOUSER" : user));
#endif

	/*
	 * If we are not running as root, the user must have the same uid as
	 * the server. (Unless you are running Windows)
	 */
#ifndef HAVE_CYGWIN
	if (!use_privsep && getuid() != 0 && authctxt->pw &&
	    authctxt->pw->pw_uid != getuid())
		packet_disconnect("Cannot change user when server not running as root.");
#endif

	/*
	 * Loop until the user has been authenticated or the connection is
	 * closed, do_authloop() returns only if authentication is successful
	 */
	do_authloop(authctxt);

	/* The user has been authenticated and accepted. */
	packet_start(SSH_SMSG_SUCCESS);
	packet_send();
	packet_write_wait();

	return (authctxt);
}

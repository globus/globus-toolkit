/*	$OpenBSD: ssh.h,v 1.64 2002/03/04 17:27:39 stevesk Exp $	*/

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef SSH_H
#define SSH_H

#include <netinet/in.h> /* For struct sockaddr_in */
#include <pwd.h> /* For struct pw */
#include <stdarg.h> /* For va_list */
#include <syslog.h> /* For LOG_AUTH and friends */
#include <sys/socket.h> /* For struct sockaddr_storage */
#include "openbsd-compat/fake-socket.h" /* For struct sockaddr_storage */
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

/* Cipher used for encrypting authentication files. */
#define SSH_AUTHFILE_CIPHER	SSH_CIPHER_3DES

/* Default port number. */
#define SSH_DEFAULT_PORT	22

/* Maximum number of TCP/IP ports forwarded per direction. */
#define SSH_MAX_FORWARDS_PER_DIRECTION	100

/*
 * Maximum number of RSA authentication identity files that can be specified
 * in configuration files or on the command line.
 */
#define SSH_MAX_IDENTITY_FILES		100

/*
 * Major protocol version.  Different version indicates major incompatiblity
 * that prevents communication.
 *
 * Minor protocol version.  Different version indicates minor incompatibility
 * that does not prevent interoperation.
 */
#define PROTOCOL_MAJOR_1	1
#define PROTOCOL_MINOR_1	5

/* We support both SSH1 and SSH2 */
#define PROTOCOL_MAJOR_2	2
#define PROTOCOL_MINOR_2	0

/*
 * Name for the service.  The port named by this service overrides the
 * default port if present.
 */
#define SSH_SERVICE_NAME	"ssh"

#if defined(USE_PAM) && !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE       __progname
#endif

/*modified by binhe*/
#ifdef GSSAPI
/*------------ GSSAPI-related functions -----------------------*/

#include <gssapi.h>
/*
 * Given a target account, and source host, perform GSSAPI authentication
 * and authorization. Returns 1 on success, 0 on failure. On success fills
 * in client_name with the GSSAPI identity of the user.
 */
int auth_gssapi(const char *target_account,
                const char *source_host,
                gss_buffer_desc *client_name);

/*
 * The userstring sent by the client may contain a GSSAPI identity which
 * the server can use to determine the target account. This function
 * parses the userstring and does the local account determination,
 * if needed.
 */
char *
gssapi_parse_userstring(char *username);

/*
 * Change the ownership of all delegated credentials to the user.
 * Returns 0 on success, non-zero on error.
 */
int
gssapi_chown_delegation(uid_t uid, gid_t gid);

/*
 * Remove the forwarded proxy credentials
 */
void
gssapi_remove_delegation(void);

/*
 * Clean our environment on startup. This means removing any environment
 * strings that might inadvertantly been in root's environment and
 * could cause serious security problems if we think we set them.
 */
void
gssapi_clean_env(void);

/*
 * Set up our environment for GSSAPI authentication
 */
void
gssapi_setup_env(void);

/*
 * Fix up our environment after GSSAPI authentication
 */
int
gssapi_fix_env(void);

/*
 * Pass all the GSSAPI environment variables to the child.
 */
void
gssapi_child_set_env(char ***p_env,
                     unsigned int *p_envsize);

/*
 * A string containing the version of the GSSAPI patch applied
 */
#define GSSAPI_PATCH_VERSION    "GSSAPI_PATCH FOR OPENSSH-3.0.2p1"

#ifndef GSSAPI_SERVICE_NAME
#define GSSAPI_SERVICE_NAME             "host"
#endif /* GSSAPI_SERVICE_NAME */

#ifndef GSSAPI_SERVICE_NAME_FORMAT
#define GSSAPI_SERVICE_NAME_FORMAT      "%s@%s"         /* host@fqdn */
#endif /* GSSAPI_SERVICE_NAME_FORMAT */

/* String to send if we don't have a valid hash of sshd keys */
#define GSSAPI_NO_HASH_STRING           "GSSAPI_NO_HASH"
#endif /* GSSAPI */
/*end of modification*/

/*
 * Name of the environment variable containing the pathname of the
 * authentication socket.
 */
#define SSH_AGENTPID_ENV_NAME	"SSH_AGENT_PID"

/*
 * Name of the environment variable containing the pathname of the
 * authentication socket.
 */
#define SSH_AUTHSOCKET_ENV_NAME "SSH_AUTH_SOCK"

/*
 * Environment variable for overwriting the default location of askpass
 */
#define SSH_ASKPASS_ENV		"SSH_ASKPASS"

/*
 * Force host key length and server key length to differ by at least this
 * many bits.  This is to make double encryption with rsaref work.
 */
#define SSH_KEY_BITS_RESERVED		128

/*
 * Length of the session key in bytes.  (Specified as 256 bits in the
 * protocol.)
 */
#define SSH_SESSION_KEY_LENGTH		32

/* Name of Kerberos service for SSH to use. */
#define KRB4_SERVICE_NAME		"rcmd"

/* Used to identify ``EscapeChar none'' */
#define SSH_ESCAPECHAR_NONE		-2

#endif				/* SSH_H */

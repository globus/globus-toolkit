/*
 * auth-gssapi.c
 *
 * Authentication using a gssapi library.
 *
 * Written by Von Welch (vwelch@ncsa.uiuc.edu)
 */


/*
 * This code stolen from the gss-server.c sample program from MIT's
 * kerberos 5 distribution.
 */

#include <config.h>

#include <gssapi.h>

#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>		/* For MAXPATHLEN */

#include "xmalloc.h"

#ifdef GSSAPI_KRB5
#include <krb5.h>
#endif /* GSSAPI_KRB5 */

#include "includes.h"
#include "ssh.h"
#include "packet.h"
#include "log.h"
#include "ssh1.h"

/*modified by binhe*/
#include "ssh-gss.h"
/*end of modification*/

/* Version Tag */
static char gssapi_patch_version[] = GSSAPI_PATCH_VERSION;

/*
 * Declarations for mechanism-specific OIDs
 */
#ifdef GSSAPI_KRB5
extern const gss_OID gss_nt_service_name;

#ifndef GSS_C_NT_HOSTBASED_SERVICE
#define GSS_C_NT_HOSTBASED_SERVICE	gss_nt_service_name
extern const gss_OID gss_nt_service_name;
#endif /* GSS_C_NT_HOSTBASED_SERVICE */

#endif /* GSSAPI_KRB5 */

#ifdef GSI
#include "globus_gss_assist.h"
#endif

/*
 * String describing our authentication type
 */
#ifdef GSI
#define GSSAPI_AUTH_TYPE	"Globus/ssleay"

#elif defined(GSSAPI_KRB5)
#define GSSAPI_AUTH_TYPE      	"Kerberos 5"
#else
#define GSSAPI_AUTH_TYE		"Unknown"
#endif

/*
 * Environment variables pointing to delegated credentials
 */
static char *delegation_env[] = {
  "X509_USER_PROXY",		/* GSSAPI/SSLeay */
  "KRB5CCNAME",			/* Krb5 and possibly SSLeay */
  NULL
};

/*
 * Internal functions
 */
static int gssapi_setenv(const char *var, const char *value, const int override);
static void gssapi_unsetenv(const char *var);

/*
 * This holds the MD5 hash of the server and host keys. It's
 * filled in in sshd.c
 */
unsigned char ssh_key_digest[16];



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


static int gssapi_mechs_match(mech1, mech2)
  gss_OID mech1;
  gss_OID mech2;
{
  if (mech1->length != mech2->length)
    return 0;

  return (memcmp(mech1->elements, mech2->elements, mech1->length) == 0);
}
  

/*
 * Authenticate and authorize a GSSAPI user. target_user should be
 * the name of the local account the user is trying to access.
 * source_host should be the name of the host the connection is
 * coming from.
 *
 * Returns 0 on failure. On success returns 1 and fills in client_name
 * with gssapi identity of user.
 */
int auth_gssapi(const char *target_account,
		const char *source_host,
		gss_buffer_desc *client_name)
{
  gss_buffer_desc send_tok;
  gss_buffer_desc recv_tok;
  gss_buffer_desc name_buf;
  int type;
  OM_uint32 maj_stat;
  OM_uint32 min_stat;
  char *service_name = NULL;
  gss_cred_id_t server_creds;
  gss_name_t server_name;
  gss_name_t client;
  gss_OID mech_oid;
  gss_OID_desc requested_mech;
  gss_OID_set my_mechs;
  unsigned int num_mechs;
  unsigned int mech_len;
  gss_OID_set_desc requested_mech_set;
  int found_mech_match = 0;
  gss_OID name_type;
  OM_uint32 ret_flags = 0;
  gss_ctx_id_t context = GSS_C_NO_CONTEXT;
  int ret_stat = 0;		/* 1 success */
  char local_hostname[256];	/* Arbitrary size */
  char *gssapi_auth_type = GSSAPI_AUTH_TYPE;
  char *gssapi_identity = NULL;


  debug("Attempting %s GSSAPI authentication (%s). Reading mech oid from client",
	gssapi_auth_type, gssapi_patch_version);

  /*
   * Read mech OID from initial packet
   */
  num_mechs = packet_get_int();

  if (num_mechs == 0) {
    /*
     * At some point this will mean that we should do GSSAPI session
     * negotiation. Currently we don't handle it.
     */
    debug("Number of GSSAPI mechanism is zero. Sending failure.");
    
    packet_start(SSH_MSG_AUTH_GSSAPI_ABORT);	
    packet_send();
    goto cleanup;
  }

  /* Set up our environment */
  gssapi_setup_env();

  maj_stat = gss_indicate_mechs(&min_stat, &my_mechs);
  if (maj_stat != GSS_S_COMPLETE) {
    display_gssapi_status("getting our mechanisms", maj_stat, min_stat);

    /* Send abort message */
    packet_start(SSH_MSG_AUTH_GSSAPI_ABORT);
    packet_send();
  
    goto cleanup;
  }

  debug("Got %d mechanisms from client. Looking for one I know...",
	num_mechs);
	
  while (num_mechs && (found_mech_match == 0)) {
    int my_mech_num;


    requested_mech.elements = packet_get_string(&mech_len);
    requested_mech.length = mech_len;

    /*
     * See if we support this mech
     */
    for (my_mech_num = 0; my_mech_num < my_mechs->count; my_mech_num++)
    {
      if (gssapi_mechs_match(&requested_mech,
			     &(my_mechs->elements[my_mech_num]))) {
	found_mech_match = 1;
	break;
      }
    }
    num_mechs--;
  }

  packet_get_all();

  if (found_mech_match == 0) {
    /*
     * Found no supported mechanisms
     */
    debug("Unsupported GSSAPI mech(s)");

    packet_start(SSH_MSG_AUTH_GSSAPI_ABORT);
    packet_send();
    goto cleanup;
    
  }

  /*
   * Build our service name for importing credentials
   */

  if (gethostname(local_hostname, sizeof(local_hostname))) {
      debug("Failure getting local hostname (gethostname() failed)");
      goto cleanup;
  }

  service_name = (char *) malloc(strlen(local_hostname) +
				 strlen(GSSAPI_SERVICE_NAME) +
				 strlen(GSSAPI_SERVICE_NAME_FORMAT) +
				 1 /* for NUL */);

  if (service_name == NULL) {
      debug("malloc() failed");
      packet_start(SSH_MSG_AUTH_GSSAPI_ABORT);
      packet_send();
      goto cleanup;
  }

  sprintf(service_name, GSSAPI_SERVICE_NAME_FORMAT,
	  GSSAPI_SERVICE_NAME, local_hostname);

  name_type = GSS_C_NT_HOSTBASED_SERVICE;

  debug("Attempting %s authentication", gssapi_auth_type);
  debug("Service name is %s", service_name);

  /*
   * Import the service name
   */
  name_buf.value = service_name;
  name_buf.length = strlen(name_buf.value) + 1;
  maj_stat = gss_import_name(&min_stat, &name_buf, 
			     name_type, &server_name);
  if (maj_stat != GSS_S_COMPLETE) {
    display_gssapi_status("importing name", maj_stat, min_stat);

    /* Send abort message */
    packet_start(SSH_MSG_AUTH_GSSAPI_ABORT);
    packet_send();
  
    goto cleanup;
  }

  /*
   * Build set of mech oids
   */
  requested_mech_set.elements = &requested_mech;
  requested_mech_set.count = 1;

  /*
   * Get server credentials
   */
  maj_stat = gss_acquire_cred(&min_stat, server_name, 0,
			      &requested_mech_set, GSS_C_ACCEPT,
			      &server_creds, NULL, NULL);
  
  (void) gss_release_name(&min_stat, &server_name);

  if (maj_stat != GSS_S_COMPLETE) {
    display_gssapi_status("acquiring credentials", maj_stat, min_stat);

    /* Send abort message */
    packet_start(SSH_MSG_AUTH_GSSAPI_ABORT);
    packet_send();
  
    goto cleanup;
  }	

  /*
   * Respond to let client know mechanism was OK.
   */
  packet_start(SSH_SMSG_AUTH_GSSAPI_RESPONSE);
  packet_put_string(requested_mech.elements, requested_mech.length);
  packet_send();

  do {
    debug("Reading token from client...");

    type = packet_read();

    switch(type) {

    case SSH_MSG_AUTH_GSSAPI_TOKEN:
      /* This is what we expect */
      break;

    case SSH_MSG_AUTH_GSSAPI_ABORT:
      debug("Client aborted connection");
      packet_get_all();
      goto cleanup;

    default:
      packet_disconnect("Protocol error during GSSAPI authentication: "
			"Unknown packet type %d",
			type);
      /* Does not return */
    }

    recv_tok.value = packet_get_string((unsigned int *) &recv_tok.length);
    packet_get_all();

    debug("Got %d byte token from client", recv_tok.length);

#ifdef GSI
#ifdef GSS_C_GLOBUS_LIMITED_PROXY_FLAGS
    /* 
     * We will not accept limited proxies for authentication, as
     * they may have been stolen. This enforces part of the 
     * Globus security policy.
     */
    ret_flags = GSS_C_GLOBUS_LIMITED_PROXY_FLAG;

#endif /* GSS_C_GLOBUS_LIMITED_PROXY_FLAGS */
#endif /* GSI */

    maj_stat =
      gss_accept_sec_context(&min_stat,
			     &context,
			     server_creds,
			     &recv_tok,
			     GSS_C_NO_CHANNEL_BINDINGS,
			     &client,
			     &mech_oid,
			     &send_tok,
			     &ret_flags,
			     NULL, 	/* ignore time_rec */
			     //NULL); 	/* ignore del_cred_handle */
/*modified by binhe*/
			     &gssapi_client_creds); 
   gssapi_client_type = GSS_GSI;
/*end of modification*/


    (void) gss_release_buffer(&min_stat, &recv_tok);

    if (maj_stat!=GSS_S_COMPLETE && maj_stat!=GSS_S_CONTINUE_NEEDED) {
      display_gssapi_status("accepting context", maj_stat, min_stat);

      /* Send abort message */
      packet_start(SSH_MSG_AUTH_GSSAPI_ABORT);
      packet_send();
    
      goto cleanup;
    }

    if (send_tok.length != 0) {
      debug("Sending response (%d bytes)...", send_tok.length);
      packet_start(SSH_MSG_AUTH_GSSAPI_TOKEN);
      packet_put_string((char *) send_tok.value, send_tok.length);
      packet_send();
      packet_write_wait();

      (void) gss_release_buffer(&min_stat, &send_tok);
    }	

    if (maj_stat == GSS_S_CONTINUE_NEEDED)
      debug("Continue needed...");

  } while (maj_stat == GSS_S_CONTINUE_NEEDED);

  maj_stat = gss_display_name(&min_stat, client, client_name, &mech_oid);

#ifdef HAVE_GSS_EXPORT_NAME
  if (maj_stat != GSS_S_COMPLETE) {
    /*
     * gss_display_name() in the globus gssapi_ssleay currently always
     * fails, so fall back on gss_export_name().
     */
    maj_stat = gss_export_name(&min_stat, client, client_name);
  }
#endif /* HAVE_GSS_EXPORT_NAME */

  if (maj_stat != GSS_S_COMPLETE) {
    display_gssapi_status("getting client name", maj_stat, min_stat);

    /* Send an abort message */
    packet_start(SSH_MSG_AUTH_GSSAPI_ABORT);
    packet_send();

    goto cleanup;
  }

  /* Successful authentication */

  debug("%s authentication of %s successful",
	gssapi_auth_type, (char *)client_name->value);

  {
    /*
     * Send over hash of host and server keys.
     */
    gss_buffer_desc unwrapped_buf;
    gss_buffer_desc wrapped_buf;
    int conf_req_flag = 0;	/* No encryption, just integrity */
    int qop_req = GSS_C_QOP_DEFAULT;	/* Default */
    int conf_state;

    debug("Sending hash of server and host keys...");

    unwrapped_buf.value = ssh_key_digest;
    unwrapped_buf.length = sizeof(ssh_key_digest);

    maj_stat = gss_wrap(&min_stat,
			context,
			conf_req_flag,
			qop_req,
			&unwrapped_buf,
			&conf_state,
			&wrapped_buf);

    if (maj_stat != GSS_S_COMPLETE) {
      char *bogus = GSSAPI_NO_HASH_STRING;

      display_gssapi_status("wrapping SSHD key hash",
			    maj_stat, min_stat);

      /*
       * Send over bogus packet and let client fail or not.
       */
      packet_start(SSH_SMSG_AUTH_GSSAPI_HASH);
      packet_put_string(bogus, strlen(bogus));
      packet_send();
      packet_write_wait();

    } else {

      packet_start(SSH_SMSG_AUTH_GSSAPI_HASH);
      packet_put_string(wrapped_buf.value, wrapped_buf.length);
      packet_send();
      packet_write_wait();

      gss_release_buffer(&min_stat, &wrapped_buf);
    }
  }

  /*
   * Now check to see if user is authorized
   */

  /* Get copy of name we know is NUL terminated */
  gssapi_identity = malloc(client_name->length + 1);

  if (gssapi_identity == NULL) {
    debug("Out of memory");
    goto cleanup;
  }

  memcpy(gssapi_identity, (char *) client_name->value, client_name->length);
  gssapi_identity[client_name->length] = '\0';

  debug("Checking to see if \"%s\" is authorized to access account %s",
	gssapi_identity, target_account);

  /*
   * Use mechanism-specific code to check authorization
   */
#if defined(GSSAPI_KRB5)
  {
    /*
     * Kerberos 5 authorization
     */
    krb5_context k5context;
    krb5_principal princ;
    krb5_error_code k5error;


    k5error = krb5_init_context(&k5context);
    if (k5error) {
      debug("Initialization of Kerberos context failed: %s",
	      error_message(k5error));
      goto cleanup;
    }

    k5error = krb5_parse_name(k5context, gssapi_identity, &princ);
    if (k5error) {
      debug("Parsing of Kerberos principal \"%s\" failed: %s",
	      gssapi_identity, error_message(k5error));
      krb5_free_context(k5context);
      goto cleanup;
    }

    if (krb5_kuserok(k5context, princ, target_account)) {
      /* Success */
      ret_stat = 1;
    }

    krb5_free_principal(k5context, princ);
    krb5_free_context(k5context);

  }
#endif /* GSSAPI_KRB5 */

#if defined(GSI)
  {
    /* NB: cast of target_account should not be necessary; it's a read-only
           argument; should be a const char * */
    if (globus_gss_assist_userok(gssapi_identity, (char*)target_account) != 0) {
      debug("globus_gss_assist_userok() failed");

    } else {
      /* Success */
      ret_stat = 1;
    }
  }
#endif /* GSI */
   
  debug("%s authorization of \"%s\" from %s to account %s %s",
	  gssapi_auth_type, gssapi_identity, source_host, target_account,
	  (ret_stat ? "successful" : "failed"));

 cleanup:
  if (gssapi_identity != NULL)
    free(gssapi_identity);

  if (service_name != NULL)
    free(service_name);

  return ret_stat;
}


/*
 * SSLeay GSSAPI clients may send us a user name of the form:
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
char *
gssapi_parse_userstring(char *userstring)
{
  char name_type = '\0';	/* explicit 'x' or implicit 'i' */
  char *ssl_subject_name = NULL;
  char *delim = NULL;
  char *gridmapped_name = NULL;

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
    switch (name_type) {
    case 'x':
      debug("explicit name given, using %s as username", userstring);
      break;

    case 'i':
      /* gridmap check */
      debug("implicit name given. gridmapping '%s'", ssl_subject_name);

      /* Need to setup environment early for this call */
      gssapi_setup_env();

      if(globus_gss_assist_gridmap(ssl_subject_name,
				     &gridmapped_name) == 0) {
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


/*
 * Setup our environment with defaults for the GSSAPI library.
 */
void
gssapi_setup_env(void)
{
    char ccname[MAXPATHLEN + 10 /* just to be sure */];
    struct stat st;
    int tmp_index = 0;
    static int gssapi_env_setup_done = 0;	/* Have been called */
#ifdef KERBEROS
    extern char *ticket;
#endif /* KERBEROS */


    if (gssapi_env_setup_done)
	return;	 /* Already have been called */

    debug("Setting up environment variables for GSSAPI library");

#ifdef GSI    
#ifdef PATH_GSSAPI_GLOBUS_USER_KEY
    gssapi_setenv("X509_USER_KEY", PATH_GSSAPI_GLOBUS_USER_KEY, 0);
#endif /* PATH_GSSAPI_GLOBUS_USER_KEY */
#ifdef PATH_GSSAPI_GLOBUS_USER_CERT
    gssapi_setenv("X509_USER_CERT", PATH_GSSAPI_GLOBUS_USER_CERT, 0);
#endif /* PATH_GSSAPI_GLOBUS_USER_CERT */
#ifdef PATH_GSSAPI_GLOBUS_CERT_DIR
    gssapi_setenv("X509_CERT_DIR", PATH_GSSAPI_GLOBUS_CERT_DIR, 0);
#endif /* PATH_GSSAPI_GLOBUS_CERT_DIR */
#ifdef PATH_GSSAPI_GLOBUS_GRIDMAP
    gssapi_setenv("GRIDMAP", PATH_GSSAPI_GLOBUS_GRIDMAP, 0);
#endif /* PATH_GSSAPI_GLOBUS_GRIDMAP */
#endif /* GSI */

  /*
   * Always make sure that KRB5CCNAME is set.
   *
   * For the Kerberos 5 GSSAPI library this is needed so that we know
   * where to put the delegated credentials, since the library itself
   * will try to put them in a default location.
   *
   * For the Globus/GSI GSSAPI library this is needed in case we want
   * to run sslk5 afterwards and get a Kerberos 5 ticket, we'll know
   * where sslk5 put it.
   */

    debug("Making sure KRB5CCNAME is set");

    sprintf(ccname, "FILE:/tmp/krb5cc_p%d", getpid());

    /* Make sure we have a unique name */
    while(stat(ccname, &st) == 0) {
      sprintf(ccname, "FILE:/tmp/krb5cc_p%d.%d", getpid(), tmp_index++);
    }

#ifdef KERBEROS
    /*
     * If Kerberos already has a cache picked, then use it instead.
     * Otherwise tell it what we're up to.
     */
    if (!ticket || strcmp(ticket, "none") == 0) {
      ticket = xstrdup(ccname);

    } else {
      debug("Using KRB5CCNAME generated by Kerberos code");
      strncpy(ccname, ticket, sizeof(ccname));
    }
#endif /* KERBEROS */

    debug("Setting KRB5CCNAME to %s", ccname);
    gssapi_setenv("KRB5CCNAME", ccname, 1);

    gssapi_env_setup_done = 1;
}



/*
 * Clean our environment on startup. This means removing any environment
 * strings that might inadvertantly been in root's environment and 
 * could cause serious security problems if we think we set them.
 */
void
gssapi_clean_env(void)
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
 * Fix up our environment after GSSAPI authentication
 */
int
gssapi_fix_env(void)
{
  int status = 0;
#ifdef KERBEROS
  extern char *ticket;
#endif /* KERBEROS */


#ifdef GSI
  /*
   * The gssapi library puts the user's credentials into
   * X509_USER_DELEG_PROXY. We need to copy that over into
   * X509_USER_PROXY for actual use.
   */
  if (getenv("X509_USER_DELEG_PROXY")) {
    debug("Setting X509_USER_PROXY to '%s'",
	  getenv("X509_USER_DELEG_PROXY"));
    
    if (gssapi_setenv("X509_USER_PROXY", getenv("X509_USER_DELEG_PROXY"), 1)) {
      debug("Failed to set X509_USER_PROXY environment variable");
      status = 1;
    }
  }
#endif /* GSI */

#ifdef GSSAPI_KRB5
#ifdef KERBEROS
  {
      /*
       * If the Kerberos 5 GSSAPI library set KRB5CCNAME make sure it's
       * reflected in the ticket variable.
       */
      char *env_ticket;

      env_ticket = getenv("KRB5CCNAME");

      if (env_ticket && *env_ticket &&
	  (!ticket ||
	   strcmp(env_ticket, ticket))) {

	  /* Deallocate old string if present */
	  if (ticket && strcmp(ticket, "none"))
	      free(ticket);

	  ticket = xstrdup(env_ticket);

	  debug("Using KRB5CCNAME set by GSSAPI code: %s", ticket);
      }
  }
#endif /* KERBEROS */
#endif /* GSSAPI_KRB5 */

  return status;
}

/*
 * Fix the ownership on delegated credentials. Returns 0 on success,
 * non-zero on error.
 */
int
gssapi_chown_delegation(uid_t uid, gid_t gid)
{
  char *envstr;
  int envstr_index;
  char *cred_path;
  int status = 0;
  struct stat buf;


  for (envstr_index = 0;
       (envstr = delegation_env[envstr_index]) != NULL;
       envstr_index++) {

    cred_path = getenv(envstr);

    if (!cred_path || !*cred_path)
      continue;

    /* For Kerberos strip leading 'FILE:' if present */
    if (strncmp(cred_path, "FILE:", 5) == 0)
      cred_path += 5;

    if (stat(cred_path, &buf) != 0)
      continue;		/* File does not exist */

    /* Do some sanity checking on the file */
    if (!S_ISREG(buf.st_mode)) {
	debug("Environment variable %s points at %s which is not a regular file",
		envstr, cred_path);
	continue;
    }

    debug("Changing ownership of credentials cache '%s'", cred_path);

    if (chown(cred_path, uid, gid) != 0) {
      debug("Warning: chown of '%s' failed (errno = %d)",
	    cred_path, errno);
      status = 1;
    }
  }

  return status;
}


/*
 * Remove the forwarded proxy credentials
 */
void
gssapi_remove_delegation(void)
{
  char *envstr;
  int envstr_index;
  char *cred_path;
  struct stat buf;


  for (envstr_index = 0;
       (envstr = delegation_env[envstr_index]) != NULL;
       envstr_index++) {

    cred_path = getenv(envstr);

    if (!cred_path)
      continue;

    /* For Kerberos strip leading 'FILE:' if present */
    if (strncmp(cred_path, "FILE:", 5) == 0)
      cred_path += 5;
    
    /*
     * If this is a DCE context, then don't remove it as we may
     * be sharing it with other PAGSs
     */
    if (strncmp(cred_path, "/opt/dcelocal/var/security/creds", 32) == 0)
      continue;

    if (stat(cred_path, &buf) != 0)
      continue;		/* File does not exist */

    if (remove(cred_path) != 0) {
      debug("Error removing credentials cache '%s' (errno = %d)",
	    cred_path, errno);
    }
  }
}


/*
 * Wrapper around putenv. Return zero on success, non-zero on error.
 */
static int
gssapi_setenv(const char *var,
	      const char *value,
	      const int override)
{
  char *envstr = NULL;
  int status;


  /* If we're not overriding and it's already set, then return */
  if (!override && getenv(var))
      return 0;

  envstr = xmalloc(strlen(var) + strlen(value) + 2 /* '=' and NUL */);

  sprintf(envstr, "%s=%s", var, value);

  status = putenv(envstr);

  /* Don't free envstr as it may still be in use */
  
  return status;
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
		

    

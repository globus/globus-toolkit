/*
 * gssapi.c
 *
 * GSSAPI authentication support for wuftpd.
 *
 */

#include "config.h"
#include "proto.h"
#ifdef GSSAPI

#ifdef GSSAPI_KRB5
#include <krb5.h>
#endif /* GSSAPI_KRB5 */

#include "gssapi-local.h"
#include "secure_ext.h"

#include <unistd.h>		/* For syslog() */
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif
#ifdef GSSAPI_KRB5
#include <netinet/in.h>
#endif /* GSSAPI_KRB5 */

/* Service names to use for importing credentials */
#ifdef GSSAPI_KRB5
char* gss_services[] = { "ftp", "host", 0 };
extern struct sockaddr_in his_addr;
extern struct sockaddr_in ctrl_addr;
#ifndef GSS_C_NT_HOSTBASED_SERVICE
#define GSS_C_NT_HOSTBASED_SERVICE	gss_nt_service_name
#endif /* GSS_C_NT_HOSTBASED_SERVICE */
#endif /* GSSAPI_KRB5 */

#include "gssapi.h"

#ifdef GSSAPI_GLOBUS
char* gss_services[] = { "ftp", "host", 0 };
extern const gss_OID_desc * const gss_untrusted_group;

/* Compare OIDs */

#define g_OID_equal(o1,o2) \
        (((o1) == (o2)) || \
         ((o1) && (o2) && \
         ((o1)->length == (o2)->length) && \
         (memcmp((o1)->elements,(o2)->elements,(int) (o1)->length) == 0)))

#endif /* GSSAPI_GLOBUS */

#if USE_GLOBUS_DATA_CODE
#include "globus_ftp_control.h"
extern globus_ftp_control_handle_t g_data_handle;
extern gss_cred_id_t g_deleg_cred;
#endif

extern int debug;			/* From ftpd.c */

/* Server credentials */
static gss_cred_id_t server_creds = GSS_C_NO_CREDENTIAL;     

/* GSSAPI context */
static gss_ctx_id_t gcontext = GSS_C_NO_CONTEXT;

/* Identity of authenticated client */
static gss_buffer_desc client_name = { 0, NULL };

static char * group_info = NULL;

#ifndef NUL
#define	NUL	'\0'
#endif /* NUL */

#ifndef h_errno
/*
 * Under AIX h_errno is a macro.
 * XXX This should really be a feature test.
 */
extern int h_errno;
#endif /* !h_errno */

static int gssapi_reply_error();
static int gssapi_setenv();
static void gssapi_unsetenv();

/*
 * Environment variables pointing to delegated credentials
 */
static char *delegation_env[] = {
    /* "X509_USER_PROXY",		 GSSAPI/SSLeay */
  "KRB5CCNAME",			/* Krb5 and possibly SSLeay */
  NULL
};


/*
 * gssapi_setup_environment()
 *
 * Set up our environment with regards to GSSAPI authentication.
 *
 * Arguments: None
 * Returns: Nothing
 */
void
gssapi_setup_environment()
{
    char		ccname[50];	/* Big enough to hold KRB5CCNAME */
    struct stat		st;
    int			index = 0;
    
    /*
     * Just in case we're using Kerberos, setup a private
     * credential cache. Overwrite any value that exists
     * as we probably inherited it from inetd and don't
     * want it.
     */
    sprintf(ccname, "FILE:/tmp/krb5cc_gsiftpd_p%d", getpid());

    /* Make sure we have a unique name */
    while(stat(ccname, &st) == 0) {
	sprintf(ccname, "FILE:/tmp/krb5cc_gsiftpd_p%d.%d", getpid(), index++);
    }
    
    gssapi_setenv("KRB5CCNAME", ccname, 1);
    if (debug)
	syslog(LOG_DEBUG, "Setting KRB5CCNAME to %s", ccname);
    
}


/*
 * Fix up our environment
 */
int
gssapi_fix_env()
{
  int status = 0;


  if (debug)
      syslog(LOG_DEBUG, "gssapi_fix_env() called");

#ifdef GSSAPI_GLOBUS
  /*
   * The gssapi library puts the user's credentials into
   * X509_USER_DELEG_PROXY. We need to copy that over into
   * X509_USER_PROXY for actual use.
   */

  
  if (getenv("X509_USER_DELEG_PROXY")) {
      if (debug)
	  syslog(LOG_DEBUG, "Setting X509_USER_PROXY to '%s'",
		 getenv("X509_USER_DELEG_PROXY"));
      
      if (gssapi_setenv("X509_USER_PROXY", getenv("X509_USER_DELEG_PROXY"), 1)) {
	  syslog(LOG_ERR, "Failed to set X509_USER_PROXY environment variable");
	  status = 1;
      }
  }

  /*
   * Unset X509_USER_KEY and X509_USER_CERT that might be set to point
   * at the host key and certificate for authentication.
   * This isn't a security problem, just possibly confusing.
   */
  gssapi_unsetenv("X509_USER_KEY");
  gssapi_unsetenv("X509_USER_CERT");

#endif /* GSSAPI_GLOBUS */

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


    if (debug)
	syslog(LOG_DEBUG, "gssapi_chown_delegation(%d, %d) called",
	       uid, gid);
    
    for (envstr_index = 0;
	 (envstr = delegation_env[envstr_index]) != NULL;
	 envstr_index++) {
      
	cred_path = getenv(envstr);

	if (!cred_path)
	    continue;

	/* For Kerberos strip leading 'FILE:' if present */
	if (strncmp(cred_path, "FILE:", 5) == 0)
	    cred_path += 5;

	if (stat(cred_path, &buf) != 0)
	    continue;		/* File does not exist */

	if (debug)
	    syslog(LOG_DEBUG, "Changing ownership of credentials cache '%s'",
		   cred_path);

	if (chown(cred_path, uid, gid) != 0) {
	    syslog(LOG_ERR, "chown of '%s' failed (errno = %d)",
		   cred_path, errno);
	    status = 1;
	}
    }

    return status;
}

/*
 * Remove the forwarded proxy credentials
 */
int
gssapi_remove_delegation()
{
    char *envstr;
    int envstr_index;
    char *cred_path;
    struct stat buf;


    if (debug)
	syslog(LOG_DEBUG, "gssapi_remove_delegation() called");
    
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
	if (strncmp(cred_path, "/opt/declocal/var/security/creds", 32) == 0)
	    continue;

	if (stat(cred_path, &buf) != 0)
	    continue;		/* File does not exist */

	if (debug)
	    syslog(LOG_DEBUG, "Removing delegated credentials in %s", cred_path);
	
	if (remove(cred_path) != 0) {
	    if (debug)
		syslog(LOG_INFO, "Error removing credentials cache '%s' (errno = %d)",
		       cred_path, errno);
	}
    }
    return(0);
}


#ifdef GLOBUS_AUTHORIZATION
extern char * ftp_authz_identity();
#endif

/*
 * gssapi_identity()
 *
 * Return remote identity of authenticated user, to be used for authorization.
 *
 * Arguments: None
 * Returns: Identity (NUL-terminated string)
 */
char *
gssapi_identity()
{
#ifdef GLOBUS_AUTHORIZATION

    /*
     * If the authorization system wants us to use a particular identity,
     * use it.  Otherwise, just use the normal authenticated identity.
     */

    char *identity;
    if (identity = ftp_authz_identity())
    {
	return(identity);
    }

#endif /* GLOBUS_AUTHORIZATION */    

    return (char *)client_name.value;

}

/*
 * gssapi_audit_identity()
 *
 * Return the authenticated remote identity of authenticated user, to be
 * used for audit.
 *
 * Arguments: None
 * Returns: Identity (NUL-terminated string)
 */
char *
gssapi_audit_identity()
{
    return (char *)client_name.value;
}


/*
 * gssapi_check_authorization()
 *
 * Check if the given GSSAPI identify is authorized to access the
 * given local account.
 *
 * Arguments: GSSAPI identity (NUL-terminated string)
 *            account(NUL-terminated string)
 * Returns: 0 on success, -1 on error
 */
int
gssapi_check_authorization(char *gssapi_name, char *account)
{
/* we can use the KRB5 kuserok, or the gridmap */
#if defined(GSSAPI_KRB5) && !defined(GRIDMAP_WITH_KRB5)
    	int retval = -1;
	krb5_boolean k5ret;
	krb5_context kc;
	krb5_principal p;
	krb5_error_code kerr;
	
	if (debug)
	    syslog(LOG_DEBUG, "Check authorization for %s to account %s",
		   gssapi_name, account);
	
	kerr = krb5_init_context(&kc);
	if (kerr) {
	    syslog(LOG_ERR, "krb5_init_context() failed");
	    
	    return -1;
	}

	kerr = krb5_parse_name(kc, gssapi_name, &p);
	if (kerr) {
	    syslog(LOG_ERR, "krb5_parse_name(%s) failed",
		   gssapi_name);
	    retval = -1;
	    goto fail;
	}

	k5ret = krb5_kuserok(kc, p, account);
	if (k5ret == TRUE)
		retval = 0;
	else 
		retval = -1;

	krb5_free_principal(kc, p);
 fail:
	krb5_free_context(kc);

	if (debug)
	    syslog(LOG_DEBUG, "Authorization for %s to %s %s",
		   gssapi_name, account,
		   (retval == 0) ? "granted" : "denied");

	return retval;
#endif /* GSSAPI_KRB5 */

#if defined(GSSAPI_GLOBUS) || defined(GRIDMAP_WITH_KRB5)
	int retval = -1;	/* 0 == authorized */
        char identity_buffer[256];
        globus_result_t result;
        globus_object_t * error;
        char * error_string;

        
	/*
	 *  Check mapping between client name and local name
	 */

        result = globus_gss_assist_map_and_authorize(gssapi_get_gss_ctx_id_t(),
                                                     "gridftp",
                                                     account,
                                                     identity_buffer,
                                                     256);
        
	if (result == GLOBUS_SUCCESS) {
	    /* Success */
	    retval = 0;
	} else {
            error = globus_error_get(result);
            error_string = globus_error_print_chain(error);
            syslog(LOG_INFO,
                   "globus_gss_assist_map_and_authorize() failed: %s",
                   error_string);
            globus_object_free(error);
            free(error_string);
	}

	return retval;

#endif /* GSSAPI_GLOBUS */
}





/*
 * gssapi_unwrap_message()
 *
 * Unwrap the given message.
 *
 * Arguments: wrapped message, wrapped message length,
 *            buffer to store message, size of buffer,
 *            decrypt (1 == message is encrypted)
 * Returns: 0 on success, -1 on error
 */

int
gssapi_unwrap_message(char *wrapped_message,
		      int wrapped_len,
		      char *message,
		      int *message_len,
		      int msg_prot_level)
{
    gss_buffer_desc wrapped_buf;
    gss_buffer_desc msg_buf;
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    int conf_state;
    char *eom;
    int decrypt = PROT_ENCRYPTION(msg_prot_level);
    

    if (msg_prot_level == PROT_E) {
	syslog(LOG_ERR, "gssapi_unwrap_message() called with unsupported protection level %d",
	       msg_prot_level);
	*message_len = 0;
	message[0] = NUL;
	return -1;
    }
	
    if (debug)
	syslog(LOG_DEBUG, "Calling gss_unwrap() with %d byte message",
	       wrapped_len);
    
    wrapped_buf.value = wrapped_message;
    wrapped_buf.length = wrapped_len;

    /* decrypt the message */
    maj_stat = gss_unwrap(&min_stat,
			  gcontext,
			  &wrapped_buf,
			  &msg_buf,
			  &decrypt,
			  NULL);

    if (maj_stat == GSS_S_CONTINUE_NEEDED) {
	if (debug)
	    syslog(LOG_DEBUG, "%s-unwrap continued", decrypt?"MIC":"ENC");
	reply(535, "%s-unwrap continued, oops",
	      decrypt?"MIC":"ENC");
	*message_len = 0;
	message[0] = NUL;
	return -1;
    }

    if (maj_stat != GSS_S_COMPLETE) {
	if (debug)
	    syslog(LOG_DEBUG, "Failed unwrapping %s message",
		   (decrypt ? "ENC" : "MIC"));
	
	gssapi_reply_error(535, maj_stat, min_stat, 
			   (decrypt? "failed unwrapping MIC message":
			    "failed unwrapping ENC message"));
	message[0] = NUL;
	*message_len = 0;
	return -1;
    }

    if (debug)
	syslog(LOG_DEBUG, "Unwrapped buffer to %d bytes", msg_buf.length);

    if (msg_buf.length  + 2 /* for CRLF */ > *message_len) {
	if (debug) {
	    syslog(LOG_DEBUG,
		   "GSSAPI Unwrapped message too large (%d) for buffer (%d)",
		   msg_buf.length, *message_len);
	}
	reply(535, "GSSAPI Unwrapped message too large");
	message[0] = NUL;
	*message_len = 0;
	gss_release_buffer(&min_stat, &msg_buf);
	return -1;
    }

    memcpy(message, msg_buf.value, msg_buf.length);
    *message_len = msg_buf.length;

    /* Find end of string and append CRLF */
    eom = &(message[msg_buf.length]);

    /* Is message NUL terminated? */
    if (message[msg_buf.length - 1] == NUL) {
	/* Yes, overwrite NUL and we will be adding only 2 bytes */
	eom--;
	*message_len += 2;
    } else {
	/* No, just append and we will be adding 3 bytes */
	*message_len += 3;
    }

    /* And append... */
    strcpy(eom, "\r\n");

    if (debug)
	syslog(LOG_DEBUG, "INPUT: %s", message);

    gss_release_buffer(&min_stat, &msg_buf);
    
    /* Success */
    return 0;
}


/*
 * gssapi_wrap_message()
 *
 * Wrap the given message.
 *
 * Arguments: message (a NUL-terminated string),
 *            wrapped message buffer, wrapped message buffer length,
 *            protection_level
 * Returns: 0 on success, -1 on error
 */
int
gssapi_wrap_message(
    char *                              message,
    char *                              wrapped_message,
    int *                               wrapped_len,
    int                                 msg_prot_level)
{
    gss_buffer_desc in_buf, out_buf;
    OM_uint32 maj_stat, min_stat;
    int conf_state;
    

    if (msg_prot_level == PROT_E)
    {
        syslog(
            LOG_ERR,
            "gssapi_wrap_message() called with unsupported protection level %d",
            msg_prot_level);
        *wrapped_len = 0;
        return -1;
    }
    

    in_buf.value = message;
    in_buf.length = strlen(message);

    if (debug)
    {
        syslog(LOG_DEBUG, "Calling gss_wrap() with %d byte message",
               in_buf.length);
        syslog(LOG_DEBUG, "Target buffer is %d bytes. Encrypt is %s",
               *wrapped_len,
               (PROT_ENCRYPTION(msg_prot_level) ? "on" : "off"));
    }
    
    maj_stat = gss_wrap(&min_stat, gcontext,
                        PROT_ENCRYPTION(msg_prot_level),
                        GSS_C_QOP_DEFAULT,
                        &in_buf,
                        &conf_state,
                        &out_buf);

    if (maj_stat != GSS_S_COMPLETE)
    {
        syslog(LOG_ERR,
               PROT_ENCRYPTION(msg_prot_level) ?
               "gss_wrap ENC didn't complete":
               "gss_wrap MIC didn't complete");
        *wrapped_len = 0;
        return -1;
        
    }
    else if (PROT_ENCRYPTION(msg_prot_level) && !conf_state)
    {
        syslog(LOG_ERR, "GSSAPI didn't encrypt message");
        gss_release_buffer(&min_stat, &out_buf);
        *wrapped_len = 0;
        return -1;
    }

    if (debug)
        syslog(LOG_DEBUG, "gss_wrap() producted %d bytes buffer",
               out_buf.length);
    
    /* Don't overflow output buffer */
    if (out_buf.length > *wrapped_len)
    {
        syslog(LOG_ERR, "GSSAPI wrapped message too large (%d)", 
               out_buf.length);
        gss_release_buffer(&min_stat, &out_buf);
        *wrapped_len = 0;
        return -1;
    }

    memcpy(wrapped_message, out_buf.value, out_buf.length);
    *wrapped_len = out_buf.length;
    gss_release_buffer(&min_stat, &out_buf);
    
    if (debug)
        syslog(LOG_DEBUG, "gssapi wrapping complete");
    
    return 0;
}



/*
 * gssapi_can_encrypt()
 *
 * Do we support encryption?
 *
 * Arguments: None
 * Returns: 1 if encryption supported, 0 otherwise
 */
int
gssapi_can_encrypt()
{ /* XXX */
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    OM_uint32 max_input_size;

	    
    /*
     * Check and see if we can do handle the requested level.
     * We'll do that with a call to gss_wrap_size_limit specifying
     * the level and check for a GSS_S_BAD_QOP error.
     * I don't know if this is guarenteed to work, but it does.
     */
    maj_stat = gss_wrap_size_limit(&min_stat, gcontext,
				   1 /* encryption */,
				   GSS_C_QOP_DEFAULT,
				   64 /* Arbitraty */,
				   &max_input_size);

    if (maj_stat == GSS_S_BAD_QOP) {
	if (debug)
	    syslog(LOG_INFO,
		   "gss_wrap_size_limit() called failed testing encryption");
	return 0;
    }

    /* XXX Should check for other maj_stats */
    return 1;
}



/* returns -1 if cannot acquire credentials (having sent an error reply)
 * if it can, or has already done so, returns 0
 */
static
int
gssapi_acquire_server_credentials(void)
{
    int found = 0;
    struct gss_channel_bindings_struct *pchan;
#ifndef GSSAPI_GLOBUS
    struct gss_channel_bindings_struct chan;
#endif /* !GSSAPI_GLOBUS */
    gss_buffer_desc name_buf;
    gss_name_t server_name;

    OM_uint32 acquire_maj;
    OM_uint32 acquire_min;
    OM_uint32 stat_maj;
    OM_uint32 stat_min;

    char localname[MAXHOSTNAMELEN];
    char service_name[MAXHOSTNAMELEN+10];
    char **service;
    struct hostent *hp;
#ifdef KRB5_MULTIHOMED_FIXES
    struct sockaddr_in saddr;
    int slen;
#endif /* KRB5_MULTIHOMED_FIXES */
    gss_OID name_type;
#ifdef GSSAPI_KRB5
    extern const gss_OID gss_nt_service_name;	/* From GSSAPI library */
#endif /* GSSAPI_KRB5 */

#ifdef GSSAPI_GLOBUS
    pchan = GSS_C_NO_CHANNEL_BINDINGS;
#else /* GSSAPI_GLOBUS */
    chan.initiator_addrtype = GSS_C_AF_INET;
    chan.initiator_address.length = 4;
    chan.initiator_address.value = &his_addr.sin_addr.s_addr;
    chan.acceptor_addrtype = GSS_C_AF_INET;
    chan.acceptor_address.length = 4;
    chan.acceptor_address.value = &ctrl_addr.sin_addr.s_addr;
    chan.application_data.length = 0;
    chan.application_data.value = 0;
    pchan = &chan;
#endif /* !GSSAPI_GLOBUS */

    if(server_creds != GSS_C_NO_CREDENTIAL)
    {
	return 0;
    }

    /* if not run as root try to acquire any credential we can get
     */
    
    if(getuid())
    {
	acquire_maj = gss_acquire_cred(&acquire_min, GSS_C_NO_NAME, 0,
				       GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
				       &server_creds, NULL, NULL);
        
	if (acquire_maj == GSS_S_COMPLETE)
        {
            return 0;
        }
        else
        {
            gssapi_reply_error(501, acquire_maj, acquire_min,
                               "acquiring credentials");
            syslog(LOG_ERR, "gssapi error acquiring credentials");
            return -1;
        }
    }
    
#ifndef KRB5_MULTIHOMED_FIXES
    /* Get all default hostname */
    if (gethostname(localname, sizeof(localname))) {
	reply(501, "couldn't get local hostname (%d)\n", errno);
	syslog(LOG_ERR, "Couldn't get local hostname (%d)", errno);
	return -1;
    }
    if (!(hp = gethostbyname(localname))) {
	reply(501, "couldn't canonicalize local hostname (%d)\n", h_errno);
	syslog(LOG_ERR, "Couldn't canonicalize local hostname (%d)", h_errno);
	return -1;
    }
#else /* KRB5_MULTIHOMED_FIXES */
    /* Get hostname of interface client is coming in on */
    slen = sizeof(saddr);
    if (getsockname(0, (struct sockaddr *) &saddr, &slen) < 0) {
	reply(501, "couldn't get socket name (%d)\n", errno);
	syslog(LOG_ERR, "Couldn't get socket name (%d)", errno);
	return -1;
    }
    if (!(hp = gethostbyaddr((char *)&saddr.sin_addr.s_addr,
			     sizeof(saddr.sin_addr.s_addr),
			     AF_INET))) {
	reply(501, "couldn't canonicalize local hostname (%d)\n", h_errno);
	syslog(LOG_ERR, "Couldn't canonicalize local hostname (%d)", h_errno);
	return -1;
    }
#endif /* KRB5_MULTIHOMED_FIXES */

    strncpy(localname, hp->h_name, sizeof(localname));
		
    for (service = gss_services; *service && !found; service++) {

	sprintf(service_name, "%s@%s", *service, localname);
	name_type = GSS_C_NT_HOSTBASED_SERVICE;

	name_buf.value = service_name;
	name_buf.length = strlen(name_buf.value) + 1;
	if (debug)
	    syslog(LOG_INFO, "importing <%s>", service_name);
	stat_maj = gss_import_name(&stat_min,
				   &name_buf, 
				   name_type,
				   &server_name);
	if (stat_maj != GSS_S_COMPLETE) {
	    gssapi_reply_error(501, stat_maj, stat_min, "importing name");
	    syslog(LOG_ERR, "gssapi error importing name");
	    return -1;
	}
			
	acquire_maj = gss_acquire_cred(&acquire_min, server_name, 0,
				       GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
				       &server_creds, NULL, NULL);

	if (acquire_maj == GSS_S_COMPLETE)
	    found++;
	else
	{
	    (void) gss_release_name(&stat_min, &server_name);
	    server_creds = GSS_C_NO_CREDENTIAL;
	}
    }

    if (!found) {
	gssapi_reply_error(501, acquire_maj, acquire_min,
			   "acquiring credentials");
	syslog(LOG_ERR, "gssapi error acquiring credentials");
	return -1;
    }
    else
    {
	return 0;
    }
}
/* gssapi_acquire_server_credentials() */


/*
 * gssapi_handle_auth_data()
 *
 * Handle an authentication_data packet
 *
 * Arguments: Data (NUL-terminated string)
 * Returns: 1 on successful authentication
 *          0 on continue needed
 *         -1 on error
 */
int
gssapi_handle_auth_data(char *data, int length)
{
    int replied = 0;			/* Have we replied */
    int rc;
    int i;
    static gss_name_t client;
    OM_uint32 ret_flags = 0;
    struct gss_channel_bindings_struct *pchan;
#ifndef GSSAPI_GLOBUS
    struct gss_channel_bindings_struct chan;
#else
    gss_buffer_set_t client_group = GSS_C_NO_BUFFER_SET;
    gss_OID_set subgroup_types = GSS_C_NO_OID_SET;
#endif /* !GSSAPI_GLOBUS */

    OM_uint32 accept_maj;
    OM_uint32 accept_min;
    OM_uint32 stat_maj;
    OM_uint32 stat_min;

    gss_OID mechid;
    gss_buffer_desc in_tok;
    gss_buffer_desc out_tok;

#ifdef KRB5_MULTIHOMED_FIXES
    struct sockaddr_in saddr;
    int slen;
#endif /* KRB5_MULTIHOMED_FIXES */

    g_deleg_cred = GSS_C_NO_CREDENTIAL;

#ifdef GSSAPI_GLOBUS
    pchan = GSS_C_NO_CHANNEL_BINDINGS;
#else /* GSSAPI_GLOBUS */
    chan.initiator_addrtype = GSS_C_AF_INET;
    chan.initiator_address.length = 4;
    chan.initiator_address.value = &his_addr.sin_addr.s_addr;
    chan.acceptor_addrtype = GSS_C_AF_INET;
    chan.acceptor_address.length = 4;
    chan.acceptor_address.value = &ctrl_addr.sin_addr.s_addr;
    chan.application_data.length = 0;
    chan.application_data.value = 0;
    pchan = &chan;
#endif /* !GSSAPI_GLOBUS */

    rc = gssapi_acquire_server_credentials();

    if(rc == -1)
    {
	return -1;
    }

    in_tok.value = data;
    in_tok.length = length;

    if (debug)
	syslog(LOG_INFO, "Input ADAT token length is %d",
	       in_tok.length);
    if (debug)
	    syslog(LOG_INFO, "Accepting GSS context");

    accept_maj = gss_accept_sec_context(&accept_min,
					&gcontext, /* context_handle */
					server_creds, /* verifier_cred_handle */
					&in_tok, /* input_token */
					pchan, /* channel bindings */
					&client, /* src_name */
					&mechid, /* mech_type */
					&out_tok, /* output_token */
					&ret_flags,
					NULL, 	/* ignore time_rec */
					&g_deleg_cred   /* don't ignore del_cred_handle */
					);

#if USE_GLOBUS_DATA_CODE
    if (accept_maj == GSS_S_COMPLETE) 
    {
	extern globus_ftp_control_dcau_t                g_dcau;

	globus_ftp_control_local_dcau(&g_data_handle, &g_dcau, g_deleg_cred);
    }
#endif
    
    if ((accept_maj != GSS_S_COMPLETE) &&
	(accept_maj != GSS_S_CONTINUE_NEEDED)) {
	gssapi_reply_error(535, accept_maj, accept_min, "accepting context");
	syslog(LOG_ERR, "failed accepting context");
	return -1;
    }

    /* Successfully processed token */
    
    if (out_tok.length) {
	int reply_code;

	/* We have a token to send back */

	if (accept_maj == GSS_S_COMPLETE)
	    reply_code = 235;	/* Complete */
	else
	    reply_code = 335;	/* More data needed */
	
	if (debug)
	    syslog(LOG_INFO, "Sending reply token of length %d",
		   out_tok.length);

	if (send_adat_reply(reply_code, out_tok.value, out_tok.length) < 0)
	    return -1;
	
	replied = 1;
	(void) gss_release_buffer(&stat_min, &out_tok);
    }

    if (accept_maj == GSS_S_COMPLETE) {
	/* GSSAPI authentication succeeded */
	if (debug)
	    syslog(LOG_INFO, "GSSAPI authentication succeeed");

	stat_maj = gss_display_name(&stat_min, client, &client_name, &mechid);

	if (stat_maj != GSS_S_COMPLETE) {
	    gssapi_reply_error(535, stat_maj, stat_min,
			       "extracting GSSAPI identity name");
	    syslog(LOG_ERR, "gssapi error extracting identity");
	    return -1;
	}
        
	if (debug)
	    syslog(LOG_INFO, "Client identity is: %s", client_name.value);
        
	/* If the server accepts the security data, but does
	   not require any additional data (i.e., the security
	   data exchange has completed successfully), it must
	   respond with reply code 235. */
	if (!replied) reply(235, "GSSAPI Authentication succeeded");

	return(1);

    } else if (accept_maj == GSS_S_CONTINUE_NEEDED) {
	/* If the server accepts the security data, and
	   requires additional data, it should respond with
	   reply code 335. */
	if (debug)
	    syslog(LOG_INFO, "Continue needed...");

	if (!replied) reply(335, "more data needed");

	return(0);

    } else { /* accept_maj == error of some sort */
	/* "If the server rejects the security data (if 
	   a checksum fails, for instance), it should 
	   respond with reply code 535." */
	gssapi_reply_error(535, stat_maj, stat_min, 
			   "GSSAPI failed processing ADAT");
	syslog(LOG_ERR, "GSSAPI failed processing ADAT");
	return(-1);
    }
    /* Not reachable */
}

static int
gssapi_reply_error(code, maj_stat, min_stat, s)
     int code;
     OM_uint32 maj_stat;
     OM_uint32 min_stat;
     char *s;
{
    /* a lot of work just to report the error */
    OM_uint32 gmaj_stat, gmin_stat;
    gss_buffer_desc msg;
    OM_uint32 msg_ctx;

    /* Current line and end of line in message */
    char *line;
    char *eol;

    /* Codes to use */
    OM_uint32 codes[2] = { GSS_C_GSS_CODE, GSS_C_MECH_CODE };
    int code_num;
    
    for (code_num = 0; code_num < 2 ; code_num++) {
	msg_ctx = 0;
	while (!msg_ctx) {
	    gmaj_stat = gss_display_status(&gmin_stat,
                                           code_num ? min_stat : maj_stat,
					   codes[code_num],
					   GSS_C_NULL_OID,
					   &msg_ctx, &msg);
	    if ((gmaj_stat == GSS_S_COMPLETE)||
		(gmaj_stat == GSS_S_CONTINUE_NEEDED))
		{
		    /*
		     * Might return multiple lines in one string
		     * which the client doesn't handle, so split
		     * up into multiple replies
		     */
		    line = msg.value;
		    while(line && *line)
			{
			    eol = strchr(line, '\n');
			    if (eol)
				{	
				    *eol = '\0';
				}
			    lreply(code, "FTPD GSSAPI error: %s", line);
			    line = eol ? eol + 1 : NULL;
			}
		    (void) gss_release_buffer(&gmin_stat, &msg);
		}
	    if (gmaj_stat != GSS_S_CONTINUE_NEEDED)
		break;
	}
    }
    
    reply(code, "FTPD GSSAPI error: %s", s);
    return(0);
}

#ifdef GSSAPI_GLOBUS
/*
 * Return the local user the globus ID maps to
 */
char *globus_local_name(globus_id)
     char *globus_id;
{
    char identity_buffer[256];
    globus_result_t result;

    if (globus_id == NULL)
	return NULL;

    result = globus_gss_assist_map_and_authorize(gssapi_get_gss_ctx_id_t(),
                                                 "gridftp",
                                                 NULL,
                                                 identity_buffer,
                                                 256);
    if(result != GLOBUS_SUCCESS)
    { 
        return NULL;
    }
    else
    {
        return strdup(identity_buffer);
    }
}
#endif /* GSSAPI_GLOBUS */



/*
 * Set an environment variable.
 *
 * If override != 0 override an existing value.
 */
static int
gssapi_setenv(const char *var,
	      const char *value,
	      const int override)
{
#ifdef HAVE_SETENV
  return setenv(var, value, override);
#else /* !HAVE_SETENV */

  char *envstr = NULL;
  int status;


  /* If we're not overriding and it's already set, then return */
  if (!override && getenv(var))
      return 0;

  envstr = malloc(strlen(var) + strlen(value) + 2 /* '=' and NUL */);
  
  if (!envstr)
      return -1;
  
  sprintf(envstr, "%s=%s", var, value);

  status = putenv(envstr);

  /* Don't free envstr as it may still be in use */
  
  return status;
#endif /* !HAVE_SETENV */
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

/*
 * gssapi_get_gss_ctx_id_t()
 * 
 * Used by globus Authorization functions
 *
 * Arguments: none
 * Returns: the gss security context
 *
 */

gss_ctx_id_t
gssapi_get_gss_ctx_id_t(void)
{
    return gcontext;
}

#endif /* GSSAPI */

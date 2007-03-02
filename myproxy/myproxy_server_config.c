/*
 * myproxy_server_config.c
 *
 * Routines from reading and parsing the server configuration.
 *
 * See myproxy_server.h for documentation.
 */

#include "myproxy_common.h"	/* all needed headers included here */

#if defined(HAVE_REGCOMP) && defined(HAVE_REGEX_H)
#include <regex.h>

#elif defined(HAVE_COMPILE) && defined(HAVE_REGEXPR_H)
#include <regexpr.h>

#else
#define NO_REGEX_SUPPORT

#endif

#define REGULAR_EXP 1
#define NON_REGULAR_EXP 0

/**********************************************************************
 *
 * Internal Functions
 *
 */

/*
 * add_entry()
 *
 * Add a entry to an array of string, allocating as needed.
 */
static char **
add_entry(char **entries,
	  const char *entry)
{
    int current_length = 0;
    char **new_entries;
    char *my_entry;
    int new_size;
    
    assert(entry != NULL);
    
    my_entry = strdup(entry);
    
    if (my_entry == NULL) {
	return NULL;
    }
    
    if (entries != NULL) {
	while (entries[current_length] != NULL) {
	    current_length++;
	}
    }

    /* Add enough for new pointer and NULL */
    new_size = sizeof(char *) * (current_length + 2);

    new_entries = realloc(entries, new_size);
    
    if (new_entries == NULL) {
	return NULL;
    }
    
    new_entries[current_length] = my_entry;
    new_entries[current_length + 1] = NULL;
    
    return new_entries;
}

/*
 * line_parse_callback()
 *
 * Callback for vparse_stream().
 *
 * This function should return 0 unless it wants parsing to stop
 * which should only happen on fatal error - e.g. malloc() failing.
 */
static int
line_parse_callback(void *context_arg,
		    int line_number,
		    const char **tokens)
{
    myproxy_server_context_t *context = context_arg;
    const char *directive;
    int return_code = -1;
    int index;
    
    assert(context != NULL);
    
    if ((tokens == NULL) || (*tokens == NULL) || (**tokens == '#')) {
	return 0; /* Blank line or comment */
    }

    directive = tokens[0];
    
    /* allowed_clients is the old name for accepted_credentials */
    if ((strcmp(directive, "allowed_clients") == 0) ||
	(strcmp(directive, "accepted_credentials") == 0)) {
	for (index=1; tokens[index] != NULL; index++) {
	    context->accepted_credential_dns =
		add_entry(context->accepted_credential_dns, tokens[index]);
	    if (context->accepted_credential_dns == NULL) {
		goto error;
	    }
	}
    }

    /* allowed_services is the old name for authorized_retrievers */
    else if ((strcmp(directive, "allowed_services") == 0) ||
	     (strcmp(directive, "authorized_retrievers") == 0)) {
	for (index=1; tokens[index] != NULL; index++) {
	    context->authorized_retriever_dns =
		add_entry(context->authorized_retriever_dns,
			  tokens[index]);
	    if (context->authorized_retriever_dns == NULL) {
		goto error;
	    }
	}
    }
    else if((strcmp(directive, "default_retrievers") == 0)) {
	for (index=1; tokens[index] != NULL; index++) {
	    context->default_retriever_dns =
		add_entry(context->default_retriever_dns,
			  tokens[index]);
	    if (context->default_retriever_dns == NULL) {
		goto error;
	    }
	}
    }
    else if (strcmp(directive, "authorized_renewers") == 0) {
	for (index=1; tokens[index] != NULL; index++) {
	    context->authorized_renewer_dns =
		add_entry(context->authorized_renewer_dns,
			  tokens[index]);
	    if (context->authorized_renewer_dns == NULL) {
		goto error;
	    }
	}
    }
    else if (strcmp(directive, "default_renewers") == 0) {
	for (index=1; tokens[index] != NULL; index++) {
	    context->default_renewer_dns =
		add_entry(context->default_renewer_dns,
			  tokens[index]);
	    if (context->default_renewer_dns == NULL) {
		goto error;
	    }
	}
    }
    else if (strcmp(directive, "authorized_key_retrievers") == 0) {
	for (index=1; tokens[index] != NULL; index++) {
	    context->authorized_key_retrievers_dns =
		add_entry(context->authorized_key_retrievers_dns,
			  tokens[index]);
	    if (context->authorized_key_retrievers_dns == NULL) {
		goto error;
	    }
	}
    }
    else if (strcmp(directive, "default_key_retrievers") == 0) {
	for (index=1; tokens[index] != NULL; index++) {
	    context->default_key_retrievers_dns =
		add_entry(context->default_key_retrievers_dns,
			  tokens[index]);
	    if (context->default_key_retrievers_dns == NULL) {
		goto error;
	    }
	}
    }
    else if (strcmp(directive, "trusted_retrievers") == 0) {
	for (index=1; tokens[index] != NULL; index++) {
	    context->trusted_retriever_dns =
		add_entry(context->trusted_retriever_dns,
			  tokens[index]);
	    if (context->trusted_retriever_dns == NULL) {
		goto error;
	    }
	}
    }
    else if (strcmp(directive, "default_trusted_retrievers") == 0) {
	for (index=1; tokens[index] != NULL; index++) {
	    context->default_trusted_retriever_dns =
		add_entry(context->default_trusted_retriever_dns,
			  tokens[index]);
	    if (context->default_trusted_retriever_dns == NULL) {
		goto error;
	    }
	}
    }
    else if (strcmp(directive, "passphrase_policy_program") == 0) {
	context->passphrase_policy_pgm = strdup(tokens[1]);
    }
    else if (strcmp(directive, "max_proxy_lifetime") == 0) {
	context->max_proxy_lifetime = 60*60*atoi(tokens[1]);
    }
    else if (strcmp(directive, "ignore_globus_limited_proxy_flag") == 0) {
        if ((strcasecmp(tokens[1], "true")) ||
            (strcasecmp(tokens[1], "enabled")) ||
            (strcasecmp(tokens[1], "yes")) ||
            (strcasecmp(tokens[1], "on")) ||
            (strcmp(tokens[1], "1"))) {
            context->limited_proxy = -1;
        }
    }
    else if (strcmp(directive, "cert_dir") == 0) {
	context->cert_dir = strdup(tokens[1]);
    }
    else if (strcmp(directive, "pam") == 0) {
	context->pam_policy = strdup(tokens[1]);
    }
    else if (strcmp(directive, "pam_id") == 0) {
	context->pam_id = strdup(tokens[1]);
    }
    else if (strcmp(directive, "sasl") == 0) {
	context->sasl_policy = strdup(tokens[1]);
    }

    /* these were added to support the online CA functionality */
    else if (strcmp(directive, "certificate_issuer_program") == 0) {
	context->certificate_issuer_program = strdup(tokens[1]);
    }
    else if (strcmp(directive, "certificate_issuer_cert") == 0) {
	context->certificate_issuer_cert = strdup(tokens[1]);
    }
    else if (strcmp(directive, "certificate_issuer_key") == 0) {
	context->certificate_issuer_key = strdup(tokens[1]);
    }
    else if (strcmp(directive, "certificate_issuer_key_passphrase") == 0) {
	context->certificate_issuer_key_passphrase = strdup(tokens[1]);
    }
    else if (strcmp(directive, "certificate_openssl_engine_id") == 0) {
        context->certificate_openssl_engine_id = strdup(tokens[1]);
    }
    else if (strcmp(directive, "certificate_openssl_engine_pre") == 0) {
        for (index=1; tokens[index] != NULL; index++) {
            context->certificate_openssl_engine_pre =
                add_entry(context->certificate_openssl_engine_pre,
                          tokens[index]);
            if (context->certificate_openssl_engine_pre == NULL) {
                goto error;
            }
        }
    }
    else if (strcmp(directive, "certificate_openssl_engine_post") == 0) {
        for (index=1; tokens[index] != NULL; index++) {
            context->certificate_openssl_engine_post =
                add_entry(context->certificate_openssl_engine_post,
                          tokens[index]);
            if (context->certificate_openssl_engine_post == NULL) {
                goto error;
            }
        }
    }
    else if (strcmp(directive, "certificate_issuer_email_domain") == 0) {
	context->certificate_issuer_email_domain = strdup(tokens[1]);
    }
    else if (strcmp(directive, "certificate_extfile") == 0) {
	context->certificate_extfile = strdup(tokens[1]);
    }
    else if (strcmp(directive, "certificate_extapp") == 0) {
	context->certificate_extapp = strdup(tokens[1]);
    }
    else if (strcmp(directive, "certificate_mapfile") == 0) {
	context->certificate_mapfile = strdup(tokens[1]);
    }
    else if (strcmp(directive, "certificate_mapapp") == 0) {
	context->certificate_mapapp = strdup(tokens[1]);
    }
    else if (strcmp(directive, "max_cert_lifetime") == 0) {
	context->max_cert_lifetime = 60*60*atoi(tokens[1]);
    }
    else if (strcmp(directive, "certificate_serialfile") == 0) {
	context->certificate_serialfile = strdup(tokens[1]);
    }
    else if (strcmp(directive, "certificate_out_dir") == 0) {
	context->certificate_out_dir = strdup(tokens[1]);
    }

    /* added for username-to-dn ldap support for internal CA */
    else if (strcmp(directive, "ca_ldap_server") == 0) {
	context->ca_ldap_server = strdup(tokens[1]);
    }
    else if (strcmp(directive, "ca_ldap_searchbase") == 0) {
	context->ca_ldap_searchbase = strdup(tokens[1]);
    }
    else if (strcmp(directive, "ca_ldap_connect_dn") == 0) {
	context->ca_ldap_connect_dn = strdup(tokens[1]);
    }
    else if (strcmp(directive, "ca_ldap_connect_passphrase") == 0) {
	context->ca_ldap_connect_passphrase = strdup(tokens[1]);
    }
    else if (strcmp(directive, "ca_ldap_uid_attribute") == 0) {
	context->ca_ldap_uid_attribute = strdup(tokens[1]);
    }
    else if (strcmp(directive, "ca_ldap_dn_attribute") == 0) {
	context->ca_ldap_dn_attribute = strdup(tokens[1]);
    }

    /* pubcookie stuff */
    else if (strcmp(directive, "pubcookie_granting_cert") == 0) {
	context->pubcookie_cert = strdup(tokens[1]);
    }
    else if (strcmp(directive, "pubcookie_app_server_key") == 0) {
	context->pubcookie_key = strdup(tokens[1]);
    }

    /* added by Terry Fleury to support web portal security */
    else if (strcmp(directive, "accepted_credentials_mapfile") == 0) {
        context->accepted_credentials_mapfile = strdup(tokens[1]);
    }
    else if (strcmp(directive, "accepted_credentials_mapapp") == 0) {
        context->accepted_credentials_mapapp = strdup(tokens[1]);
    }
    else if (strcmp(directive, "check_multiple_credentials") == 0) {
        context->check_multiple_credentials = 0;
        if ((strcasecmp(tokens[1], "true")) ||
            (strcasecmp(tokens[1], "enabled")) ||
            (strcasecmp(tokens[1], "yes")) ||
            (strcasecmp(tokens[1], "on")) ||
            (strcmp(tokens[1], "1"))) {
            context->check_multiple_credentials = 1;
        }
    }

#if defined(HAVE_OCSP)
    /* OCSP stuff */
    else if (strcmp(directive, "ocsp_policy") == 0) {
        myproxy_ocsp_set_policy(tokens[1]);
    }
    else if (strcmp(directive, "ocsp_responder_url") == 0) {
        myproxy_ocsp_set_responder(tokens[1]);
    }
    else if (strcmp(directive, "ocsp_responder_cert") == 0) {
        myproxy_ocsp_set_responder_cert(tokens[1]);
    }
#endif

    /* added by Terry Fleury for enhanced logging */
    else if (strcmp(directive, "syslog_ident") == 0) {
        context->syslog_ident = strdup(tokens[1]);
    }

    else {
	myproxy_log("warning: unknown directive (%s) in myproxy-server.config",
		    directive);
    }

    return_code = 0;
    
  error:
    return return_code;
}

/*
 * regex_compare()
 *
 * Does string match regex?
 *
 * Returns 1 if match, 0 if they don't and -1 on error setting verror.
 */
static int
regex_compare(const char *regex,
	      const char *string)
{
    int			result;

#ifndef NO_REGEX_SUPPORT
    char 		*buf;
    char		*bufp;

    /*
     * First we convert the regular expression from the human-readable
     * form (e.g. *.domain.com) to the machine-readable form
     * (e.g. ^.*\.domain\.com$).
     *
     * Make a buffer large enough to hold the largest possible converted
     * regex from the string plus our extra characters (one at the
     * begining, one at the end, plus a NULL).
     */
    buf = (char *) malloc(2 * strlen(regex) + 3);

    if (!buf)
    {
	verror_put_errno(errno);
	verror_put_string("malloc() failed");
	return -1;
    }

    bufp = buf;
    *bufp++ = '^';

    while (*regex)
    {
	switch(*regex)
	{

	case '*':
	    /* '*' turns into '.*' */
	    *bufp++ = '.';
	    *bufp++ = '*';
	    break;

	case '?':
	    /* '?' turns into '.' */
	    *bufp++ = '.';
	    break;

	    /* '.' needs to be escaped to '\.' */
	case '.':
	    *bufp++ = '\\';
	    *bufp++ = '.';
	    break;

	default:
	    *bufp++ = *regex;
	}

	regex++;
    }

    *bufp++ = '$';
    *bufp++ = '\0';

#ifdef HAVE_REGCOMP
    {
	regex_t preg;

	if (regcomp(&preg, buf, REG_EXTENDED))
	{
	    verror_put_string("Error parsing string \"%s\"",
			      regex);
	    /* Non-fatal error, just indicate failure to match */
	    result = 0;
	}
	else
	{
	    result = (regexec(&preg, string, 0, NULL, 0) == 0);
	    regfree(&preg);
	}
    }

#elif HAVE_COMPILE
    {
	char *expbuf;

	expbuf = compile(buf, NULL, NULL);

	if (!expbuf)
	{
	    verror_put_string("Error parsing string \"%s\"",
			      regex);
	    /* Non-fatal error, just indicate failure to match */
	    result = 0;

	} else {
	    result = step(string, expbuf);
	    free(expbuf);
	}
    }
#else

    /*
     * If we've gotten here then there is an error in the configuration
     * process or this file's #ifdefs
     */
    error -  No regular expression support found.

#endif

    if (buf)
	free(buf);

#else /* NOREGEX_SUPPORT */

    /* No regular expression support */
    result = (strcmp(regex, string) == 0);

#endif /* NO_REGEX_SUPPORT */

    return result;

}


/*
 * is_name_in_list()
 *
 * Is the given name in the given list of regular expressions.
 *
 * Returns 1 if it is, 0 if it isn't, -1 on error setting verror.
 */
static int
is_name_in_list(const char **list,
		const char *name)
{
    int return_code = -1;

    assert(name != NULL);
    
    if (list == NULL)
    {
	/* Empty list */
	return_code = 0;
	goto done;
    }

    while (*list != NULL)
    {
	int rc;

	  rc = regex_compare(*list, name);
	
	if (rc != 0)
	{
	    return_code = rc;
	    goto done;
	}
	
	list++;
    }
    
    /* If we got here we failed to find the name in the list */
    return_code = 0;

  done:
    return return_code;
}

static int
check_config(myproxy_server_context_t *context)
{
    int rval = 0;

    if (!context->accepted_credential_dns) {
	myproxy_debug("accepted_credentials not set.");
	myproxy_debug("server will not allow clients to store credentials.");
    }
    if (!context->authorized_retriever_dns) {
	myproxy_debug("authorized_retrievers not set.");
	myproxy_debug("server will not allow clients to retrieve credentials.");
    }
    if (!context->authorized_renewer_dns) {
	myproxy_debug("authorized_renewers not set.");
	myproxy_debug("server will not allow clients to renew credentials.");
    }
    if (!context->authorized_key_retrievers_dns) {
	myproxy_debug("authorized_key_retrievers not set.");
	myproxy_debug("server will not allow clients to retrieve keys.");
    }
    if (context->passphrase_policy_pgm) {
	if (access(context->passphrase_policy_pgm, X_OK) < 0) {
	    verror_put_string("passphrase_policy_pgm %s not executable",
			      context->passphrase_policy_pgm);
	    verror_put_errno(errno);
	    rval = -1;
	} else {
	    myproxy_log("passphrase policy checking enabled: %s",
			context->passphrase_policy_pgm);
	}
    }
    if (context->max_proxy_lifetime) {
	myproxy_log("max_proxy_lifetime: %d seconds",
		    context->max_proxy_lifetime);
    }
    if (context->pam_policy &&
	(!strcmp(context->pam_policy, "required") ||
	 (strcmp(context->pam_policy, "sufficient")))) {
	myproxy_log("PAM enabled, policy %s", context->pam_policy);
    }
    if (context->sasl_policy &&
	(!strcmp(context->sasl_policy, "required") ||
	 (strcmp(context->sasl_policy, "sufficient")))) {
	myproxy_log("SASL enabled, policy %s", context->sasl_policy);
    }
    if (context->certificate_issuer_program) {
	if (access(context->certificate_issuer_program, X_OK) < 0) {
	    verror_put_string("certificate_issuer_program %s not executable",
			      context->certificate_issuer_program);
	    verror_put_errno(errno);
	    rval = -1;
	} else {
	    myproxy_log("CA enabled: %s", context->certificate_issuer_program);
	}
    }
    if (context->certificate_issuer_cert) {
	if (access(context->certificate_issuer_cert, R_OK) < 0) {
	    verror_put_string("certificate_issuer_cert %s unreadable",
			      context->certificate_issuer_cert);
	    verror_put_errno(errno);
	    rval = -1;
	}
	if (context->certificate_openssl_engine_id) {
	   if (!context->certificate_issuer_key) {
	       verror_put_string("certificate_issuer_key not set");
               verror_put_errno(errno);
               rval = -1;
 	    }
	} else {
	    if (access(context->certificate_issuer_key, R_OK) < 0) {
	        verror_put_string("certificate_issuer_key %s unreadable",
	    		          context->certificate_issuer_key);
	        verror_put_errno(errno);
	        rval = -1;
	    }
	}
	if (context->certificate_extfile &&
	    access(context->certificate_extfile, R_OK) < 0) {
	    verror_put_string("certificate_extfile %s not readable",
			      context->certificate_extfile);
	    verror_put_errno(errno);
	    rval = -1;
	}
	if (context->certificate_extapp &&
	    access(context->certificate_extapp, X_OK) < 0) {
	    verror_put_string("certificate_extapp %s not executable",
			      context->certificate_extapp);
	    verror_put_errno(errno);
	    rval = -1;
	}
	if (context->certificate_mapfile &&
	    access(context->certificate_mapfile, R_OK) < 0) {
	    verror_put_string("certificate_mapfile %s not readable",
			      context->certificate_mapfile);
	    verror_put_errno(errno);
	    rval = -1;
	}
	if (context->certificate_mapapp &&
	    access(context->certificate_mapapp, X_OK) < 0) {
	    verror_put_string("certificate_mapapp %s not executable",
			      context->certificate_mapapp);
	    verror_put_errno(errno);
	    rval = -1;
	}
	if (context->certificate_serialfile &&
	    access(context->certificate_serialfile, W_OK) < 0) {
	    verror_put_string("certificate_serialfile %s not writeable",
			      context->certificate_serialfile);
	    verror_put_errno(errno);
	    rval = -1;
	}
	if (context->certificate_out_dir &&
	    access(context->certificate_out_dir, W_OK) < 0) {
	    verror_put_string("certificate_out_dir %s not writeable",
			      context->certificate_out_dir);
	    verror_put_errno(errno);
	    rval = -1;
	}
	if (!rval) {
	    myproxy_log("CA enabled");
	    if (context->max_cert_lifetime) {
		myproxy_log("max certificate lifetime: %d seconds",
			    context->max_cert_lifetime);
	    }
	    if (context->ca_ldap_server) {
		if (!context->ca_ldap_searchbase) {
		    verror_put_string("ca_ldap_server requires ca_ldap_searchbase");
		    rval = -1;
		}
		if (!context->ca_ldap_uid_attribute) {
		    verror_put_string("ca_ldap_server requires ca_ldap_searchbase");
		    rval = -1;
		}
	    }
	}
    }
    if (context->pubcookie_cert) {
	if (access(context->pubcookie_cert, R_OK) < 0) {
	    verror_put_string("pubcookie_cert %s unreadable",
			      context->pubcookie_cert);
	    verror_put_errno(errno);
	    rval = -1;
	} else {
	    myproxy_log("Pubcookie support enabled");
	}
    }
    if (context->accepted_credentials_mapfile) {
        if (access(context->accepted_credentials_mapfile, R_OK) < 0) {
            verror_put_string("accepted_credentials_mapfile %s not readable",
                              context->accepted_credentials_mapfile);
            verror_put_errno(errno);
            rval = -1;
        } else {
            myproxy_log("using accepted_credentials_mapfile %s",
                        context->accepted_credentials_mapfile);
        }
    }
	if (context->accepted_credentials_mapapp &&
	    access(context->accepted_credentials_mapapp, X_OK) < 0) {
	    verror_put_string("accepted_credentials_mapapp %s not executable",
			      context->accepted_credentials_mapapp);
	    verror_put_errno(errno);
	    rval = -1;
	}
    if (context->check_multiple_credentials) {
        myproxy_log("Checking multiple credentials during authorization");
    }

    return rval;
}


/**********************************************************************
 *
 * API Functions
 *
 */

static const char default_config_file[] = "/etc/myproxy-server.config";

int
myproxy_server_config_read(myproxy_server_context_t *context)
{
    FILE *config_stream = NULL;
    const char *config_open_mode = "r";
    int rc;
    int return_code = -1;

    if (context == NULL) 
    {
	verror_put_errno(EINVAL);
	return -1;
    }
    
    if (context->config_file == NULL) {
	if (access(default_config_file, R_OK) == 0) {
	    context->config_file = strdup(default_config_file);
	    if (context->config_file == NULL) {
		verror_put_string("strdup() failed");
		return -1;
	    }
	} else {
	    char *conf, *GL;
	    GL = getenv("GLOBUS_LOCATION");
	    if (!GL) {
		verror_put_string("$GLOBUS_LOCATION undefined.  "
				  "myproxy-server.config not found.\n");
		return -1;
	    }
	    conf = (char *)malloc(strlen(GL)+strlen(default_config_file)+1);
	    if (!conf) {
		perror("malloc()");
		exit(1);
	    }
	    sprintf(conf, "%s%s", GL, default_config_file);
	    if (access(conf, R_OK) < 0) {
		fprintf(stderr, "%s not found.\n", conf);
		exit(1);
	    }
	    context->config_file = conf;
	}
    }

    config_stream = fopen(context->config_file, config_open_mode);

    if (config_stream == NULL)
    {
	verror_put_errno(errno);
	verror_put_string("opening configuration file \"%s\"",
			  context->config_file);
	goto error;
    }
    myproxy_debug("reading configuration file %s", context->config_file);
    
    /* Clear any outstanding error */
    verror_clear();
    
    rc = vparse_stream(config_stream,
		       NULL /* Default vparse options */,
		       line_parse_callback,
		       context);
    
    if (rc == -1)
    {
	verror_put_string("Error parsing configuration file %s",
			  context->config_file);
	goto error;
    }

    if (verror_is_error())
    {
	/* Some sort of error occurred during parsing */
	goto error;
    }
    
    if (context->cert_dir == NULL)
    {
	globus_module_activate(GLOBUS_GSI_SYSCONFIG_MODULE);
	GLOBUS_GSI_SYSCONFIG_GET_CERT_DIR(&context->cert_dir);
    }

    return_code = check_config(context);
    
  error:
    if (config_stream != NULL)
    {
	fclose(config_stream);
    }
    
    return return_code;
}


int
myproxy_server_check_policy_list_ext(const char **policy_list, myproxy_server_peer_t *client)
{
    const char *policy;
    int ret;

    if ((policy_list == NULL) || (client == NULL)) {
	return 0;
    }

    while ((policy = *policy_list++) != NULL) {
       ret = myproxy_server_check_policy_ext(policy, client);
       if (ret == 1)
	  return 1;
    }

    return 0;
}

int
myproxy_server_check_policy_list(const char **dn_list, const char *client)
{
   myproxy_server_peer_t peer;
   
   memset(&peer, 0, sizeof(peer));
   strncpy(peer.name, client, sizeof(peer.name)-1);
   return myproxy_server_check_policy_list_ext(dn_list, &peer);
}

int
myproxy_server_check_policy_ext(const char *policy, myproxy_server_peer_t *client)
{
    if ((policy == NULL) || (client == NULL)) {
	return 0;
    }

    if (strncasecmp(policy, MYPROXY_SERVER_POLICY_TYPE_FQAN,
	            strlen(MYPROXY_SERVER_POLICY_TYPE_FQAN)) == 0) {
       if (client->fqans == NULL)
	  return 0;
       policy += strlen(MYPROXY_SERVER_POLICY_TYPE_FQAN);
       return is_name_in_list((const char **)client->fqans, policy);
    } else if (strncasecmp(policy, MYPROXY_SERVER_POLICY_TYPE_SUBJECT,
	     strlen(MYPROXY_SERVER_POLICY_TYPE_SUBJECT)) == 0) {
       policy += strlen(MYPROXY_SERVER_POLICY_TYPE_SUBJECT);
    }
    if (client->name == NULL)
       return 0;

    return regex_compare(policy, client->name);
}

int
myproxy_server_check_policy(const char *dn_regex, const char *client)
{
   myproxy_server_peer_t peer;

   memset(&peer, 0, sizeof(peer));
   strncpy(peer.name, client, sizeof(peer.name)-1);
   return myproxy_server_check_policy_ext(dn_regex, &peer);
}

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
    
    if (my_entry == NULL)
    {
	return NULL;
    }
    
    if (entries != NULL)
    {
	while (entries[current_length] != NULL)
	{
	    current_length++;
	}
    }

    /* Add enough for new pointer and NULL */
    new_size = sizeof(char *) * (current_length + 2);

    new_entries = realloc(entries, new_size);
    
    if (new_entries == NULL)
    {
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
    
    assert(context != NULL);
    
    if ((tokens == NULL) ||
	(*tokens == NULL))
    {
	/* Blank line */
	return 0;
    }

    directive = tokens[0];

    /* allowed_clients is the old name for accepted_credentials */
    if ((strcmp(directive, "allowed_clients") == 0) ||
	(strcmp(directive, "accepted_credentials") == 0))
    {
	int index = 1; /* Skip directive */
	
	while(tokens[index] != NULL)
	{
	    context->accepted_credential_dns =
		add_entry(context->accepted_credential_dns,
			  tokens[index]);
	    
	    if (context->accepted_credential_dns == NULL)
	    {
                verror_put_string("Parameter: %s", directive);
		goto error;
	    }

	    index++;
	}
    }

    /* allowed_services is the old name for authorized_retrievers */
    if ((strcmp(directive, "allowed_services") == 0) ||
	(strcmp(directive, "authorized_retrievers") == 0))
    {
	int index = 1; /* Skip directive */
	
	while(tokens[index] != NULL)
	{
	    context->authorized_retriever_dns =
		add_entry(context->authorized_retriever_dns,
			  tokens[index]);
	    
	    if (context->authorized_retriever_dns == NULL)
	    {
                verror_put_string("Parameter: %s", directive);
		goto error;
	    }

	    index++;
	}
    }
    
    if((strcmp(directive, "default_retrievers") == 0))
    {
	int index = 1; /* Skip directive */
	
	while(tokens[index] != NULL)
	{
	    context->default_retriever_dns =
		add_entry(context->default_retriever_dns,
			  tokens[index]);
	    
	    if (context->default_retriever_dns == NULL)
	    {
                verror_put_string("Parameter: %s", directive);
		goto error;
	    }

	    index++;
	}
    }
    
    if (strcmp(directive, "authorized_renewers") == 0)
    {
	int index = 1; /* Skip directive */
	
	while(tokens[index] != NULL)
	{
	    context->authorized_renewer_dns =
		add_entry(context->authorized_renewer_dns,
			  tokens[index]);
	    
	    if (context->authorized_renewer_dns == NULL)
	    {
                verror_put_string("Parameter: %s", directive);
		goto error;
	    }

	    index++;
	}
    }
    
    if (strcmp(directive, "default_renewers") == 0)
    {
	int index = 1; /* Skip directive */
	
	while(tokens[index] != NULL)
	{
	    context->default_renewer_dns =
		add_entry(context->default_renewer_dns,
			  tokens[index]);
	    
	    if (context->default_renewer_dns == NULL)
	    {
                verror_put_string("Parameter: %s", directive);
		goto error;
	    }

	    index++;
	}
    }
    
    if (strcmp(directive, "authorized_key_retrievers") == 0)
    {
	int index = 1; /* Skip directive */
	
	while(tokens[index] != NULL)
	{
	    context->authorized_key_retrievers_dns =
		add_entry(context->authorized_key_retrievers_dns,
			  tokens[index]);
	    
	    if (context->authorized_key_retrievers_dns == NULL)
	    {
                verror_put_string("Parameter: %s", directive);
		goto error;
	    }

	    index++;
	}
    }
    
    if (strcmp(directive, "default_key_retrievers") == 0)
    {
	int index = 1; /* Skip directive */
	
	while(tokens[index] != NULL)
	{
	    context->default_key_retrievers_dns =
		add_entry(context->default_key_retrievers_dns,
			  tokens[index]);
	    
	    if (context->default_key_retrievers_dns == NULL)
	    {
                verror_put_string("Parameter: %s", directive);
		goto error;
	    }

	    index++;
	}
    }
   
    /* List of myproxy slave servers. */ 
    if (strcmp(directive, "slave_servers") == 0)
    {
        if( context->master_server != NULL)
        {
            verror_put_string("Can't have both slave_servers and master_server set.");
            goto error;
        }

	int index = 1; /* Skip directive */
	
	while(tokens[index] != NULL)
	{
	    context->slave_servers =
		add_entry(context->slave_servers,
			  tokens[index]);
	    
	    if (context->slave_servers == NULL)
	    {
                verror_put_string("Parameter: %s", directive);
		goto error;
	    }

	    index++;
	}
    }
   
    /* Myproxy master server used in fail over. */ 
    if (strcmp(directive, "master_server") == 0)
    {
        if( context->slave_servers != NULL)
        {
            verror_put_string("Can't have both slave_servers and master_server set.");
            goto error;
        }

	int index = 1; /* Skip directive */
	
	while(tokens[index] != NULL)
	{
	    context->master_server =
		add_entry(context->master_server,
			  tokens[index]);
	    
	    if (context->master_server == NULL)
	    {
                verror_put_string("Parameter: %s", directive);
		goto error;
	    }

	    index++;
	}
    }

    if (strcmp(directive, "passphrase_policy_program") == 0)
    {
	context->passphrase_policy_pgm = strdup(tokens[1]);
    }

    if (strcmp(directive, "max_proxy_lifetime") == 0)
    {
	context->max_proxy_lifetime = 60*60*atoi(tokens[1]);
    }

    if (strcmp(directive, "cert_dir") == 0)
    {
	context->cert_dir = strdup(tokens[1]);
    }

    if (strcmp(directive, "pam") == 0)
    {
	context->pam_policy = strdup(tokens[1]);
    }

    if (strcmp(directive, "pam_id") == 0)
    {
	context->pam_id = strdup(tokens[1]);
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

    /* Success */
    return_code = 0;
    
  error:
    if (config_stream != NULL)
    {
	fclose(config_stream);
    }
    
    return return_code;
}


int
myproxy_server_check_policy_list(const char **dn_list, const char *client_name)
{
    if ((dn_list == NULL) || (client_name == NULL)) {
	return 0;
    }

    return is_name_in_list(dn_list, client_name);
}

int
myproxy_server_check_policy(const char *dn_regex, const char *client_name)
{
    if ((dn_regex == NULL) || (client_name == NULL)) {
	return 0;
    }

    return regex_compare(dn_regex, client_name);
}

/*
 * myproxy_server_config.c
 *
 * Routines from reading and parsing the server configuration.
 */

#include "myproxy_server.h"
#include "vparse.h"
#include "verror.h"

#include <sys/param.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

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
    
    new_entries = realloc(entries,
			  current_length + 2 /* New pointer and NULL */);
    
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
    int matched = 0;
    
    assert(context != NULL);
    
    if ((tokens == NULL) ||
	(*tokens == NULL))
    {
	/* Blank line */
	return 0;
    }

    directive = tokens[0];
    
    if (strcmp(directive, "allowed_clients") == 0)
    {
	int index = 0;
	
	matched = 1;
	
	while(tokens[index] != NULL)
	{
	    context->authorized_client_dns =
		add_entry(context->authorized_client_dns,
			  tokens[index]);
	    
	    if (context->authorized_service_dns == NULL)
	    {
		goto error;
	    }
	}
    }

    if (strcmp(directive, "allowed_services") == 0)
    {
	int index = 0;
	
	matched = 1;
	
	while(tokens[index] != NULL)
	{
	    context->authorized_service_dns =
		add_entry(context->authorized_service_dns,
			  tokens[index]);
	    
	    if (context->authorized_service_dns == NULL)
	    {
		goto error;
	    }
	}
    }
    
    if (!matched)
    {
	verror_put_string("Unrecognized directive \"%s\" on line %d of configuration file",
			  directive, line_number);
    }
    
  error:
    return return_code;
}


/**********************************************************************
 *
 * API Functions
 *
 */

int
myproxy_server_config_read(myproxy_server_context_t *context)
{
    char config_file[MAXPATHLEN];
    FILE *config_stream = NULL;
    const char *config_open_mode = "r";
    int rc;
    int return_code = -1;

    if (context == NULL) 
    {
	verror_put_errno(EINVAL);
	return -1;
    }
    
    if (context->config_file != NULL)
    {
	snprintf(config_file, sizeof(config_file), "%s", config_file);
    }
    else
    {
	verror_put_string("No configuration file specified");
	goto error;
    }

    config_stream = fopen(config_file, config_open_mode);

    if (config_stream == NULL)
    {
	verror_put_errno(errno);
	verror_put_string("opening configuration file \"%s\"", config_file);
	goto error;
    }
    
    context->authorized_client_dns = NULL;
    context->authorized_service_dns = NULL;
    
    /* Clear any outstanding error */
    verror_clear();
    
    rc = vparse_stream(config_stream,
		       NULL /* Default vparse options */,
		       line_parse_callback,
		       context);
    
    if (rc == -1)
    {
	verror_put_string("Error parsing configuration file %s",
			  config_file);
	goto error;
    }

    if (verror_is_error())
    {
	/* Some sort of error occurred during parsing */
	goto error;
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

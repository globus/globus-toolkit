/*****************************************************************************
gass_cache.c 

Description:

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_common.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#include "globus_gram_client.h"
#include "globus_gass_copy.h"
#include "globus_gass_server_ez.h"
#include "globus_gass_cache.h"
#include "version.h"  /* provides local_version */

/******************************************************************************
                             Type definitions
******************************************************************************/
typedef enum {
    GASSL_UNKNOWN = 0,
    GASSL_ADD,
    GASSL_DELETE,
    GASSL_CLEANUP_TAG,
    GASSL_CLEANUP_URL,
    GASSL_LIST,
    GASSL_QUERY_URL
} globus_l_cache_op_t;

/******************************************************************************
                             Module specific prototypes
******************************************************************************/
static void globus_l_cache_remote_op(globus_l_cache_op_t op,
			             char *tag,
			             char *url,
				     char *name,
			             char *rm_contact);
static void globus_l_cache_local_op(globus_l_cache_op_t op,
			            char *tag,
			            char *url,
				    char *name);
#if 0
static void globus_l_cache_print_url(globus_gass_cache_entry_t *entry,
		                     char *tag);
#endif
static char *globus_l_cache_tag_arg(char *tag);
static char *globus_l_cache_name_arg(char *name);
static char *globus_l_cache_url_arg(char *url);
/******************************************************************************
			     Module specific variables
******************************************************************************/
static globus_mutex_t globus_l_cache_monitor_mutex;
static globus_cond_t  globus_l_cache_monitor_cond;
static globus_bool_t  globus_l_cache_monitor_done = GLOBUS_FALSE;


static char * oneline_usage = 
"globus-gass-cache [-help] -op [-r resource][-t tag]...[URL]";

static char * long_usage = 
"\n"
"Usage: globus-gass-cache -help | -usage | -version[s]\n"
"       globus-gass-cache -op [-r resource][-n new_name][-t tag]...[URL]\n"
"\n"
"Valid operations (-op) are:\n"
"    -add           - add an URL to the cache\n"
"                     This operation requires that an URL be specified on\n"
"                     the command line. If the [-t tag] option is specified\n"
"                     the URL will be added with that tag; Otherwise the \n"
"                     default \"null\" tag will be used.\n"
"    -delete        - decrement the reference count for an URL\n"
"                     This operation requires that an URL be specified on\n"
"                     the command line. If the [-t tag] option is specified\n"
"                     a single instance of that tag will be removed from\n"
"                     that URLs cache entry; Otherwise, a single reference\n"
"                     of the default \"null\" tag will be removed\n"
"    -cleanup-tag   - remove all references to a tag from the cache.\n"
"                     If an URL is specified, then all references to the\n"
"                     tag will be removed from that URL. If no tag is\n"
"                     specified by the [-t tag] option, then the \"null\"\n"
"                     tag will be used.\n"
"    -cleanup-url   - remove all tags for an URL in the cache\n"
"                     This operation requires that the URL be specified on\n"
"                     the command line.\n"
"    -list          - list the contents of the cache.\n"
"                     If either the [-t tag] or a URL is specified on the\n"
"                     command line, then only cache entries which match\n"
"                     those will be listed\n"
"    -query         - prints the name of the local file in the cache that\n"
"                     is associated with the URL\n"
"\n"
"Options\n"
"    -t tag         - The string passed as the tag argument will be used\n"
"                     as described above\n"
"    -n new_name    - Store the URL in the cache as new_name (argument to\n"
"                     -add only)\n"
"    -mdshost host    \n"
"    -mdsport port    \n"
"    -mdsbasedn DN    \n"
"    -mdstimeout sec  \n"
"                   - mdshost, mdsport, mdsbasedn and mdstimeout overrides\n"
"                     default settings for contacting the MDS LDAP server.\n"
"    -r resource    - The resource argument specifies that the cache\n"
"                     operation will be performed on a remote cache. The\n"
"                     resource manager contact takes the form:\n"
"                          host:port/service:subject\n\n";

int
test_hostname( char *  value, void *  ignored,  char **  errmsg )
{
    struct hostent *   hostent;
    struct hostent     result;
    char               buf[1024];
    int                rc;
    
    hostent = globus_libc_gethostbyname_r( (char *) value,
					   &result,
					   buf,
					   1024,
					   &rc     );
    if (rc != GLOBUS_SUCCESS)
	*errmsg = globus_libc_strdup("cannot resolve hostname");
    return rc;
}

int
test_integer( char *  value, void *   ignored, char **  errmsg )
{
    int  res = (atoi(value) <= 0);
    if (res)
	*errmsg = globus_libc_strdup("argument is not a positive integer");
    return res;
}


enum { arg_a = 1, arg_d, arg_ct, arg_cu, arg_l, arg_q, arg_h, arg_p,
       arg_b,     arg_T, arg_r,  arg_n,  arg_t, n_args=arg_t };

#define listname(x) x##_aliases
#define namedef(id,alias1,alias2) \
static char * listname(id)[] = { alias1, alias2, GLOBUS_NULL }
#define defname(x) x##_definition
#define flagdef(id,alias1,alias2) \
namedef(id,alias1,alias2); \
static globus_args_option_descriptor_t defname(id) = { id, listname(id), 0, \
						GLOBUS_NULL, GLOBUS_NULL }
#define funcname(x) x##_predicate_test
#define oneargdef(id,alias1,alias2,testfunc) \
namedef(id,alias1,alias2); \
static globus_args_valid_predicate_t funcname(id)[] = { testfunc }; \
globus_args_option_descriptor_t defname(id) = \
    { (int) id, (char **) listname(id), 1, funcname(id), GLOBUS_NULL }
  
flagdef(arg_a,   "-a", "-add");
flagdef(arg_d,   "-d", "-delete");
flagdef(arg_l,   "-l", "-list");
flagdef(arg_q,   "-q", "-query");

flagdef(arg_ct,  "-cleanup-tag", GLOBUS_NULL);
flagdef(arg_cu,  "-cleanup-url", GLOBUS_NULL);

oneargdef(arg_h, "-h", "-mdshost",    test_hostname);
oneargdef(arg_p, "-p", "-mdsport",    test_integer);
oneargdef(arg_b, "-b", "-mdsbasedn",  GLOBUS_NULL);
oneargdef(arg_T, "-T", "-mdstimeout", test_integer);
oneargdef(arg_r, "-r", "-resource",   GLOBUS_NULL);
oneargdef(arg_n, "-n", "-newname",    GLOBUS_NULL);
oneargdef(arg_t, "-t", "-tag",        GLOBUS_NULL);

static globus_args_option_descriptor_t args_options[n_args];

#define setupopt(id) args_options[id-1] = defname(id)

#define globus_i_gass_cache_args_init() \
    setupopt(arg_a);  setupopt(arg_d);   setupopt(arg_l); setupopt(arg_q); \
    setupopt(arg_cu); setupopt(arg_ct); \
    setupopt(arg_h);  setupopt(arg_p);   setupopt(arg_b); setupopt(arg_T); \
    setupopt(arg_r);  setupopt(arg_n);   setupopt(arg_t);


#define globus_l_args_usage() \
{ \
    globus_libc_fprintf(stderr, \
			"\nSyntax: %s\n" \
			"\nUse -help to display full usage\n", \
			oneline_usage); \
    globus_module_deactivate_all(); \
    exit(1); \
}

#define globus_l_args_error(a) \
{ \
    globus_libc_fprintf(stderr, \
			"\nERROR: " \
			a \
			"\n"); \
    globus_l_args_usage(); \
}    



/******************************************************************************
Function: main()

Description:

Parameters: 

Returns: 
******************************************************************************/
int
main(int argc, char **argv)
{
    globus_l_cache_op_t                op                = GASSL_UNKNOWN;
    globus_list_t *                    options_found     = GLOBUS_NULL;
    globus_list_t *                    list              = GLOBUS_NULL;
    globus_args_option_instance_t *    instance          = GLOBUS_NULL;
    char *                             resource          = GLOBUS_NULL;
    char *                             url               = GLOBUS_NULL;
    char *                             name              = GLOBUS_NULL;
    char *                             tag               = GLOBUS_NULL;
    int                                rc;
    
    if (rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE))
    {
	globus_libc_fprintf(stderr,
			    "ERROR initializing GRAM: %s\n",
			    globus_gram_protocol_error_string(rc));
	exit(1);
    }
    if (rc = globus_module_activate(GLOBUS_GASS_SERVER_EZ_MODULE))
    {
	globus_libc_fprintf(stderr,
			    "ERROR initializing GASS server: %d\n",
			    rc);
	exit(1);
    }
    if(rc = globus_module_activate(GLOBUS_GASS_COPY_MODULE))
    {
	globus_libc_printf("Error %d activating GASS copy library\n",
			   rc);
	exit(1);
    }
    
    globus_i_gass_cache_args_init();

    if ( 0 > globus_args_scan( &argc,
			       &argv,
			       n_args,
			       args_options,
			       "globus-gass-cache-program",
			       &local_version,
			       oneline_usage,
			       long_usage,
			       &options_found,
			       GLOBUS_NULL   ) )  /* error on argument line */
    {	 
	globus_module_deactivate_all();
	exit(1);
    }

    if (argc > 2)
	globus_l_args_usage();

    for (list = options_found; 
	 !globus_list_empty(list); 
	 list = globus_list_rest(list))
    {
	instance = globus_list_first(list);

	switch(instance->id_number)	
	{
	case arg_a: 
	case arg_d: 
	case arg_l: 
	case arg_q: 
	case arg_ct: 
	case arg_cu: 
	    if (op != GASSL_UNKNOWN)
		globus_l_args_error("only one operation can be specified");
	    switch(instance->id_number)
	    {
	    case arg_a: 
		op = GASSL_ADD;
		break;
	    case arg_d: 
		op = GASSL_DELETE;
		break;
	    case arg_q: 
		op = GASSL_QUERY_URL;
		break;
	    case arg_l: 
		op = GASSL_LIST;
		break;
	    case arg_ct: 
		op = GASSL_CLEANUP_TAG;
		break;
	    case arg_cu: 
		op = GASSL_CLEANUP_URL;
		break;
	    }
	    break;

	case arg_h:
	    globus_libc_setenv("GRID_INFO_HOST", instance->values[0], 1);
	    break;

	case arg_p:
	    globus_libc_setenv("GRID_INFO_PORT", instance->values[0], 1);
	    break;

	case arg_b:
	    globus_libc_setenv("GRID_INFO_BASEDN", instance->values[0], 1);
	    break;
	    
	case arg_T:
	    globus_libc_setenv("GRID_INFO_TIMEOUT", instance->values[0], 1);
	    break;

	case arg_r:
	    resource = globus_libc_strdup(instance->values[0]);
	    if (globus_gram_client_ping(resource))
		globus_l_args_error("cannot authenticate to remote resource");
	    break;

	case arg_t:
	    tag = globus_libc_strdup(instance->values[0]);
	    break;

	case arg_n:
	    if (op != GASSL_ADD)
		globus_l_args_error("-n option can only be used with -add");
	    name = globus_libc_strdup(instance->values[0]);
	    break;
	}
    }

    globus_args_option_instance_list_free( &options_found );

    if (op == GASSL_UNKNOWN)
	globus_l_args_error("need to specify an operation");
    
    if (argc == 2)
	url = argv[1];

    /* what options require the URL? */
    if ( !url &&
	 (op==GASSL_ADD ||  op==GASSL_DELETE || 
	 op == GASSL_CLEANUP_URL || op == GASSL_QUERY_URL) )
    {
	globus_l_args_error("operation requires an URL");
    }

    if (tag && op==GASSL_QUERY_URL)
	globus_l_args_error("tag has no meaning for -query operation")

    if (resource)
    {
	globus_l_cache_remote_op(op, tag, url, name, resource);
    }
    else
    {
	globus_l_cache_local_op(op, tag, url, name);
    }
    return 0;
} /* main() */


/******************************************************************************
Function: globus_l_cache_url_arg()

Description:

Parameters: 

Returns: 
******************************************************************************/
static char *
globus_l_cache_url_arg(char *url)
{
    static char arg[1024];

    /* globus_libc_lock is acquired before this is called */
    if(url != GLOBUS_NULL)
    {
	sprintf(arg,
	        "\"%s\"",
	        url);
    }
    else
    {
	arg[0]='\0';
    }

    return arg;
} /* globus_l_cache_url_arg() */

/******************************************************************************
Function: globus_l_cache_name_arg()

Description:

Parameters: 

Returns: 
******************************************************************************/
static char *
globus_l_cache_name_arg(char *name)
{
    static char arg[1024];

    if(name != GLOBUS_NULL)
    {
	sprintf(arg,
		"-n \"%s\"",
		name);
    }
    else
    {
	arg[0]='\0';
    }
    return arg;
} /* globus_l_cache_name_arg() */

/******************************************************************************
Function: globus_l_cache_tag_arg()

Description:

Parameters: 

Returns: 
******************************************************************************/
static char *
globus_l_cache_tag_arg(char *tag)
{
    static char arg[1024];

    /* globus_libc_lock is acquired before this is called */
    if(tag != GLOBUS_NULL)
    {
	sprintf(arg,
	        "-t \"%s\"",
	        tag);
    }
    else
    {
	arg[0]='\0';
    }

    return arg;
} /* globus_l_cache_tag_arg() */

/******************************************************************************
Function: globus_l_cache_op_string()

Description:

Parameters: 

Returns: 
******************************************************************************/
static char *
globus_l_cache_op_string(globus_l_cache_op_t op)
{
    switch(op)
    {
    case GASSL_ADD:
	return "-add";
    case GASSL_DELETE:
	return "-delete";
    case GASSL_CLEANUP_TAG:
	return "-cleanup-tag";
    case GASSL_CLEANUP_URL:
	return "-cleanup-url";
    case GASSL_LIST:
	return "-list";
    case GASSL_QUERY_URL:
	return "-query";
    default:
	return "";
    }
} /* globus_l_cache_op_string() */

/******************************************************************************
Function: globus_l_cache_callback_func()
Description:

Parameters: 

Returns: 
******************************************************************************/
static void
globus_l_cache_callback_func(void *arg,
			     char *job_contact,
			     int state,
			     int errorcode)
{
    if(state == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED ||
       state == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)
    {
	globus_mutex_lock(&globus_l_cache_monitor_mutex);
	globus_l_cache_monitor_done = GLOBUS_TRUE;
	globus_cond_signal(&globus_l_cache_monitor_cond);
	globus_mutex_unlock(&globus_l_cache_monitor_mutex);
    }
} /* globus_l_cache_callback_func() */

/******************************************************************************
Function: globus_l_cache_remote_op()

Description:

Parameters: 

Returns: 
******************************************************************************/
static void
globus_l_cache_remote_op( globus_l_cache_op_t op,
			  char *              tag,
			  char *              url,
			  char *              name,
			  char *              rm_contact)
{
    int                                       rc;
    char *                                    callback_contact;
    char *                                    job_contact;
    char                                      spec[1024];
    char *                                    server_url	= GLOBUS_NULL;
    char *                                    scheme            = GLOBUS_NULL;
    unsigned short                            port              = 0;
    globus_gass_transfer_listener_t           listener;
    globus_gass_transfer_listenerattr_t *     attr              = GLOBUS_NULL;
    globus_gass_transfer_requestattr_t *      reqattr           = GLOBUS_NULL;
    
    

    rc = globus_gram_client_callback_allow(globus_l_cache_callback_func,
			                   GLOBUS_NULL,
			                   &callback_contact);
    if ( rc != GLOBUS_SUCCESS )
    {
	printf("Error allowing GRAM callback: %s\n",
	       globus_gram_protocol_error_string(rc));
	globus_module_deactivate_all();
	exit(1);
    }
    
    rc = globus_gass_server_ez_init(&listener,
                                    attr,
                                    scheme,
                                    reqattr,
                                    GLOBUS_GASS_SERVER_EZ_STDOUT_ENABLE|
                                    GLOBUS_GASS_SERVER_EZ_STDERR_ENABLE|
                                    GLOBUS_GASS_SERVER_EZ_LINE_BUFFER,
                                    (globus_gass_server_ez_client_shutdown_t)
                                        GLOBUS_NULL);

    if ( rc != GLOBUS_SUCCESS )
    {
	printf("Error %d initializing GASS server\n", rc);
	globus_module_deactivate_all();
	exit(1);
    }

    server_url=globus_gass_transfer_listener_get_base_url(listener);

    globus_libc_sprintf(
	spec,
	"&(executable=$(GLOBUS_LOCATION)/bin/globus-gass-cache)"
	" (environment=(LD_LIBRARY_PATH $(GLOBUS_LOCATION)/lib))"
	" (stdout=%s/dev/stdout)"
	" (stderr=%s/dev/stdout)"
	" (stdin=/dev/null)"
	" (arguments=%s %s %s %s)",
	server_url,
	server_url,
	globus_l_cache_op_string(op),
	globus_l_cache_tag_arg(tag),
	globus_l_cache_name_arg(name),
	globus_l_cache_url_arg(url));

    globus_mutex_init(&globus_l_cache_monitor_mutex, GLOBUS_NULL);
    globus_cond_init(&globus_l_cache_monitor_cond, GLOBUS_NULL);

    globus_mutex_lock(&globus_l_cache_monitor_mutex);
    
    rc = globus_gram_client_job_request(rm_contact,
					spec,
					31,
					callback_contact,
					&job_contact);
				
    if(rc != GLOBUS_SUCCESS)
    {
	globus_libc_printf("Error submitting remote cache request\n");
	return ;
    }
    while(!globus_l_cache_monitor_done)
    {
	globus_cond_wait(&globus_l_cache_monitor_cond,
			 &globus_l_cache_monitor_mutex);
    }
    globus_mutex_unlock(&globus_l_cache_monitor_mutex);
    globus_gass_server_ez_shutdown(listener);
} /* globus_l_cache_remote_op() */

/******************************************************************************
Function: globus_l_cache_local_op()

Description:

Parameters: 

Returns: 
******************************************************************************/
static void
globus_l_cache_local_op( globus_l_cache_op_t op,
	                 char *              tag,
	                 char *              url,
			 char *              name)
{
    globus_gass_cache_t          cache_handle;
    unsigned long                timestamp;
    char *                       local_filename;
    int                          rc;
    int                          i;
    int                          size             = 0;
    
    rc = globus_gass_cache_open(GLOBUS_NULL, &cache_handle);
    if(rc != GLOBUS_SUCCESS)
    {
	globus_libc_fprintf(stderr,
			    "ERROR: Could not open GASS cache because %s\n",
			    globus_gass_cache_error_string(rc));
	return;
    }
    
    switch(op)
    {
    case GASSL_ADD:
	if(name == GLOBUS_NULL)
	{
	    name = url;
	}
	rc = globus_gass_cache_add(&cache_handle,
			           name,
			           tag,
			           GLOBUS_TRUE,
			           &timestamp,
			           &local_filename);
	if(rc == GLOBUS_GASS_CACHE_ADD_EXISTS)
	{
	    globus_gass_cache_add_done(&cache_handle,
				       name,
				       tag,
				       timestamp);
	}
	else if(rc == GLOBUS_GASS_CACHE_ADD_NEW)
	{
	    globus_gass_copy_handle_t  copy_handle;
	    globus_result_t result;

	    char * fileurl = globus_libc_malloc(strlen(local_filename) +
		                                strlen("file://") + 1);
	    sprintf(fileurl, "file://%s", local_filename);

	    globus_gass_copy_handle_init(&copy_handle, GLOBUS_NULL);

	    result = globus_gass_copy_url_to_url(
		    &copy_handle,
		    url,
		    GLOBUS_NULL,
		    fileurl,
		    GLOBUS_NULL);
	    globus_gass_copy_handle_destroy(&copy_handle);

	    if(result != GLOBUS_SUCCESS)
	    {
		printf("Error transferring %s\n",
		       url);

		rc = globus_gass_cache_delete(&cache_handle,
					      name,
					      tag,
					      timestamp,
					      GLOBUS_TRUE);
	    }
	    else
	    {
		rc = globus_gass_cache_add_done(&cache_handle,
						name,
						tag,
						timestamp);
	    }
            if(rc != GLOBUS_SUCCESS)
            {
                globus_libc_printf("Could not unlock cache entry because %s\n",
                                   globus_gass_cache_error_string(rc));
            }
	}
	else
	{
	    globus_libc_fprintf(
		stderr,
		"Could not add cache entry because %s\n",
		globus_gass_cache_error_string(rc));
	}
	free(local_filename);
	break;

    case GASSL_DELETE:
	rc = globus_gass_cache_delete_start(&cache_handle,
				            url,
				            tag,
				            &timestamp);
	if(rc != GLOBUS_SUCCESS)
	{
	    globus_libc_fprintf(stderr,
				"Could not delete cache entry because %s\n",
				globus_gass_cache_error_string(rc));
	}
	rc = globus_gass_cache_delete(&cache_handle,
			              url,
			              tag,
			              timestamp,
			              GLOBUS_TRUE);
	if(rc != GLOBUS_SUCCESS)
	{
	    globus_libc_fprintf(stderr,
				"Could not unlock cache entry because %s\n",
				globus_gass_cache_error_string(rc));
	}
	break;

    case GASSL_CLEANUP_TAG:
	if( url == GLOBUS_NULL )
	{
	    rc = globus_gass_cache_cleanup_tag_all( &cache_handle, tag );
	}
	else
	{
	    rc = globus_gass_cache_cleanup_tag(&cache_handle,
			                       url,
			                       tag);
	}
	if( rc != GLOBUS_SUCCESS)
	{
	    globus_libc_fprintf(stderr,
				"Could not clean up tag because %s\n",
				globus_gass_cache_error_string(rc));
	}
	break;
	
    case GASSL_CLEANUP_URL:
#if 0
	rc = globus_gass_cache_cleanup_file(&cache_handle,
				            url);
	if(rc != GLOBUS_SUCCESS)
	{
	    globus_libc_fprintf(stderr,
				"Could not clean up file because %s\n",
				globus_gass_cache_error_string(rc));
	}
#endif
	break;

    case GASSL_LIST:
#if 0
	rc = globus_gass_cache_list(&cache_handle,
			            &entries,
			            &size);
        if(rc != GLOBUS_SUCCESS)
	{
	    globus_libc_fprintf(stderr,
				"Could not list cache entries because %s\n",
				globus_gass_cache_error_string(rc));
	    break;
	}

	for (i=0; i<size; i++)
	{
	    if (url)
	    {
		if(strcmp(url, entries[i].url) == 0)
		    globus_l_cache_print_url(&entries[i], tag);
	    }
	    else
		globus_l_cache_print_url(&entries[i], tag);
	}
	globus_gass_cache_list_free(entries, size);
#endif
	break;

    case GASSL_QUERY_URL:
	rc = globus_gass_cache_add(&cache_handle,
				   url,
				   tag,
				   GLOBUS_FALSE, /* DO NOT CREATE */
				   &timestamp,
				   &local_filename);
	
	if(rc == GLOBUS_GASS_CACHE_ADD_EXISTS)
	{
	    globus_gass_cache_delete(&cache_handle,
				     url,
				     tag,
				     timestamp,
				     GLOBUS_TRUE);
	    globus_libc_printf("%s\n",local_filename);
	}
	else if(rc == GLOBUS_GASS_CACHE_URL_NOT_FOUND)
	{
	    globus_libc_printf("\n");
	}
	else
	{
	    globus_libc_fprintf(stderr,
				"Could not query cache because %s\n",
				globus_gass_cache_error_string(rc));
	    return;
	}
	globus_free(local_filename);
	break;
    case GASSL_UNKNOWN:
	break;
    }
    globus_gass_cache_close(&cache_handle);

} /* globus_l_cache_local_op() */

/******************************************************************************
Function: globus_l_cache_print_url()

Description:

Parameters: 

Returns: 
******************************************************************************/
#if 0
static void
globus_l_cache_print_url(globus_gass_cache_entry_t *entry,
	  char *tag)
{
    unsigned long j;
    globus_bool_t print_all_tags=GLOBUS_FALSE;

    if(tag == GLOBUS_NULL)
    {
	print_all_tags = GLOBUS_TRUE;
    }

    printf("%s\n", entry->url);
    for(j = 0; j < entry->num_tags; j++)
    {
	if(print_all_tags || strcmp(tag, entry->tags[j].tag) == 0)
	{
	    printf("\ttag '%s' (%i refs)\n",
		   entry->tags[j].tag,
		   entry->tags[j].count);
	}
    }
} /* globus_l_cache_print_url() */
#endif

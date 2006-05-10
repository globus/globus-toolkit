/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
    GASSL_QUERY_URL,
    GASSL_MANGLE,
    GASSL_DIRS,
    GASSL_TYPE
} globus_l_cache_op_t;

/******************************************************************************
                             Module specific prototypes
******************************************************************************/
static int globus_l_cache_remote_op(globus_l_cache_op_t op,
			             char *tag,
			             char *url,
				     char *name,
			             char *rm_contact);
static int globus_l_cache_local_op(globus_l_cache_op_t op,
			            char *tag,
			            char *url,
				    char *name);
static char *globus_l_cache_tag_arg(char *tag);
static char *globus_l_cache_name_arg(char *name);
static char *globus_l_cache_url_arg(char *url);
/******************************************************************************
			     Module specific variables
******************************************************************************/
static globus_mutex_t	globus_l_cache_monitor_mutex;
static globus_cond_t	globus_l_cache_monitor_cond;
static globus_bool_t	globus_l_cache_monitor_done = GLOBUS_FALSE;
static globus_bool_t	globus_l_cache_status = 0;
static int		globus_l_cache_verbose = 0;


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
"    -mangle        - prints the mangled versions of the URL / tag\n"
"    -dirs          - Displays internal directory names:\n"
"                     The \"local\" data directory (from the tag / URL )\n"
"                     The \"global\" data directory (from the URL )\n"
"                     The base directories\n"
"    -type          - prints the cache type (normal/flat):\n"
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
"                          host:port/service:subject\n"
"    -verbose       - Turn on verbose output\n"
"\n";

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


enum { arg_a = 1,	/* Add */
       arg_d,		/* Delete */
       arg_ct,		/* Cleanup Tag */
       arg_m,		/* Mangled output */
       arg_dir,		/* Directories */
       arg_type,	/* Directories */
       arg_q,		/* Query */
       arg_h,		/* hostname */
       arg_p,		/* Port */
       arg_b,		/* */
       arg_T,		/* */
       arg_r,		/* Resource */
       arg_n,		/* NewName */
       arg_t,		/* Tag */
       arg_v,		/* Verbose */
       n_args=arg_v };

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
flagdef(arg_dir, "-dirs", GLOBUS_NULL );
flagdef(arg_type, "-type", GLOBUS_NULL );
flagdef(arg_m,   "-m", "-mangle" );
flagdef(arg_q,   "-q", "-query");
flagdef(arg_v,   "-v", "-vebose");

flagdef(arg_ct,  "-cleanup-tag", GLOBUS_NULL);

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
    setupopt(arg_a);	\
    setupopt(arg_d);	\
    setupopt(arg_m);	\
    setupopt(arg_dir);	\
    setupopt(arg_type);	\
    setupopt(arg_q);	\
    setupopt(arg_ct);	\
    setupopt(arg_h);	\
    setupopt(arg_p);	\
    setupopt(arg_b);	\
    setupopt(arg_T);	\
    setupopt(arg_r);	\
    setupopt(arg_n);	\
    setupopt(arg_t);	\
    setupopt(arg_v);


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
			"\nERROR: %s\n", \
			a); \
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
    int		       		       failed_gram_init  = GLOBUS_SUCCESS;
    
    if (GLOBUS_SUCCESS !=
	    (rc = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE)))
    {
	failed_gram_init = rc;
    }
    if (GLOBUS_SUCCESS !=
	    (rc = globus_module_activate(GLOBUS_GASS_SERVER_EZ_MODULE)))
    {
	globus_libc_fprintf(stderr,
			    "ERROR initializing GASS server: %d\n",
			    rc);
	exit(1);
    }
    if(GLOBUS_SUCCESS != 
	    (rc = globus_module_activate(GLOBUS_GASS_COPY_MODULE)))
    {
	globus_libc_printf("Error %d activating GASS copy library\n",
			   rc);
	exit(1);
    }
    
    globus_i_gass_cache_args_init();

    if ( 0 > (rc = globus_args_scan( &argc,
			       &argv,
			       n_args,
			       args_options,
			       "globus-gass-cache-program",
			       &local_version,
			       oneline_usage,
			       long_usage,
			       &options_found,
			       GLOBUS_NULL   )) )  /* error on argument line */
    {	 
	globus_module_deactivate_all();
	exit(rc == GLOBUS_FAILURE ? 1 : 0);
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
	case arg_dir:
	case arg_type:
	case arg_m:
	case arg_q:
	case arg_ct:
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
	    case arg_m:
		op = GASSL_MANGLE;
		break;
	    case arg_dir:
		op = GASSL_DIRS;
		break;
	    case arg_type:
		op = GASSL_TYPE;
		break;
	    case arg_ct: 
		op = GASSL_CLEANUP_TAG;
		break;
	    case arg_v:
		globus_l_cache_verbose++;
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
	    if(failed_gram_init != GLOBUS_SUCCESS)
	    {
		globus_l_args_error(globus_gram_client_error_string(failed_gram_init));
	    }
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
    if ( ( !url ) && ( ( GASSL_ADD==op ) || ( GASSL_DELETE==op ) || 
		       ( GASSL_QUERY_URL==op ) )   )
    {
	globus_l_args_error("operation requires an URL");
    }

    if (resource)
    {
	rc = globus_l_cache_remote_op(op, tag, url, name, resource);
    }
    else
    {
	rc = globus_l_cache_local_op(op, tag, url, name);
    }

    globus_module_deactivate_all();

    return rc;
}
/* main() */


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
    case GASSL_QUERY_URL:
	return "-query";
    case GASSL_MANGLE:
	return "-mangle";
    case GASSL_DIRS:
	return "-dirs";
    case GASSL_TYPE:
	return "-type";
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
	globus_l_cache_status = errorcode;
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
static
int
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
    globus_gass_transfer_listener_t           listener;
    globus_gass_transfer_listenerattr_t *     attr              = GLOBUS_NULL;
    globus_gass_transfer_requestattr_t *      reqattr           = GLOBUS_NULL;

    rc = globus_gram_client_callback_allow(globus_l_cache_callback_func,
			                   GLOBUS_NULL,
			                   &callback_contact);
    if ( rc != GLOBUS_SUCCESS )
    {
	printf("Error allowing GRAM callback: %s\n",
	       globus_gram_client_error_string(rc));
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
	return GLOBUS_FAILURE;
    }
    while(!globus_l_cache_monitor_done)
    {
	globus_cond_wait(&globus_l_cache_monitor_cond,
			 &globus_l_cache_monitor_mutex);
    }
    globus_mutex_unlock(&globus_l_cache_monitor_mutex);
    globus_gass_server_ez_shutdown(listener);

    return GLOBUS_SUCCESS;
} /* globus_l_cache_remote_op() */

/******************************************************************************
Function: globus_l_cache_local_op()

Description:

Parameters: 

Returns: 
******************************************************************************/
static
int
globus_l_cache_local_op(
    globus_l_cache_op_t			op,
    char *				tag,
    char *				url,
    char *				name)
{
    globus_gass_cache_t			cache_handle;
    unsigned long			timestamp;
    char *				local_filename = NULL;
    int					rc;
    int					return_value = GLOBUS_SUCCESS;

    
    rc = globus_gass_cache_open(GLOBUS_NULL, &cache_handle);
    if(rc != GLOBUS_SUCCESS)
    {
	globus_libc_fprintf(stderr,
			    "ERROR: Could not open GASS cache because %s\n",
			    globus_gass_cache_error_string(rc));
	return GLOBUS_FAILURE;
    }
    
    switch(op)
    {
    case GASSL_ADD:
	if(name == GLOBUS_NULL)
	{
	    name = url;
	}
	rc = globus_gass_cache_add(cache_handle,
			           name,
			           tag,
			           GLOBUS_TRUE,
			           &timestamp,
			           &local_filename);
	if(rc == GLOBUS_GASS_CACHE_ADD_EXISTS)
	{
	    globus_gass_cache_add_done(cache_handle,
				       name,
				       tag,
				       timestamp);
	}
	else if(rc == GLOBUS_GASS_CACHE_ADD_NEW)
	{
	    globus_gass_copy_handle_t  copy_handle;
	    globus_result_t result;
	    char * fileurl ;
	    return_value = GLOBUS_SUCCESS;

	    if(strcmp(url, "file:/dev/null") != 0 &&
	       strcmp(url, "file:///dev/null") != 0)
	    {
		fileurl = globus_libc_malloc(strlen(local_filename) +
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

		    rc = globus_gass_cache_delete(cache_handle,
						  name,
						  tag,
						  timestamp,
						  GLOBUS_TRUE);
		    return_value = GLOBUS_FAILURE;
		}
	    }
	    if(return_value == GLOBUS_SUCCESS)
	    {
		rc = globus_gass_cache_add_done(cache_handle,
						name,
						tag,
						timestamp);
	    }
	    if(rc != GLOBUS_SUCCESS)
	    {
		globus_libc_printf("Could not unlock cache entry because %s\n",
				   globus_gass_cache_error_string(rc));
		return_value = GLOBUS_FAILURE;
	    }
	}
	else
	{
	    globus_libc_fprintf(
		stderr,
		"Could not add cache entry because %s\n",
		globus_gass_cache_error_string(rc));
	}
	if(local_filename != NULL)
	{
	    free(local_filename);
	}
	break;

    case GASSL_DELETE:
	rc = globus_gass_cache_delete_start(cache_handle,
				            url,
				            tag,
				            &timestamp);
	if(rc != GLOBUS_SUCCESS)
	{
	    globus_libc_fprintf(stderr,
				"Could not delete cache entry because %s\n",
				globus_gass_cache_error_string(rc));
	    return_value = GLOBUS_FAILURE;
	}
	rc = globus_gass_cache_delete(cache_handle,
			              url,
			              tag,
			              timestamp,
			              GLOBUS_TRUE);
	if(rc != GLOBUS_SUCCESS)
	{
	    globus_libc_fprintf(stderr,
				"Could not unlock cache entry because %s\n",
				globus_gass_cache_error_string(rc));
	    return_value = GLOBUS_FAILURE;
	}
	break;

    case GASSL_CLEANUP_TAG:
	if( url == GLOBUS_NULL )
	{
	    rc = globus_gass_cache_cleanup_tag_all( cache_handle, tag );
	}
	else
	{
	    rc = globus_gass_cache_cleanup_tag(cache_handle,
			                       url,
			                       tag);
	}
	if( rc != GLOBUS_SUCCESS)
	{
	    globus_libc_fprintf(stderr,
				"Could not clean up tag because %s\n",
				globus_gass_cache_error_string(rc));
	    return_value = GLOBUS_FAILURE;
	}
	break;

    case GASSL_QUERY_URL:
	rc = globus_gass_cache_query(cache_handle,
				     url,
				     tag,
				     GLOBUS_FALSE,	/* Don't wait 4 lock */
				     &timestamp,
				     &local_filename,
				     GLOBUS_NULL );	/* Dont care */
	if( GLOBUS_SUCCESS == rc )
	{
	    globus_libc_printf( "%s\n", local_filename );
	    globus_free( local_filename );
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
	    return_value = GLOBUS_FAILURE;
	}
	break;

    case GASSL_MANGLE:
    {
	char *	mangled;
	int	mangled_length;
	if ( GLOBUS_NULL != url )
	{
	    rc = globus_gass_cache_mangle_url( cache_handle,
					       url, 
					       &mangled,
					       &mangled_length
					       );
	    if ( GLOBUS_SUCCESS != rc )
	    {
		globus_libc_fprintf(stderr,
				    "Could not mangle URL because %s\n",
				    globus_gass_cache_error_string(rc) );
		return_value = GLOBUS_FAILURE;

		break;
	    }
	    globus_libc_printf( "URL: '%s'\n", mangled );
	    globus_free( mangled );
	}
	if ( GLOBUS_NULL != tag )
	{
	    rc = globus_gass_cache_mangle_tag( cache_handle,
					       tag, 
					       &mangled,
					       &mangled_length
					       );
	    if ( GLOBUS_SUCCESS != rc )
	    {
		globus_libc_fprintf(stderr,
				    "Could not mangle tag because %s\n",
				    globus_gass_cache_error_string(rc) );
		return_value = GLOBUS_FAILURE;
		break;
	    }
	    globus_libc_printf( "TAG: '%s'\n", mangled );
	    globus_free( mangled );
	}
	break;
    }

    case GASSL_DIRS:
    {
	char	*cache_root, *global_root, *local_root, *tmp_root, *log_root;
	char	*global_dir, *local_dir;

	/* Go get 'em all */
	rc = globus_gass_cache_get_cache_dir( cache_handle,
					      &cache_root );
	if ( GLOBUS_SUCCESS == rc )
	{
	    rc = globus_gass_cache_get_dirs( cache_handle,
					     url,
					     tag,
					     &global_root,
					     &local_root,
					     &tmp_root,
					     &log_root,
					     &global_dir,
					     &local_dir );
	}
	if ( GLOBUS_SUCCESS != rc )
	{
	    if ( cache_root )
	    {
		globus_free( cache_root );
	    }
	    globus_libc_fprintf(stderr,
				"Could not get global because %s\n",
				globus_gass_cache_error_string(rc) );
	    return_value = GLOBUS_FAILURE;
	    break;
	}

	/* Dump 'em all out.. */
	if ( cache_root )
	{
	    globus_libc_printf( "CACHE_DIRECTORY: '%s'\n", cache_root );
	    globus_free( cache_root );
	}
	if ( global_root )
	{
	    globus_libc_printf( "GLOBAL_ROOT: '%s'\n", global_root );
	    globus_free( global_root );
	}
	if ( local_root )
	{
	    globus_libc_printf( "LOCAL_ROOT: '%s'\n", local_root );
	    globus_free( local_root );
	}
	if ( tmp_root )
	{
	    globus_libc_printf( "TMP_ROOT: '%s'\n", tmp_root );
	    globus_free( tmp_root );
	}
	if ( log_root )
	{
	    globus_libc_printf( "LOG_ROOT: '%s'\n", log_root );
	    globus_free( log_root );
	}
	if ( global_dir )
	{
	    globus_libc_printf( "GLOBAL_DIR: '%s'\n", global_dir );
	    globus_free( global_dir );
	}
	if ( local_dir )
	{
	    globus_libc_printf( "LOCAL_DIR: '%s'\n", local_dir );
	    globus_free( local_dir );
	}
	break;
    }

    case GASSL_TYPE:
    {
	char	*cache_type;

	/* Go get the cache type string */
	rc = globus_gass_cache_get_cache_type_string( cache_handle,
						      &cache_type );
	if ( GLOBUS_SUCCESS != rc )
	{
	    globus_libc_fprintf(stderr,
				"Could not get global because %s\n",
				globus_gass_cache_error_string(rc) );
	    return_value = GLOBUS_FAILURE;
	    break;
	}

	/* Dump 'em all out.. */
	globus_libc_printf( "CACHE_TYPE: '%s'\n", cache_type );
	globus_free( cache_type );
	break;
    }

    case GASSL_UNKNOWN:
        return_value = GLOBUS_FAILURE;
	break;
    }
    globus_gass_cache_close(&cache_handle);

    return return_value;
} /* globus_l_cache_local_op() */

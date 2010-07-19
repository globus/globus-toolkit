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

/******************************************************************************
gassd.c
 
Description:
    Simple File Server Implementation using GASS Server API
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_gass_server_ez.h"
#include "globus_gss_assist.h"

#include <stdio.h>
#include <stdlib.h>
#include "version.h"  /* provides local_version */


static char *  oneline_usage
   =  "globus-gass-server [-help][-{s,l,t,u,r,w,c,o,e}][-p port]";

static char *  long_usage = \
"\n" \
"Syntax: globus-gass-server [options]\n"\
"        globus-gass-server -version[s]\n"\
"        globus-gass-server -help\n"\
"\n" \
"    Options\n"\
"    -help | -usage\n"\
"        Displays usage\n"
"    -version\n"
"        Displays version\n"
"    -versions\n"
"        Display versions of all modules that this program uses\n"
"    -s | -silent\n"
"        Enable silent mode (Don't output server URL)\n"
"    -l | -linebuffer\n"
"        Enable line buffering (multiple writers will be line-interleaved)\n"
"    -t | -tilde-expand\n"
"        Expand ~ in <URL>/~/filename\n"
"    -u | -user-expand\n"
"        Expand ~username in <URL>/~username/filename\n"
"    -r | -read\n"
"        Enable read access to the local file system\n"
"    -w | -write\n"
"        Enable write access to the local file system\n"
"    -c | -client-shutdown\n"
"        Allow client to trigger shutdown the GASS server\n"
"        See globus-gass-server-shutdown\n"
"    -o\n"
"        Writes to <base URL>/dev/stdout will be forwarded to stdout\n"
"    -e\n"
"        Writes to <base URL>/dev/stderr will be forwarded to stderr\n"
"    -p <port>\n"
"        Start the GASS server using the specified TCP port.\n"
"    -i | -insecure\n"
"        Start the GASS server without using GSSAPI security.\n"
"    -n <options>\n"
"        Disable <options>, which is a string consisting of one or many of\n"
"        the letters \"sclturwoe\"\n\n";




enum { arg_c = 1, arg_s, arg_l, arg_t, arg_u, arg_r, arg_w, arg_o,
       arg_e, arg_n, arg_p, arg_i, arg_num=arg_i };

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

flagdef(arg_c, "-c", "-client-shutdown");
flagdef(arg_s, "-s", "-silent");
flagdef(arg_l, "-l", "-linebuffer");
flagdef(arg_t, "-t", "-tilde-expand");
flagdef(arg_u, "-u", "-user-expand");
flagdef(arg_r, "-r", "-read");
flagdef(arg_w, "-w", "-write");
flagdef(arg_o, "-o", GLOBUS_NULL);
flagdef(arg_e, "-e", GLOBUS_NULL);
flagdef(arg_i, "-i", "-insecure");

int
test_dashp( char *   value,
	    void *   ignored,
	    char **  errmsg )
{
    int  res = (atoi(value) <= 0);
    if (res)
	*errmsg = globus_libc_strdup("argument is not a positive integer");
    return res;
}

int
test_dashn( char *   value,
	    void *   ignored,
	    char **  errmsg )
{
    globus_bool_t  b = GLOBUS_TRUE;
    char *         p;
    int            res = 0;

    for (p=value; (*p) && !res; ++p)
    {
	if (!strchr("sclturwoe",*p))
	{
	    *errmsg =globus_libc_strdup("other characters than \"sclturwoe\"");
	    res = 1;
	}
    }
    return res;
}

oneargdef(arg_n, "-n", GLOBUS_NULL, test_dashn);
oneargdef(arg_p, "-p", "-port", test_dashp);

static globus_args_option_descriptor_t args_options[arg_num];

#define setupopt(id) args_options[id-1] = defname(id)

#define globus_i_gass_server_args_init() \
    setupopt(arg_c); setupopt(arg_s); setupopt(arg_l); setupopt(arg_t); \
    setupopt(arg_u); setupopt(arg_r); setupopt(arg_w); setupopt(arg_o); \
    setupopt(arg_e); setupopt(arg_n); setupopt(arg_p); setupopt(arg_i);


static globus_bool_t done = GLOBUS_FALSE;
#define GASSD_DEFAULT_OPTIONS (GLOBUS_GASS_SERVER_EZ_LINE_BUFFER |\
			       GLOBUS_GASS_SERVER_EZ_TILDE_EXPAND |\
			       GLOBUS_GASS_SERVER_EZ_TILDE_USER_EXPAND |\
			       GLOBUS_GASS_SERVER_EZ_READ_ENABLE |\
			       GLOBUS_GASS_SERVER_EZ_WRITE_ENABLE |\
			       GLOBUS_GASS_SERVER_EZ_STDOUT_ENABLE |\
			       GLOBUS_GASS_SERVER_EZ_STDERR_ENABLE)

globus_mutex_t mutex;
globus_cond_t cond;


void client_shutdown_callback()
{
    globus_mutex_lock(&mutex);
    done = GLOBUS_TRUE;
    globus_cond_signal(&cond);
    globus_mutex_unlock(&mutex);
}

int main(int argc, char **argv)
{
    unsigned short                     port            = 0U;
    globus_bool_t                      silent          = GLOBUS_FALSE;
    unsigned long                      default_options = GASSD_DEFAULT_OPTIONS;
    unsigned long                      options         = 0UL;
    globus_list_t *                    options_found   = GLOBUS_NULL;
    globus_list_t *                    list            = GLOBUS_NULL;
    globus_args_option_instance_t *    instance        = GLOBUS_NULL;
    char *                             p;
    char *                             url;
    int                                rc;
    globus_gass_transfer_listener_t    listener;
    globus_gass_transfer_listenerattr_t  attr;
    char                               * scheme;
    globus_bool_t			insecure = GLOBUS_FALSE;
    globus_gass_transfer_requestattr_t  * reqattr      = GLOBUS_NULL;
    OM_uint32                           maj_stat;
    OM_uint32                           min_stat;
    static gss_cred_id_t                globus_l_gass_server_credential;
    char *				env;


    /*
     *    Check for credentials, if not there, give warning.
     */

    globus_l_gass_server_credential=GSS_C_NO_CREDENTIAL;

    maj_stat = globus_gss_assist_acquire_cred(
        &min_stat,
        GSS_C_ACCEPT,
        &globus_l_gass_server_credential);

    if (maj_stat != GSS_S_COMPLETE)
    {
	fprintf(stderr, "Warning:  You do not have valid credentials at this time\n");
    }

    gss_release_cred(&maj_stat,&globus_l_gass_server_credential);

    globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    globus_module_activate(GLOBUS_GASS_SERVER_EZ_MODULE);

    globus_mutex_init(&mutex, NULL);
    globus_cond_init(&cond, NULL);

    globus_i_gass_server_args_init();

    if ( 0 > (rc = globus_args_scan( &argc,
			       &argv,
			       arg_num,
			       args_options,
			       "globus-gass-server",
			       &local_version,
			       oneline_usage,
			       long_usage,
			       &options_found,
			       GLOBUS_NULL   ) ))  /* error to stderr */
    {	 
	globus_module_deactivate_all();
	exit(rc == GLOBUS_FAILURE ? 1 : 0);
    }

    for (list = options_found; 
	 !globus_list_empty(list); 
	 list = globus_list_rest(list))
    {
	instance = globus_list_first(list);
	
	switch(instance->id_number)
	{
	case arg_c:
	    options |= GLOBUS_GASS_SERVER_EZ_CLIENT_SHUTDOWN_ENABLE;
	    break;
	case arg_s:
	    silent = GLOBUS_TRUE;
	    break;
	case arg_l:
	    options |= GLOBUS_GASS_SERVER_EZ_LINE_BUFFER;
	    break;
	case arg_t:
	    options |= GLOBUS_GASS_SERVER_EZ_TILDE_EXPAND;
	    break;
	case arg_u:
	    options |= GLOBUS_GASS_SERVER_EZ_TILDE_USER_EXPAND;
	    break;
	case arg_r:
	    options |= GLOBUS_GASS_SERVER_EZ_READ_ENABLE;
	    break;
	case arg_w:
	    options |= GLOBUS_GASS_SERVER_EZ_WRITE_ENABLE;
	    break;
	case arg_o:
	    options |= GLOBUS_GASS_SERVER_EZ_STDOUT_ENABLE;
	    break;
	case arg_e:
	    options |= GLOBUS_GASS_SERVER_EZ_STDERR_ENABLE;
	    break;
	case arg_p:
	    port = (unsigned short) atoi(instance->values[0]);
	    break;
	case arg_i:
	    insecure = GLOBUS_TRUE;
	    break;
	case arg_n:
	    for (p=instance->values[0]; (*p); ++p)
	    {
		switch(*p)
		{
		case 's':
		    silent = GLOBUS_FALSE;
		    break;
		case 'l':
		    options &= ~GLOBUS_GASS_SERVER_EZ_LINE_BUFFER;
		    break;
		case 't':
		    options &= ~GLOBUS_GASS_SERVER_EZ_TILDE_EXPAND;
		    break;
		case 'u':
		    options &= ~GLOBUS_GASS_SERVER_EZ_TILDE_USER_EXPAND;
		    break;
		case 'r':
		    options &= ~GLOBUS_GASS_SERVER_EZ_READ_ENABLE;
		    break;
		case 'w':
		    options &= ~GLOBUS_GASS_SERVER_EZ_WRITE_ENABLE;
		    break;
		case 'o':
		    options &= ~GLOBUS_GASS_SERVER_EZ_STDOUT_ENABLE;
		    break;
		case 'e':
		    options &= ~GLOBUS_GASS_SERVER_EZ_STDERR_ENABLE;
		    break;
		case 'c':
		    options &= ~GLOBUS_GASS_SERVER_EZ_CLIENT_SHUTDOWN_ENABLE;
		    break;
		}
	    }
	    break;
	}
    }

    if(insecure)
    {
        scheme = "http";
    }
    else
    {
        scheme = "https";
    }

    globus_gass_transfer_listenerattr_init(&attr,
					   scheme);
    if(port != 0)
    {
        rc=globus_gass_transfer_listenerattr_set_port(&attr,
						      port);
	if(rc!=GLOBUS_SUCCESS)
	{
	    exit(1);
	}
    }
    globus_args_option_instance_list_free( &options_found );

    if(options == 0)
	options = default_options;

    rc = globus_gass_server_ez_init(
		&listener,
        	&attr,
        	scheme,
        	reqattr,
        	options,
        	options & GLOBUS_GASS_SERVER_EZ_CLIENT_SHUTDOWN_ENABLE
        	? client_shutdown_callback
        	: (globus_gass_server_ez_client_shutdown_t) GLOBUS_NULL);

    if(rc != GLOBUS_SUCCESS)
    {
	globus_gass_transfer_listenerattr_get_port(&attr,
					    	   &port);
	if(port == 0)
	{
	    globus_libc_printf("Error: Cannot listen on port\n");
	    return -1;
	}
	else
	{
	    globus_libc_printf("Error: Failed to initialize gass server library\n");
	    return -1;
	}
    }
    if(!silent)
    {
	url=globus_gass_transfer_listener_get_base_url(listener);	
	globus_libc_printf("%s\n",url);
	fflush(stdout);
    }

    /* need to either cond_wait,
       call globus_gass_simple_server_poll() occasionally, or be
       running with threaded globus_nexus to service gass requests
       */
    globus_mutex_lock(&mutex);
    while(!done)
    {
	globus_cond_wait(&cond, &mutex);
    }
    globus_mutex_unlock(&mutex);

    globus_cond_destroy(&cond);
    globus_mutex_destroy(&mutex);
    
    globus_gass_server_ez_shutdown(listener);

    globus_module_deactivate(GLOBUS_GASS_SERVER_EZ_MODULE);
    return 0;
}


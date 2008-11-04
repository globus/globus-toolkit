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
globusrun.c

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

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>

#if !defined(PATH_MAX) && defined(MAXPATHLEN)
#   define PATH_MAX MAXPATHLEN
#endif

#include "globus_nexus.h"
#include "globus_duroc_control.h"
#include "globus_gram_client.h"
#include "globus_gram_protocol.h"
#include "globus_gass_server_ez.h"
#include "globus_rsl.h"

#include "globus_rsl_assist.h"
#include "globus_gss_assist.h"
#include "version.h" /* provides local_version */


/******************************************************************************
                               Type definitions
******************************************************************************/
typedef struct globus_i_globusrun_gram_monitor_s
{
    globus_bool_t  done;
    globus_mutex_t mutex;
    globus_cond_t  cond;

    globus_bool_t  verbose;
    unsigned long  job_state;
    int            submit_done;
    int            failure_code;
    char *         failure_message;
    char *         job_contact;
} globus_i_globusrun_gram_monitor_t;


static
globus_io_secure_delegation_mode_t  globus_l_delegation_mode =
        GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY;

/*****************************************************************************
                          Module specific prototypes
*****************************************************************************/

/**** Creation of RSL Substitution variable for GASS url ****/
static int
globus_l_globusrun_rsl_gass_subst(globus_rsl_t *  request,
				  char *          globusrun_url_string);

/**** RSL Substitution of GASS redirection of stdout and stderr ****/
static int
globus_l_globusrun_rsl_output_subst(globus_rsl_t *  request,
				    char *          globusrun_url_string);

/**** RSL Substitution of (dryrun=yes) for -dryrun flag ****/
static int
globus_l_globusrun_rsl_dryrun_subst(globus_rsl_t *request);

/**** Run job using GRAM ****/
static int
globus_l_globusrun_gramrun(char *          request_string,
			   unsigned long   options,
			   char *          rm_contact);

/**** Run job using DUROC ****/
static int
globus_l_globusrun_durocrun(char *         request_ast,
			    unsigned long  options,
			    int            mpirun_version);

static int
globus_l_globusrun_fault_callback(void *   user_arg,
				  int      fault_code);

static char **
globus_l_globusrun_duroc_subjob_labels(char *   request_string);

static
int
globus_l_globusrun_refresh_proxy(
    char *			job_contact);
static
int
globus_l_globusrun_stop_manager(
    char *			job_contact);

static char *
globus_l_globusrun_get_credential(void);

static int
globus_l_globusrun_kill_job(char * job_contact);

static int
globus_l_globusrun_status_job(char * job_contact);

static
void
globus_l_submit_callback(
    void *                              user_callback_arg,
    globus_gram_protocol_error_t        operation_failure_code,
    const char *                        job_contact,
    globus_gram_protocol_job_state_t    job_state,
    globus_gram_protocol_error_t        job_failure_code);

/**** Support for SIGINT handling ****/
static RETSIGTYPE
globus_l_globusrun_sigint_handler(int dummy);

/**** add by bresnaha ******/
static globus_callback_handle_t          globus_l_run_callback_handle;
/**** end add by bresnaha ******/

static int
globus_l_globusrun_signal(int signum, RETSIGTYPE (*func)(int));

#if defined(BUILD_LITE)
    static void globus_l_globusrun_signal_wakeup(
                   void *                              user_args);

#   define globus_l_globusrun_remove_cancel_poll()  \
    globus_callback_unregister(globus_l_run_callback_handle, GLOBUS_NULL, GLOBUS_NULL, GLOBUS_NULL);
#else
#   define globus_l_globusrun_remove_cancel_poll()
#endif

/*****************************************************************************
                          Module specific variables
*****************************************************************************/
enum
{
    GLOBUSRUN_ARG_INTERACTIVE           = 1,
    GLOBUSRUN_ARG_QUIET                 = 2,
    GLOBUSRUN_ARG_DRYRUN                = 4,
    GLOBUSRUN_ARG_PARSE_ONLY            = 8,
    GLOBUSRUN_ARG_AUTHENTICATE_ONLY     = 16,
    GLOBUSRUN_ARG_USE_GASS              = 32,
    GLOBUSRUN_ARG_ALLOW_READS           = 64,
    GLOBUSRUN_ARG_ALLOW_WRITES          = 128,
    GLOBUSRUN_ARG_IGNORE_CTRLC          = 256,
    GLOBUSRUN_ARG_BATCH                 = 512,
    GLOBUSRUN_ARG_STATUS                = 1024,
    GLOBUSRUN_ARG_LIST                  = 2048,
    GLOBUSRUN_ARG_BATCH_FAST            = 4096
};

static globus_byte_t globus_l_globusrun_file_version=1;

static char *  oneline_usage
   =  "globusrun [-help] [-f RSL file] [-s][-b][-d][...] [-r RM] [RSL]";

static char *  long_usage = \
"\n" \
"Syntax: globusrun [options] [RSL String]\n"\
"        globusrun -version[s]\n"\
"        globusrun -help\n"\
"\n" \
"    Options\n"\
"    -help | -usage\n"\
"           Display help\n"\
"    -version\n"\
"           Display version\n"\
"    -versions\n"\
"           Display versions of all activated modules\n"\
"    -i | -interactive \n"\
"           Run globusrun in interactive mode (multirequests only)\n"\
"    -f <rsl filename> | -file <rsl filename> \n"\
"           Read RSL from the local file <rsl filename>. The RSL can\n"\
"           be either a single job request, or a multirequest\n"\
"    -q | -quiet\n"\
"           Quiet mode (do not print diagnostic messages)\n"\
"    -o | -output-enable\n"\
"           Use the GASS Server library to redirect standout output\n"\
"           and standard error to globusrun. Implies -quiet\n"\
"    -s | -server\n"\
"           $(GLOBUSRUN_GASS_URL) can be used to access files local\n"\
"           to the submission machine via GASS. Implies -output-enable\n"\
"           and -quiet\n"\
"    -w | -write-allow\n"\
"           Enable the GASS Server library and allow writing to\n"\
"           GASS URLs. Implies -server and -quiet.\n"\
"    -mpirun <integer>\n"\
"           Currently a no-op.\n"\
"    -r <resource manager> | -resource  <resource manager> \n"\
"           Submit the RSL job request to the specified resource manager.\n"\
"           A resource manager can be specified in the following ways: \n\n"\
"           host\n"\
"           host:port\n"\
"           host:port/service\n"\
"           host/service\n"\
"           host:/service\n"\
"           host::subject\n"\
"           host:port:subject\n"\
"           host/service:subject\n"\
"           host:/service:subject\n"\
"           host:port/service:subject\n\n"\
"           For those resource manager contacts which omit the port, \n"\
"           service or subject field the following defaults are used:\n\n"\
"           port = 2119 \n"\
"           service = jobmanager \n"\
"           subject = subject based on hostname\n\n"\
"           This is a required argument when submitting a single RSL\n"\
"           request\n"\
"    -n | -no-interrupt\n"\
"           Cause SIGINT to terminate globusrun, while leaving the\n"\
"           submitted job to run to completion. By default the SIGINT\n"\
"           signal will be trapped and the job will be terminated\n"\
"    -k | -kill <job ID>\n"\
"           Kill a disconnected globusrun job\n"\
"    -status <job ID>\n"\
"           Print the current status of the specified job.\n"\
"    -b | -batch\n"\
"           Cause globusrun to terminate after the job is successfully\n"\
"           submitted to the scheduler. Useful for batch jobs. This option\n"\
"           cannot be used together with -interactive, and is also\n"\
"           incompatible with multi-request jobs.\n" \
"           If used with -s, files may be staged in to the job, but stdout\n"\
"           and stderr will not be redirected.\n"\
"           The \"handle\" or job ID of the submitted job will be written on\n"\
"           stdout.\n"\
"    -F | -fast-batch\n"\
"           Similar to -b but will exit as soon as the job has been sent\n"\
"           to the GRAM job manager service without waiting for a callback\n"\
"           with job submission state. Useful for hosts which are not able\n"\
"           to receive job state callbacks.\n"\
"    -full-proxy | -D\n"\
"           Delegate a full proxy instead of a limited proxy.\n"\
"    -refresh-proxy | -y <job ID>\n"\
"           Cause globusrun to delegate a new proxy to the job named by the\n"\
"           <job ID>\n"\
"    -stop-manager <job  ID>\n"\
"           Cause globusrun to stop the job manager, without killing the\n"\
"           job. If the save_state RSL attribute is present, then a\n"\
"           job manager can be restarted by using the restart RSL attribute.\n"\
"\n"\
"    Diagnostic Options\n"\
"    -p | -parse\n"\
"           Parse and validate the RSL only. Do not submit the job to\n"\
"           a GRAM gatekeeper\n"\
"    -a | -authenticate-only\n"\
"           Submit a gatekeeper \"ping\" request only. Do not parse the\n"\
"           RSL or submit the job request. Requires the -resource-manger \n"\
"           argument\n"\
"    -d | -dryrun\n"\
"           Submit the RSL to the job manager as a \"dryrun\" test\n"\
"           The request will be parsed and authenticated. The job manager\n"\
"           will execute all of the preliminary operations, and stop\n"\
"           just before the job request would be executed\n"\
"\n";

#if 0 /* unimplemented */

"    -mdshost   <mds ldap server hostname>\n"\
"    -mdsport   <mds ldap server port to contact>\n"\
"    -T | -mdstimeout <timeout in seconds>\n"\
"    -mdsbasedn <mds ldap server hostname>\n"\
"           mdshost, mdsport and mdsbasedn let you overwrite the default\n"\
"           information necessary to contact the MDS ldap server. Used only\n"\
"           together with the option -list\n"\
"           Those options can also be set using the environment variable \n"\
"           GRID_INFO_HOST, GRID_INFO_PORT, GRID_INFO_TIMEOUT and\n"\
"           GRID_INFO_BASEDN.\n"\

"    -l | -list\n"\
"           List disconnected globusrun jobs\n"

#endif

#define globusrun_l_args_error(a) \
{ \
    globus_libc_fprintf(stderr, \
			"\nERROR: " \
			a \
			"\n\nSyntax: %s\n" \
			"\nUse -help to display full usage\n", \
			oneline_usage); \
    globus_module_deactivate_all(); \
    exit(-1); \
}

#define globusrun_l_args_error_fmt(fmt,arg) \
{ \
    globus_libc_fprintf(stderr, \
			"\nERROR: " \
			fmt \
			"\n\nSyntax: %s\n" \
			"\nUse -help to display full usage\n", \
			arg, oneline_usage); \
    globus_module_deactivate_all(); \
    exit(-1); \
}



int
test_job_id( char *    value,
	     void *    ignored,
	     char **   errmsg )
{
    int res = (strncmp(value,"https://", strlen("https://")));
    if (res)
	*errmsg = globus_libc_strdup("invalid format of job ID");
    return res;
}

int
test_hostname( char *   value,
	       void *   ignored,
	       char **  errmsg )
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
    if (hostent == GLOBUS_NULL)
	*errmsg = globus_libc_strdup("cannot resolve hostname");
    return rc;
}

int
test_integer( char *   value,
	      void *   ignored,
	      char **  errmsg )
{
    int  res = (atoi(value) <= 0);
    if (res)
	*errmsg = globus_libc_strdup("argument is not a positive integer");
    return res;
}


enum { arg_i = 1, arg_q, arg_o, arg_s, arg_w, arg_n, arg_l, arg_b,
	     arg_p, arg_d, arg_a,
	     arg_r, arg_f, arg_k, arg_y, arg_mpirun, arg_status,
	     arg_stop_manager,
	     arg_mdshost, arg_mdsport, arg_mdsbasedn, arg_mdstimeout,
	     arg_F, arg_full_proxy,
	     arg_num = arg_full_proxy };

#define listname(x) x##_aliases
#define namedef(id,alias1,alias2) \
static char * listname(id)[] = { alias1, alias2, GLOBUS_NULL }

#define defname(x) x##_definition
#define flagdef(id,alias1,alias2) \
namedef(id,alias1,alias2); \
static globus_args_option_descriptor_t defname(id) = { id, listname(id), 0, \
						GLOBUS_NULL, GLOBUS_NULL }
#define funcname(x) x##_predicate_test
#define paramsname(x) x##_predicate_params
#define oneargdef(id,alias1,alias2,testfunc,testparams) \
namedef(id,alias1,alias2); \
static globus_args_valid_predicate_t funcname(id)[] = { testfunc }; \
static void* paramsname(id)[] = { (void *) testparams }; \
globus_args_option_descriptor_t defname(id) = \
    { (int) id, (char **) listname(id), 1, funcname(id), (void **) paramsname(id) }

flagdef(arg_i, "-i", "-interactive");
flagdef(arg_q, "-q", "-quiet");
flagdef(arg_o, "-o", "-output-enable");
flagdef(arg_s, "-s", "-server");
flagdef(arg_w, "-w", "-write-allow");
flagdef(arg_n, "-n", "-no-interrupt");
flagdef(arg_l, "-l", "-list");
flagdef(arg_b, "-b", "-batch");
flagdef(arg_p, "-p", "-parse");
flagdef(arg_d, "-d", "-dryrun");
flagdef(arg_a, "-a", "-authenticate-only");
flagdef(arg_F, "-F", "-fast-batch");
flagdef(arg_full_proxy, "-D", "-full-proxy");

static int arg_f_mode = O_RDONLY;

    oneargdef(arg_f, "-f", "-file", globus_validate_filename, &arg_f_mode);
    oneargdef(arg_r, "-r", "-resource", GLOBUS_NULL, GLOBUS_NULL);
    oneargdef(arg_k, "-k", "-kill", test_job_id, GLOBUS_NULL);
    oneargdef(arg_y, "-y", "-refresh-proxy", test_job_id, GLOBUS_NULL);
    oneargdef(arg_stop_manager, "-stop-manager", NULL, test_job_id, GLOBUS_NULL);
    oneargdef(arg_mpirun, "-mpirun", GLOBUS_NULL, test_integer, GLOBUS_NULL);
    oneargdef(arg_status, "-status", GLOBUS_NULL, test_job_id, GLOBUS_NULL);
    oneargdef(arg_mdshost, "-mdshost", GLOBUS_NULL, test_hostname, GLOBUS_NULL);
    oneargdef(arg_mdsport, "-mdsport", GLOBUS_NULL, test_integer, GLOBUS_NULL);
    oneargdef(arg_mdstimeout, "-T", "-mdstimeout", test_integer, GLOBUS_NULL);
    oneargdef(arg_mdsbasedn, "-mdsbasedn", GLOBUS_NULL, GLOBUS_NULL, GLOBUS_NULL);

    static globus_args_option_descriptor_t args_options[arg_num];

#define setupopt(id) args_options[id-1] = defname(id)

#define globusrun_i_args_init() \
	setupopt(arg_i); setupopt(arg_q); setupopt(arg_o); setupopt(arg_s); \
	setupopt(arg_w); setupopt(arg_n); setupopt(arg_l); setupopt(arg_b); \
	setupopt(arg_p); setupopt(arg_d); setupopt(arg_a); \
	setupopt(arg_r); setupopt(arg_f); setupopt(arg_k); setupopt(arg_y); \
	setupopt(arg_mpirun); setupopt(arg_stop_manager); \
	setupopt(arg_status); setupopt(arg_mdshost); setupopt(arg_mdsport); \
	setupopt(arg_mdsbasedn); setupopt(arg_mdstimeout); setupopt(arg_F); \
	setupopt(arg_full_proxy);

    static globus_bool_t globus_l_globusrun_ctrlc = GLOBUS_FALSE;
    static globus_bool_t globus_l_globusrun_ctrlc_handled = GLOBUS_FALSE;

    /******************************************************************************
    Function: main()

    Description:

    Parameters:

    Returns:
    ******************************************************************************/
    int
    main(int argc, char* argv[])
    {
	char *                             request_string    = GLOBUS_NULL;
	char *                             request_file      = GLOBUS_NULL;
	char *                             rm_contact        = GLOBUS_NULL;
	char *                             program           = GLOBUS_NULL;
	globus_bool_t                      ignore_ctrlc      = GLOBUS_FALSE;
	globus_rsl_t *                     request_ast       = GLOBUS_NULL;
	globus_list_t *                    options_found     = GLOBUS_NULL;
	globus_list_t *                    list              = GLOBUS_NULL;
	globus_args_option_instance_t *    instance          = GLOBUS_NULL;
	unsigned short                     gass_port         = 0;
	unsigned long                      options           = 0UL;
	int                                mpirun_version    = 0;
	int                                err               = GLOBUS_SUCCESS;
	globus_gass_transfer_listener_t   listener		 =GLOBUS_NULL;
	globus_gass_transfer_listenerattr_t * attr		 =GLOBUS_NULL;
	char *                             scheme		 =GLOBUS_NULL;
	globus_gass_transfer_requestattr_t * reqattr	 =GLOBUS_NULL;
	const char *                             activation_err  = GLOBUS_NULL;

	err = globus_module_activate(GLOBUS_COMMON_MODULE);
	if ( err != GLOBUS_SUCCESS )
	{
	    activation_err = "Error initializing globus\n";
	}

	if(activation_err == NULL)
	{
	    err = globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
	    if ( err != GLOBUS_SUCCESS )
	    {
		activation_err = "Error initializing GSI GSS ASSIST\n";
		return 1;
	    }
        }

	if(activation_err == NULL)
	{
	    err = globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);
	    if ( err != GLOBUS_SUCCESS)
	    {
		activation_err = globus_gram_protocol_error_string(err);
	    }
	}
	if(activation_err == NULL)
	{
	    err = globus_module_activate(GLOBUS_NEXUS_MODULE);
	    if ( err != GLOBUS_SUCCESS )
	    {
		activation_err = "Error initializing nexus\n";
	    }
	}
	if(activation_err == NULL)
	{
	    err = globus_module_activate(GLOBUS_GASS_SERVER_EZ_MODULE);
	    if ( err != GLOBUS_SUCCESS )
	    {
		activation_err = "Error initializing gass_server_ez\n";
	    }
	}
	if(activation_err == NULL)
	{
	    err = globus_module_activate(GLOBUS_DUROC_CONTROL_MODULE);
	    if ( err != GLOBUS_SUCCESS )
	    {
		activation_err = "Error initializing duroc control\n";
	    }
	}
        
	if (strrchr(argv[0],'/'))
	    program = strrchr(argv[0],'/') + 1;
	else
	    program = argv[0];

	globusrun_i_args_init();

	if ( 0 > (err = globus_args_scan( &argc,
				   &argv,
				   arg_num,
				   args_options,
				   "globusrun",
				   &local_version,
				   oneline_usage,
				   long_usage,
				   &options_found,
				   GLOBUS_NULL   )) )  /* error on argument line */
	{
	    globus_module_deactivate_all();
	    exit(err == GLOBUS_FAILURE ? 1 : 0);
	}

	/* maximum one unflagged argument should remain: the RSL string */
	if (argc > 2)
	{
	    globusrun_l_args_error("too many request strings specified");
	}
	
	if (argc > 1)
	    request_string = globus_libc_strdup(argv[1]);

	if (activation_err != NULL)
	{
	    fprintf(stderr, "%s", activation_err);

	    exit(-2);
	}

	for (list = options_found;
	     !globus_list_empty(list);
	     list = globus_list_rest(list))
	{
	    instance = globus_list_first(list);

	    switch(instance->id_number)
	    {
	    case arg_i:
		options |= GLOBUSRUN_ARG_INTERACTIVE;
		break;

	    case arg_w:
		options |= GLOBUSRUN_ARG_ALLOW_WRITES;
	    case arg_s:
		options |= GLOBUSRUN_ARG_ALLOW_READS;
	    case arg_o:
		options |= GLOBUSRUN_ARG_USE_GASS;
	    case arg_q:
		options |= GLOBUSRUN_ARG_QUIET;
		break;

	    case arg_n:
		options |= GLOBUSRUN_ARG_IGNORE_CTRLC;
		ignore_ctrlc = GLOBUS_TRUE;
		break;

	    case arg_a:
		options |= GLOBUSRUN_ARG_AUTHENTICATE_ONLY;
		break;

	    case arg_p:
		options |= GLOBUSRUN_ARG_PARSE_ONLY;
		break;

	    case arg_b:
		options |= GLOBUSRUN_ARG_BATCH;
		break;

	    case arg_d:
		options |= GLOBUSRUN_ARG_DRYRUN;
		break;

            case arg_F:
                options |= GLOBUSRUN_ARG_BATCH_FAST|GLOBUSRUN_ARG_BATCH;
                break;

	    case arg_r:
		rm_contact=globus_libc_strdup(instance->values[0]);
		if(rm_contact == GLOBUS_NULL)
		{
		    globusrun_l_args_error_fmt("resolving resource manager %s",
					       instance->values[0] );
		}
		break;

	    case arg_f:
		request_file = globus_libc_strdup(instance->values[0]);
	    break;

	case arg_k:
	    return(globus_l_globusrun_kill_job(instance->values[0]));
	    break;

	case arg_full_proxy:
            globus_l_delegation_mode =
                    GLOBUS_IO_SECURE_DELEGATION_MODE_FULL_PROXY;
	    break;

	case arg_y:
	    return globus_l_globusrun_refresh_proxy(instance->values[0]);
	    break;
	case arg_mpirun:
	    /* no-op */
	    break;

	case arg_stop_manager:
	    return globus_l_globusrun_stop_manager(instance->values[0]);

	case arg_status:
	    return(globus_l_globusrun_status_job(instance->values[0]));
	    break;

	case arg_mdshost:
	    globus_libc_setenv("GRID_INFO_HOST", instance->values[0], 1);
	    break;

	case arg_mdsport:
	    globus_libc_setenv("GRID_INFO_PORT", instance->values[0], 1);
	    break;

	case arg_mdsbasedn:
	    globus_libc_setenv("GRID_INFO_BASEDN", instance->values[0], 1);
	    break;

	case arg_mdstimeout:
	    globus_libc_setenv("GRID_INFO_TIMEOUT", instance->values[0], 1);
	    break;

	default:
	    globusrun_l_args_error_fmt("parse panic, arg id = %d",
				       instance->id_number );
	    break;
	}
    }

    globus_args_option_instance_list_free( &options_found );

    if ( (options & GLOBUSRUN_ARG_BATCH) &&
	 (options & GLOBUSRUN_ARG_INTERACTIVE) )
    {
	globusrun_l_args_error("option -i and -b are exclusive");
    }

    if(options & GLOBUSRUN_ARG_AUTHENTICATE_ONLY)
    {
	if(!rm_contact)
	{
	    globusrun_l_args_error("no resource manager contact specified"
				   "for authentication test" );
	}
	err = globus_gram_client_ping(rm_contact);
	if(err == GLOBUS_SUCCESS)
	{
	    globus_libc_fprintf(stdout,
				"\nGRAM Authentication test successful\n");
	    return 0;
	}
	else
	{
	    globus_libc_fprintf(stdout,
				"\nGRAM Authentication test failure: %s\n",
				globus_gram_protocol_error_string(err));
	    return 1;
	}
    }  /* authentication test */
    if ( (request_string!=NULL)
	 && (request_file!=NULL) )
    {
	    globusrun_l_args_error("cannot specify both request string and "
				   "request file" );
    }

    if ( request_file != NULL)
    {
	int fd;

	fd = globus_libc_open (request_file, O_RDONLY, 0600);
	if ( fd >= 0 )
	{
	    int i;
	    char c;
	    globus_off_t len = 0;

	    len = globus_libc_lseek(fd, 0, SEEK_END);
	    globus_libc_lseek(fd, 0, SEEK_SET);

	    request_string = (char *) malloc (sizeof (char)
					      * (len + 1));
	    i=0;

	    while ( (i<len)  && read(fd, &c, 1) > 0)
	    {
		request_string[i] = c;
		i++;
	    }
	    request_string[i] = '\0';

	    free (request_file);
	    request_file = NULL;

	    globus_libc_close (fd);
	}
	else
	{
	    globusrun_l_args_error_fmt("cannot open request file: %s",
				       request_file);
	}
    }

    if ( (request_string==NULL)
	 && (request_file==NULL))
    {
	globusrun_l_args_error("must specify a request string or "
			       "request file");
    }

    request_ast = globus_rsl_parse(request_string);
    if(request_ast == GLOBUS_NULL)
    {
	globusrun_l_args_error_fmt("cannot parse RSL %s",
				   request_string );
    }

    if(!globus_rsl_is_boolean(request_ast))
    {
	globus_libc_fprintf(stderr,
			    "%s Error: Bad RSL\n",
			    program);
	err=GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL;
	return err;
    }

    if(options & GLOBUSRUN_ARG_PARSE_ONLY)
    {
	globus_libc_printf("RSL Parsed Successfully...\n");
	return 0;
    }

    if((!globus_rsl_is_boolean_multi(request_ast)) &&
       rm_contact == GLOBUS_NULL)
    {
	globusrun_l_args_error("no resource manager contact");
    }

    /* intialize and start nexus */
    globus_nexus_enable_fault_tolerance(globus_l_globusrun_fault_callback,
					GLOBUS_NULL);


    if (options & GLOBUSRUN_ARG_USE_GASS)
    {
	/* transform the RSL to send "free" output streams to our
	 * stdout/stderr via gass, rather than to /dev/null */
	char *gass_server_url = GLOBUS_NULL;
	unsigned long server_ez_opts=0UL;
	char *url_relation_string;
	char *relation_format="rsl_substitution=(GLOBUSRUN_GASS_URL %s)";

	server_ez_opts |=
	    GLOBUS_GASS_SERVER_EZ_LINE_BUFFER
	    | GLOBUS_GASS_SERVER_EZ_TILDE_EXPAND
	    | GLOBUS_GASS_SERVER_EZ_TILDE_USER_EXPAND;

	if ( !(options & GLOBUSRUN_ARG_BATCH) ) {
	    server_ez_opts |=
		GLOBUS_GASS_SERVER_EZ_STDOUT_ENABLE
		| GLOBUS_GASS_SERVER_EZ_STDERR_ENABLE;

	    if(options & GLOBUSRUN_ARG_ALLOW_WRITES)
	    {
		server_ez_opts |=
		    GLOBUS_GASS_SERVER_EZ_WRITE_ENABLE;
	    }
	}

	if(options & GLOBUSRUN_ARG_ALLOW_READS)
	{
	    server_ez_opts |=
		GLOBUS_GASS_SERVER_EZ_READ_ENABLE;
	}

	err = globus_gass_server_ez_init(&listener,
                                         attr,
                                         scheme,
                                         reqattr,
                                         server_ez_opts,
                                         NULL);

 	gass_server_url=globus_gass_transfer_listener_get_base_url(listener);

	if((err != GLOBUS_SUCCESS))
	{
	    globus_libc_fprintf(stderr,
				"%s Error: initializing GASS (%d)\n",
				program,
				err);
	    goto hard_exit;
	}

	url_relation_string = globus_malloc(strlen(relation_format) +
					    strlen(gass_server_url));

	if(url_relation_string == GLOBUS_NULL)
	{
	    err=GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

	    globus_libc_fprintf(stderr,
				"%s Error: Malloc failed\n",
				program);
	    goto hard_exit;
	}


	globus_libc_lock();
	sprintf(url_relation_string,
		relation_format,
		gass_server_url);
	globus_libc_unlock();

	/* replace stdout and stderr in request if not in batch mode*/
	if ( !(options & GLOBUSRUN_ARG_BATCH) ) {
	    globus_l_globusrun_rsl_output_subst(request_ast,
						url_relation_string);
	}

	globus_l_globusrun_rsl_gass_subst(request_ast,
					  url_relation_string);

	globus_free (url_relation_string);

	gass_server_url = NULL;
    }
    if(options & GLOBUSRUN_ARG_DRYRUN)
    {
	globus_l_globusrun_rsl_dryrun_subst(request_ast);
    }
    if(request_string)
    {
	globus_free(request_string);
    }
    request_string = globus_rsl_unparse(request_ast);

    if(globus_rsl_is_boolean_multi(request_ast))
    {
	char *req;

	if ( options & GLOBUSRUN_ARG_BATCH )
	{
	    globusrun_l_args_error("batch mode (-b) not supported for multi-requests");
	}

	if(rm_contact != GLOBUS_NULL)
	{
	    globus_libc_fprintf(stderr,
				"%s warning: ignoring "
				"resource manager contact for mulirequest\n",
				program);
	}
	req = globus_rsl_unparse(request_ast);

	err = globus_l_globusrun_durocrun(req,
					      options,
					      mpirun_version);
	globus_free(req);
    }
    else
    {
	char *req;

	req = globus_rsl_unparse(request_ast);

	err = globus_l_globusrun_gramrun(req,
					 options,
					 rm_contact);
	globus_free(req);
    }

hard_exit:
    globus_l_globusrun_signal(SIGINT, SIG_DFL);

    if ( (options & GLOBUSRUN_ARG_USE_GASS) &&
	 (gass_port != 0U))
    {
	globus_gass_server_ez_shutdown (listener);
    }

    globus_free (request_string);

    globus_module_deactivate_all();

    return err;
} /* main() */

/******************************************************************************
Function: globus_l_globusrun_new_subst()

Description:

Parameters:

Returns:
******************************************************************************/
static globus_rsl_t *
globus_l_globusrun_new_subst(char *var)
{
    globus_rsl_t *relation;
    char *relation_format = "%s=$(GLOBUSRUN_GASS_URL)/dev/%s";
    char *val;

    val = globus_malloc((2 * strlen(var)) +
			strlen(relation_format));

    globus_libc_lock();
    sprintf(val, relation_format, var, var);
    globus_libc_unlock();

    relation = globus_rsl_parse(val);

    globus_free(val);

    return relation;
} /* globus_l_globusrun_new_subst() */

/******************************************************************************
Function: globus_l_globusrun_var_exists()

Description:

Parameters:

Returns:
******************************************************************************/
static globus_bool_t
globus_l_globusrun_var_exists(globus_rsl_t *subrequest,
			      char *val)
{
    if(globus_rsl_is_relation_eq(subrequest))
    {
	if(strcmp(globus_rsl_relation_get_attribute(subrequest), val) == 0)
	{
	    return GLOBUS_TRUE;
	}
    }
    return GLOBUS_FALSE;
} /* globus_l_globusrun_var_exists() */

/******************************************************************************
Function: globus_l_globusrun_rsl_dryrun_subst()

Description:

Parameters:

Returns:
******************************************************************************/
static int
globus_l_globusrun_rsl_dryrun_subst(globus_rsl_t *request)
{
    int level = 0;

    /* for multirequests */
    if(globus_rsl_is_boolean_multi(request))
    {
	globus_list_t *lists;

	lists = (globus_list_t *) globus_rsl_boolean_get_operand_list(request);

	while(!globus_list_empty(lists))
	{
	    level += globus_l_globusrun_rsl_dryrun_subst(
		globus_list_first(lists));
	    lists=globus_list_rest(lists);
	}
    }
    else if(globus_rsl_is_boolean(request))
    {
	globus_list_t *l;
	globus_bool_t dryrun_exists = GLOBUS_FALSE;

	l = globus_rsl_boolean_get_operand_list(request);
	while(!globus_list_empty(l))
	{

	    if(globus_rsl_is_boolean(globus_list_first(l)))
	    {
		level += globus_l_globusrun_rsl_dryrun_subst(
		    globus_list_first(l));
	    }

	    if(globus_l_globusrun_var_exists(globus_list_first(l),
						    "dryrun"))
	    {
		dryrun_exists = GLOBUS_TRUE;
	    }

	    l = globus_list_rest(l);
	}

	if(level == 0)
	{
	    if(!dryrun_exists)
	    {
		globus_list_insert(
		    globus_rsl_boolean_get_operand_list_ref(request),
		    globus_rsl_parse("dryrun = yes"));

	    }
	    level++;
	}
    }
    return level;
} /* globus_l_globusrun_rsl_dryrun_subst() */

/******************************************************************************
Function: globus_l_globusrun_rsl_gass_subst()

Description:

Parameters:

Returns:
******************************************************************************/
static int
globus_l_globusrun_rsl_gass_subst(globus_rsl_t *request,
				    char *globusrun_gass_url_string)
{
    int level = 0;

    /* for multirequests */
    if(globus_rsl_is_boolean_multi(request))
    {
	globus_list_t *lists;

	lists = (globus_list_t *) globus_rsl_boolean_get_operand_list(request);

	while(!globus_list_empty(lists))
	{
	    level += globus_l_globusrun_rsl_gass_subst(
		globus_list_first(lists),
		globusrun_gass_url_string);
	    lists=globus_list_rest(lists);
	}
    }
    else if(globus_rsl_is_boolean(request))
    {
	globus_list_t *l;

	l = globus_rsl_boolean_get_operand_list(request);
	while(!globus_list_empty(l))
	{

	    if(globus_rsl_is_boolean(globus_list_first(l)))
	    {
		level += globus_l_globusrun_rsl_gass_subst(
		    globus_list_first(l),
		    globusrun_gass_url_string);
	    }

	    l = globus_list_rest(l);
	}

	if(level == 0)
	{
	    globus_list_insert(
		globus_rsl_boolean_get_operand_list_ref(request),
		globus_rsl_parse(globus_libc_strdup(globusrun_gass_url_string)));
	    level++;
	}
    }
    return level;
} /* globus_l_globusrun_rsl_gass_subst() */

/******************************************************************************
Function: globus_l_globusrun_rsl_output_subst()

Description:

Parameters:

Returns:
******************************************************************************/
static int
globus_l_globusrun_rsl_output_subst(globus_rsl_t *request,
				    char *globusrun_gass_url_string)
{
    int level = 0;

    /* for multirequests */
    if(globus_rsl_is_boolean_multi(request))
    {
	globus_list_t *lists;

	lists = (globus_list_t *) globus_rsl_boolean_get_operand_list(request);

	while(!globus_list_empty(lists))
	{
	    level += globus_l_globusrun_rsl_output_subst(
		globus_list_first(lists),
		globusrun_gass_url_string);
	    lists=globus_list_rest(lists);
	}
    }
    else if(globus_rsl_is_boolean(request))
    {
	globus_list_t *l;
	globus_bool_t stdout_exists = GLOBUS_FALSE;
	globus_bool_t stderr_exists = GLOBUS_FALSE;

	l = globus_rsl_boolean_get_operand_list(request);
	while(!globus_list_empty(l))
	{

	    if(globus_rsl_is_boolean(globus_list_first(l)))
	    {
		level += globus_l_globusrun_rsl_output_subst(
		    globus_list_first(l),
		    globusrun_gass_url_string);
	    }

	    if(globus_l_globusrun_var_exists(globus_list_first(l),
						    "stdout"))
	    {
		stdout_exists=GLOBUS_TRUE;
	    }
	    if(globus_l_globusrun_var_exists(globus_list_first(l),
						    "stderr"))
	    {
		stderr_exists=GLOBUS_TRUE;
	    }

	    l = globus_list_rest(l);
	}

	if(level == 0)
	{
	    if(!stdout_exists)
	    {
		globus_list_insert(
		    globus_rsl_boolean_get_operand_list_ref(request),
		    globus_l_globusrun_new_subst("stdout"));
	    }
	    if(!stderr_exists)
	    {
		globus_list_insert(
		    globus_rsl_boolean_get_operand_list_ref(request),
		    globus_l_globusrun_new_subst("stderr"));
	    }
	    level++;
	}
    }
    return level;
} /* globus_l_globusrun_rsl_output_subst() */

/******************************************************************************
Function: globus_l_globusrun_gram_callback_func()

Description:

Parameters:

Returns:
******************************************************************************/
static void
globus_l_globusrun_gram_callback_func(void *user_arg,
				      char *job_contact,
				      int state,
				      int errorcode)
{
    globus_i_globusrun_gram_monitor_t *monitor;

    monitor = (globus_i_globusrun_gram_monitor_t *) user_arg;

    globus_mutex_lock(&monitor->mutex);

    if(monitor->job_contact != NULL &&
            (strcmp(monitor->job_contact, job_contact) != 0))
    {
        globus_mutex_unlock(&monitor->mutex);
        return;
    }

    monitor->job_state = state;

    switch(state)
    {
    case GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING:
	if(monitor->verbose)
	{
	    globus_libc_printf("GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING\n");
	}
	break;
    case GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_IN:
	if(monitor->verbose)
	{
	    globus_libc_printf("GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_IN\n");
	}
	break;
    case GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_OUT:
	if(monitor->verbose)
	{
	    globus_libc_printf("GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_OUT\n");
	}
	break;
    case GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE:
	if(monitor->verbose)
	{
	    globus_libc_printf("GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE\n");
	}
	break;
    case GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED:
	if(monitor->verbose)
	{
	    globus_libc_printf("GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED\n");
	}
        monitor->done = GLOBUS_TRUE;
	monitor->failure_code = errorcode;
	break;
    case GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE:
	if(monitor->verbose)
	{
	    globus_libc_printf("GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE\n");
	}
        monitor->done = GLOBUS_TRUE;
	break;
    case GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED:
	if(monitor->verbose)
	{
	    globus_libc_printf("GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED\n");
	}
        monitor->done = GLOBUS_TRUE;
	break;
    }

    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);
} /* globus_l_globusrun_gram_callback_func() */

/******************************************************************************
Function: globus_l_globusrun_gramrun()

Description:

Parameters:

Returns:
******************************************************************************/
static int
globus_l_globusrun_gramrun(char * request_string,
			   unsigned long options,
			   char *rm_contact)
{
    char *callback_contact = GLOBUS_NULL;
    globus_i_globusrun_gram_monitor_t monitor;
    int err;
    globus_bool_t verbose = !(options & GLOBUSRUN_ARG_QUIET);
    globus_bool_t send_commit = GLOBUS_FALSE;
    int tmp1, tmp2;
    globus_gram_client_attr_t attr = NULL;

    /* trap SIGINTs */
    if(!(options & GLOBUSRUN_ARG_IGNORE_CTRLC))
    {
	globus_l_globusrun_signal(SIGINT,
                                  globus_l_globusrun_sigint_handler);
#       if defined(BUILD_LITE)
	{
            globus_reltime_t          delay_time;
            globus_reltime_t          period_time;

            GlobusTimeReltimeSet(delay_time, 0, 0);
            GlobusTimeReltimeSet(period_time, 0, 500000);
	    globus_callback_register_periodic(&globus_l_run_callback_handle,
					      &delay_time,
					      &period_time,
	                                      globus_l_globusrun_signal_wakeup,
					      GLOBUS_NULL);
	}
#       endif
    }

    if (globus_l_delegation_mode !=
                GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY)
    {
        err = globus_gram_client_attr_init(&attr);
        if (err != GLOBUS_SUCCESS)
        {

            fprintf(stderr,
                   "Error initialized attribute %s (errorcode %d)\n",
                                globus_gram_protocol_error_string(err),
                                err);
            goto hard_exit;
        }
        err = globus_gram_client_attr_set_delegation_mode(
                attr,
                globus_l_delegation_mode);
        if (err != GLOBUS_SUCCESS)
        {

            fprintf(stderr,
               "Error setting delegation mode attribute: %s (errorcode %d)\n",
               globus_gram_protocol_error_string(err),
               err);
            goto hard_exit;
        }
    }

    monitor.done = GLOBUS_FALSE;
    monitor.failure_code = 0;
    monitor.verbose=verbose;
    monitor.job_state = 0;
    monitor.job_contact = NULL;
    monitor.submit_done = GLOBUS_FALSE;
    monitor.failure_message = NULL;
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);

    if(options & GLOBUSRUN_ARG_IGNORE_CTRLC)
    {
        globus_l_globusrun_signal(SIGINT,
                                  SIG_DFL);
#       if defined(BUILD_LITE)
	{
	    globus_callback_unregister(
	        globus_l_run_callback_handle,
	        GLOBUS_NULL,
	        GLOBUS_NULL, 
	        GLOBUS_NULL);
	}
#       endif
    }

    err = globus_gram_client_callback_allow(
        globus_l_globusrun_gram_callback_func,
        (void *) &monitor,
        &callback_contact);

    if(err != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(stderr,
                            "Initializing GRAM Callback failed because %s (errorcode %d)\n",
                            globus_gram_protocol_error_string(err),
                            err);

        goto hard_exit;
    }
    else if(verbose)
    {
        globus_libc_printf("globus_gram_client_callback_allow "
                           "successful\n");
    }

    globus_mutex_lock(&monitor.mutex);
    err = globus_gram_client_register_job_request(
            rm_contact,
            request_string,
            GLOBUS_GRAM_PROTOCOL_JOB_STATE_ALL,
            callback_contact,
            attr,
            globus_l_submit_callback,
            &monitor);
    if (err != GLOBUS_SUCCESS)
    {
	if(callback_contact)
	{
	    globus_gram_client_callback_disallow(callback_contact);
	    globus_free(callback_contact);
	}
        globus_libc_fprintf(stderr,
                            "GRAM Job submission failed because %s (error code %d)\n",
                            globus_gram_protocol_error_string(err),
                            err);
	goto hard_exit;
    }

    while (!monitor.submit_done)
    {
        globus_cond_wait(&monitor.cond, &monitor.mutex);
        err = monitor.failure_code;
    }
    globus_mutex_unlock(&monitor.mutex);

    if(err == GLOBUS_GRAM_PROTOCOL_ERROR_WAITING_FOR_COMMIT)
    {
	send_commit = GLOBUS_TRUE;
	err = globus_gram_client_job_signal(monitor.job_contact,
				GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_REQUEST,
					    "commit",
					    &tmp1,
					    &tmp2);
    }

    if(err != GLOBUS_SUCCESS)
    {
	if(callback_contact)
	{
	    globus_gram_client_callback_disallow(callback_contact);
	    globus_free(callback_contact);
	}

	if((err == GLOBUS_GRAM_PROTOCOL_ERROR_DRYRUN) &&
	   (options & GLOBUSRUN_ARG_DRYRUN))
	{
	    if(verbose)
	    {
		globus_libc_fprintf(stderr,
				    "Dryrun successful\n");
	    }
	    err=0;
	}
	else
	{
	    globus_libc_fprintf(stderr,
				"GRAM Job submission failed because %s (error code %d)\n",
				monitor.failure_message
                                    ? monitor.failure_message
                                    : globus_gram_protocol_error_string(err),
				err);

	}

	if  ((options & GLOBUSRUN_ARG_BATCH) && monitor.job_contact)
	    globus_libc_printf("%s\n",monitor.job_contact);

	goto hard_exit;
    }
    else if(verbose)
    {
	globus_libc_printf("GRAM Job submission successful\n");
    }

    if  (options & GLOBUSRUN_ARG_BATCH)
    {
	globus_libc_printf("%s\n",monitor.job_contact);
    }

    globus_mutex_lock(&monitor.mutex);

    /* If we're running in fast batch mode, and don't need to allow GASS
     * reads for staging, we will exit immediately without waiting for any
     * job state callbacks.
     */
    if((options &
            (GLOBUSRUN_ARG_BATCH | GLOBUSRUN_ARG_ALLOW_READS
                | GLOBUSRUN_ARG_BATCH_FAST))
        == (GLOBUSRUN_ARG_BATCH|GLOBUSRUN_ARG_BATCH_FAST))
    {
        monitor.done = GLOBUS_TRUE;
    }

    while(!monitor.done)
    {
        /* If we're running in batch mode and need to allow for GASS reads
         * we have to wait until the job is submitted and finished staging
         */
        if ((options & GLOBUSRUN_ARG_BATCH) &&
            (monitor.job_state != 0 &&
             monitor.job_state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED
                    &&
             monitor.job_state != GLOBUS_GRAM_PROTOCOL_JOB_STATE_STAGE_IN))
        {
            monitor.done = GLOBUS_TRUE;
            continue;
        }
	globus_cond_wait(&monitor.cond, &monitor.mutex);
	if(globus_l_globusrun_ctrlc && (!globus_l_globusrun_ctrlc_handled))
	{
	    if(verbose)
	    {
		printf("Cancelling job...\n");
	    }
	    globus_l_globusrun_remove_cancel_poll();
	    globus_gram_client_job_cancel(monitor.job_contact);
	    globus_l_globusrun_ctrlc_handled = GLOBUS_TRUE;
	}
    }
    globus_mutex_unlock(&monitor.mutex);

    /* If we're using two phase commits then we need to send commit end
     * signal if the job is DONE
     */
    err = GLOBUS_SUCCESS;
    if (monitor.job_state == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE ||
        monitor.job_state == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
    {
        if(send_commit == GLOBUS_TRUE)
        {
            err = globus_gram_client_job_signal(monitor.job_contact,
                    GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_COMMIT_END,
                    "commit",
                    &tmp1,
                    &tmp2);
        }
        if (monitor.job_state == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)
        {
            err = monitor.failure_code;
        }
    }
    else
    {
        err = monitor.failure_code;
    }

    if (options & GLOBUSRUN_ARG_BATCH)
    {
        globus_gram_client_job_callback_unregister(
                monitor.job_contact,
                callback_contact,
                &tmp1,
                &tmp2);
    }

    globus_gram_client_callback_disallow(callback_contact);
    globus_free(callback_contact);

    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);

    if((err == GLOBUS_GRAM_PROTOCOL_ERROR_DRYRUN) &&
             (options & GLOBUSRUN_ARG_DRYRUN))
    {
        if(verbose)
        {
            globus_libc_fprintf(stderr,
                                "Dryrun successful\n");
        }
    }
    else if(err != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(stderr,
                            "GRAM Job failed because %s (error code %d)\n",
                            globus_gram_protocol_error_string(err),
                            err);
    }
hard_exit:

    if(monitor.job_contact != GLOBUS_NULL)
    {
	globus_gram_client_job_contact_free(monitor.job_contact);
    }

    return err;
} /* globus_l_globusrun_gramrun() */

/******************************************************************************
Function: globus_l_globusrun_durocrun()

Description:

Parameters:

Returns:
******************************************************************************/
static int
globus_l_globusrun_durocrun(char *request_string,
			    unsigned long options,
			    int mpi_version)
{
    globus_duroc_control_t control;
    char *job_contact = GLOBUS_NULL;
    int results_count;
    int *results;
    int err=0;
    globus_bool_t verbose = !(options & (GLOBUSRUN_ARG_QUIET));

    if (globus_l_delegation_mode !=
            GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY)
    {
        fprintf(stderr, "Error: full delegation not supported for multijobs\n");
        err = GLOBUS_GRAM_PROTOCOL_ERROR_DELEGATION_FAILED;

        goto user_exit;
    }

    /* trap SIGINTs until job is submitted, then potentially ignore them */
    globus_l_globusrun_signal(SIGINT,
                              globus_l_globusrun_sigint_handler);
#   if defined(BUILD_LITE)
    {
            globus_reltime_t          delay_time;
            globus_reltime_t          period_time;

            GlobusTimeReltimeSet(delay_time, 0, 0);
            GlobusTimeReltimeSet(period_time, 0, 500000);
	    globus_callback_register_periodic(&globus_l_run_callback_handle,
					      &delay_time,
					      &period_time,
	                                      globus_l_globusrun_signal_wakeup,
					      GLOBUS_NULL);
    }
#   endif

    err = globus_duroc_control_init (&control);

    if(err != GLOBUS_SUCCESS)
    {
	globus_libc_fprintf(stderr,
			    "Error initializing duroc control (%d)\n",
			    err);
	goto user_exit;
    }

    if(verbose)
    {
	globus_libc_fprintf(stderr,
			   "making globus_duroc request: %s\n",
			   request_string);
    }

    err = globus_duroc_control_job_request (&control,
					    request_string,
					    0,
					    GLOBUS_NULL,
					    &job_contact,
					    &results_count,
					    (volatile int **) &results);

    if(verbose)
    {
	globus_libc_printf("duroc request status: %d\n"
			   "duroc job contact: \"%s\"\n",
			   err,
			   ((err==GLOBUS_DUROC_SUCCESS)
			    ? job_contact
			    : ""));
    }

    if(globus_l_globusrun_ctrlc && (!globus_l_globusrun_ctrlc_handled))
    {
        if(verbose)
        {
            globus_libc_printf("Cancelling job\n");
        }
	globus_l_globusrun_remove_cancel_poll();

        globus_duroc_control_job_cancel(&control,
                                        job_contact);
        globus_l_globusrun_ctrlc_handled = GLOBUS_TRUE;
        goto user_exit;
    }

    if(options & GLOBUSRUN_ARG_IGNORE_CTRLC)
    {
	globus_l_globusrun_signal(SIGINT,
                                  SIG_DFL);
#       if defined(BUILD_LITE)
	{
	    globus_callback_unregister(
	        globus_l_run_callback_handle,
	        GLOBUS_NULL,
	        GLOBUS_NULL,
	        GLOBUS_NULL);
	}
#       endif
    }

    /* handle result of job request now */
    if ( err == GLOBUS_DUROC_SUCCESS )
    {
	int i;

	if(options & GLOBUSRUN_ARG_DRYRUN)
	{
	    globus_bool_t dryrun_ok=GLOBUS_TRUE;
	    char **subjob_labels;

	    subjob_labels = globus_l_globusrun_duroc_subjob_labels(request_string);
	    for(i = 0; i < results_count; i++)
	    {
		if(results[i] != GLOBUS_DUROC_SUCCESS)
		{
		    if(globus_duroc_error_is_gram_client_error(results[i]) &&
		       globus_duroc_error_get_gram_client_error(results[i]) != GLOBUS_GRAM_PROTOCOL_ERROR_DRYRUN)
		    {
			dryrun_ok = GLOBUS_FALSE;
			globus_libc_printf("Duroc subjob (label = \"%s\") failed because %s (error code %d)\n",
					   subjob_labels[i],
					   globus_duroc_error_string(results[i]),
					   results[i]);
			globus_free(subjob_labels[i]);
		    }
		}
		if(dryrun_ok)
		{
		    globus_libc_printf("Dryrun successful\n");
		}
            }
            globus_free(subjob_labels);
	    goto user_exit;
	}
	else			/* !dryrun */
	{
	    char **subjob_labels;

	    subjob_labels = globus_l_globusrun_duroc_subjob_labels(request_string);

	    if(verbose)
	    {
		globus_libc_printf("duroc subjob status:\n");
	    }
	    for (i=0; i<results_count; i++)
	    {
	        if(results[i] == GLOBUS_DUROC_SUCCESS)
	        {
		    if(verbose)
		    {
			globus_libc_printf("    Submission of subjob (label = \"%s\") succeeded\n",
					   subjob_labels[i]);
		    }
	        }
	        else
	        {
			globus_libc_printf("    Submission of subjob (label = \"%s\") failed because %s (error code %d)\n",
					   subjob_labels[i],
					   globus_duroc_error_string(results[i]),
					   results[i]);
	        }
		  globus_free(subjob_labels[i]);
	     }
	     globus_free(subjob_labels);

	    globus_free (results);
	}
    }
    else
    {
	if(options & GLOBUSRUN_ARG_DRYRUN)
	{
	    if(verbose)
	    {
		globus_libc_printf("Dryrun failure\n");
	    }
	}
	else
	{
	    if(verbose)
	    {
		globus_libc_fprintf(stderr,
				    "duroc request failed, exiting.\n");
	    }
	}
	return err;
    }

    if (options & GLOBUSRUN_ARG_INTERACTIVE)
    {

	globus_libc_printf ("entering interactive control mode...\n\n");

	/* loop for commands */
	while (1)
	{
	    int i;
	    int     subjob_count;
	    char ** subjob_labels;
	    int   * subjob_states;

            if(globus_l_globusrun_ctrlc && (!globus_l_globusrun_ctrlc_handled))
	    {
		if(verbose)
		{
		    globus_libc_printf("Cancelling job\n");
		}
		globus_l_globusrun_remove_cancel_poll();

		globus_duroc_control_job_cancel(&control,
						job_contact);
                globus_l_globusrun_ctrlc_handled = GLOBUS_TRUE;
		goto user_exit;
	    }
	    /* print job state summary */
	    err = globus_duroc_control_subjob_states (&control,
						      job_contact,
						      &subjob_count,
						      &subjob_states,
						      &subjob_labels);
	    if(err != GLOBUS_SUCCESS)
	    {
		printf("Error polling duroc control subjob states (%d)\n",
		       err);
		goto user_exit;
	    }

	    globus_libc_fprintf (stdout, "subjob states:\n");

	    for (i=0; i<subjob_count; i++)
	    {
		globus_libc_printf (
		    "subjob >>%s<< %s\n",
		    (subjob_labels[i] ? subjob_labels[i] : "(none)"),
		    ((subjob_states[i]
		      ==GLOBUS_DUROC_SUBJOB_STATE_PENDING)
		     ? "PEND"
		     : ((subjob_states[i]
			 ==GLOBUS_DUROC_SUBJOB_STATE_ACTIVE)
			? "pend ACTIVE"
			: ((subjob_states[i]
			    ==GLOBUS_DUROC_SUBJOB_STATE_CHECKED_IN)
			   ? "pend active CHECKIN"
			   : ((subjob_states[i]
			       ==GLOBUS_DUROC_SUBJOB_STATE_RELEASED)
			      ? "pend active checkin RUN"
			      : (subjob_states[i]
				 ==GLOBUS_DUROC_SUBJOB_STATE_DONE)
			      ? "DONE"
			      : "FAILED")))));
		globus_free (subjob_labels[i]);
		subjob_labels[i] = NULL;
	    }

	    globus_libc_fprintf (stdout, "end subjob states.\n\n");

	    globus_free (subjob_states);
	    globus_free (subjob_labels);

	    /* prompt for user command */

	    globus_libc_fprintf (stdout, "\n"
			   "enter command \"Dlabel\" (delete labeled subjob),\n"
			   "              \"K\" (kill entire job),\n"
			   "              \"C\" (commit current job),\n"
			   "           or \"Q\" (quit request tool)\n\n");

	    /* get user command and perform background processing */
	    {
		globus_fifo_t input;

		err = globus_fifo_init (&input);
		if(err != GLOBUS_SUCCESS)
		{
		    globus_libc_printf("Internal error intializing data structure\n");
		    goto user_exit;
		}

		while ( globus_fifo_empty (&input) ) {
		    ssize_t size;
		    char buf[1];

                    if(globus_l_globusrun_ctrlc && (!globus_l_globusrun_ctrlc_handled))
		    {
			if(verbose)
			{
			    globus_libc_printf("Cancelling job\n");
			}
			globus_l_globusrun_remove_cancel_poll();

			globus_duroc_control_job_cancel(&control,
							job_contact);
                        globus_l_globusrun_ctrlc_handled = GLOBUS_TRUE;
			goto user_exit;
		    }
		    size = read(fileno(stdin), buf, 1);

		    if (size == 1)
		    {
			/* queue up data just read */
			globus_fifo_enqueue (&input, (void *) (long) buf[0]);
		    }
		    else if (size < 0)
		    {
			/* no input ready */
			globus_poll();
		    }
		    else
		    {
			/* eof? */
			globus_libc_fprintf(stdout, "eof reached. exiting.\n");

			goto user_exit;
		    }
		}

		if ( ((char) (long) globus_fifo_peek (&input)) == 'C' )
		{
		    globus_libc_fprintf (stdout, "C commit requested\n");
		    globus_fifo_dequeue (&input);

		    globus_libc_fprintf (stdout,
					 "releasing barrier at "
					 "user's request...\n");

		    err = globus_duroc_control_barrier_release (&control,
								job_contact,
								GLOBUS_TRUE);

		    globus_libc_fprintf (stdout,
					 "release returned %s.\n",
					 (err ? "failure" : "success"));
		}
		else if ( ((char) (long) globus_fifo_peek (&input)) == 'Q' )
		{
		    globus_libc_fprintf (stdout, "Q quit requested\n");
		    globus_fifo_dequeue (&input);

		    goto user_exit;
		}
		else if ( ((char) (long) globus_fifo_peek (&input)) == 'K' )
		{
		    globus_libc_fprintf (stdout, "K kill job requested\n");
		    globus_fifo_dequeue (&input);

		    globus_libc_fprintf (stdout,
					 "canceling job at user's request.\n");

		    err = globus_duroc_control_job_cancel (&control,
							   job_contact);

		    globus_libc_fprintf (stdout,
					 "cancel returned %s.\n",
					 (err ? "failure" : "success"));
		}
		else if ( ((char) (long) globus_fifo_peek (&input)) == 'D' )
		{
		    /* get subjob label..
		     * all characters up to but not including newline */
		    int newline_read = 0;
		    ssize_t size;
		    char buf[1];
		    char *subjob_label;

		    globus_fifo_dequeue (&input); /* throw out 'D' */

		    while ( ! newline_read )
		    {
                        if(globus_l_globusrun_ctrlc && (!globus_l_globusrun_ctrlc_handled))
			{
			    if(verbose)
			    {
				printf("Cancelling job\n");
			    }

			    globus_l_globusrun_remove_cancel_poll();
			    globus_duroc_control_job_cancel(&control,
							    job_contact);
                            globus_l_globusrun_ctrlc_handled = GLOBUS_TRUE;
			    goto user_exit;
			}
			size = read (fileno(stdin), buf, 1);

			if (size == 1)
			{
			    if ( buf[0] != '\n' )
			    {
				globus_fifo_enqueue (&input,
						     (void *) (long) buf[0]);
			    }
			    else
			    {
				newline_read = 1;
			    }
			}
			else if ( size == -1 )
			{
			    /* no input ready */
			}
			else
			{
			    /* eof? */
			    globus_libc_fprintf (stdout,
						 "eof reached. exiting.\n");
			    goto user_exit;
			}
		    }

		    {
			int len;

			len = globus_fifo_size (&input);
			if (len>0)
			{
			    subjob_label = globus_malloc (sizeof(char)
							  * (len + 1));
			    for (i=0; i<len; i++)
			    {
				subjob_label[i] = (char)
				    (long) globus_fifo_dequeue (&input);
			    }
			    subjob_label[len] = '\0';
			}
			else
			{
			    subjob_label = "";
			}
		    }

		    globus_libc_fprintf (stdout,
					 "D delete subjob >>%s<< requested\n",
					 subjob_label);

		    err = globus_duroc_control_subjob_delete (&control,
							      job_contact,
							      subjob_label);

		    if (!err)
		    {
			globus_libc_fprintf (stdout,
					     "subjob >>%s<< deleted\n",
					     subjob_label);
		    }
		    else
		    {
			globus_libc_fprintf (stdout,
					     "subjob >>%s<< deletion failed "
					     "(code %d)\n",
					     subjob_label,
					     err);
		    }
		}
		else
		{
		    /* unknown character, reissue prompt */
		    globus_fifo_dequeue (&input);
		}
	    }

	    globus_poll ();
	}

    after_loop2: /* eliminate pesky dead-code compiler warning */
	;
    }
    else
    {
	if(verbose)
	{
	    globus_libc_printf("releasing barrier in automatic mode...\n");
	}

	err = globus_duroc_control_barrier_release (&control,
						    job_contact,
						    GLOBUS_TRUE);

	if(err)
	{
	    globus_libc_printf("barrier release failed because %s\n",
			       globus_duroc_error_string(err));
	}

	if(verbose)
	{
	    globus_libc_printf("waiting for job termination\n");
	}

	while (GLOBUS_TRUE)
	{
	    int i;
	    int     subjob_count;
	    char ** subjob_labels;
	    int   * subjob_states;
	    int not_terminated = 0;

	    /* poll for job state */
            if(globus_l_globusrun_ctrlc && (!globus_l_globusrun_ctrlc_handled))
	    {
		if(verbose)
		{
		    globus_libc_printf("Cancelling job\n");
		}
		globus_l_globusrun_remove_cancel_poll();
		globus_duroc_control_job_cancel(&control,
						job_contact);
                globus_l_globusrun_ctrlc_handled = GLOBUS_TRUE;
		goto user_exit;
	    }
	    err = globus_duroc_control_subjob_states (&control,
						      job_contact,
						      &subjob_count,
						      &subjob_states,
						      &subjob_labels);
            if(err != GLOBUS_SUCCESS)
            {
                globus_libc_printf("Error polling duroc control subjob states (%d)\n",
                                   err);
                goto user_exit;
            }

	    for (i=0; i<subjob_count; i++)
	    {
		if ( (subjob_states[i] != GLOBUS_DUROC_SUBJOB_STATE_DONE) &&
		     (subjob_states[i] != GLOBUS_DUROC_SUBJOB_STATE_FAILED) )
		{
		    not_terminated = 1;
		}

		globus_free (subjob_labels[i]);
		subjob_labels[i] = NULL;
	    }

	    globus_free (subjob_states);
	    globus_free (subjob_labels);

	    if ( not_terminated )
	    {
		globus_poll_blocking ();
	    }
	    else
	    {
		goto job_terminated;
	    }
	}

    job_terminated:
	goto user_exit;
    }

user_exit:

    if (job_contact != NULL)
    {
        globus_libc_free(job_contact);
    }
    return err;
} /* globus_l_globusrun_durocrun() */

/******************************************************************************
Function: globus_l_globusrun_fault_callback()

Description:

Parameters:

Returns:
******************************************************************************/
static int
globus_l_globusrun_fault_callback (void *user_arg, int fault_code)
{
    int debug=0;
    if(debug)
    {

	globus_libc_printf("globusrun received nexus fault code %d\n",
			   fault_code);
    }
    return 0;
} /* globus_l_globusrun_fault_callback() */


/******************************************************************************
Function: globus_l_globusrun_kill_job()

Description:

Parameters:

Returns:
******************************************************************************/
static int
globus_l_globusrun_kill_job(char * job_contact)
{

    int err;

    err = globus_gram_client_job_cancel(job_contact);
    if ( err != GLOBUS_SUCCESS )
    {
	globus_libc_fprintf(stderr, "Error canceling job\n");
    }

    return err;
}

static
int
globus_l_globusrun_refresh_proxy(
    char *			job_contact)
{
    int err;
    globus_i_globusrun_gram_monitor_t monitor;
    globus_gram_client_attr_t attr = NULL;
    
    monitor.done = GLOBUS_FALSE;
    monitor.failure_code = 0;
    monitor.verbose = GLOBUS_FALSE;
    monitor.job_state = 0;
    monitor.job_contact = NULL;
    monitor.submit_done = GLOBUS_FALSE;
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);

    if (globus_l_delegation_mode !=
                GLOBUS_IO_SECURE_DELEGATION_MODE_LIMITED_PROXY)
    {
        err = globus_gram_client_attr_init(&attr);
        if (err != GLOBUS_SUCCESS)
        {

            fprintf(stderr,
                   "Error initialized attribute %s (errorcode %d)\n",
                                globus_gram_protocol_error_string(err),
                                err);
            goto hard_exit;
        }
        err = globus_gram_client_attr_set_delegation_mode(
                attr,
                globus_l_delegation_mode);
        if (err != GLOBUS_SUCCESS)
        {

            fprintf(stderr,
               "Error setting delegation mode attribute: %s (errorcode %d)\n",
               globus_gram_protocol_error_string(err),
               err);
            goto hard_exit;
        }
    }

    err = globus_gram_client_register_job_refresh_credentials(
            job_contact,
            GSS_C_NO_CREDENTIAL,
            attr,
            globus_l_submit_callback,
            &monitor);

    if ( err != GLOBUS_SUCCESS )
    {
	globus_libc_fprintf(stderr, "Error refreshing proxy: %s\n",
		            globus_gram_client_error_string(err));
    }
    while (!monitor.submit_done)
    {
        globus_cond_wait(&monitor.cond, &monitor.mutex);
        err = monitor.failure_code;
    }
    globus_mutex_unlock(&monitor.mutex);
    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);

hard_exit:
    return err;
}

static
int
globus_l_globusrun_stop_manager(
    char *			job_contact)
{
    int err;
    int tmp1,tmp2;

    err = globus_gram_client_job_signal(
            job_contact,
	    GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_STOP_MANAGER,
	    NULL,
	    &tmp1,
	    &tmp2);

    if(err != GLOBUS_SUCCESS)
    {
	globus_libc_fprintf(stderr, "Error stopping job manager: %s\n",
		            globus_gram_client_error_string(err));
    }
    return err;
}
/******************************************************************************
Function: globus_l_globusrun_status_job()

Description:

Parameters:

Returns:
******************************************************************************/
static int
globus_l_globusrun_status_job(char * job_contact)
{
    int job_status;
    int failure_code;
    int err;

    err = globus_gram_client_job_status(job_contact,
					&job_status,
					&failure_code);
    if ( err != GLOBUS_SUCCESS )
    {
	if (failure_code==GLOBUS_GRAM_PROTOCOL_ERROR_CONTACTING_JOB_MANAGER)
	{
            err = GLOBUS_SUCCESS;
	    globus_libc_printf("DONE\n");
	}
	else
	{
	    globus_libc_printf("ERROR\n");
	    globus_libc_fprintf(stderr,
                 "GRAM Job status failed because %s (error code %d)\n",
                 globus_gram_protocol_error_string(failure_code),
                 failure_code);
	    return failure_code;
	}
    }
    else
    {
	switch(job_status)
	{
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING:
	    globus_libc_printf("PENDING\n");
	    break;
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE:
	    globus_libc_printf("ACTIVE\n");
	    break;
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED:
	    globus_libc_printf("FAILED\n");
	    break;
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_SUSPENDED:
	    globus_libc_printf("SUSPENDED\n");
	    break;
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE:
	    globus_libc_printf("DONE\n");
	    break;
	case GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED:
	    globus_libc_printf("UNSUBMITTED\n");
	    break;
	default:
	    globus_libc_printf("UNKNOWN JOB STATE %d\n", job_status);
	    break;
	}
    }

    return err;
} /* globus_l_globusrun_status_job() */

/******************************************************************************
Function: globus_l_globusrun_sigint_handler()

Description:

Parameters:

Returns:
******************************************************************************/
static RETSIGTYPE
globus_l_globusrun_sigint_handler(int dummy)
{
    globus_l_globusrun_ctrlc = GLOBUS_TRUE;

    /* don't trap any more signals */
    globus_l_globusrun_signal(SIGINT, SIG_DFL);
} /* globus_l_globusrun_sigint_handler() */

#if defined(BUILD_LITE)
/******************************************************************************
Function: globus_l_globusrun_signal_wakeup()

Description:

Parameters:

Returns:
******************************************************************************/
static
void
globus_l_globusrun_signal_wakeup(
    void *                              user_args)
{
    if(globus_l_globusrun_ctrlc)
    {
        globus_callback_signal_poll();
    }
} /* globus_l_globusrun_signal_wakeup() */
#endif


/******************************************************************************
Function: globus_l_globusrun_duroc_subjob_labels()

Description:

Parameters:

Returns:
******************************************************************************/
static char **
globus_l_globusrun_duroc_subjob_labels(char *request_string)
{
    char **subjob_labels;
    globus_rsl_t *ast;
    globus_list_t *subjob_list;
    globus_rsl_t *subjob;
    int list_size;
    int i;

    ast = globus_rsl_parse(request_string);

    subjob_list = globus_rsl_boolean_get_operand_list(ast);

    list_size = globus_list_size(subjob_list);

    subjob_labels = globus_malloc(list_size * sizeof(char *));

    for(i = 0; i < list_size; i++)
    {
	char **values;

	subjob = globus_list_first(subjob_list);

	globus_rsl_param_get(subjob,
			     GLOBUS_RSL_PARAM_SINGLE_LITERAL,
			     "label",
			     &values);

	if(values[0] != GLOBUS_NULL)
	{
	    subjob_labels[i] = globus_libc_strdup(values[0]);
	}
	else
	{
	    subjob_labels[i] = globus_libc_strdup("<no label>");
	}

	globus_free(values);

	subjob_list = globus_list_rest(subjob_list);
    }

    globus_rsl_free_recursive(ast);

    return subjob_labels;
} /* globus_l_globusrun_duroc_subjob_labels() */

/******************************************************************************
Function: globus_l_globusrun_signal()

Description:

Parameters:

Returns:
******************************************************************************/
static int
globus_l_globusrun_signal(int signum, RETSIGTYPE (*func)(int))
{
    struct sigaction act;

    memset(&act, '\0', sizeof(struct sigaction));
    sigemptyset(&(act.sa_mask));
    act.sa_handler = func;
    act.sa_flags = 0;

    return sigaction(signum, &act, GLOBUS_NULL);
} /* globus_l_globusrun_signal() */

/******************************************************************************
Function: globus_l_globusrun_get_credential()

Description:

Parameters:

Returns:
******************************************************************************/
static
char *
globus_l_globusrun_get_credential(void)
{
    OM_uint32			major_status = 0;
    OM_uint32			minor_status = 0;
    gss_cred_id_t		credential = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc		tmp_buffer_desc = GSS_C_EMPTY_BUFFER;
    gss_buffer_t		tmp_buffer = &tmp_buffer_desc;
    gss_name_t			my_name = GSS_C_NO_NAME;
    char *			name;

    major_status = globus_gss_assist_acquire_cred(&minor_status,
					          GSS_C_BOTH,
					          &credential);

    if(major_status != GSS_S_COMPLETE)
    {
	globus_gss_assist_display_status(stdout,
					 "Failed to acquire credentials: ",
					 major_status,
					 minor_status,
					 0);
	return GLOBUS_NULL;
    }

    major_status =
	gss_inquire_cred(&minor_status,
			credential,
			&my_name,
			GLOBUS_NULL,
			GLOBUS_NULL,
			GLOBUS_NULL);

    if(major_status != GSS_S_COMPLETE)
    {
	globus_gss_assist_display_status(stdout,
					 "Failed to determine my name: ",
					 major_status,
					 minor_status,
					 0);

	gss_release_cred(&minor_status,
			 &credential);
	return GLOBUS_NULL;
    }
    major_status =
	gss_display_name(&minor_status,
			 my_name,
			 tmp_buffer,
			 NULL);

    if(major_status != GSS_S_COMPLETE)
    {
	globus_gss_assist_display_status(
	    stdout,
	    "Failed to convert my name to string: ",
	    major_status,
	    minor_status,
	    0);

	gss_release_name(&minor_status,
			 &my_name);
	gss_release_cred(&minor_status,
			 &credential);
	return GLOBUS_NULL;
    }

    name = globus_libc_strdup((char *) tmp_buffer_desc.value);

    gss_release_buffer(&minor_status,
		       tmp_buffer);
    gss_release_name(&minor_status,
		     &my_name);

    gss_release_cred(&minor_status,
		     &credential);
    /*
    printf("my name is %s\n", name);
    */
    return name;

}/* globus_l_globusrun_get_credential() */


static
void
globus_l_submit_callback(
    void *                              user_callback_arg,
    globus_gram_protocol_error_t        operation_failure_code,
    const char *                        job_contact,
    globus_gram_protocol_job_state_t    job_state,
    globus_gram_protocol_error_t        job_failure_code)
{
    globus_i_globusrun_gram_monitor_t * monitor = user_callback_arg;

    globus_mutex_lock(&monitor->mutex);
    monitor->submit_done = GLOBUS_TRUE;
    monitor->job_contact = globus_libc_strdup(job_contact);
    if (operation_failure_code != GLOBUS_SUCCESS)
    {
        char * err = globus_gram_protocol_error_string(operation_failure_code);
        monitor->failure_code = operation_failure_code;
        monitor->failure_message = globus_libc_strdup(err);
    }
    else if (job_state > monitor->job_state)
    {
        monitor->job_state = job_state;
        monitor->failure_code = job_failure_code;
    }
    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);
}
/* globus_l_submit_callback() */

/******************************************************************************
globus_gram_job_manager.c 

Description:
    Globus Job Management API

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

#include <stdio.h>
#include <malloc.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <strings.h>
#include <pwd.h>
#include <signal.h>
#include <fcntl.h>
#include "globus_gram_protocol.h"
#include "globus_gram_job_manager.h"
#include "version.h"

#define GLOBUS_GRAM_JOB_MANAGER_TOOLS "/libexec/globus-gram-job-manager-tools.sh"

/******************************************************************************
                          Module specific prototypes
******************************************************************************/
static int 
globus_l_gram_fork_execute(globus_gram_jobmanager_request_t * request,
                           int processes_requested);

static int 
globus_l_gram_environment_get(char *** env,
                              FILE * log_fp);

static int
globus_l_gram_env_not_set(char * env_name,
                          char *** env_list);

static void
globus_l_gram_param_prepare( char * param,
                             char * new_param);

static void
globus_l_gram_param_list_prepare( char ** param_list,
                                  char * new_param,
                                  int * num_in_list);

static int
globus_l_gram_script_run(char * cmd,
                         globus_gram_jobmanager_request_t * request);

static int
globus_l_gram_request_validate(globus_gram_jobmanager_request_t * request);

static int 
globus_l_gram_request_fork(globus_gram_jobmanager_request_t * request);
static int 
globus_l_gram_check_fork(globus_gram_jobmanager_request_t * request);
static int 
globus_l_gram_cancel_fork(globus_gram_jobmanager_request_t * request);

static int 
globus_l_gram_request_shell(globus_gram_jobmanager_request_t * request);
static int 
globus_l_gram_check_shell(globus_gram_jobmanager_request_t * request);
static int 
globus_l_gram_cancel_shell(globus_gram_jobmanager_request_t * request);

static int globus_l_gram_jobmanager_activate(void);
static int globus_l_gram_jobmanager_deactivate(void);

/******************************************************************************
                       Define module specific variables
******************************************************************************/
#define MAXARGS 256

#if ( !(defined TARGET_ARCH_LINUX) && !(defined TARGET_ARCH_FREEBSD) )
    extern char * sys_errlist[];
#endif

extern int errno;

static int globus_l_is_initialized = 0;

static int graml_processes_started = 0;
static int graml_processes_completed = 0;

static int * graml_child_pid_ptr = NULL;
static int * graml_child_pid_head = NULL;

static char * graml_script_arg_file = NULL;
static char * graml_env_krb5ccname;
static char * graml_env_nlspath;
static char * graml_env_lang;
static char * graml_env_logname;
static char * graml_env_home;
static char * graml_env_tz;

static char * graml_poe_executable = NULL;
static char * graml_mpirun_executable = NULL;

globus_module_descriptor_t globus_i_gram_jobmanager_module = {
    "globus_gram_job_manager",
    globus_l_gram_jobmanager_activate,
    globus_l_gram_jobmanager_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/******************************************************************************
Function:       globus_l_gram_jobmanager_activate()
Description:
Parameters:
Returns:
******************************************************************************/
static
int
globus_l_gram_jobmanager_activate(void)
{
    int              rc;
    globus_result_t  res;

    globus_l_is_initialized = 1;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        return(rc);
    }
    /* 
     * don't bother about errors; we will only signal error if we really
     * need to use one of the executables, and it's not defined.
     */
    res = globus_common_get_attribute_from_config_file(
	GLOBUS_NULL,
	GLOBUS_GRAM_JOB_MANAGER_TOOLS,
	"GLOBUS_GRAM_JOB_MANAGER_POE",
	&graml_poe_executable );
    
    res = globus_common_get_attribute_from_config_file(
	GLOBUS_NULL,
	GLOBUS_GRAM_JOB_MANAGER_TOOLS,
	"GLOBUS_GRAM_JOB_MANAGER_MPIRUN",
	&graml_mpirun_executable );
    
    graml_env_krb5ccname = (char *) getenv("KRB5CCNAME");
    graml_env_nlspath    = (char *) getenv("NLSPATH");
    graml_env_lang       = (char *) getenv("LANG");
    graml_env_logname    = (char *) getenv("LOGNAME");
    graml_env_home       = (char *) getenv("HOME");
    graml_env_tz         = (char *) getenv("TZ");

    return GLOBUS_SUCCESS;
} /* globus_l_gram_jobmanager_activate() */

/******************************************************************************
Function:       globus_l_gram_jobmanager_deactivate()
Description:    Initialize variables
Parameters:
Returns:
******************************************************************************/
static
int
globus_l_gram_jobmanager_deactivate(void)
{
    int rc;

    if ( globus_l_is_initialized == 0 )
    {
        return(GLOBUS_FAILURE);
    }

    if (graml_poe_executable)
	globus_libc_free(graml_poe_executable);

    if (graml_mpirun_executable)
	globus_libc_free(graml_mpirun_executable);

    rc = globus_module_deactivate(GLOBUS_COMMON_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        return(rc);
    }

    return 0;
} /* globus_i_gram_jobmanager_deactivate() */

/******************************************************************************
Function:       globus_jobmanager_request_init()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_jobmanager_request_init(globus_gram_jobmanager_request_t ** request)
{
    globus_gram_jobmanager_request_t * r;

    /*** creating request structure ***/
    *request = (globus_gram_jobmanager_request_t * ) globus_libc_malloc
                   (sizeof(globus_gram_jobmanager_request_t));

    r = *request;

    r->failure_code = 0;
    r->user_pointer = NULL;
    r->job_id = NULL;
    r->poll_frequency = 0;
    r->jobmanager_type = NULL;
    r->jobmanager_libexecdir = NULL;
    r->jobmanager_logfile = NULL;
    r->jobmanager_log_fp = NULL;
    r->executable = NULL;
    r->directory = NULL;
    r->environment = NULL;
    r->arguments = NULL;
    r->my_stdin = NULL;
    r->my_stdout = NULL;
    r->my_stdout_tag = NULL;
    r->my_stderr = NULL;
    r->my_stderr_tag = NULL;
    r->start_time = NULL;
    r->condor_os = NULL;
    r->condor_arch = NULL;
    r->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_UNSUBMITTED;
    r->count = 0;
    r->host_count = 0;
    r->queue = NULL;
    r->reservation_handle = NULL;
    r->project = NULL;
    r->max_time = 0;
    r->max_cpu_time = 0;
    r->max_wall_time = 0;
    r->min_memory = 0;
    r->max_memory = 0;
    r->filename_callback_func = NULL;
    r->two_phase_commit = GLOBUS_FALSE;
    r->save_state = GLOBUS_FALSE;
    r->jm_restart = NULL;
    r->scheduler_specific = GLOBUS_NULL;

    return(GLOBUS_SUCCESS);

} /* globus_jobmanager_request_init() */

/******************************************************************************
Function:       globus_jobmanager_request_destroy()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_jobmanager_request_destroy(globus_gram_jobmanager_request_t * request)
{
    if (!request)
        return(GLOBUS_FAILURE);

    if (request->job_id)
        globus_libc_free(request->job_id);
    if (request->jobmanager_type)
        globus_libc_free(request->jobmanager_type);
    if (request->jobmanager_libexecdir)
        globus_libc_free(request->jobmanager_libexecdir);
    if (request->jobmanager_logfile)
        globus_libc_free(request->jobmanager_logfile);
    if (request->executable)
        globus_libc_free(request->executable);
    if (request->directory)
        globus_libc_free(request->directory);
    if (request->my_stdin)
        globus_libc_free(request->my_stdin);
    if (request->my_stdout)
        globus_libc_free(request->my_stdout);
    if (request->my_stderr)
        globus_libc_free(request->my_stderr);
    if (request->queue)
        globus_libc_free(request->queue);
    if (request->project)
        globus_libc_free(request->project);

    globus_libc_free(request);

    return(GLOBUS_SUCCESS);

} /* globus_jobmanager_request_destroy() */

/******************************************************************************
Function:       globus_jobmanager_request()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_jobmanager_request(globus_gram_jobmanager_request_t * request)
{
    if (!request)
        return(GLOBUS_FAILURE);

    if (globus_l_gram_request_validate(request) != GLOBUS_SUCCESS)
        return(GLOBUS_FAILURE);

    if ((strncmp(request->jobmanager_type, "fork", 4) == 0) ||
        (strncmp(request->jobmanager_type, "poe", 3) == 0))
    {
         return(globus_l_gram_request_fork(request));
    }
    else
    {
         return(globus_l_gram_request_shell(request));
    }
} /* globus_jobmanager_request() */

/******************************************************************************
Function:       globus_jobmanager_request_cancel()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_jobmanager_request_cancel(globus_gram_jobmanager_request_t * request)
{
    if (!request)
        return(GLOBUS_FAILURE);

    if ((strncmp(request->jobmanager_type, "fork", 4) == 0) ||
        (strncmp(request->jobmanager_type, "poe", 3) == 0))
    {
         return(globus_l_gram_cancel_fork(request));
    }
    else
    {
         return(globus_l_gram_cancel_shell(request));
    }
} /* globus_jobmanager_request_cancel() */

/******************************************************************************
Function:       globus_jobmanager_request_signal()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_jobmanager_request_signal(globus_gram_jobmanager_request_t * request)
{
    if (!request)
        return(GLOBUS_FAILURE);

    if ((strncmp(request->jobmanager_type, "fork", 4) == 0) ||
        (strncmp(request->jobmanager_type, "poe", 3) == 0))
    {
         return(globus_l_gram_signal_fork(request));
    }
    else
    {
         return(globus_l_gram_signal_shell(request));
    }
} /* globus_jobmanager_request_signal() */

/******************************************************************************
Function:       globus_jobmanager_request_check()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_jobmanager_request_check(globus_gram_jobmanager_request_t * request)
{
    if (!request)
        return(GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED);

    if ((strncmp(request->jobmanager_type, "fork", 4) == 0) ||
        (strncmp(request->jobmanager_type, "poe", 3) == 0))
    {
         return(globus_l_gram_check_fork(request));
    }
    else
    {
         return(globus_l_gram_check_shell(request));
    }
} /* globus_job_manager_request_check() */

/******************************************************************************
Function:       globus_jobmanager_log()
Description:
Parameters:
Returns:
******************************************************************************/
int
globus_jobmanager_log( FILE *log_fp, const char *format, ... )
{
    struct tm *curr_tm;
    time_t curr_time;
    va_list ap;
    int rc;
    int save_errno;

    if ( log_fp == GLOBUS_NULL ) {
	return -1;
    }

    time( &curr_time );
    curr_tm = localtime( &curr_time );

    globus_libc_lock();

    fprintf( log_fp, "%d/%d %02d:%02d:%02d ",
	     curr_tm->tm_mon + 1, curr_tm->tm_mday,
	     curr_tm->tm_hour, curr_tm->tm_min,
	     curr_tm->tm_sec );

#ifdef HAVE_STDARG_H
    va_start(ap, format);
#else
    va_start(ap);
#endif

    rc = vfprintf( log_fp, format, ap );
    save_errno=errno;

    globus_libc_unlock();

    errno=save_errno;
    return rc;
} /* globus_jobmanager_log() */

/******************************************************************************
Function:       globus_l_gram_request_fork()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_l_gram_request_fork(globus_gram_jobmanager_request_t * request)
{
    unsigned int  i;
    int  rc;
    unsigned int  processes_requested;
    char ** new_args;
    char tmp_arg[1024];
    char * tmp_hostfilename = NULL;

    globus_jobmanager_log(request->jobmanager_log_fp,
	    "JMI: in globus_l_gram_request_fork()\n");

    if (strncmp(request->jobmanager_type, "poe", 3) == 0)
    {
        tmp_hostfilename = tempnam(NULL, "grami_poe");
    }

    if (strncmp(request->jobmanager_type, "poe", 3) == 0)
    {
        processes_requested = 1;
    }
    else
    {
        if (request->job_type == GLOBUS_GRAM_JOBMANAGER_JOBTYPE_MULTIPLE)
        {
            processes_requested = request->count;
        }
        else
        {
	    /* single or mpi */
	    processes_requested = 1;
        }
    }

    if (processes_requested > 30)
    {
        request->poll_frequency = 30;
    }
    else
    {
        request->poll_frequency = processes_requested;
    }

    if ((rc = globus_l_gram_environment_get(&(request->environment),
                                            request->jobmanager_log_fp)) != 0)
    {
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = rc;
        return(GLOBUS_FAILURE);
    }

    globus_jobmanager_log(request->jobmanager_log_fp,
	    "JMI: after globus_l_gram_environment_get()\n");

    graml_child_pid_ptr = (int *) calloc (processes_requested, sizeof(int));
    graml_child_pid_head = graml_child_pid_ptr;

    if (strncmp(request->jobmanager_type, "poe", 3) == 0)
    {   /* GRAMI_POE_MANAGER */

	if (!graml_poe_executable)
	{
	    globus_jobmanager_log(request->jobmanager_log_fp,
			  "JMI: poe not found!\n");
	    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE;
	    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_POE_NOT_FOUND;
	    return(GLOBUS_FAILURE);
	}

        if (request->job_type == GLOBUS_GRAM_JOBMANAGER_JOBTYPE_MULTIPLE)
	{
	    char hostname[MAXHOSTNAMELEN];
	    FILE *tmp_hostfile;
	    
	    globus_libc_gethostname(hostname, MAXHOSTNAMELEN);
	    
	    tmp_hostfile = fopen(tmp_hostfilename, "w");
	    
	    for(i = 0; i < request->count; i++)
	    {
		fprintf(tmp_hostfile, "%s\n", hostname);
	    }
	    fclose(tmp_hostfile);
	    
	    
            /* total up the number of arguments
             */
            for (i = 0; (request->arguments)[i]; i++)
                ;
	    
            /* make new args big enough to handle all the poe arguments 
             * plus the old ones.
             */
            new_args = (char **)globus_libc_malloc(sizeof(char *) * (i + 8));

	    /* poe searches path for executable, if no '/' is present */
	    if(!strchr(request->executable, '/'))
	    {
		(new_args)[0] = (char *) globus_libc_malloc (sizeof(char *) *
					strlen(request->executable) + 3);
		globus_libc_sprintf(new_args[0], "./%s", request->executable);
	    }
	    else
	    {
		(new_args)[0]=(char *) globus_libc_malloc (sizeof(char *) *
				        strlen(request->executable) +1);
		strcpy((new_args)[0], request->executable);
	    }
	    
            /* Tack on the user defined arguments to the list
             */
            for (i = 0; (request->arguments)[i]; i++)
            {
                (new_args)[i+1] = (char *) globus_libc_malloc (sizeof(char *) *
                                     strlen((request->arguments)[i]) +1);
                strcpy((new_args)[i+1], (request->arguments)[i]);
            }
	    
	    /* tack on required poe arguments */
	    ++i;
            (new_args)[i] = (char *) globus_libc_malloc (sizeof(char *) * 10);
            strcpy((new_args)[i], "-hostfile");
	    
	    ++i;
            (new_args)[i] = (char *) globus_libc_malloc (sizeof(char *) *
				    strlen(tmp_hostfilename) +1);
            strcpy((new_args)[i], tmp_hostfilename);
	    
	    ++i;
            (new_args)[i] = (char *) globus_libc_malloc (sizeof(char *) * 8);
            strcpy((new_args)[i], "-euilib");
	    
	    ++i;
            (new_args)[i] = (char *) globus_libc_malloc (sizeof(char *) * 3);
            strcpy((new_args)[i], "ip");

	    ++i;
            (new_args)[i] = (char *) globus_libc_malloc (sizeof(char *) * 7);
            strcpy((new_args)[i], "-procs");

	    ++i;
            sprintf(tmp_arg,"%u", request->count);
            (new_args)[i] = (char *) globus_libc_malloc (sizeof(char *) * 
                                                 strlen(tmp_arg) +1);
            strcpy((new_args)[i], tmp_arg);

            ++i;
            (new_args)[i] = GLOBUS_NULL;

            request->executable = globus_libc_strdup(graml_poe_executable);
            globus_libc_free(request->arguments);
            request->arguments = new_args;
        }
    }
    else
    {
	if (request->job_type == GLOBUS_GRAM_JOBMANAGER_JOBTYPE_MPI)
	{
	    if (!graml_mpirun_executable)
	    {
		globus_jobmanager_log(request->jobmanager_log_fp,
			      "JMI: mpirun not found!\n");
		request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE;
		request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_MPIRUN_NOT_FOUND;
		return(GLOBUS_FAILURE);
	    }

	    /* total up the number of arguments
	     */
	    for (i = 0; (request->arguments)[i]; i++)
		;
	    
	    /* make new args big enough to handle all the mpirun arguments 
	     * plus the old ones.
			 */
	    new_args = (char **)globus_libc_malloc(sizeof(char *) * (i + 4));
	    
	    (new_args)[0] = (char *) globus_libc_malloc (sizeof(char *) * 4);
	    strcpy((new_args)[0], "-np");
	    
	    sprintf(tmp_arg,"%u", request->count);
	    (new_args)[1] = (char *) globus_libc_malloc 
		(sizeof(char *) * strlen(tmp_arg) +1);
	    strcpy((new_args)[1], tmp_arg);

	    (new_args)[2]=(char *) globus_libc_malloc
		(sizeof(char *) * strlen(request->executable) +1);
	    strcpy((new_args)[2], request->executable);
	    
	    /* Tack on the user defined arguments to the list
	     */
	    for (i = 0; (request->arguments)[i]; i++)
	    {
		(new_args)[i+3] = (char *) globus_libc_malloc (sizeof(char *) *
				  strlen((request->arguments)[i]) +1);
		strcpy((new_args)[i+3], (request->arguments)[i]);
	    }
	    
	    (new_args)[i+3] = NULL;
	    
	    request->executable = globus_libc_strdup(graml_mpirun_executable);
	    globus_libc_free(request->arguments);
	    request->arguments = new_args;
        }
    }

    /* used to test job manager functionality without actually submitting
     * job
     */
    if (request->dry_run)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
		"JMI: This is a dry run!!\n");
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE;
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_DRYRUN;
        return(GLOBUS_FAILURE);
    }

    if (request->jm_restart != GLOBUS_NULL)
    {
	char *job_pids = strdup(request->job_id);
	char *new_pid;

	graml_child_pid_ptr = graml_child_pid_head;
	new_pid = strtok( job_pids, " " );
	while ( new_pid != NULL )
	{
	    *graml_child_pid_ptr = atoi(new_pid);
	    graml_child_pid_ptr++;
	    graml_processes_started++;
	    new_pid = strtok( NULL, " " );
	}

	globus_l_gram_check_fork(request);

	free(job_pids);
    }
    else
    {
	if (globus_l_gram_fork_execute(request, processes_requested) != 0)
	{
	    if (strncmp(request->jobmanager_type, "poe", 3) == 0)
	    {
		unlink(tmp_hostfilename);
	    }

	    return(GLOBUS_FAILURE);
	}

	if (strncmp(request->jobmanager_type, "poe", 3) == 0)
	{
	    unlink(tmp_hostfilename);
	}

	graml_child_pid_ptr = graml_child_pid_head;
	tmp_arg[0] = '\0';
	for (i = 0; i < graml_processes_started; i++, graml_child_pid_ptr++)
	{
	    char buf[10];
	    if (graml_child_pid_ptr != graml_child_pid_head)
	    {
		sprintf(buf, " %lu", *graml_child_pid_ptr);
	    } else {
		sprintf(buf, "%lu", *graml_child_pid_ptr);
	    }
	    strcat(tmp_arg, buf);
	}
	request->job_id = (char *) globus_libc_malloc (sizeof(char *) *
						       strlen(tmp_arg) + 1);
	strcpy(request->job_id, tmp_arg);
	globus_jobmanager_log(request->jobmanager_log_fp,
		       "JMI: job id = %s\n", request->job_id );
	request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE;
    }
    return(GLOBUS_SUCCESS);

} /* globus_l_gram_request_fork() */

/******************************************************************************
Function:       globus_l_gram_request_shell()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_l_gram_request_shell(globus_gram_jobmanager_request_t * request)
{
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    FILE * script_arg_fp;
    char new_param[4096];
    int num_in_list;
    char * stdout_filename = GLOBUS_NULL;
    char * stderr_filename = GLOBUS_NULL;

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_l_gram_request_shell()\n" );

    request->poll_frequency = 30;

    /*
     * create a file that will be used to pass all parameters to and 
     * amongst the globus_gram_script_<scheduler>_* scripts.
     */
    if ( (graml_script_arg_file = tempnam(NULL, "grami")) == NULL )
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to create gram script argument file name\n");
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code =
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        return(GLOBUS_FAILURE);
    }

    if (request->filename_callback_func == GLOBUS_NULL ||
        request->jm_restart != GLOBUS_NULL)
    {
        if (request->my_stdout != GLOBUS_NULL)
            stdout_filename = request->my_stdout;
        else
        {
            stdout_filename = (char *) globus_libc_malloc(sizeof(char *) * 10);
            strcpy(stdout_filename, "/dev/null");
        }

        if (request->my_stderr != GLOBUS_NULL)
            stderr_filename = request->my_stderr;
        else
        {
            stderr_filename = (char *) globus_libc_malloc(sizeof(char *) * 10);
            strcpy(stderr_filename, "/dev/null");
        }
    }
    else
    {
        /* get stdout and stderr files from callback function */
        /* set the argument to 1 to indicate requesting a stdout file */
        stdout_filename = (*request->filename_callback_func)(1);
        if (stdout_filename == GLOBUS_NULL)
        {
            request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
            /* shouldn't we be setting a failure code here? */
            return(GLOBUS_FAILURE);
        }

        /* set the argument to 0 to indicate requesting a stderr file */
        stderr_filename = (*request->filename_callback_func)(0);
        if (stderr_filename == GLOBUS_NULL)
        {
            request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
            /* shouldn't we be setting a failure code here? */
            return(GLOBUS_FAILURE);
        }
    }

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: local stdout filename = %s.\n", stdout_filename);
    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: local stderr filename = %s.\n", stderr_filename);

    if ((script_arg_fp = fopen(graml_script_arg_file, "w")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to open gram script argument file. %s\n",
              graml_script_arg_file );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = 
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        return(GLOBUS_FAILURE);
    }

    globus_l_gram_param_prepare(request->jobmanager_logfile, new_param);
    fprintf(script_arg_fp,"grami_logfile='%s'\n", new_param);

    globus_l_gram_param_prepare(request->directory, new_param);
    fprintf(script_arg_fp,"grami_directory='%s'\n", new_param);

    globus_l_gram_param_prepare(request->executable, new_param);
    fprintf(script_arg_fp,"grami_program='%s'\n", new_param);

    globus_l_gram_param_list_prepare(request->arguments, 
                                     new_param,
                                     &num_in_list);
    fprintf(script_arg_fp,"grami_args='%s'\n", new_param);

    globus_l_gram_param_list_prepare(request->environment,
                                     new_param,
                                     &num_in_list);
    /* if the number of globus RSL environment vars is not even then the
     * parameter parsed ok, but it invalid because we assume they come in
     * pairs.  So return an error
     */
    if (num_in_list % 2)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Got an uneven number %d of rsl environment variables!!\n",
              num_in_list);
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL_ENVIRONMENT;
        return(GLOBUS_FAILURE);
    }

    fprintf(script_arg_fp,"grami_env='%s'\n", new_param);
    fprintf(script_arg_fp,"grami_count='%u'\n", request->count);

    if(request->scheduler_specific != GLOBUS_NULL)
    {
	int i = 0;

	for(i = 0; request->scheduler_specific[i].option_name; i++)
	{
	    globus_l_gram_param_list_prepare(
		    request->scheduler_specific[i].option_string,
		    new_param,
		    &num_in_list);

	    fprintf(script_arg_fp,"grami_scheduler_specific_%s='%s'\n",
		    request->scheduler_specific[i].option_name,
		    new_param);
	}
    }
    globus_l_gram_param_prepare(request->my_stdin, new_param);
    fprintf(script_arg_fp,"grami_stdin='%s'\n", new_param);
    fprintf(script_arg_fp,"grami_stdout='%s'\n", stdout_filename);
    fprintf(script_arg_fp,"grami_stderr='%s'\n", stderr_filename);
    fprintf(script_arg_fp,"grami_max_wall_time='%lu'\n", request->max_wall_time);
    fprintf(script_arg_fp,"grami_max_cpu_time='%lu'\n", request->max_cpu_time);
    fprintf(script_arg_fp,"grami_max_time='%lu'\n", request->max_time);
    globus_l_gram_param_prepare(request->start_time, new_param);
    fprintf(script_arg_fp,"grami_start_time='%s'\n", new_param);
    fprintf(script_arg_fp,"grami_min_memory='%lu'\n", request->min_memory);
    fprintf(script_arg_fp,"grami_max_memory='%lu'\n", request->max_memory);
    fprintf(script_arg_fp,"grami_host_count='%u'\n", request->host_count);
    fprintf(script_arg_fp,"grami_job_type='%d'\n", request->job_type);
    globus_l_gram_param_prepare(request->queue, new_param);
    fprintf(script_arg_fp,"grami_queue='%s'\n", new_param);
    globus_l_gram_param_prepare(request->project, new_param);
    fprintf(script_arg_fp,"grami_project='%s'\n", new_param);
    globus_l_gram_param_prepare(request->reservation_handle, new_param);
    fprintf(script_arg_fp,"grami_reservation_handle='%s'\n", new_param);

    if (request->uniq_id == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
		   "JMI: uniq_id not specified, using process id\n");
	fprintf(script_arg_fp,"grami_uniq_id='%d'\n", getpid());
    }
    else
    {
	fprintf(script_arg_fp,"grami_uniq_id='%s'\n", request->uniq_id);
    }

    if (strcasecmp(request->jobmanager_type, "condor") == 0)
    {
        if (request->condor_arch == NULL)
        {
	    globus_jobmanager_log(request->jobmanager_log_fp,
                "JMI: Condor_arch must be specified when "
                "jobmanager type is condor\n");
           request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
           request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_CONDOR_ARCH;
           return(GLOBUS_FAILURE);
        }
        if (request->condor_os == NULL)
        {
	    globus_jobmanager_log(request->jobmanager_log_fp,
                "JMI: Condor_os must be specified when "
                "jobmanager type is condor\n");
           request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
           request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_CONDOR_OS;
           return(GLOBUS_FAILURE);
        }
        fprintf(script_arg_fp,"grami_condor_arch='%s'\n", request->condor_arch);
        fprintf(script_arg_fp,"grami_condor_os='%s'\n", request->condor_os);
    }

    if (graml_env_krb5ccname)
    {
       fprintf(script_arg_fp,"KRB5CCNAME='%s'\n", graml_env_krb5ccname);
    }

    if (request->jm_restart != GLOBUS_NULL)
    {
	fprintf(script_arg_fp,"grami_job_id='%s'\n", request->job_id);
    }

    fclose(script_arg_fp);

    if ( request->jm_restart == GLOBUS_NULL )
    {
	sprintf(script_cmd, "%s/globus-script-%s-submit %s\n",
                            request->jobmanager_libexecdir,
                            request->jobmanager_type,
                            graml_script_arg_file);
    } else {
	sprintf(script_cmd, "%s/globus-script-%s-poll %s\n",
                            request->jobmanager_libexecdir,
                            request->jobmanager_type,
                            graml_script_arg_file);
    }

    /* used to test job manager functionality without actually submitting
     * job
     */
    if (request->dry_run)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
		"JMI: This is a dry run!!\n");
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE;
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_DRYRUN;
        return(GLOBUS_FAILURE);
    }

    if (globus_l_gram_script_run(script_cmd, request) != GLOBUS_SUCCESS)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning with error: %d\n", request->failure_code );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        return(GLOBUS_FAILURE);
    }

    if ( (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE)  &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING) &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)  &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)    &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_SUSPENDED) )
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: grami_gram_job_request(): submit script returned"
              " unknown value: %d\n", request->status );
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOBSTATE;
        return(GLOBUS_FAILURE);
    }

    globus_jobmanager_log(request->jobmanager_log_fp,
	    "JMI: returning with success\n" );
    return(GLOBUS_SUCCESS);

} /* globus_l_gram_request_shell() */


/******************************************************************************
Function:       globus_l_gram_cancel_fork()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_l_gram_cancel_fork(globus_gram_jobmanager_request_t * request)
{
    int x;

    globus_jobmanager_log(request->jobmanager_log_fp,
        "JMI: in globus_l_gram_cancel_fork()\n");

    graml_child_pid_ptr = graml_child_pid_head;

    for (x=0; x<graml_processes_started; x++)
    {
	if ( *graml_child_pid_ptr > 0 )
	{
	    globus_jobmanager_log(request->jobmanager_log_fp,
			   "JMI: killing child %d with SIGTERM\n",
			   *graml_child_pid_ptr);
	    kill(*graml_child_pid_ptr, SIGTERM);
	    graml_child_pid_ptr++;
	}
    }

    /* TODO: This should become a loop with waitpid() */
    sleep(10);
    
    graml_child_pid_ptr = graml_child_pid_head;
    for (x=0; x<graml_processes_started; x++)
    {
	if ( *graml_child_pid_ptr > 0 )
	{
	    globus_jobmanager_log(request->jobmanager_log_fp,
			   "JMI: killing child %d with SIGKILL\n",
			   *graml_child_pid_ptr);
	    kill(*graml_child_pid_ptr, SIGKILL);
	    graml_child_pid_ptr++;
	}
    }

    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_USER_CANCELLED;

    return(GLOBUS_SUCCESS);

} /* globus_l_gram_cancel_fork() */

/******************************************************************************
Function:       globus_l_gram_cancel_shell()
Description:
Parameters:
Returns:
******************************************************************************/
int
globus_l_gram_cancel_shell(globus_gram_jobmanager_request_t * request)
{
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int rc;

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_l_gram_cancel_shell()\n" );

    sprintf(script_cmd, "%s/globus-script-%s-rm %s\n",
                         request->jobmanager_libexecdir,
                         request->jobmanager_type,
                         graml_script_arg_file);

    rc = globus_l_gram_script_run(script_cmd, request);

    if (remove(graml_script_arg_file) != 0)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
                     "JM: Cannot remove argument file --> %s\n",
                     graml_script_arg_file);
    }

    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
    request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_USER_CANCELLED;

    if (rc == GLOBUS_FAILURE)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: received error from script: %d\n", rc );
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning job state failed.\n" );
        return(GLOBUS_FAILURE);
    }

    return(GLOBUS_SUCCESS);

} /* globus_l_gram_cancel_shell() */


/******************************************************************************
Function:       globus_l_gram_signal_fork()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_l_gram_signal_fork(globus_gram_jobmanager_request_t * request)
{
    int x;

    globus_jobmanager_log(request->jobmanager_log_fp,
        "JMI: in globus_l_gram_signal_fork()\n");

    /* not sure what we should do with anything except for cancel,
     * so for now just return.
     */
    if (request->signal != GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_CANCEL)
    {
        return(GLOBUS_GRAM_PROTOCOL_ERROR_UNKNOWN_SIGNAL_TYPE);
    }

    graml_child_pid_ptr = graml_child_pid_head;

    for (x=0; x<graml_processes_started; x++)
    {
	if ( *graml_child_pid_ptr > 0 )
	{
	    globus_jobmanager_log(request->jobmanager_log_fp,
			   "JMI: killing child %d with SIGTERM\n",
			   *graml_child_pid_ptr);
	    kill(*graml_child_pid_ptr, SIGTERM);
	    graml_child_pid_ptr++;
	}
    }

    /* TODO: This should become a loop with waitpid() */
    sleep(10);
    
    graml_child_pid_ptr = graml_child_pid_head;
    for (x=0; x<graml_processes_started; x++)
    {
	if ( *graml_child_pid_ptr > 0 )
	{
	    globus_jobmanager_log(request->jobmanager_log_fp,
			   "JMI: killing child %d with SIGKILL\n",
			   *graml_child_pid_ptr);
	    kill(*graml_child_pid_ptr, SIGKILL);
	    graml_child_pid_ptr++;
	}
    }

    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;

    return(GLOBUS_SUCCESS);

} /* globus_l_gram_signal_fork() */

/******************************************************************************
Function:       globus_l_gram_signal_shell()
Description:
Parameters:
Returns:
******************************************************************************/
int
globus_l_gram_signal_shell(globus_gram_jobmanager_request_t * request)
{
    FILE * signal_arg_fp;
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int rc;
    char * tmp_signalfilename = NULL;

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_l_gram_signal_shell()\n" );

    tmp_signalfilename = tempnam(NULL, "grami_signal");

    if ((signal_arg_fp = fopen(tmp_signalfilename, "w")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Failed to open gram signal script argument file. %s\n",
              tmp_signalfilename );
        return(GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED);
    }

    /*
     * add the signal and signal_arg to the script arg file
     */

    /* overloading the use of the script_cmd variable just temporarily */
    globus_l_gram_param_prepare(request->signal_arg, script_cmd);
    fprintf(signal_arg_fp,"grami_signal_arg='%s'\n", script_cmd);
    fprintf(signal_arg_fp,"grami_signal='%d'\n", request->signal);

    fclose(signal_arg_fp);

    sprintf(script_cmd, "%s/globus-script-%s-signal %s\n",
                         request->jobmanager_libexecdir,
                         request->jobmanager_type,
                         tmp_signalfilename);

    rc = globus_l_gram_script_run(script_cmd, request);

    if (request->signal == GLOBUS_GRAM_PROTOCOL_JOB_SIGNAL_CANCEL)
    {
        if (remove(graml_script_arg_file) != 0)
        {
	    globus_jobmanager_log(request->jobmanager_log_fp,
                         "JM: Cannot remove argument file --> %s\n",
                         graml_script_arg_file);
        }
        request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
    }

    if (rc == GLOBUS_FAILURE)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: received error from script: %d\n", request->failure_code );
        return(GLOBUS_GRAM_PROTOCOL_ERROR_SIGNALING_JOB);
    }

    return(GLOBUS_SUCCESS);

} /* globus_l_gram_signal_shell() */

/******************************************************************************
Function:       globus_l_gram_check_fork()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_l_gram_check_fork(globus_gram_jobmanager_request_t * request)
{
    int i;
    int pid = 99999;
    int new_job_status;
# ifdef HAS_WAIT_UNION_WAIT
    union wait status;
# else
    int status;
# endif 

    new_job_status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE;

    while (pid > 0)
    {
#       ifdef HAS_WAIT3
            pid = wait3(&status, WNOHANG, NULL);
#       else
            pid = waitpid(-1, &status, WNOHANG);
#       endif /* HAS_WAIT */

/*
        if (pid > 0)
            graml_processes_completed++;
*/
    }

    graml_child_pid_ptr = graml_child_pid_head;

    for (i = 0; i < graml_processes_started; i++, graml_child_pid_ptr++)
    {
	if ( *graml_child_pid_ptr > 0 && kill( *graml_child_pid_ptr, 0 ) < 0 )
	{
	    graml_processes_completed++;
	    *graml_child_pid_ptr = -(*graml_child_pid_ptr);
	}
    }

    if (graml_processes_completed >= graml_processes_started)
    {
        new_job_status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE;
    }

    if (request->status == new_job_status)
    {
        return(GLOBUS_GRAM_JOBMANAGER_STATUS_UNCHANGED);
    }
    else
    {
        request->status = new_job_status;
        return(GLOBUS_GRAM_JOBMANAGER_STATUS_CHANGED);
    }

} /* globus_l_gram_check_fork() */

/******************************************************************************
Function:       globus_l_gram_check_shell()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_l_gram_check_shell(globus_gram_jobmanager_request_t * request)
{
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int old_status;

    sprintf(script_cmd, "%s/globus-script-%s-poll %s\n",
                         request->jobmanager_libexecdir,
                         request->jobmanager_type,
                         graml_script_arg_file);

    old_status = request->status;

    if (globus_l_gram_script_run(script_cmd, request) != GLOBUS_SUCCESS)
    {
        return(GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED);
    }

    if ( (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_ACTIVE)  &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_PENDING) &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED)  &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE)    &&
         (request->status != GLOBUS_GRAM_PROTOCOL_JOB_STATE_SUSPENDED) )
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: globus_l_gram_check_shell(): poll script returned unknown "
              "value: %d\n", request->status );
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOBSTATE;
        return(GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED);
    }

    if (request->status == old_status)
    {
        return(GLOBUS_GRAM_JOBMANAGER_STATUS_UNCHANGED);
    }
    else
    {
        if ( (request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED) ||
             (request->status == GLOBUS_GRAM_PROTOCOL_JOB_STATE_DONE) )
        {
            if (remove(graml_script_arg_file) != 0)
            {
		globus_jobmanager_log(request->jobmanager_log_fp,
                         "JM: Cannot remove argument file --> %s\n",
                         graml_script_arg_file);
            }
        }

        return(GLOBUS_GRAM_JOBMANAGER_STATUS_CHANGED);
    }

} /* globus_l_gram_check_shell() */

/******************************************************************************
Function:       globus_l_gram_fork_execute()
Description:
Parameters:
Returns:
******************************************************************************/
static int 
globus_l_gram_fork_execute(globus_gram_jobmanager_request_t * request,
                           int processes_requested)
{
    int n, i, x;
    int p[2];
    int rd;
    int wr;
    int pid;
    char * s;
    char buf[1024];
    char tmpbuf[256];
    char * stdout_filename = GLOBUS_NULL;
    char * stderr_filename = GLOBUS_NULL;
    int stdin_fd, stdout_fd, stderr_fd;
    
    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_l_gram_fork_execute\n");

    for (i = 0; (request->environment)[i]; i++)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: env[%d] is \"%s\"\n", i, (request->environment)[i]);
    }

    /* create the processes */
    for (x=0;x<processes_requested; x++)
    {

        if (pipe(p) != 0)
        {
	    globus_jobmanager_log(request->jobmanager_log_fp,
                  "JMI: Cannot create pipe: %s\n", sys_errlist[errno] );
            request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
            request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_CREATING_PIPE;
            return(GLOBUS_FAILURE);
        }

        rd = p[0];
        wr = p[1];

        if (fcntl(wr, F_SETFD, 1) != 0)
        {
	    globus_jobmanager_log(request->jobmanager_log_fp,
                  "JMI: fcntl F_SETFD failed: %s\n", sys_errlist[errno] );
            request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
            request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_FCNTL_FAILED;
            return(GLOBUS_FAILURE);
        }

        if (request->filename_callback_func == GLOBUS_NULL)
        {
            if (request->my_stdout != GLOBUS_NULL)
                stdout_filename = request->my_stdout;

            if (request->my_stderr != GLOBUS_NULL)
                stderr_filename = request->my_stderr;
        }
        else
        {
            if (strcmp(request->my_stdout, "/dev/null") == 0)
            {
                stdout_filename = "/dev/null";
            }
            else
            {
                /* get stdout and stderr files from callback function */
                /* set the argument to 1 to indicate requesting a stdout file */
                stdout_filename = (*request->filename_callback_func)(1);
                if (stdout_filename == GLOBUS_NULL)
                {
                    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
                    request->failure_code = 
                          GLOBUS_GRAM_PROTOCOL_ERROR_STDOUT_FILENAME_FAILED;
                    return(GLOBUS_FAILURE);
                }
            }

            if (strcmp(request->my_stderr, "/dev/null") == 0)
            {
                stderr_filename = "/dev/null";
            }
            else
            {
                /* set the argument to 0 to indicate requesting a stderr file */
                stderr_filename = (*request->filename_callback_func)(0);
                if (stderr_filename == GLOBUS_NULL)
                {
                    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
                    request->failure_code = 
                          GLOBUS_GRAM_PROTOCOL_ERROR_STDERR_FILENAME_FAILED;
                    return(GLOBUS_FAILURE);
                }
            }
        }

	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: local stdout filename = %s.\n", stdout_filename);
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: local stderr filename = %s.\n", stderr_filename);
		
        pid = globus_libc_fork();

        if (pid < 0)
        {
	    globus_jobmanager_log(request->jobmanager_log_fp,
                  "JMI: fork failed: %s\n", sys_errlist[errno]);
            request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_FORKING_EXECUTABLE;
            return(GLOBUS_FAILURE);
        }

        if (pid == 0)
        {
            close(rd);

	    stdin_fd = open(request->my_stdin, O_RDONLY);
            stdout_fd = globus_libc_open(stdout_filename,
                                     O_APPEND | O_WRONLY | O_CREAT,
                                     0600);
            if(stdout_fd < 0)
            {
                stdout_fd = globus_libc_open("/dev/null", O_WRONLY);
            }

            stderr_fd = globus_libc_open(stderr_filename,
                                         O_APPEND | O_WRONLY | O_CREAT,
                                         0600);
            if(stderr_fd < 0)
            {
                stderr_fd = globus_libc_open("/dev/null", O_WRONLY);
            }

            /* close stdin stdout stderr */
            close(0);
            close(1);
            close(2);

            /* dup stdin stdout stderr with the fd's just created */
            dup2(stdin_fd, 0);
            dup2(stdout_fd, 1);
            dup2(stderr_fd, 2);

	    globus_jobmanager_log(request->jobmanager_log_fp,
                  "JMI: executing program - '%s'\n", request->executable );
	    /* add the pgm name as argv[0] for the execv call */
	    {
		char **new_pgm_args;
		int pgm_argc;
		int openfds;

		for(pgm_argc = 0; (request->arguments)[pgm_argc]; pgm_argc++)
		    ;
		
		new_pgm_args = (char **)
		    globus_libc_malloc((pgm_argc+2) * sizeof(char *));

		new_pgm_args[0] = request->executable;
		for(i=1; i <= pgm_argc; i++)
		{
		    new_pgm_args[i] = request->arguments[i-1];
		}
		new_pgm_args[i] = GLOBUS_NULL;
    
                /*
                 * loop thru args printing them out for debug purposes
                 */
		for(pgm_argc = 0; new_pgm_args[pgm_argc]; pgm_argc++)
		{
		    globus_jobmanager_log(request->jobmanager_log_fp,
		          "new_pgm_args[%i]=%s\n",
			   pgm_argc,
			   new_pgm_args[pgm_argc]);
			   
		}

		/* Close all files except stdin/out/err and the pipe to
		 * our parent.
		 */
		openfds = getdtablesize();
		for(i=3; i < openfds; i++)
		{
		    if ( i != wr )
		    {
			close(i);
		    }
		}

		if ((request->environment)[0])
		{
		    /* some environment vars exist */
		    i = execve(request->executable,
                               new_pgm_args,
                               request->environment);
		}
		else
		{
		    i = execv(request->executable, new_pgm_args);
		}
		globus_libc_free(new_pgm_args);
	    }
            if (i != 0)
            {
                fprintf(stderr, "Exec failed: %s\n", sys_errlist[errno]);
                sprintf(tmpbuf, "Exec failed: %s\n", sys_errlist[errno]);
                write(wr, tmpbuf, strlen(tmpbuf));
                _exit(1);/*return(1);*/
            }
        }

        close(wr);

        if ((n = read(rd, buf, sizeof(buf))) > 0)
        {
            buf[n] = 0;
            s = index(buf, '\n');
            if (s)
                *s = 0;

	    globus_jobmanager_log(request->jobmanager_log_fp,
                  "JMI: child failed: %s\n", buf );

            /* kill off processes that were started successfully
             * either all processes start or terminate everything!
             */
            graml_child_pid_ptr = graml_child_pid_head;

	    close(rd);
            request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
            request->failure_code =
                GLOBUS_GRAM_PROTOCOL_ERROR_JOB_EXECUTION_FAILED;
            return(GLOBUS_FAILURE);
        }
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: Child %d started\n", pid );
	close(rd);
        *graml_child_pid_ptr++ = pid;
        graml_processes_started += 1;
    } /* end for */

    return(GLOBUS_SUCCESS);

} /* globus_l_gram_fork_execute() */

/******************************************************************************
Function:       globus_l_gram_environment_get()
Description:
Parameters:
Returns:
******************************************************************************/
/*
 * globus_l_gram_environment_get()
 *
 * environment vars come in pairs, first the var then the value.
 * So 2 environment vars will be converted to one.
 *
 * For example:
 *       env[0] = "FOO"
 *       env[1] = "bar"
 *
 *       new_env[0] = "FOO=bar"
 */
static int 
globus_l_gram_environment_get(char *** env, FILE * log_fp)
{
    char ** new_env;
    int env_count;
    int i, j;
    int jm_env_num = 0;

    /* count up the environment vars */
    for (env_count = 0; (*env)[env_count] != NULL; env_count++)
        ;

    /* if the number of environment vars is not even then the 
     * parameter parsed ok, but it invalid because we assume they come in 
     * pairs.  So return an error
     */
    if (env_count % 2)
    {
        globus_jobmanager_log(log_fp, 
              "JMI: Error: Got an uneven number %d of environment variables!\n",
                env_count);
        return(GLOBUS_GRAM_PROTOCOL_ERROR_BAD_RSL_ENVIRONMENT);
    }
    
    /* divided by 2 because 2 rsl env vars equal 1 var=value pair.
     */
    env_count = env_count / 2;

    globus_jobmanager_log(log_fp, 
          "JMI: %d variables identified in the request environment parameter\n",
          env_count);

    if ( graml_env_krb5ccname ) jm_env_num++;
    if ( graml_env_nlspath ) jm_env_num++;
    if ( graml_env_lang ) jm_env_num++;
    if ( graml_env_logname ) jm_env_num++;
    if ( graml_env_home ) jm_env_num++;
    if ( graml_env_tz ) jm_env_num++;
    
    globus_jobmanager_log(log_fp, "JMI: %d variables from job manager's environment "
                          "will be appended to the request environment.\n",
                          jm_env_num);

    new_env = (char **) globus_libc_malloc(sizeof(char *) * 
                          (env_count + jm_env_num + 1));

    /* tack on the globus environment vars to the beginning of the list */
    for (i = 0, j=0; (*env)[i]; i++, j++)
    {
        globus_jobmanager_log(log_fp,
                      "env[%d] is \"%s\"\n", i, (*env)[i]);
        if ((*env)[i+1])
        {
            globus_jobmanager_log(log_fp,
                          "env[%d] is \"%s\"\n", i+1, (*env)[i+1]);

            (new_env)[j] = (char *) globus_libc_malloc ( sizeof(char *) *
                                       (strlen( (*env)[i]) +
                                        strlen( (*env)[i+1]) + 2));

            sprintf((new_env)[j], "%s=%s", (*env)[i],
                                            (*env)[i+1]);
        }
        else
        {
            (new_env)[j] = (char *) globus_libc_malloc (sizeof(char *) *
                                       (strlen((*env)[i]) + 2));
            sprintf((new_env)[j], "%s=", (*env)[i]);
        }
        i++;
    }

    if (graml_env_krb5ccname)
    {
        if (globus_l_gram_env_not_set("KRB5CCNAME", env))
        {
            (new_env)[j] = (char *) globus_libc_malloc ( sizeof(char *) *
                                   (strlen("KRB5CCNAME") +
                                    strlen(graml_env_krb5ccname) + 2));
            sprintf((new_env)[j], "%s=%s", "KRB5CCNAME",
                                           graml_env_krb5ccname);
            j++;
        }
    }

    if (graml_env_nlspath)
    {
        if (globus_l_gram_env_not_set("NLSPATH", env))
        {
            (new_env)[j] = (char *) globus_libc_malloc ( sizeof(char *) *
                                   (strlen("NLSPATH") +
                                    strlen(graml_env_nlspath) + 2));
            sprintf((new_env)[j], "%s=%s", "NLSPATH",
                                           graml_env_nlspath);
            j++;
        }
    }

    if (graml_env_lang)
    {
        if (globus_l_gram_env_not_set("LANG", env))
        {
            (new_env)[j] = (char *) globus_libc_malloc ( sizeof(char *) *
                                   (strlen("LANG") +
                                    strlen(graml_env_lang) + 2));
            sprintf((new_env)[j], "%s=%s", "LANG", graml_env_lang);
            j++;
        }
    }

    if (graml_env_logname)
    {
        if (globus_l_gram_env_not_set("LOGNAME", env))
        {
            (new_env)[j] = (char *) globus_libc_malloc ( sizeof(char *) *
                                   (strlen("LOGNAME") +
                                    strlen(graml_env_logname) + 2));
            sprintf((new_env)[j], "%s=%s", "LOGNAME",
                                           graml_env_logname);
            j++;
        }
    }

    if (graml_env_home)
    {
        if (globus_l_gram_env_not_set("HOME", env))
        {
            (new_env)[j] = (char *) globus_libc_malloc ( sizeof(char *) *
                                   (strlen("HOME") +
                                    strlen(graml_env_home) + 2));
            sprintf((new_env)[j], "%s=%s", "HOME",
                                           graml_env_home);
            j++;
        }
    }

    if (graml_env_tz)
    {
        if (globus_l_gram_env_not_set("TZ", env))
        {
            (new_env)[j] = (char *) globus_libc_malloc ( sizeof(char *) *
                                   (strlen("TZ") +
                                    strlen(graml_env_tz) + 2));
            sprintf((new_env)[j], "%s=%s", "TZ",
                                           graml_env_tz);
            j++;
        }
    }
    
    /* set the last environment var to NULL */
    (new_env)[j] = NULL;

    /* replace the old environment vars with the newly created one */
    *env = new_env;

    return(GLOBUS_SUCCESS);

} /* globus_l_gram_environment_get() */

/******************************************************************************
Function:       globus_l_gram_env_not_set()
Description:
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_env_not_set(char * env_name, char *** env_list)
{
    int i;

    if (!env_name)
        return(0);

    /* if the list is empty then it is ok to set the variable */
    if ( (*env_list)[0] == NULL )
        return(1);

    /* check every 2 RSL env because they come in the form
     * env[0] = var
     * env[1] = value
     */
    for (i=0; (*env_list)[i]; i=i+2)
    {
        if (strcmp(env_name,(*env_list)[i]) == 0)
           return(0);
    }

    /* it is ok to set the variable */
    return(1);

} /* globus_l_gram_env_not_set() */

/******************************************************************************
Function:       globus_l_gram_param_prepare()
Description:
Parameters:
Returns:
******************************************************************************/
static void
globus_l_gram_param_prepare(char * param,
                            char * new_param)
{
    char * param_ptr;
    char tmp_param[4096];
    int x;

    if (param == NULL)
    {
       new_param[0] = '\0';
       return;
    }

    for (param_ptr = param, x=0; *param_ptr != '\0'; param_ptr++, x++)
    {

        if ( *param_ptr == '"' )
        {
           tmp_param[x] = '\\';
           x++;
           tmp_param[x] = '"';
        }
        else if ( *param_ptr == '$' )
        {
           tmp_param[x] = '\'';
           x++;
           tmp_param[x] = '"';
           x++;
           tmp_param[x] = '\\';
           x++;
           tmp_param[x] = '\\';
           x++;
           tmp_param[x] = '$';
           x++;
           tmp_param[x] = '"';
           x++;
           tmp_param[x] = '\'';
        }
        else if ( *param_ptr == '\\' )
        {
           tmp_param[x] = '\\';
           x++;
           tmp_param[x] = '\\';
           x++;
           tmp_param[x] = '\\';
           x++;
           tmp_param[x] = '\\';
        }
        else if ( *param_ptr == '\'' )
        {
           tmp_param[x] = '\'';
           x++;
           tmp_param[x] = '"';
           x++;
           tmp_param[x] = '\'';
           x++;
           tmp_param[x] = '"';
           x++;
           tmp_param[x] = '\'';
        }
        else
        {
           tmp_param[x] = *param_ptr;
        }
    }
    tmp_param[x] = '\0';

    sprintf(new_param, "%s", tmp_param);

    return;

} /* globus_l_gram_param_prepare() */

/******************************************************************************
Function:       globus_l_gram_param_list_prepare()
Description:
Parameters:
Returns:
******************************************************************************/
static void
globus_l_gram_param_list_prepare(char ** param_list,
                                 char * new_param,
                                 int * num_in_list)
{

    char tmp_param[4096];
    char tmp_arg[4096];
    int i;

    if ((param_list)[0] == NULL)
    {
        new_param[0] = '\0';
        *num_in_list=0;
        return;
    }
    else
    {
        tmp_param[0] = '\0';
        /* loop through the args */
        for (i = 0; (param_list)[i] != NULL; i++)
        {
            globus_l_gram_param_prepare(param_list[i], tmp_arg);
            if (i == 0)
                sprintf(tmp_param, "\"%s\"", tmp_arg);
            else
                sprintf(tmp_param, "%s \"%s\"",
                               tmp_param,
                               tmp_arg);
        }
        *num_in_list=i;
    }

    sprintf(new_param, "%s", tmp_param);

    return;

} /* globus_l_gram_param_list_prepare() */

/******************************************************************************
Function:       globus_l_gram_script_run()
Description:
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_script_run(char * cmd,
                         globus_gram_jobmanager_request_t * request)
{
    FILE * fp;
    char return_buf[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int script_status;

    globus_jobmanager_log(request->jobmanager_log_fp,
	    "JMI: cmd = %s\n", cmd );

    if ((fp = popen(cmd, "r")) == NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
		"JMI: Cannot popen shell file\n");
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_OPENING_JOBMANAGER_SCRIPT;
        return(GLOBUS_FAILURE);
    }

    return_buf[0] = '\0';

    while (fgets(return_buf, GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE, fp) != NULL)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
		"JMI: while return_buf = %s\n",
                       return_buf );
        if (strncmp(return_buf, "GRAM_SCRIPT_JOB_ID:", 19) == 0)
        {
            return_buf[strlen(return_buf)-1] = '\0';
            request->job_id = (char *) globus_libc_malloc (sizeof(char *) *
                 strlen(&return_buf[19]) + 1);
            strcpy(request->job_id, &return_buf[19]);
	    globus_jobmanager_log(request->jobmanager_log_fp,
                  "JMI: job id = %s\n", request->job_id );
        }
    }

    pclose(fp);

    return_buf[strlen(return_buf)-1] = '\0';
    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: return_buf = %s\n", return_buf );

    if (strncmp(return_buf, "GRAM_SCRIPT_SUCCESS:", 20) == 0)
    {
        if ((script_status = atoi(&return_buf[20])) < 0)
        {
            /* unable to determine script status */
            request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
            return(GLOBUS_FAILURE);
        }
	globus_jobmanager_log(request->jobmanager_log_fp,
		"JMI: ret value = %d\n",
                       script_status );

        request->status = script_status;
        return(GLOBUS_SUCCESS);
    }
    else if (strncmp(return_buf, "GRAM_SCRIPT_ERROR:", 18) == 0)
    {
        if ((script_status = atoi(&return_buf[18])) < 0)
        {
            request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_STATUS;
        }
        else
        {
            request->failure_code = script_status;
        }

	globus_jobmanager_log(request->jobmanager_log_fp,
		"JMI: ret value = %d\n",
		request->failure_code );

        return(GLOBUS_FAILURE);
    }
    else
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_SCRIPT_REPLY;
        return(GLOBUS_FAILURE);
    }

} /* globus_l_gram_script_run() */


/******************************************************************************
Function:       globus_l_gram_request_validate()
Description:
Parameters:
Returns:
******************************************************************************/
static int
globus_l_gram_request_validate(globus_gram_jobmanager_request_t * request)
{
    struct stat statbuf;
    char script_path[512];

    /*
     * change to the right directory, so that std* files
     * are interpreted relative to this directory
     */
    if (chdir(request->directory) != 0)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
	    "JMI: Couldn't change to directory %s\n", request->directory );
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_BAD_DIRECTORY;
        return(GLOBUS_FAILURE);
    }

    /*
     * test that stdin file exists
     */
    if (stat(request->my_stdin, &statbuf) != 0)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_STDIN_NOT_FOUND;
        return(GLOBUS_FAILURE);
    }

    /*
     * test that executable file exists
     */
    if (stat(request->executable, &statbuf) != 0)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_EXECUTABLE_NOT_FOUND;
        return(GLOBUS_FAILURE);
    }

    if (!(statbuf.st_mode & 0111))
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_EXECUTABLE_PERMISSIONS;
        return(GLOBUS_FAILURE);
    }

    if (request->count < 1)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_COUNT;
        return(GLOBUS_FAILURE);
    }

    if (request->job_type != GLOBUS_GRAM_JOBMANAGER_JOBTYPE_MPI &&
        request->job_type != GLOBUS_GRAM_JOBMANAGER_JOBTYPE_SINGLE &&
        request->job_type != GLOBUS_GRAM_JOBMANAGER_JOBTYPE_MULTIPLE &&
        request->job_type != GLOBUS_GRAM_JOBMANAGER_JOBTYPE_CONDOR)
    {
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOBTYPE;
        return(GLOBUS_FAILURE);
    }

    if (! request->jobmanager_type)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
            "JMI: job manager type is not specified, cannot continue.\n");
        request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_INVALID_JOB_MANAGER_TYPE;
        return(GLOBUS_FAILURE);
    }

    if ((strncmp(request->jobmanager_type, "fork", 4) != 0) &&
        (strncmp(request->jobmanager_type, "poe", 3) != 0))
    {
       /*
        * test that the scheduler script files exist and
        * that the user has permission to execute then.
        */
	globus_jobmanager_log(request->jobmanager_log_fp,
            "JMI: testing job manager scripts for type %s exist and "
            "permissions are ok.\n", request->jobmanager_type);

       /*---------------- submit script -----------------*/
       sprintf(script_path, "%s/globus-script-%s-submit",
                            request->jobmanager_libexecdir,
                            request->jobmanager_type);

       if (stat(script_path, &statbuf) != 0)
       {
	   globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: ERROR: script %s was not found.\n", script_path);
          request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_NOT_FOUND;
          return(GLOBUS_FAILURE);
       }

       if (!(statbuf.st_mode & 0111))
       {
	   globus_jobmanager_log(request->jobmanager_log_fp,
             "JMI: ERROR: Not permitted to execute script %s.\n", script_path);
           request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_PERMISSIONS;
           return(GLOBUS_FAILURE);
       }

       /*---------------- poll script -----------------*/
       sprintf(script_path, "%s/globus-script-%s-poll",
                            request->jobmanager_libexecdir,
                            request->jobmanager_type);

       if (stat(script_path, &statbuf) != 0)
       {
	   globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: ERROR: script %s was not found.\n", script_path);
          request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_NOT_FOUND;
          return(GLOBUS_FAILURE);
       }

       if (!(statbuf.st_mode & 0111))
       {
	   globus_jobmanager_log(request->jobmanager_log_fp,
             "JMI: ERROR: Not permitted to execute script %s.\n", script_path);
           request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_PERMISSIONS;
           return(GLOBUS_FAILURE);
       }

       /*---------------- rm script -----------------*/
       sprintf(script_path, "%s/globus-script-%s-rm",
                            request->jobmanager_libexecdir,
                            request->jobmanager_type);

       if (stat(script_path, &statbuf) != 0)
       {
	   globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: ERROR: script %s was not found.\n", script_path);
          request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_NOT_FOUND;
          return(GLOBUS_FAILURE);
       }

       if (!(statbuf.st_mode & 0111))
       {
	   globus_jobmanager_log(request->jobmanager_log_fp,
             "JMI: ERROR: Not permitted to execute script %s.\n", script_path);
           request->failure_code = GLOBUS_GRAM_PROTOCOL_ERROR_JM_SCRIPT_PERMISSIONS;
           return(GLOBUS_FAILURE);
       }
    }

    globus_jobmanager_log(request->jobmanager_log_fp,
        "JMI: job manager type is %s.\n", request->jobmanager_type);

    return(GLOBUS_SUCCESS);

}
/* globus_l_gram_request_validate() */

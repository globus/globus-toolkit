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

#define GLOBUS_GRAM_JOB_MANAGER_TOOLS "/libexec/globus-gram-job-manager-tools.sh"

/******************************************************************************
                          Module specific prototypes
******************************************************************************/
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
    "globus_gram_jobmanager",
    globus_l_gram_jobmanager_activate,
    globus_l_gram_jobmanager_deactivate,
    GLOBUS_NULL
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
    r->scratchdir = GLOBUS_NULL;
    r->scratch_dir_base = GLOBUS_NULL;
    r->paradyn = NULL;

    if ( (graml_script_arg_file = tempnam(NULL, "grami")) == NULL )
    {
        r->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;
        r->failure_code =
              GLOBUS_GRAM_PROTOCOL_ERROR_ARG_FILE_CREATION_FAILED;
        return(GLOBUS_FAILURE);
    }

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
Function:       globus_jobmanager_request()
Description:
Parameters:
Returns:
******************************************************************************/
int 
globus_jobmanager_request(globus_gram_jobmanager_request_t * request)
{
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    FILE * script_arg_fp;
    char new_param[4096];
    int num_in_list;
    char * stdout_filename = GLOBUS_NULL;
    char * stderr_filename = GLOBUS_NULL;

    if (!request)
        return(GLOBUS_FAILURE);

    if (globus_l_gram_request_validate(request) != GLOBUS_SUCCESS)
        return(GLOBUS_FAILURE);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_jobmanager_request()\n" );

    request->poll_frequency = 30;

    /*
     * create a file that will be used to pass all parameters to and 
     * amongst the globus_gram_script_<scheduler>_* scripts.
     */
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
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int rc;

    if (!request)
        return(GLOBUS_FAILURE);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_jobmanager_request_cancel()\n" );

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

    if (rc == GLOBUS_FAILURE)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: received error from script: %d\n", rc );
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning job state failed.\n" );
        return(GLOBUS_FAILURE);
    }

    return(GLOBUS_SUCCESS);

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
    FILE * signal_arg_fp;
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int rc;
    char * tmp_signalfilename = NULL;

    if (!request)
        return(GLOBUS_FAILURE);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_jobmanager_request_signal()\n" );

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
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int old_status;

    if (!request)
        return(GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED);

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
              "JMI: globus_jobmanager_request_check(): poll script returned unknown "
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

} /* globus_jobmanager_request_check() */

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

    globus_jobmanager_log(request->jobmanager_log_fp,
        "JMI: job manager type is %s.\n", request->jobmanager_type);

    return(GLOBUS_SUCCESS);

}
/* globus_l_gram_request_validate() */

int 
globus_jobmanager_request_scratchdir(
	globus_gram_jobmanager_request_t * request)
{
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int rc;
    FILE * script_arg_fp;
    long pos, end;

    if (!request)
        return(GLOBUS_FAILURE);

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

    fprintf(script_arg_fp,
	    "grami_scratch_dir_base='%s'\n",
	    request->scratch_dir_base);

    fclose(script_arg_fp);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_jobmanager_request_scratchdir()\n" );

    sprintf(script_cmd, "%s/globus-script-%s-scratchdir %s\n",
                         request->jobmanager_libexecdir,
                         request->jobmanager_type,
                         graml_script_arg_file);

    rc = globus_l_gram_script_run(script_cmd, request);

    if(rc == GLOBUS_SUCCESS)
    {
	script_arg_fp = fopen(graml_script_arg_file, "r");

	if(script_arg_fp != GLOBUS_NULL)
	{
	    fscanf(script_arg_fp, "grami_scratch_dir_base='%*[^\n]\n");
	    fscanf(script_arg_fp, "grami_scratch_dir='");
	    pos = ftell(script_arg_fp);
	    fscanf(script_arg_fp, "%*[^']'");
	    end = ftell(script_arg_fp);
	    fseek(script_arg_fp, pos, SEEK_SET);

	    request->scratchdir = globus_libc_malloc(end-pos + 2);
	    fscanf(script_arg_fp, "%[^']'", request->scratchdir);
	}
	fclose(script_arg_fp);
    }

    if (remove(graml_script_arg_file) != 0)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
                     "JM: Cannot remove argument file --> %s\n",
                     graml_script_arg_file);
    }

    request->status = GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED;

    if (rc == GLOBUS_FAILURE)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: received error from script: %d\n", rc );
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning job state failed.\n" );
        return(GLOBUS_FAILURE);
    }

    return(GLOBUS_SUCCESS);
} /* globus_jobmanager_request_scratchdir() */

int 
globus_jobmanager_request_rm_scratchdir(
	globus_gram_jobmanager_request_t * request)
{
    char script_cmd[GLOBUS_GRAM_PROTOCOL_MAX_MSG_SIZE];
    int rc;
    FILE * script_arg_fp;

    if (!request)
        return(GLOBUS_FAILURE);
    if (!request->scratchdir)
	return(GLOBUS_SUCCESS);

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

    fprintf(script_arg_fp, "grami_scratch_dir='%s'\n", request->scratchdir);

    fclose(script_arg_fp);

    globus_jobmanager_log(request->jobmanager_log_fp,
          "JMI: in globus_jobmanager_request_scratchdir()\n" );

    sprintf(script_cmd, "%s/globus-script-%s-rm-scratchdir %s\n",
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

    if (rc == GLOBUS_FAILURE)
    {
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: received error from script: %d\n", rc );
	globus_jobmanager_log(request->jobmanager_log_fp,
              "JMI: returning job state failed.\n" );
        return(GLOBUS_FAILURE);
    }

    return(GLOBUS_SUCCESS);
}
/* globus_jobmanager_request_rm_scratchdir() */

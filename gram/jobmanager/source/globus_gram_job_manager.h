/******************************************************************************
globus_gram_job_manager.h
 
Description:
    This header contains the exported interface of the Job Management.
 
CVS Information:
******************************************************************************/
 
#ifndef GLOBUS_GRAM_JOB_MANAGER_INCLUDE
#define GLOBUS_GRAM_JOB_MANAGER_INCLUDE

/******************************************************************************
                               Includes
******************************************************************************/

#include "globus_common.h"
#include "globus_rsl.h"
#include "globus_gram_client.h"

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

/******************************************************************************
                               Type definitions
******************************************************************************/
#define GLOBUS_GRAM_JOBMANAGER_VERSION 1

#define   GLOBUS_GRAM_JOBMANAGER_STATUS_UNCHANGED   0
#define   GLOBUS_GRAM_JOBMANAGER_STATUS_CHANGED     1
#define   GLOBUS_GRAM_JOBMANAGER_STATUS_FAILED      2

typedef enum
{
   GLOBUS_GRAM_JOBMANAGER_JOBTYPE_MPI      = 0,
   GLOBUS_GRAM_JOBMANAGER_JOBTYPE_SINGLE   = 1,
   GLOBUS_GRAM_JOBMANAGER_JOBTYPE_MULTIPLE = 2,
   GLOBUS_GRAM_JOBMANAGER_JOBTYPE_CONDOR   = 3
} globus_gram_jobmanager_jobtype_t;

typedef char * (* globus_gram_job_manager_callback_func_t) (int stdout_flag);

typedef struct
{
 int	version;         /* The jobmanager library version */

 int	status;		 /* The state of the job:
			  *     GLOBUS_GRAM_STATE_PENDING
			  *     GLOBUS_GRAM_STATE_ACTIVE
			  *     GLOBUS_GRAM_STATE_FAILED
			  *     GLOBUS_GRAM_STATE_DONE
			  *     GLOBUS_GRAM_STATE_SUSPENDED
			  */

 int	failure_code;    /* If the state is GLOBUS_GRAM_STATE_FAILED, then this
                          * is an integer code that defines the failure. It is
                          * one of GLOBUS_GRAM_ERROR_*.
                          */

 void *	user_pointer;    /* A pointer that can be used by the user for
                          * any purpose.
                          */

 char *	job_id;	         /* Underlying queueing system job id for this job
                          * This value is filled in when the request is done
                          */

 unsigned int poll_frequency;  /* How often should a check of the job status
                                * and output files be done.
                                */
 /************************************************************
  * The rest of these can be optionally filled in by the user,
  * to define the request. All of these values should be
  * allocated using globus_libc_malloc().
  * The globus_gram_jobmanager_request_destroy() function
  * will free all of these values using globus_libc_free().
  ************************************************************/


 char *	jobmanager_type; /* fork, loadleveler, lsf, easymcs, pbs, ... */

 char *	jobmanager_libexecdir; /* location of the jobmanager shell files */


 char * jobmanager_logfile;
 FILE *	jobmanager_log_fp;     /* file and fp to which stuff should be
                                * logged, or NULL for none
                                */

 char *	executable;	/* executable path, either full or relative to home,
                         * no ~
                         */

 char *	directory;      /* directory path, either full or relative to home,
                         * no ~
                         */

 char ** environment;  /* An argv[] with the programs environment */

 char ** arguments;   /* An argv[] with the programs arguments */

 char * my_stdin;     /* File path (full, relative to home, no) for stdin */

 char * my_stdout;    /* File path (full, relative to home, no ~) for stdout */
 char * my_stdout_tag;/* Specific tag, used only for stdout x-gass-cache URL */

 char * my_stderr;    /* File path (full, relative to home, no ~) for stderr */
 char * my_stderr_tag;/* Specific tag, used only for stderr x-gass-cache URL */

 unsigned int count;       /* Number of processes to start */

 unsigned int host_count;  /* Number of hosts across which the count processes
                            * should be spread
                            */

 char * queue;       /* The name of the queue to submit the job to */

 char * project;      /* The project to which the job should be billed */

 char * reservation_handle; /* used for network Quality of Service (QOS) */

 char * condor_arch;  /* Used only when type=condor.  Must match one of the
                       * archetecture values as defined by condor
                       */

 char * condor_os;    /* Used only when type=condor.  Must match one of the
                       * opsys values as defined by condor
                       */

 char * paradyn; 

 globus_gram_jobmanager_jobtype_t job_type;   /* The way in which the job 
                                              * should be started
                                              */
 char * start_time;     /* The wallclock time the job should be started */

 unsigned long max_wall_time;    /* Maximum system wall clock runtime
                                  * in minutes, 0 means use the system default
                                  */

 unsigned long max_cpu_time;    /* Maximum system cpu runtime
                                 * in minutes, 0 means use the system default
                                 */

 unsigned long max_time;    /* Maximum runtime in minutes, 0 means use the
                            * system default
                            */

 unsigned long min_memory;    /* Minimum amount of memory in MB needed for job,
                               * 0 is the default.
                               */

 unsigned long max_memory;    /* Maximum amount of memory in MB needed for job,
                               * 0 is the default which means unlimited.
                               */

 globus_bool_t dry_run;    /* GLOBUS_TRUE if this is a dryrun */

 
 globus_gram_client_job_signal_t signal;  /* enum of type of signal to job
                                           * (cancel, suspend, priority, ...)
                                           */

 char * signal_arg;           /* could be anything.
                               * if a priority change maybe something like
                               * high, medium, low...
                               */

 /* Other opaque fields may be added here */

 globus_gram_job_manager_callback_func_t filename_callback_func;

} globus_gram_jobmanager_request_t;

typedef struct globus_l_gram_scheduler_s
{
    int add_entries_flag;
    int maxtime;
    int maxcputime;
    int maxcount;
    int maxrunningjobs;
    int maxjobsinqueue;
    int maxtotalmemory;
    int maxsinglememory;
    int totalnodes;
    int freenodes;
    char * queuename;
    char * whenactive;
    char * status;
    char * dispatchtype;
    char * priority;
    char * alloweduserlist; /* char * of globusUserNames */
    char * jobwait;
    char * schedulerspecific;
    globus_list_t * entry_list; /* globus_gram_scheduler_queue_entry_t */
} globus_gram_scheduler_t;

typedef struct globus_l_gram_scheduler_entry_s
{
    char * local_job_id;
    char * global_job_id;
    char * local_user_name;
    char * global_user_name;
    int count;
    char * status;
    unsigned long start_time;
    unsigned long finish_time;
    unsigned long elapsed_time;
    int requested memory;
    int requested_time;
    char * schedulerspecific;
    char * specification;
} globus_gram_scheduler_entry_t;

/******************************************************************************
                              Function prototypes
******************************************************************************/

/* Initialize the request structure to its default values.
 */
extern int
globus_jobmanager_request_init(
	globus_gram_jobmanager_request_t ** request);

/*-----------------------------------------------------------------------
 * Destroy the request structure, and free any associated memory.
 * This function does NOT cancel the job request
 */
extern int 
globus_jobmanager_request_destroy(
	globus_gram_jobmanager_request_t * request);

/*-----------------------------------------------------------------------
 * This function makes a request for resources to the local scheduler.
 * It returns GLOBUS_SUCCESS if the job request was able to be executed,
 * otherwise it returns GLOBUS_FAILURE, with the request->failure_code
 * set to GLOBUS_GRAM_ERROR_*.
 */
extern int 
globus_jobmanager_request(
	globus_gram_jobmanager_request_t * request);

/*-----------------------------------------------------------------------
 * This function cancels a job regardless of the job's current state.
 * It returns GLOBUS_SUCCESS if the job was successfully cancelled,
 * otherwise it returns GLOBUS_FAILURE.
 */
extern int 
globus_jobmanager_request_cancel(
	globus_gram_jobmanager_request_t * request);

/*-----------------------------------------------------------------------
 * This function checks the job's current status, and updates the request
 * structure appropriately.
 * It returns GLOBUS_GRAM_JOBMANAGER_STATE_UNCHANGED if the job status has
 * not changed since the last check, or GLOBUS_GRAM_JOBMANAGER_STATE_CHANGED
 * if the job status has changed
 */
extern int 
globus_jobmanager_request_check(
	globus_gram_jobmanager_request_t * request);

/*-----------------------------------------------------------------------
 * This function gets a list of the queue(s) paramters and entries managed by
 * the GRAM.
 */
extern int 
globus_gram_scheduler_queue_list_get(
        char * script_cmd,
	globus_list_t ** queue_list);

/*-----------------------------------------------------------------------
 * This function free the memory from a previous
 * globus_gram_queue_list_get() call
 */
extern int 
globus_gram_scheduler_queue_list_free(
	globus_list_t * queue_list);

/*-----------------------------------------------------------------------
 * This function initializes the passed in scheduler queue node
 */
extern void
globus_i_gram_q_init(
        globus_gram_scheduler_t * q_node);

/*-----------------------------------------------------------------------
 * This function initializes the passed in scheduler queue entry node
 */
extern void
globus_i_gram_q_entry_init(
        globus_gram_scheduler_entry_t * q_entry_node);

/******************************************************************************
                               Define constants
******************************************************************************/
#define GRAM_VERSION "@GRAMVERSION@"
#define GRAM_VERSION_DATE "@GRAMVERSIONDATE@"
#define GRAM_SECURITY "@GSSAPI_TYPE@"

/* remove or ignore old status files after no activity for
 * GRAM_JOB_MANAGER_STATUS_FILE_SECONDS
 */
#define GRAM_JOB_MANAGER_STATUS_FILE_SECONDS 600


/******************************************************************************
 *                    Module Definition
 *****************************************************************************/
extern int
globus_i_gram_jobmanager_activate(void);
 
extern int
globus_i_gram_jobmanager_deactivate(void);

#define GLOBUS_GRAM_JOBMANAGER_MODULE (&globus_i_gram_jobmanager_module)
extern globus_module_descriptor_t globus_i_gram_jobmanager_module;

EXTERN_C_END

#endif /* GLOBUS_GRAM_JOB_MANAGER_INCLUDE */

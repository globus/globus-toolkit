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
#include "globus_gram_protocol.h"

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

typedef struct
{
    char *				option_name;
    char **				option_string; /* NULL terminated */
}
globus_gram_job_manager_scheduler_specific_t;

typedef char * (* globus_gram_job_manager_callback_func_t) (int stdout_flag);

typedef struct
{
    /**
     * Job State
     *
     * The state of the job:
     * - GLOBUS_GRAM_STATE_UNSUBMITTED
     * - GLOBUS_GRAM_STATE_PENDING
     * - GLOBUS_GRAM_STATE_ACTIVE
     * - GLOBUS_GRAM_STATE_FAILED 
     * - GLOBUS_GRAM_STATE_DONE
     * - GLOBUS_GRAM_STATE_SUSPENDED
     */ 
    int					status;

    /**
     * Job Failure Reason
     *
     * If the state is GLOBUS_GRAM_STATE_FAILED, then this
     * is an integer code that defines the failure. It is one of
     * GLOBUS_GRAM_PROTOCOL_ERROR_*.
     */
    int					failure_code;

    /**
     * User data
     *
     * A pointer that can be used by the user for
     * any purpose.
     */ 
    void *				user_pointer;
    
    /**
     * Job identifier
     *
     * Underlying queueing system job id for this job.
     * This value is filled in when the request is submitted.
     */
    char *				job_id;

    /**
     * Unique job identifier
     *
     * Unique id for this job that will be consistent
     * across jobmanager restarts/recoveries.
     */
    char *				uniq_id;

    /**
     * Poll Frequency
     *
     * How often should a check of the job status and output files be done.
     */
    unsigned int			poll_frequency;


    /*
     * The rest of these can be optionally filled in by the user,
     * to define the request. All of these values should be
     * allocated using globus_libc_malloc().
     * The globus_gram_jobmanager_request_destroy() function
     * will free all of these values using globus_libc_free().
     */

    /**
     * Job Manager Type
     *
     * Identifies the scheduler which will be used to process this job
     * request. Possible values are fork, loadleveler, lsf, easymcs, pbs,
     * and others.
     */ 
    char *				jobmanager_type;

    /**
     * Job Manager Script Directory
     *
     * The path to the directory containing the Job Manager's scheduler
     * interface scripts. Usually $GLOBUS_LOCATION/libexec
     */
    char *				jobmanager_libexecdir;

    /**
     * Log File Name
     *
     * A path to a file to append logging information to.
     */
    char *				jobmanager_logfile;

    /**
     * Log File Pointer
     *
     * A stdio FILE pointer used for logging. NULL if no logging is requested.
     */
    FILE *				jobmanager_log_fp;

    /**
     * Executable Path
     * 
     * Path to the executable to run. This may be either a full path or relative
     * to the directory.
     */
    char *				executable;

    /**
     * Directory path
     *
     * Path to the job's starting directory. This may be either full or
     * relative to the user's home directory.
     */
    char *				directory;

    /**
     * Environment variables
     * An array alternating between environment variables and their values.
     * The array must be NULL-terminated.
     */
    char **				environment;

    /**
     * Program Arguments
     *
     * A NULL-terminated array of program arguments.
     */
    char **				arguments;

     /**
      * Standard Input File Name
      *
      * Absolute path to a file to be fed to the executable as it's
      * standard input.
      */
    char *				my_stdin;

     /**
      * Standard Output File Name
      *
      * Absolute path to a file to be used as standard output for the
      * executable.
      */
    char *				my_stdout;

    /**
     * Standard Output GASS Cache Tag
     *
     * Tag string to be used when stdout is a x-gass-cache URL.
     */
    char *				my_stdout_tag;

    /**
     * Standard Error File Name
     *
     * Absolute path to a file to be used as standard error for the
     * executable.
     */
    char *				my_stderr;

    /**
     * Standard Error GASS Cache Tag
     *
     * Tag string to be used when stderr is a x-gass-cache URL.
     */
    char *				my_stderr_tag;

    /**
     * Process count
     *
     * Number of processes to start
     */
    unsigned int			count;

    /**
     * Host count
     *
     * Number of hosts across which the count processes
     * should be spread. Useful for SMP systems.
     */
    unsigned int			host_count;

    /**
     * Job Queue
     *
     * The name of the queue to submit the job to.
     */ 
    char *				queue;

    /**
     * Job Project
     *
     * The project to which the job should be billed.
     */
    char *				project;

    /**
     * Job QoS handle
     *
     * used for network Quality of Service (QOS)
     */
    char *				reservation_handle;

    /**
     * Condor Architecture
     *
     * Used only when type=condor.  Must match one of the archetecture values
     * as defined by condor
     */
    char *				condor_arch;

    /**
     * Condor Operating System
     *
     * Used only when type=condor.  Must match one of the opsys values as
     * defined by condor
     */ 
    char *				condor_os;

    /**
     * Paradyn Instrumentation.
     */
    char *				paradyn; 

   /**
    * Type of Job
    *
    * Indicates which startup method needs to be used to run the job.
    */
    globus_gram_jobmanager_jobtype_t	job_type;
    /**
     * Job Start Time
     *
     * The wallclock time the job should be started
     */
    char *				start_time;

    /**
     * Maximum Job Time (wallclock)
     *
     * Maximum wall clock run time in minutes, 0 means use the system
     * default.
     */
    unsigned long			max_wall_time;

    /**
     * Maximum Job Time (CPU)
     *
     * Maximum system cpu runtime in minutes, 0 means use the system default.
     */
    unsigned long			max_cpu_time;

    /**
     * Maximum runtime in minutes (cpu or wallclock), 0 means use the system
     * default. This is entirely scheduler-specific.
     */
    unsigned long			max_time;

    /**
     * Minimum Memory Requirements
     *
     * Minimum amount of memory in MB needed for job, 0 is the default.
     */
    unsigned long			min_memory;

    /**
     * Maximum Memory Requirements
     *
     * Maximum amount of memory in MB needed for job, 0 is the default which
     * means unlimited.
     */
    unsigned long			max_memory;

    /**
     * Dry Run
     *
     * If this is GLOBUS_TRUE, do not actually submit the job to the scheduler,
     * just verify the job parameters.
     */
    globus_bool_t			dry_run;

    /**
     * Signal
     *
     * Type of signal to process.
     */
    globus_gram_protocol_job_signal_t	signal;

    /**
     * Signal-specific data
     *
     * If a priority change maybe something like high, medium, low. see
     * the documentation on signals in the globus_gram_protocol library.
     */
    char *				signal_arg;

    /**
     *
     * Two-phase commit.
     *
     * Non-zero if request should be confirmed via another signal.
     *
     * The value is how many seconds to wait before timing out.
     */
    int					two_phase_commit;

    /**
     * Save Job Manager State
     *
     * Generate a state file for possibly restarting the job manager
     * at a later time after a failure or signal.
     */
    globus_bool_t			save_state;

    /**
     * Previous Job Manager Contact 
     *
     * If we're restarting from a terminated Job Manager, this will specify the
     * old job contact so we can locate the Job Manager state file.
     */
    char *				jm_restart;

     /**
      * Restart Standard Output Position
      *
      * The position to start resending stdout from for remote stdout on a
      * restart
      */
    int					stdout_position;

     /**
      * Restart Standard Error Position
      *
      * The position to start resending stderr from for remote stderr on a
      * restart
      */
    int					stderr_position;

    /**
     * Array of Scheduler Specific Options
     *
     * A NULL-terminated set of scheduler specific options and their values.
     */
    globus_gram_job_manager_scheduler_specific_t *
     					scheduler_specific;

    globus_gram_job_manager_callback_func_t
					filename_callback_func;
}
globus_gram_jobmanager_request_t;

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
 * ???
 */
extern int 
globus_jobmanager_request_signal(
	globus_gram_jobmanager_request_t * request);

extern int
globus_jobmanager_log(
	FILE *log_fp,
	const char *format, ...);

/******************************************************************************
 *                    Module Definition
 *****************************************************************************/
#define GLOBUS_GRAM_JOBMANAGER_MODULE (&globus_i_gram_jobmanager_module)
extern globus_module_descriptor_t globus_i_gram_jobmanager_module;

EXTERN_C_END

#endif /* GLOBUS_GRAM_JOB_MANAGER_INCLUDE */

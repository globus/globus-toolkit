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

 char * my_stderr;    /* File path (full, relative to home, no ~) for stderr */

 unsigned int count;       /* Number of processes to start */

 unsigned int host_count;  /* Number of hosts across which the count processes
                            * should be spread
                            */

 char * queue;       /* The name of the queue to submit the job to */

 char * project;      /* The project to which the job should be billed */

 char * paradyn; 

 globus_gram_jobmanager_jobtype_t jobtype;   /* The way in which the job 
                                              * should be started
                                              */

 unsigned long maxtime;    /* Maximum runtime in minutes, 0 means use the
                            * system default
                            */

 globus_bool_t dryrun;    /* GLOBUS_TRUE if this is a dryrun */

 globus_gram_job_manager_callback_func_t filename_callback_func;

} globus_gram_jobmanager_request_t;

/* Other opaque fields may be added here */

/******************************************************************************
                              Function prototypes
******************************************************************************/

/* Initialize the request structure to its default values.
 */
extern int
globus_gram_jobmanager_request_init(
	globus_gram_jobmanager_request_t ** request);

/*-----------------------------------------------------------------------
 * Destroy the request structure, and free any associated memory.
 * This function does NOT cancel the job request
 */
extern int 
globus_gram_jobmanager_request_destroy(
	globus_gram_jobmanager_request_t * request);

/*-----------------------------------------------------------------------
 * This function makes a request for resources to the local scheduler.
 * It returns GLOBUS_SUCCESS if the job request was able to be executed,
 * otherwise it returns GLOBUS_FAILURE, with the request->failure_code
 * set to GLOBUS_GRAM_ERROR_*.
 */
extern int 
globus_gram_jobmanager_request(
	globus_gram_jobmanager_request_t * request);

/*-----------------------------------------------------------------------
 * This function cancels a job regardless of the job's current state.
 * It returns GLOBUS_SUCCESS if the job was successfully cancelled,
 * otherwise it returns GLOBUS_FAILURE.
 */
extern int 
globus_gram_jobmanager_request_cancel(
	globus_gram_jobmanager_request_t * request);

/*-----------------------------------------------------------------------
 * This function checks the job's current status, and updates the request
 * structure appropriately.
 * It returns GLOBUS_GRAM_JOBMANAGER_STATE_UNCHANGED if the job status has
 * not changed since the last check, or GLOBUS_GRAM_JOBMANAGER_STATE_CHANGED
 * if the job status has changed
 */
extern int 
globus_gram_jobmanager_request_check(
	globus_gram_jobmanager_request_t * request);

/******************************************************************************
                               Define constants
******************************************************************************/
#define GLOBUS_MPIRUN_PATH "@MPIRUN@"
#define GLOBUS_POE_PATH "@POE@"

/******************************************************************************
 *                    Module Definition
 *****************************************************************************/
extern int
globus_i_gram_jobmanager_activate(void);
 
extern int
globus_i_gram_jobmanager_deactivate(void);

#define GLOBUS_GRAM_JOBMANAGER_MODULE (&globus_i_gram_jobmanager_module)
extern globus_module_descriptor_t globus_i_gram_jobmanager_module;

#endif /* GLOBUS_GRAM_JOB_MANAGER_INCLUDE */

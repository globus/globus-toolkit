/******************************************************************************
gram_client.h

Description:
    This header file contains the exported client interface of 
    the Resource Allocation Management System, including the new Globus 1.1
    asynchronous functions.

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

#ifndef GLOBUS_I_GRAM_CLIENT_INCLUDE
#define GLOBUS_I_GRAM_CLIENT_INCLUDE

/******************************************************************************
                             Include header files
******************************************************************************/

#include "globus_common.h"

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
                               Define constants
******************************************************************************/

#define GLOBUS_GRAM_CLIENT_MAX_MSG_SIZE                    64000
#define GLOBUS_GRAM_CLIENT_PARAM_SIZE                      1024
#define GLOBUS_GRAM_CLIENT_STRING_SIZE                     256

/* 
 *  Job State Constants
 */
#define GLOBUS_GRAM_CLIENT_JOB_STATE_PENDING \
	@GLOBUS_GRAM_CLIENT_JOB_STATE_PENDING@
#define GLOBUS_GRAM_CLIENT_JOB_STATE_ACTIVE \
	@GLOBUS_GRAM_CLIENT_JOB_STATE_ACTIVE@
#define GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED \
	@GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED@
#define GLOBUS_GRAM_CLIENT_JOB_STATE_DONE \
	@GLOBUS_GRAM_CLIENT_JOB_STATE_DONE@
#define GLOBUS_GRAM_CLIENT_JOB_STATE_SUSPENDED \
	@GLOBUS_GRAM_CLIENT_JOB_STATE_SUSPENDED@
#define GLOBUS_GRAM_CLIENT_JOB_STATE_ALL \
	@GLOBUS_GRAM_CLIENT_JOB_STATE_ALL@

/*
 *  Job Result Constants
 */
#define GLOBUS_GRAM_CLIENT_ERROR_PARAMETER_NOT_SUPPORTED \
	@GLOBUS_GRAM_CLIENT_ERROR_PARAMETER_NOT_SUPPORTED@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_REQUEST \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_REQUEST@
#define GLOBUS_GRAM_CLIENT_ERROR_NO_RESOURCES \
	@GLOBUS_GRAM_CLIENT_ERROR_NO_RESOURCES@
#define GLOBUS_GRAM_CLIENT_ERROR_BAD_DIRECTORY \
	@GLOBUS_GRAM_CLIENT_ERROR_BAD_DIRECTORY@
#define GLOBUS_GRAM_CLIENT_ERROR_EXECUTABLE_NOT_FOUND \
	@GLOBUS_GRAM_CLIENT_ERROR_EXECUTABLE_NOT_FOUND@
#define GLOBUS_GRAM_CLIENT_ERROR_INSUFFICIENT_FUNDS \
	@GLOBUS_GRAM_CLIENT_ERROR_INSUFFICIENT_FUNDS@
#define GLOBUS_GRAM_CLIENT_ERROR_AUTHORIZATION \
	@GLOBUS_GRAM_CLIENT_ERROR_AUTHORIZATION@
#define GLOBUS_GRAM_CLIENT_ERROR_USER_CANCELLED \
	@GLOBUS_GRAM_CLIENT_ERROR_USER_CANCELLED@
#define GLOBUS_GRAM_CLIENT_ERROR_SYSTEM_CANCELLED \
	@GLOBUS_GRAM_CLIENT_ERROR_SYSTEM_CANCELLED@
#define GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_STDIN_NOT_FOUND \
	@GLOBUS_GRAM_CLIENT_ERROR_STDIN_NOT_FOUND@
#define GLOBUS_GRAM_CLIENT_ERROR_CONNECTION_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_CONNECTION_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_MAXTIME \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_MAXTIME@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_COUNT \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_COUNT@
#define GLOBUS_GRAM_CLIENT_ERROR_NULL_SPECIFICATION_TREE \
	@GLOBUS_GRAM_CLIENT_ERROR_NULL_SPECIFICATION_TREE@
#define GLOBUS_GRAM_CLIENT_ERROR_JM_FAILED_ALLOW_ATTACH \
	@GLOBUS_GRAM_CLIENT_ERROR_JM_FAILED_ALLOW_ATTACH@
#define GLOBUS_GRAM_CLIENT_ERROR_JOB_EXECUTION_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_JOB_EXECUTION_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_PARADYN \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_PARADYN@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOBTYPE \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOBTYPE@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_GRAM_MYJOB \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_GRAM_MYJOB@
#define GLOBUS_GRAM_CLIENT_ERROR_BAD_SCRIPT_ARG_FILE \
	@GLOBUS_GRAM_CLIENT_ERROR_BAD_SCRIPT_ARG_FILE@
#define GLOBUS_GRAM_CLIENT_ERROR_ARG_FILE_CREATION_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_ARG_FILE_CREATION_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOBSTATE \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOBSTATE@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_SCRIPT_REPLY \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_SCRIPT_REPLY@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_SCRIPT_STATUS \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_SCRIPT_STATUS@
#define GLOBUS_GRAM_CLIENT_ERROR_JOBTYPE_NOT_SUPPORTED \
	@GLOBUS_GRAM_CLIENT_ERROR_JOBTYPE_NOT_SUPPORTED@
#define GLOBUS_GRAM_CLIENT_ERROR_UNIMPLEMENTED \
	@GLOBUS_GRAM_CLIENT_ERROR_UNIMPLEMENTED@
#define GLOBUS_GRAM_CLIENT_ERROR_TEMP_SCRIPT_FILE_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_TEMP_SCRIPT_FILE_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_USER_PROXY_NOT_FOUND \
	@GLOBUS_GRAM_CLIENT_ERROR_USER_PROXY_NOT_FOUND@
#define GLOBUS_GRAM_CLIENT_ERROR_OPENING_USER_PROXY\
	@GLOBUS_GRAM_CLIENT_ERROR_OPENING_USER_PROXY@
#define GLOBUS_GRAM_CLIENT_ERROR_JOB_CANCEL_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_JOB_CANCEL_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_MALLOC_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_MALLOC_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_DUCT_INIT_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_DUCT_INIT_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_DUCT_LSP_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_DUCT_LSP_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_HOST_COUNT \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_HOST_COUNT@
#define GLOBUS_GRAM_CLIENT_ERROR_UNSUPPORTED_PARAMETER \
	@GLOBUS_GRAM_CLIENT_ERROR_UNSUPPORTED_PARAMETER@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_QUEUE \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_QUEUE@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_PROJECT \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_PROJECT@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_EVALUATION_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_EVALUATION_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_BAD_RSL_ENVIRONMENT \
	@GLOBUS_GRAM_CLIENT_ERROR_BAD_RSL_ENVIRONMENT@
#define GLOBUS_GRAM_CLIENT_ERROR_DRYRUN \
	@GLOBUS_GRAM_CLIENT_ERROR_DRYRUN@
#define GLOBUS_GRAM_CLIENT_ERROR_ZERO_LENGTH_RSL \
	@GLOBUS_GRAM_CLIENT_ERROR_ZERO_LENGTH_RSL@
#define GLOBUS_GRAM_CLIENT_ERROR_STAGING_EXECUTABLE \
	@GLOBUS_GRAM_CLIENT_ERROR_STAGING_EXECUTABLE@
#define GLOBUS_GRAM_CLIENT_ERROR_STAGING_STDIN \
	@GLOBUS_GRAM_CLIENT_ERROR_STAGING_STDIN@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_MANAGER_TYPE \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_MANAGER_TYPE@
#define GLOBUS_GRAM_CLIENT_ERROR_BAD_ARGUMENTS \
	@GLOBUS_GRAM_CLIENT_ERROR_BAD_ARGUMENTS@
#define GLOBUS_GRAM_CLIENT_ERROR_GATEKEEPER_MISCONFIGURED \
	@GLOBUS_GRAM_CLIENT_ERROR_GATEKEEPER_MISCONFIGURED@
#define GLOBUS_GRAM_CLIENT_ERROR_BAD_RSL \
	@GLOBUS_GRAM_CLIENT_ERROR_BAD_RSL@
#define GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH \
	@GLOBUS_GRAM_CLIENT_ERROR_VERSION_MISMATCH@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_ARGUMENTS \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_ARGUMENTS@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_COUNT \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_COUNT@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_DIRECTORY \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_DIRECTORY@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_DRYRUN \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_DRYRUN@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_ENVIRONMENT \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_ENVIRONMENT@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_EXECUTABLE \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_EXECUTABLE@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_HOST_COUNT \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_HOST_COUNT@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_JOBTYPE \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_JOBTYPE@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_MAXTIME \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_MAXTIME@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_MYJOB \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_MYJOB@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_PARADYN \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_PARADYN@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_PROJECT \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_PROJECT@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_QUEUE \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_QUEUE@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_STDERR \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_STDERR@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_STDIN \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_STDIN@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_STDOUT \
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_STDOUT@
#define GLOBUS_GRAM_CLIENT_ERROR_OPENING_JOBMANAGER_SCRIPT \
	@GLOBUS_GRAM_CLIENT_ERROR_OPENING_JOBMANAGER_SCRIPT@
#define GLOBUS_GRAM_CLIENT_ERROR_CREATING_PIPE \
	@GLOBUS_GRAM_CLIENT_ERROR_CREATING_PIPE@
#define GLOBUS_GRAM_CLIENT_ERROR_FCNTL_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_FCNTL_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_STDOUT_FILENAME_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_STDOUT_FILENAME_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_STDERR_FILENAME_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_STDERR_FILENAME_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_FORKING_EXECUTABLE \
	@GLOBUS_GRAM_CLIENT_ERROR_FORKING_EXECUTABLE@
#define GLOBUS_GRAM_CLIENT_ERROR_EXECUTABLE_PERMISSIONS \
	@GLOBUS_GRAM_CLIENT_ERROR_EXECUTABLE_PERMISSIONS@
#define GLOBUS_GRAM_CLIENT_ERROR_OPENING_STDOUT \
	@GLOBUS_GRAM_CLIENT_ERROR_OPENING_STDOUT@
#define GLOBUS_GRAM_CLIENT_ERROR_OPENING_STDERR \
	@GLOBUS_GRAM_CLIENT_ERROR_OPENING_STDERR@
#define GLOBUS_GRAM_CLIENT_ERROR_OPENING_CACHE_USER_PROXY \
	@GLOBUS_GRAM_CLIENT_ERROR_OPENING_CACHE_USER_PROXY@
#define GLOBUS_GRAM_CLIENT_ERROR_OPENING_CACHE\
	@GLOBUS_GRAM_CLIENT_ERROR_OPENING_CACHE@
#define GLOBUS_GRAM_CLIENT_ERROR_INSERTING_CLIENT_CONTACT\
	@GLOBUS_GRAM_CLIENT_ERROR_INSERTING_CLIENT_CONTACT@
#define GLOBUS_GRAM_CLIENT_ERROR_CLIENT_CONTACT_NOT_FOUND\
	@GLOBUS_GRAM_CLIENT_ERROR_CLIENT_CONTACT_NOT_FOUND@
#define GLOBUS_GRAM_CLIENT_ERROR_CONTACTING_JOB_MANAGER\
	@GLOBUS_GRAM_CLIENT_ERROR_CONTACTING_JOB_MANAGER@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_CONTACT\
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOB_CONTACT@
#define GLOBUS_GRAM_CLIENT_ERROR_UNDEFINED_EXE\
	@GLOBUS_GRAM_CLIENT_ERROR_UNDEFINED_EXE@
#define GLOBUS_GRAM_CLIENT_ERROR_CONDOR_ARCH\
	@GLOBUS_GRAM_CLIENT_ERROR_CONDOR_ARCH@
#define GLOBUS_GRAM_CLIENT_ERROR_CONDOR_OS\
	@GLOBUS_GRAM_CLIENT_ERROR_CONDOR_OS@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_MIN_MEMORY\
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_MIN_MEMORY@
#define GLOBUS_GRAM_CLIENT_ERROR_RSL_MAX_MEMORY\
	@GLOBUS_GRAM_CLIENT_ERROR_RSL_MAX_MEMORY@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_MIN_MEMORY\
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_MIN_MEMORY@
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_MAX_MEMORY\
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_MAX_MEMORY@
/* ASYNCHRONOUS code ERRORs */
#define GLOBUS_GRAM_CLIENT_ERROR_NEED_STATUS_CALLBACK\
	@GLOBUS_GRAM_CLIENT_ERROR_NEED_STATUS_CALLBACK@
#define GLOBUS_GRAM_CLIENT_ERROR_OUT_OF_MEMORY\
	@GLOBUS_GRAM_CLIENT_ERROR_OUT_OF_MEMORY@

/* Add new GLOBUS_GRAM_CLIENT_ERROR code here */
/* don't forget to update globus_gram_error.c also !! */

#define GLOBUS_GRAM_CLIENT_ERROR_LAST \
	@GLOBUS_GRAM_CLIENT_ERROR_LAST@

/*
 *  Job Parameter Constants
 */
#define GLOBUS_GRAM_CLIENT_EXECUTABLE_PARAM               "executable"
#define GLOBUS_GRAM_CLIENT_ARGUMENTS_PARAM                "arguments"
#define GLOBUS_GRAM_CLIENT_ENVIRONMENT_PARAM              "environment"
#define GLOBUS_GRAM_CLIENT_DIR_PARAM                      "directory"
#define GLOBUS_GRAM_CLIENT_COUNT_PARAM                    "count"
#define GLOBUS_GRAM_CLIENT_STDIN_PARAM                    "stdin"
#define GLOBUS_GRAM_CLIENT_STDOUT_PARAM                   "stdout"
#define GLOBUS_GRAM_CLIENT_STDERR_PARAM                   "stderr"
#define GLOBUS_GRAM_CLIENT_MAX_TIME_PARAM                 "max_time"
#define GLOBUS_GRAM_CLIENT_PARADYN_PARAM                  "paradyn"
#define GLOBUS_GRAM_CLIENT_JOB_TYPE_PARAM                 "job_type"
#define GLOBUS_GRAM_CLIENT_MYJOB_PARAM                    "gram_myjob"
#define GLOBUS_GRAM_CLIENT_QUEUE_PARAM                    "queue"
#define GLOBUS_GRAM_CLIENT_PROJECT_PARAM                  "project"
#define GLOBUS_GRAM_CLIENT_HOST_COUNT_PARAM               "host_count"
#define GLOBUS_GRAM_CLIENT_DRY_RUN_PARAM                  "dry_run"
#define GLOBUS_GRAM_CLIENT_MIN_MEMORY_PARAM               "min_memory"
#define GLOBUS_GRAM_CLIENT_MAX_MEMORY_PARAM               "max_memory"

/*
 *  Job Default Constants
 */
#define GLOBUS_GRAM_CLIENT_DEFAULT_STDIN                  "/dev/null"
#define GLOBUS_GRAM_CLIENT_DEFAULT_STDOUT                 "/dev/null"
#define GLOBUS_GRAM_CLIENT_DEFAULT_STDERR                 "/dev/null"
#define GLOBUS_GRAM_CLIENT_DEFAULT_MYJOB                  "collective"
#define GLOBUS_GRAM_CLIENT_DEFAULT_JOBTYPE                "multiple"
#define GLOBUS_GRAM_CLIENT_DEFAULT_DRYRUN                 "no"


/******************************************************************************
                               Type definitions
******************************************************************************/


typedef void (* globus_gram_client_callback_func_t)(void * user_callback_arg,
						    char * job_contact,
						    int state,
						    int errorcode);
typedef struct
{
    int dumb_time;
} globus_gram_client_time_t;


/******************************************************************************
                               Global variables
******************************************************************************/


/******************************************************************************
                              Function prototypes
******************************************************************************/
extern int 
globus_gram_client_callback_allow(
                          globus_gram_client_callback_func_t callback_func,
			  void * user_callback_arg,
			  char ** callback_contact);

extern int 
globus_gram_client_job_request(char * resource_manager_contact,
			       const char * description,
			       const int job_state_mask,
			       const char * callback_contact,
			       char ** job_contact);

extern int 
globus_gram_client_job_cancel(char * job_contact);

extern int
globus_gram_client_job_status(char * job_contact,
                              int * job_status,
                              int * failure_code);

extern int
globus_gram_client_job_callback_register(char * job_contact,
                                         const int job_state_mask,
                                         const char * callback_contact,
                                         int * job_status,
                                         int * failure_code);

extern int
globus_gram_client_job_callback_unregister(char * job_contact,
                                           const char * callback_contact,
                                           int * job_status,
                                           int * failure_code);

extern int 
globus_gram_client_callback_disallow(char * callback_contact);

extern int 
globus_gram_client_callback_check();

extern int 
globus_gram_client_job_contact_free(char * job_contact);

extern const char *
globus_gram_client_error_string(int error_code);

extern int
globus_gram_client_version(void);

extern int 
globus_gram_client_ping(char * resource_manager_contact);

extern void
globus_gram_client_debug(void);

/*** unimplemented ***
extern int 
globus_gram_client_job_check(char * resource_manager_contact,
			     const char * description,
			     float required_confidence,
			     globus_gram_client_time_t * estimate,
			     globus_gram_client_time_t * interval_size);

extern int 
globus_gram_client_job_start_time(char * job_contact,
				  float required_confidence,
				  globus_gram_client_time_t * estimate,
				  globus_gram_client_time_t * interval_size);
*** unimplemented ***/

/******************************************************************************
 *			       Module definition
 *****************************************************************************/

extern int
globus_i_gram_client_activate(void);

extern int
globus_i_gram_client_deactivate(void);

#define GLOBUS_GRAM_CLIENT_MODULE (&globus_gram_client_module)

extern globus_module_descriptor_t	globus_gram_client_module;

/******************************************************************************
 * Backward compatibility
 *****************************************************************************/

#define GRAM_JOB_STATE_PENDING \
	GLOBUS_GRAM_CLIENT_JOB_STATE_PENDING
#define GRAM_JOB_STATE_ACTIVE \
	GLOBUS_GRAM_CLIENT_JOB_STATE_ACTIVE
#define GRAM_JOB_STATE_FAILED \
	GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED
#define GRAM_JOB_STATE_DONE \
	GLOBUS_GRAM_CLIENT_JOB_STATE_DONE
#define GRAM_JOB_STATE_SUSPENDED \
	GLOBUS_GRAM_CLIENT_JOB_STATE_SUSPENDED
#define GRAM_JOB_STATE_ALL \
	GLOBUS_GRAM_CLIENT_JOB_STATE_ALL

/*
 *  Job Result Constants
 */
#define GRAM_SUCCESS \
        GLOBUS_SUCCESS
#define GRAM_ERROR_PARAMETER_NOT_SUPPORTED \
	GLOBUS_GRAM_CLIENT_ERROR_PARAMETER_NOT_SUPPORTED
#define GRAM_ERROR_INVALID_REQUEST \
	GLOBUS_GRAM_CLIENT_ERROR_INVALID_REQUEST
#define GRAM_ERROR_NO_RESOURCES \
	GLOBUS_GRAM_CLIENT_ERROR_NO_RESOURCES
#define GRAM_ERROR_BAD_DIRECTORY \
	GLOBUS_GRAM_CLIENT_ERROR_BAD_DIRECTORY
#define GRAM_ERROR_BAD_EXECUTABLE \
	GLOBUS_GRAM_CLIENT_ERROR_BAD_EXECUTABLE
#define GRAM_ERROR_INSUFFICIENT_FUNDS \
	GLOBUS_GRAM_CLIENT_ERROR_INSUFFICIENT_FUNDS
#define GRAM_ERROR_AUTHORIZATION \
	GLOBUS_GRAM_CLIENT_ERROR_AUTHORIZATION
#define GRAM_ERROR_USER_CANCELLED \
	GLOBUS_GRAM_CLIENT_ERROR_USER_CANCELLED
#define GRAM_ERROR_SYSTEM_CANCELLED \
	GLOBUS_GRAM_CLIENT_ERROR_SYSTEM_CANCELLED
#define GRAM_ERROR_PROTOCOL_FAILED \
	GLOBUS_GRAM_CLIENT_ERROR_PROTOCOL_FAILED
#define GRAM_ERROR_STDIN_NOT_FOUND \
	GLOBUS_GRAM_CLIENT_ERROR_STDIN_NOT_FOUND
#define GRAM_ERROR_CONNECTION_FAILED \
	GLOBUS_GRAM_CLIENT_ERROR_CONNECTION_FAILED
#define GRAM_ERROR_INVALID_MAXTIME \
	GLOBUS_GRAM_CLIENT_ERROR_INVALID_MAXTIME
#define GRAM_ERROR_INVALID_COUNT \
	GLOBUS_GRAM_CLIENT_ERROR_INVALID_COUNT
#define GRAM_ERROR_NULL_SPECIFICATION_TREE \
	GLOBUS_GRAM_CLIENT_ERROR_NULL_SPECIFICATION_TREE
#define GRAM_ERROR_JM_FAILED_ALLOW_ATTACH \
	GLOBUS_GRAM_CLIENT_ERROR_JM_FAILED_ALLOW_ATTACH
#define GRAM_ERROR_JOB_EXECUTION_FAILED \
	GLOBUS_GRAM_CLIENT_ERROR_JOB_EXECUTION_FAILED
#define GRAM_ERROR_INVALID_PARADYN \
	GLOBUS_GRAM_CLIENT_ERROR_INVALID_PARADYN
#define GRAM_ERROR_INVALID_JOBTYPE \
	GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOBTYPE
#define GRAM_ERROR_INVALID_GRAM_MYJOB \
	GLOBUS_GRAM_CLIENT_ERROR_INVALID_GRAM_MYJOB
#define GRAM_ERROR_BAD_SCRIPT_ARG_FILE \
	GLOBUS_GRAM_CLIENT_ERROR_BAD_SCRIPT_ARG_FILE
#define GRAM_ERROR_ARG_FILE_CREATION_FAILED \
	GLOBUS_GRAM_CLIENT_ERROR_ARG_FILE_CREATION_FAILED
#define GRAM_ERROR_INVALID_JOBSTATE \
	GLOBUS_GRAM_CLIENT_ERROR_INVALID_JOBSTATE
#define GRAM_ERROR_INVALID_SCRIPT_REPLY \
	GLOBUS_GRAM_CLIENT_ERROR_INVALID_SCRIPT_REPLY
#define GRAM_ERROR_INVALID_SCRIPT_STATUS \
	GLOBUS_GRAM_CLIENT_ERROR_INVALID_SCRIPT_STATUS
#define GRAM_ERROR_JOBTYPE_NOT_SUPPORTED \
	GLOBUS_GRAM_CLIENT_ERROR_JOBTYPE_NOT_SUPPORTED
#define GRAM_ERROR_UNIMPLEMENTED \
	GLOBUS_GRAM_CLIENT_ERROR_UNIMPLEMENTED
#define GRAM_ERROR_TEMP_SCRIPT_FILE_FAILED \
	GLOBUS_GRAM_CLIENT_ERROR_TEMP_SCRIPT_FILE_FAILED
#define GRAM_ERROR_PROXY_FILE_RELOCATION_FAILED \
	GLOBUS_GRAM_CLIENT_ERROR_PROXY_FILE_RELOCATION_FAILED
#define GRAM_ERROR_PROXY_FILE_OPEN_FAILED \
	GLOBUS_GRAM_CLIENT_ERROR_PROXY_FILE_OPEN_FAILED
#define GRAM_ERROR_JOB_CANCEL_FAILED \
	GLOBUS_GRAM_CLIENT_ERROR_JOB_CANCEL_FAILED
#define GRAM_ERROR_INVALID_HOST_COUNT \
	GLOBUS_GRAM_CLIENT_ERROR_INVALID_HOST_COUNT
#define GRAM_ERROR_UNSUPPORTED_PARAMETER \
	GLOBUS_GRAM_CLIENT_ERROR_UNSUPPORTED_PARAMETER
#define GRAM_ERROR_LAST \
	GLOBUS_GRAM_CLIENT_ERROR_LAST

/***********************************************************************/
/******************  ASYNCHRONOUS API DESCRIPTION STARTS HERE **********/
/***********************************************************************/

/* New asynchronous errors above. */

/* Version Information (the headers of the email that announced this 
   API version.)  A couple of minor typos fixed by Steve A.

   Date: Thu, 24 Jun 1999 20:37:42 -0700
   From: Karl Czajkowski <karlcz@ISI.EDU>
   To: developers@GLOBUS.ORG
   Subject: revised asynch gram api

    here is a revised GRAM API proposal, to include a fault semantics
    Brian Toonen and I discussed on the phone.

    the main point is to allow nonblocking job requests, for efficient
    overlap of communications between multiple outstanding requests.

    it allows the following matrix of behavior:
			 unconstrained start       2-phase start
    anonymous job               yes                     no
    named job                   yes                     yes

    an unconstrained start means the job can commence immediately after the
    nonblocking request call, regardless of the client status.

    a 2-phase start requires a client acknowledgement of the request status
    before the job can commence.  this means the request is issued, and
    a callback provided status data which must be acknowledged before the job
    can continue.  note that the job can still fail or be delayed any amount
    of time after the acknowledgement; it just can't start before the 
    acknowledgement.  if the client dies before acknowledging, the job is
    automatically cancelled.

    anonymous jobs are those where the client completely ignores the status
    of the unconstrained start, not even accepting the job_contact.  this is
    a client-side distinction, as the post-request client behavior doesn't 
    affect the job start for unconstrained starts.

    a good reason for the client to request unconstrained starts is to avoid
    the additional start latency of the acknowledgement phase for interactive
    tasks.  these tasks often have an application-level commit protocol that
    more effectively handles faults anyway.

    the entire existing GRAM client API persists unchanged with this 
    proposed extension.
 */

/* karlcz: new type */
typedef void *globus_gram_client_job_handle_t;

/* karlcz: new type 
 * when a nonblocking request status is known by the client lib, 
 * it invokes the status_callback provided to the nonblocking request 
 * func with the user_data also provided to that call.
 *
 * handle is the handle generated by the nonblocking call.
 * result_code is GLOBUS_SUCCESS and job_contact is non-NULL, or
 * result_code!=GLOBUS_SUCCESS and job_contact is NULL.
 *
 */
typedef void (*globus_gram_client_job_status_callback_func_t)
     (globus_gram_client_job_handle_t handle,
      char *                          job_contact,
      int                             result_code, 
      void *                          user_data);

/* karlcz: new function
 *
 * the call returns immediately after allocating
 * a handle unique within this process, but all GRAM communications
 * and RSL parsing has yet to be done.  handles are used for correlating
 * results to nonblocking requests in the job_status_callback function.
 *
 * if is_fully_asynchronous==GLOBUS_TRUE, the job may start at any time,
 * and the job_contact or failure status will be returned asynchronously
 * by the job_status_callback if job_status_callback is non-NULL or
 * will be discarded if job_status_callback is NULL.
 *
 * if is_fully_asynchronous==GLOBUS_FALSE, job_status_callback must be
 * non-NULL, and the job cannot start until the job_contact is acknowledged
 * by globus_gram_client_job_acknowledge (job_contact).  the job_contact
 * will be provided asynchronously by the job_status_callback.
 * if the client dies before acknowledging the job, the job will be canceled.
 *
 * when a job_contact is known, non-NULL job_contact_callback is triggered 
 * with the handle, the new job_contact and result code, and the user_data
 * provided in this call.
 *
 * if this call returns GLOBUS_SUCCESS, the client app should expect the
 * behavior described above.
 * if this call returns GLOBUS_GRAM_CLIENT_ERROR_NEED_STATUS_CALLBACK,
 * the call violated the above invariant for 
 * is_fully_asynchronous==GLOBUS_FALSE and the call has had no effect.
 */
extern int
globus_gram_client_job_request_nonblocking(
   char *					  resource_manager_contact,
   const char *                                   description,
   const int                                      job_state_mask,
   globus_bool_t                                  is_fully_asynchronous,
   const char *                                   state_callback_contact,
   globus_gram_client_job_status_callback_func_t  job_status_callback,
   void *                                         user_data,
   globus_gram_client_job_handle_t *              handle);

/* karlcz: new function
 * 
 * for jobs submitted by globus_gram_client_job_request_nonblocking ()
 * with is_fully_asynchronous==GLOBUS_FALSE, this call tells the job_manager
 * that the job-start may commence.  for any other jobs, this call has
 * no effect.
 *
 * this call is usually made from within the user's job_status_callback 
 * function.
 *
 * the status of the job must be monitored by the usual state callbacks
 * and reattachment process.
 */

extern void 
globus_gram_client_job_acknowledge(char * job_contact);



/***********************************************************************/
/******************  END ASYNCHRONOUS API	       *****************/
/***********************************************************************/



EXTERN_C_END
#endif /* GLOBUS_I_GRAM_CLIENT_INCLUDE */

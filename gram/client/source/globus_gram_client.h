/******************************************************************************
gram_client.h

Description:
    This header file contains the exported client interface of 
    the Resource Allocation Management System.

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
#define GLOBUS_GRAM_CLIENT_ERROR_BAD_EXECUTABLE \
	@GLOBUS_GRAM_CLIENT_ERROR_BAD_EXECUTABLE@
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
#define GLOBUS_GRAM_CLIENT_ERROR_STDIN_NOTFOUND \
	@GLOBUS_GRAM_CLIENT_ERROR_STDIN_NOTFOUND@
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
#define GLOBUS_GRAM_CLIENT_ERROR_INVALID_MYJOB \
	@GLOBUS_GRAM_CLIENT_ERROR_INVALID_MYJOB@
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
#define GLOBUS_GRAM_CLIENT_ERROR_MPI_NOT_SUPPORTED \
	@GLOBUS_GRAM_CLIENT_ERROR_MPI_NOT_SUPPORTED@
#define GLOBUS_GRAM_CLIENT_ERROR_UNIMPLEMENTED \
	@GLOBUS_GRAM_CLIENT_ERROR_UNIMPLEMENTED@
#define GLOBUS_GRAM_CLIENT_ERROR_TEMP_SCRIPT_FILE_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_TEMP_SCRIPT_FILE_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_PROXY_FILE_RELOCATION_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_PROXY_FILE_RELOCATION_FAILED@
#define GLOBUS_GRAM_CLIENT_ERROR_PROXY_FILE_OPEN_FAILED \
	@GLOBUS_GRAM_CLIENT_ERROR_PROXY_FILE_OPEN_FAILED@
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

/* Add new GLOBUS_GRAM_CLIENT_ERROR code here */
/* don't forget to update GLOBUS_GRAM_CLIENT_error.c also !! */
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
#define GLOBUS_GRAM_CLIENT_MAXTIME_PARAM                  "maxtime"
#define GLOBUS_GRAM_CLIENT_PARADYN_PARAM                  "paradyn"
#define GLOBUS_GRAM_CLIENT_JOBTYPE_PARAM                  "jobtype"
#define GLOBUS_GRAM_CLIENT_MYJOB_PARAM                    "gram_myjob"
#define GLOBUS_GRAM_CLIENT_QUEUE_PARAM                    "queue"
#define GLOBUS_GRAM_CLIENT_PROJECT_PARAM                  "project"
#define GLOBUS_GRAM_CLIENT_HOST_COUNT_PARAM               "host_count"

/*
 *  Job Default Constants
 */
#define GLOBUS_GRAM_CLIENT_DEFAULT_EXE                    "a.out"
#define GLOBUS_GRAM_CLIENT_DEFAULT_STDIN                  "/dev/null"
#define GLOBUS_GRAM_CLIENT_DEFAULT_STDOUT                 "/dev/null"
#define GLOBUS_GRAM_CLIENT_DEFAULT_STDERR                 "/dev/null"
#define GLOBUS_GRAM_CLIENT_DEFAULT_MYJOB                  "collective"
#define GLOBUS_GRAM_CLIENT_DEFAULT_JOBTYPE                "multiple"


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
globus_gram_client_job_request(char * resource_manager_contact,
			       const char * description,
			       const int job_state_mask,
			       const char * callback_contact,
			       char ** job_contact);

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

extern int 
globus_gram_client_job_cancel(char * job_contact);

extern int 
globus_gram_client_callback_allow(globus_gram_client_callback_func_t callback_func,
				  void * user_callback_arg,
				  char ** callback_contact);

extern int 
globus_gram_client_callback_disallow(char * callback_contact);

extern int 
globus_gram_client_callback_check();

extern int 
globus_gram_client_job_contact_free(char * job_contact);

extern const char *
globus_gram_client_error_string(int error_code);

extern void
globus_gram_client_debug(void);


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
#define GRAM_ERROR_STDIN_NOTFOUND \
	GLOBUS_GRAM_CLIENT_ERROR_STDIN_NOTFOUND
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
#define GRAM_ERROR_INVALID_MYJOB \
	GLOBUS_GRAM_CLIENT_ERROR_INVALID_MYJOB
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
#define GRAM_ERROR_MPI_NOT_SUPPORTED \
	GLOBUS_GRAM_CLIENT_ERROR_MPI_NOT_SUPPORTED
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


#endif /* GLOBUS_I_GRAM_CLIENT_INCLUDE */

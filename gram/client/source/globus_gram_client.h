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
#ifndef _GRAM_INCLUDE_GRAM_CLIENT_H
#define _GRAM_INCLUDE_GRAM_CLIENT_H

/******************************************************************************
                             Include header files
******************************************************************************/

/******************************************************************************
                               Define constants
******************************************************************************/
#define GRAM_TRUE                            1
#define GRAM_FALSE                           0
#define GRAM_MAX_MSG_SIZE                    64000
#define GRAM_PARAM_SIZE                      1024
#define GRAM_STRING_SIZE                     256

/* 
 *  Job State Constants
 */
#define GRAM_JOB_STATE_PENDING             @GRAM_JOB_STATE_PENDING@
#define GRAM_JOB_STATE_ACTIVE              @GRAM_JOB_STATE_ACTIVE@
#define GRAM_JOB_STATE_FAILED              @GRAM_JOB_STATE_FAILED@
#define GRAM_JOB_STATE_DONE                @GRAM_JOB_STATE_DONE@

/*
 *  Job Result Constants
 */
#define GRAM_SUCCESS                       @GRAM_SUCCESS@
#define GRAM_ERROR_PARAMETER_NOT_SUPPORTED @GRAM_ERROR_PARAMETER_NOT_SUPPORTED@
#define GRAM_ERROR_INVALID_REQUEST         @GRAM_ERROR_INVALID_REQUEST@
#define GRAM_ERROR_NO_RESOURCES            @GRAM_ERROR_NO_RESOURCES@
#define GRAM_ERROR_BAD_DIRECTORY           @GRAM_ERROR_BAD_DIRECTORY@
#define GRAM_ERROR_BAD_EXECUTABLE          @GRAM_ERROR_BAD_EXECUTABLE@
#define GRAM_ERROR_INSUFFICIENT_FUNDS      @GRAM_ERROR_INSUFFICIENT_FUNDS@
#define GRAM_ERROR_AUTHORIZATION           @GRAM_ERROR_AUTHORIZATION@
#define GRAM_ERROR_USER_CANCELLED          @GRAM_ERROR_USER_CANCELLED@
#define GRAM_ERROR_SYSTEM_CANCELLED        @GRAM_ERROR_SYSTEM_CANCELLED@
#define GRAM_ERROR_PROTOCOL_FAILED         @GRAM_ERROR_PROTOCOL_FAILED@
#define GRAM_ERROR_STDIN_NOTFOUND          @GRAM_ERROR_STDIN_NOTFOUND@
#define GRAM_ERROR_CONNECTION_FAILED       @GRAM_ERROR_CONNECTION_FAILED@
#define GRAM_ERROR_INVALID_MAXTIME         @GRAM_ERROR_INVALID_MAXTIME@
#define GRAM_ERROR_INVALID_COUNT           @GRAM_ERROR_INVALID_COUNT@
#define GRAM_ERROR_NULL_SPECIFICATION_TREE @GRAM_ERROR_NULL_SPECIFICATION_TREE@
#define GRAM_ERROR_JM_FAILED_ALLOW_ATTACH  @GRAM_ERROR_JM_FAILED_ALLOW_ATTACH@
#define GRAM_ERROR_JOB_EXECUTION_FAILED    @GRAM_ERROR_JOB_EXECUTION_FAILED@
#define GRAM_ERROR_INVALID_PARADYN         @GRAM_ERROR_INVALID_PARADYN@
/* Add new GRAM_ERROR code here */
#define GRAM_ERROR_LAST                    @GRAM_ERROR_LAST@

/*
 * gram_myjob_*() error codes
 */ 
#define GRAM_MYJOB_ERROR_BASE			(0x000f0000)
#define GRAM_MYJOB_SUCCESS			GRAM_SUCCESS
#define GRAM_MYJOB_ERROR_NOT_INITIALIZED	(GRAM_MYJOB_ERROR_BASE + 0)
#define GRAM_MYJOB_ERROR_BAD_PARAM		(GRAM_MYJOB_ERROR_BASE + 1)
#define GRAM_MYJOB_ERROR_COMM_FAILURE		(GRAM_MYJOB_ERROR_BASE + 2)
#define GRAM_MYJOB_ERROR_BAD_RANK		(GRAM_MYJOB_ERROR_BASE + 3)
#define GRAM_MYJOB_ERROR_BAD_SIZE		(GRAM_MYJOB_ERROR_BASE + 4)

/*
 *  Job Parameter Constants
 */
#define GRAM_EXECUTABLE_PARAM               "executable"
#define GRAM_ARGUMENTS_PARAM                "arguments"
#define GRAM_ENVIRONMENT_PARAM              "environment"
#define GRAM_DIR_PARAM                      "directory"
#define GRAM_COUNT_PARAM                    "count"
#define GRAM_STDIN_PARAM                    "stdin"
#define GRAM_STDOUT_PARAM                   "stdout"
#define GRAM_STDERR_PARAM                   "stderr"
#define GRAM_MAXTIME_PARAM                  "maxtime"
#define GRAM_PARADYN_PARAM                  "paradyn"
#define GRAM_JOBTYPE_PARAM                  "jobtype"
#define GRAM_MYJOB_PARAM                    "gram_myjob"

/*
 *  Job Default Constants
 */
#define GRAM_DEFAULT_EXE                    "a.out"
#define GRAM_DEFAULT_STDIN                  "/dev/null"
#define GRAM_DEFAULT_STDOUT                 "/dev/null"
#define GRAM_DEFAULT_STDERR                 "/dev/null"
#define GRAM_DEFAULT_MYJOB                  "collective"
#define GRAM_DEFAULT_JOBTYPE                "multiple"

/******************************************************************************
                               Type definitions
******************************************************************************/
typedef unsigned char gram_byte_t;

typedef int gram_bool_t;

typedef void (* gram_callback_func_t)(void * user_callback_arg,
                                      char * job_contact,
                                      int state,
                                      int errorcode);
typedef struct
{
    int dumb_time;
} gram_time_t;

typedef void *	gram_mutex_t;
typedef void *	gram_cond_t;
typedef void *	gram_mutexattr_t;
typedef void *	gram_condattr_t;

/******************************************************************************
                               Global variables
******************************************************************************/


/******************************************************************************
                              Function prototypes
******************************************************************************/
extern int 
gram_job_request(char * resource_manager_contact,
		 const char * description,
		 const int job_state_mask,
		 const char * callback_contact,
		 char ** job_contact);

extern int 
gram_job_check(char * resource_manager_contact,
               const char * description,
               float required_confidence,
               gram_time_t * estimate,
               gram_time_t * interval_size);

extern int 
gram_job_start_time(char * job_contact,
                    float required_confidence,
                    gram_time_t * estimate,
                    gram_time_t * interval_size);

extern int 
gram_init(int *argc, char ***argv);

extern int 
gram_shutdown();

extern int 
gram_job_cancel(char * job_contact);

extern int 
gram_callback_allow(gram_callback_func_t callback_func,
                    void * user_callback_arg,
                    char ** callback_contact);

extern int 
gram_callback_disallow(char * callback_contact);

extern int 
gram_callback_check();

extern int 
gram_job_contact_free(char * job_contact);

/*
 * gram_mutex_*() and gram_cond_*()
 */
extern int
gram_mutex_init(gram_mutex_t *mutex,
		gram_mutexattr_t *attr);

extern int
gram_mutex_destroy(gram_mutex_t *mutex);

extern int
gram_mutex_lock(gram_mutex_t *mutex);

extern int
gram_mutex_unlock(gram_mutex_t *mutex);

extern int
gram_mutex_trylock(gram_mutex_t *mutex);

extern int
gram_cond_init(gram_cond_t *cond,
	       gram_condattr_t *attr);

extern int
gram_cond_destroy(gram_cond_t *cond);

extern int
gram_cond_wait(gram_cond_t *cond,
	       gram_mutex_t *mutex);

extern int
gram_cond_signal(gram_cond_t *cond);

extern int
gram_cond_broadcast(gram_cond_t *cond);

/*
 * gram_error()
 */
extern const char *
gram_error_string(int error_code);

#endif /* _GRAM_INCLUDE_GRAM_CLIENT_H */

/*
gram_client.h

Description:
    This header file contains the exported client interface of 
    the Resource Allocation Management System.

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$
*/

#ifndef GLOBUS_I_GRAM_CLIENT_INCLUDE
#define GLOBUS_I_GRAM_CLIENT_INCLUDE

/* Include header files */
#include "globus_common.h"
#include "globus_gram_protocol_constants.h"

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


/** 
 * @mainpage Resource Management Client API
 * 
 * The resource management API provides functions for requesting
 * that a job be started or terminated, as well as for requesting
 * information about the status of a job.
 */

/******************************************************************************
                               Type definitions
******************************************************************************/


/**
 * @defgroup globus_gram_client_callback Job state callbacks
 */

/**
 * GRAM state callback type.
 * @ingroup globus_gram_client_callback
 *
 * Type of a GRAM Client state callback function. A pointer to a function
 * of this type is passed to the globus_gram_client_callback_allow() function
 * to create a callback contact. This contact can be passed to
 * globus_gram_client_job_request() or
 * globus_gram_client_job_callback_register() to let the job manager
 * know to send information on GRAM job state changes to the user's function.
 *
 * @param user_callback_arg
 *        A pointer to arbitrary user data.
 * @param job_contact
 *        A string containing the job contact. This string will contain
 *        the same value as the return job_contact parameter from
 *        globus_gram_client_job_request().
 * @param state
 *        The new state (one of the #globus_gram_protocol_job_state_t values)
 *        of the job.
 * @param errorcode
 *        The error code if the @a state parameter is equal to
 *        GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED.
 */
typedef void (* globus_gram_client_callback_func_t)(void * user_callback_arg,
						    char * job_contact,
						    int state,
						    int errorcode);

/******************************************************************************
                               Global variables
******************************************************************************/

/**
 * @defgroup globus_gram_client_job_functions GRAM Job Functions
 */

/******************************************************************************
                              Function prototypes
******************************************************************************/
extern int 
globus_gram_client_callback_allow(
                          globus_gram_client_callback_func_t callback_func,
			  void * user_callback_arg,
			  char ** callback_contact);

extern
int
globus_gram_client_register_job_request(
    const char *			resource_manager_contact,
    const char *			description,
    int					job_state_mask,
    const char *			callback_contact,
    globus_gram_client_callback_func_t	register_callback,
    void *				register_callback_arg);

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
globus_gram_client_job_signal(char * job_contact,
                              globus_gram_protocol_job_signal_t signal,
                              char * signal_arg,
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
globus_gram_client_job_contact_free(char * job_contact);

/**
 * @defgroup globus_gram_client Other GRAM Client Functions
 */
extern const char *
globus_gram_client_error_string(int error_code);

extern int
globus_gram_client_version(void);

extern int 
globus_gram_client_ping(char * resource_manager_contact);

extern void
globus_gram_client_debug(void);

/******************************************************************************
 *			       Module definition
 *****************************************************************************/

#define GLOBUS_GRAM_CLIENT_MODULE (&globus_gram_client_module)

extern globus_module_descriptor_t	globus_gram_client_module;

/*** internal, shouldn't be here really ***/
extern void
globus_gram_client_error_7_hack_replace_message(const char* new_message);

EXTERN_C_END
#endif /* GLOBUS_I_GRAM_CLIENT_INCLUDE */


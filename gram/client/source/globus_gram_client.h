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
#include "globus_io.h"
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
 * @anchor globus_gram_client_main
 *
 * The resource manager API provides function for requesting
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

/**
 * GRAM  operation attribute.
 * @ingroup globus_gram_client_callback
 */
typedef void * globus_gram_client_attr_t;

#define GLOBUS_GRAM_CLIENT_NO_ATTR (globus_gram_client_attr_t) NULL

/**
 * GRAM nonblocking operation callback function.
 * @ingroup globus_gram_client_callback
 *
 * Type of a callback indicating completion of a nonblocking GRAM call.
 * 
 * @param user_callback_arg
 *        The register_callback_arg value passed to the nonblocking
 *        function.
 * @param operation_failure_code
 *        The result of nonblocking call, indicating whether the call
 *        was processed by the job manager successfully or not.
 * @param job_conatc
 *        A string containing the job contact.
 * @param job_state
 *        The new state (one of the #globus_gram_protocol_job_state_t
 *        values) of the job.
 * @param job_failure_code
 *        The error code of the job request if the job_state parameter
 *        is GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED.
 */
typedef void (* globus_gram_client_nonblocking_func_t)(
    void *				user_callback_arg,
    globus_gram_protocol_error_t	operation_failure_code,
    const char *			job_contact,
    globus_gram_protocol_job_state_t	job_state,
    globus_gram_protocol_error_t	job_failure_code);


/******************************************************************************
                               Global variables
******************************************************************************/

/**
 * @defgroup globus_gram_client_job_functions GRAM Job Functions
 */

/******************************************************************************
                              Function prototypes
******************************************************************************/
int 
globus_gram_client_callback_allow(
    globus_gram_client_callback_func_t	callback_func,
    void *				user_callback_arg,
    char **				callback_contact);

int
globus_gram_client_register_job_request(
    const char *			resource_manager_contact,
    const char *			description,
    int					job_state_mask,
    const char *			callback_contact,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg);

int 
globus_gram_client_job_request(
    const char *			resource_manager_contact,
    const char *			description,
    int					job_state_mask,
    const char *			callback_contact,
    char **				job_contact);

int
globus_gram_client_register_job_cancel(
    const char *			job_contact,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg);

int 
globus_gram_client_job_cancel(
    const char *			job_contact);

int
globus_gram_client_register_job_status(
    const char *			job_contact,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg);

int
globus_gram_client_job_refresh_credentials(
    char *                              job_contact,
    gss_cred_id_t                       creds);

int
globus_gram_client_register_job_refresh_credentials(
    char *				job_contact,
    gss_cred_id_t			creds,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg);

int
globus_gram_client_job_status(
    const char *			job_contact,
    int *				job_status,
    int *				failure_code);

int
globus_gram_client_register_job_signal(
    const char *			job_contact,
    globus_gram_protocol_job_signal_t	signal,
    const char *			signal_arg,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg);

int
globus_gram_client_job_signal(
    const char *			job_contact,
    globus_gram_protocol_job_signal_t	signal,
    const char *			signal_arg,
    int *				job_status,
    int *				failure_code);


int
globus_gram_client_register_job_callback_registration(
    const char *			job_contact,
    int					job_state_mask,
    const char *			callback_contact,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg);

int
globus_gram_client_job_callback_register(
    const char *			job_contact,
    int					job_state_mask,
    const char *			callback_contact,
    int *				job_status,
    int *				failure_code);

int
globus_gram_client_register_job_callback_unregistration(
    const char *			job_contact,
    const char *			callback_contact,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg);

int
globus_gram_client_job_callback_unregister(
    const char *			job_contact,
    const char *			callback_contact,
    int *				job_status,
    int *				failure_code);

int 
globus_gram_client_callback_disallow(
    char *				callback_contact);

int 
globus_gram_client_job_contact_free(
    char *				job_contact);

/**
 * @defgroup globus_gram_client Other GRAM Client Functions
 */
const char *
globus_gram_client_error_string(
    int					error_code);

int
globus_gram_client_version(void);

int
globus_gram_client_set_credentials(gss_cred_id_t new_credentials);

int 
globus_gram_client_ping(
    const char *			resource_manager_contact);

int 
globus_gram_client_register_ping(
    const char *			resource_manager_contact,
    globus_gram_client_attr_t		attr,
    globus_gram_client_nonblocking_func_t
    					register_callback,
    void *				register_callback_arg);

void
globus_gram_client_debug(void);

/**
 * @defgroup globus_gram_client_attr GRAM Client Attribute Functions
 */
int
globus_gram_client_attr_init(
    globus_gram_client_attr_t *         attr);
int
globus_gram_client_attr_destroy(
    globus_gram_client_attr_t *         attr);

int
globus_gram_client_attr_set_credential(
    globus_gram_client_attr_t           attr,
    gss_cred_id_t                       credential);

int
globus_gram_client_attr_get_credential(
    globus_gram_client_attr_t           attr,
    gss_cred_id_t *                     credential);

#define GLOBUS_GRAM_CLIENT_MODULE (&globus_gram_client_module)

extern globus_module_descriptor_t	globus_gram_client_module;

EXTERN_C_END
#endif /* GLOBUS_I_GRAM_CLIENT_INCLUDE */


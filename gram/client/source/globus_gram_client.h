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

/*** internal, shouldn't be here really ***/
extern void
globus_gram_client_error_7_hack_replace_message(const char* new_message);

EXTERN_C_END
#endif /* GLOBUS_I_GRAM_CLIENT_INCLUDE */


/*
 * This file is a mapping between the higher level authorization API
 * for the ftp daemon and the gaa api definitions.
 */
 
#ifndef __GLOBUS_AUTH_H_
#define __GLOBUS_AUTH_H_

#include "gaa.h"
#include "gaa_core.h"
#include "globus_auth_error.h"
#include "gssapi.h"
/*
static const gss_OID_desc gss_restrictions_extension_oid =
    {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x01"};
    
static const gss_OID_desc * const gss_restrictions_extension =
                     &gss_restrictions_extension_oid;
 */

extern
const gss_OID_desc * const gss_mech_globus_gssapi_ssleay;
 
extern
const gss_OID_desc * const gss_restrictions_extension;; 

struct globus_authorization_struct
{
    gaa_ptr 		gaa;		     /*GAA pointer */
    gaa_sc_ptr 	    gaa_sc;		     /*GAA security context*/
    gss_ctx_id_t	gss_context;     /*GSS security context. Used as
    					               raw credentials for gaa_new_cred*/ 
    gaa_policy_ptr 	policy; 	
    gaa_string_data policy_source;    /*The config file from which policy info
					                  is parsed.*/ 
    #ifdef DEBUG
        gaa_answer_ptr  debug_answer;
    #endif
};

typedef struct globus_authorization_struct 
    globus_authorization_t, *globus_authorization_handle_t;
 
globus_auth_result_t
globus_authorization_handle_init(
    globus_authorization_handle_t *handle, 
    char * configfile);


globus_auth_result_t
globus_authorization_handle_destroy(
	globus_authorization_handle_t *handle);

globus_auth_result_t
globus_authorization_handle_set_policy_source(
    globus_authorization_handle_t handle,
    char * policy_source);


globus_auth_result_t
globus_authorization_handle_get_policy_source(
    globus_authorization_handle_t handle,
    char * policy_source,
    int * length);

globus_auth_result_t
globus_authorization_handle_set_gss_ctx(
    globus_authorization_handle_t handle,
    gss_ctx_id_t context);

globus_auth_result_t
globus_authorization_handle_get_gss_ctx(
    globus_authorization_handle_t handle,
    gss_ctx_id_t * context);

globus_auth_result_t
globus_authorization_handle_get_local_identity(
    globus_authorization_handle_t handle,
    char *local_identity, int *length);

/*globus_auth_result_t
globus_authorization_handle_add_service_type(
    globus_authorization_handle_t handle,
    char * service);*/

globus_auth_result_t
globus_authorization_eval(
    globus_authorization_handle_t handle,
    char * object, /* "/homes/smith/myfile","/homes/directory", etc */
    char * service_type, /* e.g. "file" */
    char * action);      /* e.g. "read", "write", ... */
 
#endif  /* __GLOBUS_AUTH_H_ */

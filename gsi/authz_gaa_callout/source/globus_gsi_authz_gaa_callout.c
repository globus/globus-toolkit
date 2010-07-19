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

#include "globus_common.h"
#include "globus_gsi_authz.h"
#include "globus_i_gsi_authz_gaa_callout.h"
#include "globus_gsi_authz_callout_error.h"
#include "globus_gsi_system_config.h"
#include "gaa.h"
#include "gaa_plugin.h"
#include "gaa_gss_generic.h"
#include "gssapi.h"
#include "globus_gss_assist.h"
#include "globus_gridmap_callout_error.h"

#include <stdlib.h>

#ifdef BUILD_DEBUG
int      globus_i_gsi_authz_gaa_callout_debug_level   = 0;
FILE *   globus_i_gsi_authz_gaa_callout_debug_fstream = 0;
#endif /* BUILD_DEBUG */

static const gss_OID_desc saml_extension_oid =
     {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x0c"}; 
const gss_OID_desc * const saml_extension = 
                &saml_extension_oid;

static const gss_OID_desc old_saml_extension_oid =
     {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x09"}; 
const gss_OID_desc * const old_saml_extension = 
                &old_saml_extension_oid;

typedef struct authz_gaa_system_state_struct {
    char *gaa_config_file_name;
} authz_gaa_system_state_s, *authz_gaa_system_state_t;


/*
 * ap is:
 *		void * authz_system_state;
 */
globus_result_t
globus_gsi_authz_gaa_system_init_callout(
    va_list                             ap)
{
    void * authz_system_state;
    
    globus_result_t                 result = GLOBUS_SUCCESS;
    static char *                   _function_name_ =
	"globus_gsi_authz_gaa_system_init_callout";
    authz_gaa_system_state_t 	    my_state = 0;
    
#ifdef BUILD_DEBUG
    char *			  tmp_string = 0;
#endif /* BUILD_DEBUG */
    
#ifdef BUILD_DEBUG    
    /* Init debug stuff */
    tmp_string = globus_module_getenv("GLOBUS_GSI_AUTHZ_DEBUG_LEVEL");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_authz_gaa_callout_debug_level = atoi(tmp_string);
        
        if(globus_i_gsi_authz_gaa_callout_debug_level < 0)
        {
            globus_i_gsi_authz_gaa_callout_debug_level = 0;
        }
    }

    tmp_string = globus_module_getenv("GLOBUS_GSI_AUTHZ_DEBUG_FILE");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_authz_gaa_callout_debug_fstream = fopen(tmp_string, "a");
    }

    if (globus_i_gsi_authz_gaa_callout_debug_fstream == 0)
    {
      /* if the env. var. isn't set (or the fopen failed), use stderr */
        globus_i_gsi_authz_gaa_callout_debug_fstream = stderr;
    }

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_ENTER;
#endif /* BUILD_DEBUG */

    authz_system_state = va_arg(ap, void *);

    if ((my_state = globus_libc_calloc(1, sizeof(struct globus_i_gsi_authz_handle_s))) == 0)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERRNO_ERROR(result, errno);
	goto end;

    }
    result = GLOBUS_GSI_SYSCONFIG_GET_GAA_CONF_FILENAME(&(my_state->gaa_config_file_name));
    if (result != GLOBUS_SUCCESS)
    {
	goto end;
    }

 end:

    if (result == GLOBUS_SUCCESS)
    {
	*(authz_gaa_system_state_t *)authz_system_state = my_state;
    }
    else
    {
	if (my_state)
	{
	    free(my_state);
	}
    }

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_EXIT;
    return(result);
}

globus_result_t
globus_gsi_authz_gaa_system_destroy_callout(
    va_list                             ap)
{
    void * authz_system_state;
    
    globus_result_t                 result = GLOBUS_SUCCESS;
    static char *                   _function_name_ =
	"globus_gsi_authz_gaa_system_destroy_callout";
    authz_gaa_system_state_t	    gaa_state;

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_ENTER;

    gaa_state = (authz_gaa_system_state_t)authz_system_state;
    
    
    authz_system_state = va_arg(ap, void *);
    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF3(
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE,
	"in %s, system state is %x\n", _function_name_,
	 (unsigned)authz_system_state);

    if (gaa_state)
    {
	/*
	 * don't free gaa_state->gaa_config_file_name -- it wasn't malloc'd.
	 */
	globus_libc_free(gaa_state->gaa_config_file_name);
	globus_libc_free(gaa_state);
    }
    
    
#ifdef BUILD_DEBUG
    if (globus_i_gsi_authz_gaa_callout_debug_fstream &&
	(globus_i_gsi_authz_gaa_callout_debug_fstream != stderr))
    {
	fclose(globus_i_gsi_authz_gaa_callout_debug_fstream);
	globus_i_gsi_authz_gaa_callout_debug_fstream = stderr;
    }
#endif /* BUILD_DEBUG */

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_EXIT;	
    return result;

}


static void callback_wrapper(
    void *                              args)
{
    globus_l_gsi_authz_gaa_cb_arg_t *   wrapper_args;
    
    wrapper_args = (globus_l_gsi_authz_gaa_cb_arg_t *) args;

    if(wrapper_args->callback)
    {
        wrapper_args->callback(wrapper_args->arg, wrapper_args->handle,
                               GLOBUS_SUCCESS);
    }
    free(wrapper_args);

    return;
}

globus_result_t
globus_gsi_authz_gaa_handle_init_callout(
    va_list                             ap)
{
    char *				service_name;
    gss_ctx_id_t 			context;
    globus_gsi_authz_cb_t 		callback;
    void * 				callback_arg;
    globus_l_gsi_authz_gaa_cb_arg_t *   callback_wrapper_arg;
    void *	 			authz_system_state;
    globus_gsi_authz_handle_t *		handle;
    gaa_status 				status;
    gaa_ptr				gaa = 0;
    gaa_sc_ptr				sc = 0;
    gss_buffer_set_t 			data_set = 0;
    gaa_gss_generic_param_s *		gaa_gss_param = 0;
    globus_reltime_t                    reltime;    
    globus_result_t                 	result = GLOBUS_SUCCESS;
    static char *                   	_function_name_ =
	"globus_gsi_authz_gaa_handle_init_callout";
    authz_gaa_system_state_t		gaa_state;
    gaa_cred_ptr			cred = 0;
    OM_uint32				minor_status;
    void *				getpolicy_param;
    void *				get_authorization_identity_param;
    char *				assertion = NULL;
    globus_size_t                       assertion_len;
    int					i;
    globus_bool_t                       der_encoded_assertion = FALSE;

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_ENTER;

    handle = va_arg(ap, globus_gsi_authz_handle_t *);
    service_name = va_arg(ap, char *);
    context = va_arg(ap, gss_ctx_id_t);
    callback = va_arg(ap,  globus_gsi_authz_cb_t);
    callback_arg = va_arg(ap, void *);
    authz_system_state = va_arg(ap, void *);
    gaa_state = (authz_gaa_system_state_t)authz_system_state;


    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF5(
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE,
	"in %s\n\tservice name is %s\n\tcontext is %x\n\tsystem state is %x\n",
	_function_name_,
	service_name,
	(unsigned)context,
	(unsigned)authz_system_state);

    if (handle == 0)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(
            result,
            GLOBUS_GSI_AUTHZ_CALLOUT_BAD_ARGUMENT_ERROR,
            ("null handle"));	
	goto end;
    }

    if ((*handle = globus_libc_calloc(
             1, sizeof(struct globus_i_gsi_authz_handle_s))) == 0)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERRNO_ERROR(result, errno);
	goto end;

    }

    /* check for current extension format first */
    if ((gss_inquire_sec_context_by_oid(&minor_status,
					context,
					(gss_OID) saml_extension,
					&data_set)) == GSS_S_COMPLETE)
    {
        der_encoded_assertion = GLOBUS_TRUE;
    }
    /* then check for old format (cas server from gt4.0.7 and lower) */
    else if ((gss_inquire_sec_context_by_oid(&minor_status,
                                            context,
                                            (gss_OID) old_saml_extension,
                                            &data_set)) != GSS_S_COMPLETE)
    {        
        GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(
            result,
            GLOBUS_GSI_AUTHZ_CALLOUT_CREDENTIAL_ERROR,
            ("error checking for authz extension"));	
        goto end;
    }
    
    if (data_set->count == 0)
    {
	(*handle)->no_cred_extension = 1;
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF2(
	    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE,
	    "%s: no assertion extension\n", _function_name_);
	goto end;
    }

    for (i = 0; i < data_set->count; i++)
    {
	if (data_set->elements[i].length && data_set->elements[i].value)
	{
	    assertion = malloc(data_set->elements[i].length+1);
	    memcpy(assertion,
		    data_set->elements[i].value,
		    data_set->elements[i].length);
	    assertion_len = data_set->elements[i].length;
	    assertion[assertion_len] = '\0';
	    break;
	}
    }

    if (! assertion)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(
            result,
            GLOBUS_GSI_AUTHZ_CALLOUT_CREDENTIAL_ERROR,
            ("authz extension found, but no assertion"));
	goto end;
    }
    
    if(der_encoded_assertion)
    {
        unsigned char *                 encoded_assertion = assertion;
        char *                          decoded_assertion = NULL;
        ASN1_UTF8STRING *               asn1_str;

        asn1_str = d2i_ASN1_UTF8STRING(
            NULL, &encoded_assertion, assertion_len);
        if(asn1_str)
        {
            decoded_assertion = malloc(asn1_str->length + 1);
            memcpy(decoded_assertion, asn1_str->data, asn1_str->length);
            decoded_assertion[asn1_str->length] = 0;

            ASN1_UTF8STRING_free(asn1_str);
            globus_free(assertion);
            assertion = decoded_assertion;
        }
        else
        {
            GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(
                result,
                GLOBUS_GSI_AUTHZ_CALLOUT_CREDENTIAL_ERROR,
                ("improperly encoded assertion found"));
            goto end;        
        }
    }
    
    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF2(
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE,
	"%s: calling gaa_init\n",
	_function_name_);

    if ((status = gaa_initialize(&gaa,
	 (void *)gaa_state->gaa_config_file_name)) != GAA_S_SUCCESS)
    {
	GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result,
                                               "gaa_initialize",
                                               status);

	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF4(
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE,
	"%s: gaa_init(%s) failed: %s\n",
	_function_name_,
	gaa_state->gaa_config_file_name,
	gaa_get_err());

	goto end;
    }

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF2(
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE,
	"%s: gaa_init succeeded\n",
	_function_name_);

    if ((status = gaa_x_get_getpolicy_param(gaa, &getpolicy_param))
        != GAA_S_SUCCESS)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(
            result,
            GLOBUS_GSI_AUTHZ_CALLOUT_CONFIGURATION_ERROR,
            ("No GAA getpolicy parameter configured"));
	goto end;
    }

    if (getpolicy_param)
	*((char **)getpolicy_param) = assertion;


    if ((status = gaa_x_get_get_authorization_identity_param(
             gaa, &get_authorization_identity_param)) != GAA_S_SUCCESS)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(
            result,
            GLOBUS_GSI_AUTHZ_CALLOUT_CONFIGURATION_ERROR,
            ("No GAA get_authorization_identity parameter configured"));
	goto end;
    }

    if (get_authorization_identity_param)
	*((char **)get_authorization_identity_param) = assertion;

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF3(
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_DEBUG,
	"%s: setting assertion to:\n%s\n",
	_function_name_,
	assertion);

    if ((status = gaa_new_sc(&sc)) != GAA_S_SUCCESS)
    {
	GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result, "gaa_new_sc", status);
	goto end;
    }

    if ((gaa_gss_param = globus_libc_malloc(sizeof(gaa_gss_generic_param_s)))
        == NULL)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERRNO_ERROR(result, errno);
	goto end;
    }
    gaa_gss_param->type = GAA_GSS_GENERIC_CTX;
    gaa_gss_param->param.ctx = context;

    if ((status = gaa_new_cred(gaa, sc, &cred, "gss", gaa_gss_param,
			       GAA_IDENTITY, 1, 0)) != GAA_S_SUCCESS)
    {
	GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result, "gaa_new_cred", status);
	goto end;
    }
    if ((status = gaa_add_cred(gaa, sc, cred)) != GAA_S_SUCCESS)
    {
	GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result, "gaa_add_cred", status);
	goto end;
    }

    if ((status = gaa_pull_creds(gaa,
				 sc,
				 GAA_ANY,
				 0)) != GAA_S_SUCCESS)
    {
	GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result, "gaa_pull_creds", status);
	goto end;
    }

    if (((*handle)->auth = globus_libc_strdup(service_name)) == 0)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(result,
				       GLOBUS_GSI_AUTHZ_CALLOUT_SYSTEM_ERROR,
				       ("globus_libc_strdup failed"));
	goto end;
    }

    (*handle)->gaa = gaa;
    (*handle)->sc = sc;
	
 end:

    if (data_set)
    {
	(void)gss_release_buffer_set(&minor_status, &data_set);
    }
    if(result == GLOBUS_SUCCESS)
    { 
        callback_wrapper_arg = malloc(sizeof(globus_l_gsi_authz_gaa_cb_arg_t));
        if(!callback_wrapper_arg)
        {
            GLOBUS_GSI_AUTHZ_CALLOUT_ERRNO_ERROR(result, errno);
        }
        else
        {
            callback_wrapper_arg->handle = *handle;
            callback_wrapper_arg->arg = callback_arg;
            callback_wrapper_arg->callback = callback;
            
            GlobusTimeReltimeSet(reltime, 0, 0);
            globus_callback_register_oneshot(
                GLOBUS_NULL,
                &reltime,
                callback_wrapper,
                callback_wrapper_arg);
        }
    }

    if (result != GLOBUS_SUCCESS)
    {
	if (gaa)
        { 
	    gaa_free_gaa(gaa);
            (*handle)->gaa = NULL;
        }
	if (sc)
        { 
	    gaa_free_sc(sc);
            (*handle)->sc = NULL;
        }
    }

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_EXIT;
    return result;
}

globus_result_t
globus_gsi_authz_gaa_authorize_async_callout(
    va_list                             ap)
{
    globus_gsi_authz_handle_t		handle;
    char * 				action;
    char * 				object;
    globus_gsi_authz_cb_t 		callback;
    void * 				callback_arg;
    void * 				authz_system_state;
    gaa_policy_ptr			policy = 0;
    gaa_status				status;
    gaa_list_ptr 			list = 0;
    gaa_request_right *			right;
    gaa_answer_ptr 			answer = 0;
    char				answer_debug_string[2048];
    globus_l_gsi_authz_gaa_cb_arg_t *   callback_wrapper_arg;
    globus_reltime_t                    reltime;    
    void *                              getpolicy_param;
    void *                              get_authorization_identity_param;

    globus_result_t                 	result = GLOBUS_SUCCESS;
    static char *                   	_function_name_ =
	"globus_gsi_authz_gaa_authorize_async_callout";
    
    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_ENTER;
    
    handle = va_arg(ap, globus_gsi_authz_handle_t);
    action = va_arg(ap, char *);
    object = va_arg(ap, char *);
    callback = va_arg(ap,  globus_gsi_authz_cb_t);
    callback_arg = va_arg(ap, void *);
    authz_system_state = va_arg(ap, void *);

    if (handle == 0)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(
            result,
            GLOBUS_GSI_AUTHZ_CALLOUT_BAD_ARGUMENT_ERROR,
            ("null handle"));	
	goto end;
    }

    if (action == 0)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(
            result,
            GLOBUS_GSI_AUTHZ_CALLOUT_BAD_ARGUMENT_ERROR,
            ("null action"));	
	goto end;
    }
    if (object == 0)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(
            result,
            GLOBUS_GSI_AUTHZ_CALLOUT_BAD_ARGUMENT_ERROR,
            ("null object"));	
	goto end;
    }

    if (handle->no_cred_extension)
    {
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF4(
	    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_DEBUG,
	    "%s:  skipping GAA check (action %s, object %s)\n",
	    _function_name_,
	    action,
	    object);
    }
    else
    {
	if (handle->gaa == 0)
	{
	    GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(
                result,
                GLOBUS_GSI_AUTHZ_CALLOUT_BAD_ARGUMENT_ERROR,
                ("bad handle"));	
	    goto end;
	}

	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF4(
	    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_DEBUG,
	    "%s:  doing GAA check (action %s, object %s)\n",
	    _function_name_,
	    action,
	    object);

        /*
         * If action is "authz_assert", overwrite the assertion in 
         * handle->gaa->getpolicy->param and 
         * handle->gaa->authorization_identity_callback->param with the
         * assertion pointed to by object
         */
        if (!strcmp(action, "authz_assert"))
        {
            if ((status = gaa_x_get_getpolicy_param(
                                handle->gaa, &getpolicy_param))
                != GAA_S_SUCCESS)
            {
                GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(
                    result,
                    GLOBUS_GSI_AUTHZ_CALLOUT_CONFIGURATION_ERROR,
                    ("No GAA getpolicy parameter configured"));
                goto end;
            }

            if (getpolicy_param)
            {
                *((char **)getpolicy_param) = globus_libc_strdup(object);
            }
            if ((status = gaa_x_get_get_authorization_identity_param(
             handle->gaa, &get_authorization_identity_param)) != GAA_S_SUCCESS)
            {
                GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(
                    result,
                    GLOBUS_GSI_AUTHZ_CALLOUT_CONFIGURATION_ERROR,
                    ("No GAA get_authorization_identity parameter configured"));
                goto end;
            }

            if (get_authorization_identity_param)
            {
                *((char **)get_authorization_identity_param) =
                        globus_libc_strdup(object);
            }
            goto end;
        }

	if ((status =
	     gaa_get_object_policy_info(object,
					handle->gaa,
					&policy)) != GAA_S_SUCCESS)
	{
	    GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(
                result,
                "gaa_get_object_policy_info",
                status);
	    goto end;
	}

	list = gaa_new_req_rightlist();
	if (list == 0)
	{
	    GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(
                result,
                GLOBUS_GSI_AUTHZ_CALLOUT_SYSTEM_ERROR,
                ("gaa_new_req_rightlist failed"));
	    goto end;
	}

	if ((status = gaa_new_request_right(handle->gaa,
					    &right,
					    handle->auth,
					    action)) != GAA_S_SUCCESS)
	{
	    GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result,
						   "gaa_new_request_right",
						   status);
	    goto end;
	}
	if ((status = gaa_add_request_right(list, right)) != GAA_S_SUCCESS) {
	    GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result,
						   "gaa_add_request_right",
						   status);
	    gaa_free_request_right(right);
	    goto end;
	}

	if ((status = gaa_new_answer(&answer)) != GAA_S_SUCCESS) {
	    GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result,
						   "gaa_add_request_right",
						   status);
	    goto end;
	}
	status = gaa_check_authorization(handle->gaa,
					 handle->sc,
					 policy,
					 list,
					 answer);

	switch(status) {
	case GAA_C_YES:
	    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF3(
		GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_DEBUG,
		"%s:  after gaa_check_authorization, answer is \n%s\n",
		_function_name_,
		gaadebug_answer_string(handle->gaa,
				       answer_debug_string,
				       sizeof(answer_debug_string),
				       answer));

	    break;
	case GAA_C_NO:
	case GAA_C_MAYBE:
	    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF3(
		GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_DEBUG,
		"%s:  after gaa_check_authorization, answer is \n%s\n",
		_function_name_,
		gaadebug_answer_string(handle->gaa,
				       answer_debug_string,
				       sizeof(answer_debug_string),
				       answer));

	    GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_DENIED_ACCESS(
		result,
		"gaa_check_authorization",
		status,
		answer,
		handle->gaa);
	    goto end;
	default:
	    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF4(
		GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_DEBUG,
		"%s:  gaa_check_authorization error: %s (%s)\n",
		_function_name_,
		gaa_x_majstat_str(status),
		gaa_get_err());

	    GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result,
						   "gaa_check_authorization",
						   status);
	    goto end;
	}
    }

 end:


    if(result == GLOBUS_SUCCESS)
    { 
        callback_wrapper_arg = malloc(sizeof(globus_l_gsi_authz_gaa_cb_arg_t));
        if(!callback_wrapper_arg)
        {
            GLOBUS_GSI_AUTHZ_CALLOUT_ERRNO_ERROR(result, errno);
        }
        else
        {
            callback_wrapper_arg->handle = handle;
            callback_wrapper_arg->arg = callback_arg;
            callback_wrapper_arg->callback = callback;
            
            GlobusTimeReltimeSet(reltime, 0, 0);
            globus_callback_register_oneshot(
                GLOBUS_NULL,
                &reltime,
                callback_wrapper,
                callback_wrapper_arg);
        }
    }

    if (policy)
    { 
        gaa_free_policy(policy);
    }
    if (list)
    { 
        gaa_list_free(list);
    }
    if (answer)
    { 
        gaa_free_answer(answer);
    }

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_EXIT;    
    return result;
}


int
globus_gsi_authz_gaa_cancel_callout(
    va_list                             ap)
{
    globus_gsi_authz_handle_t           handle;
    void * authz_system_state;
    
    int                             result = (int) GLOBUS_SUCCESS;
    static char *                   _function_name_ =
	"globus_gsi_authz_gaa_cancel_callout";

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_ENTER;
    
    handle = va_arg(ap, globus_gsi_authz_handle_t);
    authz_system_state = va_arg(ap, void *);

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF3(
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE,
	"in %s, system state is %x\n",
	_function_name_,
	(unsigned)authz_system_state);

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_EXIT;    
    return result;
}


int
globus_gsi_authz_gaa_handle_destroy_callout(
    va_list                             ap)
{
    globus_gsi_authz_handle_t		handle;
    globus_gsi_authz_cb_t		callback;
    void *				callback_arg;
    void * 				authz_system_state;
    globus_l_gsi_authz_gaa_cb_arg_t *   callback_wrapper_arg;
    globus_reltime_t                    reltime;    
    
    globus_result_t                    	result = GLOBUS_SUCCESS;
    static char *                   	_function_name_ =
	"globus_gsi_authz_gaa_handle_destroy_callout";

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_ENTER;    

    handle = va_arg(ap, globus_gsi_authz_handle_t);
    callback = va_arg(ap, globus_gsi_authz_cb_t);
    callback_arg = va_arg(ap, void *);
    authz_system_state = va_arg(ap, void *);
    
    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF3(
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE,
	"in %s, system state is %x\n",
	_function_name_,
	(unsigned)authz_system_state);
    if (handle != NULL)
    {
	if (handle->auth)
	    globus_libc_free(handle->auth);
	if (handle->sc)
	    gaa_free_sc(handle->sc);
	if (handle->gaa)
	    gaa_free_gaa(handle->gaa);
	free(handle);
    }

    if(result == GLOBUS_SUCCESS)
    { 
        callback_wrapper_arg = malloc(sizeof(globus_l_gsi_authz_gaa_cb_arg_t));
        if(!callback_wrapper_arg)
        {
            GLOBUS_GSI_AUTHZ_CALLOUT_ERRNO_ERROR(result, errno);
        }
        else
        {
            callback_wrapper_arg->handle = handle;
            callback_wrapper_arg->arg = callback_arg;
            callback_wrapper_arg->callback = callback;
            
            GlobusTimeReltimeSet(reltime, 0, 0);
            globus_callback_register_oneshot(
                GLOBUS_NULL,
                &reltime,
                callback_wrapper,
                callback_wrapper_arg);
        }
    }

    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_EXIT;
    return (int)result;
}

int
globus_gsi_authz_gaa_get_authorization_identity_callout(
    va_list                             ap)
{
    globus_gsi_authz_handle_t		handle;
    char **				identity_ptr;
    globus_gsi_authz_cb_t		callback;
    void *				callback_arg;
    void * 				authz_system_state;
    globus_l_gsi_authz_gaa_cb_arg_t *   callback_wrapper_arg;
    globus_reltime_t                    reltime;    
    
    globus_result_t                    	result = GLOBUS_SUCCESS;
    gaa_status				status;
    static char *                   	_function_name_ =
	"globus_gsi_authz_gaa_handle_destroy_callout";


    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_ENTER;    

    handle = va_arg(ap, globus_gsi_authz_handle_t);
    identity_ptr = va_arg(ap, char **);
    callback = va_arg(ap, globus_gsi_authz_cb_t);
    callback_arg = va_arg(ap, void *);
    authz_system_state = va_arg(ap, void *);

    if (handle->no_cred_extension)
    {
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF2(
	    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_DEBUG,
	    "%s:  skipping GAA authz id lookup\n",
	    _function_name_);
	return(result);
    }
    
	GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF2(
	    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_DEBUG,
	    "%s:  doing GAA authz id lookup\n",
	    _function_name_);

    status = gaa_x_get_authorization_identity(handle->gaa, identity_ptr);
    if (status != GAA_S_SUCCESS)
    {
	GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(result,
					       "gaa_x_get_authorization_identity",
					       status);
    }

    if(result == GLOBUS_SUCCESS)
    { 
        callback_wrapper_arg = malloc(sizeof(globus_l_gsi_authz_gaa_cb_arg_t));
        if(!callback_wrapper_arg)
        {
            GLOBUS_GSI_AUTHZ_CALLOUT_ERRNO_ERROR(result, errno);
        }
        else
        {
            callback_wrapper_arg->handle = handle;
            callback_wrapper_arg->arg = callback_arg;
            callback_wrapper_arg->callback = callback;
            
            GlobusTimeReltimeSet(reltime, 0, 0);
            globus_callback_register_oneshot(
                GLOBUS_NULL,
                &reltime,
                callback_wrapper,
                callback_wrapper_arg);
        }
    }
    
    GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_EXIT;
    return (int)result;
}

typedef enum {
    GLOBUS_GSI_AUTHZ_GAA_HANDLE_INIT,
    GLOBUS_GSI_AUTHZ_GAA_GET_AUTHORIZATION_IDENTITY,
    GLOBUS_GSI_AUTHZ_GAA_HANDLE_DESTROY
} globus_gsi_authz_func_t;


static
globus_result_t
globus_gsi_authz_gaa_call_func(
    globus_gsi_authz_func_t             func,
    ...)
{
    globus_result_t                     res = GLOBUS_SUCCESS;
    va_list                             ap;

    va_start(ap, func);

    switch(func)
    {
        case GLOBUS_GSI_AUTHZ_GAA_HANDLE_INIT:
            res = globus_gsi_authz_gaa_handle_init_callout(ap);
            break;
            
        case GLOBUS_GSI_AUTHZ_GAA_GET_AUTHORIZATION_IDENTITY:
            res = globus_gsi_authz_gaa_get_authorization_identity_callout(ap);
            break;
        
        case GLOBUS_GSI_AUTHZ_GAA_HANDLE_DESTROY:
            res = globus_gsi_authz_gaa_handle_destroy_callout(ap);
            break;
        
        default:
            break;
    }            
    
    va_end(ap);

    return res;
}   


globus_result_t
globus_gsi_authz_gaa_gridmap_callout(
    va_list                             ap)
{
    gss_ctx_id_t                        context;
    char *                              service;
    char *                              desired_identity;
    char *                              identity_buffer;
    char *                              local_identity;
    char *                              subject = NULL;
    unsigned int                        buffer_length;
    globus_result_t                     result = GLOBUS_SUCCESS;
    gss_name_t                          peer;
    gss_buffer_desc                     peer_name_buffer;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    int                                 rc;
    int                                 initiator;
    globus_gsi_authz_handle_t           handle;
    authz_gaa_system_state_t 	        tmp_state = NULL;

    
    context = va_arg(ap, gss_ctx_id_t);
    service = va_arg(ap, char *);
    desired_identity = va_arg(ap, char *);
    identity_buffer = va_arg(ap, char *);
    buffer_length = va_arg(ap, unsigned int);
    
 
    if((tmp_state = globus_libc_calloc(
        1, sizeof(struct globus_i_gsi_authz_handle_s))) == 0)
    {
	GLOBUS_GSI_AUTHZ_CALLOUT_ERRNO_ERROR(result, errno);
	goto error;
    }
 
    result = GLOBUS_GSI_SYSCONFIG_GET_GAA_CONF_FILENAME(
        &(tmp_state->gaa_config_file_name));
    if (result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = globus_gsi_authz_gaa_call_func(
        GLOBUS_GSI_AUTHZ_GAA_HANDLE_INIT, 
        &handle, 
        service, 
        context, 
        NULL, 
        NULL, 
        tmp_state);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_LOOKUP_FAILED,
            ("Could not initialize the GAA handle.\n"));
        goto error;
    }
    
    result = globus_gsi_authz_gaa_call_func(
        GLOBUS_GSI_AUTHZ_GAA_GET_AUTHORIZATION_IDENTITY, 
        handle, 
        &subject, 
        NULL, 
        NULL, 
        tmp_state);
    if(result != GLOBUS_SUCCESS)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_LOOKUP_FAILED,
            ("Could not initialize get the GAA identity.\n"));
        goto error;
    }

    result = globus_gsi_authz_gaa_call_func(
        GLOBUS_GSI_AUTHZ_GAA_HANDLE_DESTROY, 
        handle, 
        NULL, 
        NULL, 
        tmp_state);

    globus_free(tmp_state);
    
    rc = globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    rc = globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    rc = globus_module_activate(GLOBUS_GRIDMAP_CALLOUT_ERROR_MODULE);

    if(subject == NULL)
    {
        major_status = gss_inquire_context(&minor_status,
                                           context,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           &initiator,
                                           GLOBUS_NULL);
    
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GRIDMAP_CALLOUT_GSS_ERROR(result, major_status, minor_status);
            goto error;
        }
    
        major_status = gss_inquire_context(&minor_status,
                                           context,
                                           initiator ? GLOBUS_NULL : &peer,
                                           initiator ? &peer : GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL,
                                           GLOBUS_NULL);
    
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GRIDMAP_CALLOUT_GSS_ERROR(result, major_status, minor_status);
            goto error;
        }
        
        major_status = gss_display_name(&minor_status,
                                        peer,
                                        &peer_name_buffer,
                                        GLOBUS_NULL);
        
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GRIDMAP_CALLOUT_GSS_ERROR(result, major_status, minor_status);
            gss_release_name(&minor_status, &peer);
            goto error;
        }
        

        subject = globus_libc_strdup(peer_name_buffer.value);
        gss_release_buffer(&minor_status, &peer_name_buffer);
        gss_release_name(&minor_status, &peer);

    }
    
    if(desired_identity == NULL)
    {
        rc = globus_gss_assist_gridmap(subject, &local_identity);
        if(rc != 0)
        {
            GLOBUS_GRIDMAP_CALLOUT_ERROR(
                result,
                GLOBUS_GRIDMAP_CALLOUT_LOOKUP_FAILED,
                ("Could not map %s\n", subject));
            goto error;
        }

        if(strlen(local_identity) + 1 > buffer_length)
        {
            GLOBUS_GRIDMAP_CALLOUT_ERROR(
                result,
                GLOBUS_GRIDMAP_CALLOUT_BUFFER_TOO_SMALL,
                ("Local identity length: %d Buffer length: %d\n",
                 strlen(local_identity), buffer_length));
        }
        else
        {
            strcpy(identity_buffer, local_identity);
        }
        free(local_identity);           
    }
    else
    {
        rc = globus_gss_assist_userok(subject, desired_identity);
        if(rc != 0)
        {
            GLOBUS_GRIDMAP_CALLOUT_ERROR(
                result,
                GLOBUS_GRIDMAP_CALLOUT_LOOKUP_FAILED,
                ("Could not map %s to %s\n",
                 subject, desired_identity));
        }
    }


 error:

    globus_module_deactivate(GLOBUS_GRIDMAP_CALLOUT_ERROR_MODULE);
    globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
    globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    
    return result;
}



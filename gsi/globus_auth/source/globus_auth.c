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

#include "gaa.h"
#include "globus_auth.h"
#include "globus_auth_error.h"
#include "gaa_gss_generic.h"
#include <string.h>
#include <ctype.h>

struct cas_policy {
    char *			target_subject;
    char *			start_time;
    char *			end_time;
    char *			rights;
};
typedef struct cas_policy cas_policy;

struct parsed_line {
    char *name;
    char *value;
};

static cas_policy *globus_l_authorization_cas_policy_new();

static void globus_l_authorization_cas_policy_free(cas_policy *cp);

static cas_policy
*globus_l_authorization_parse_policy_header(char *policy_string);

static char *
globus_l_authorization_parse_policy_header_line(char * string,
						struct parsed_line *pline);

static globus_auth_result_t
globus_l_authorization_handle_set_gss_param(
    globus_authorization_handle_t handle,
    gaa_gss_generic_param_t gss_param);

/** globus_authorization_handle_init()
 *
 * Creates a globus authorization handle and registers plugins.
 *
 * @param handle
 *        output authorization handle
 * @param configfile
 *        input configfile contains plugin information
 * @param actions
 *        A NULL terminated array of strings specifying the actions
 *        which we want to manage authorization for.
 * @param urlbase
 *        A string which will be prepended to any object string for
 *        which we seek authorization. May be NULL.
 * @param service_type
 *        The type of service the actions are related to (e.g. file)
 *
 * @retval GLOBUS_SUCCESS
 *         success
 * @retval GLOBUS_AUTH_INTERNAL_GAA_ERROR
 *         an error occurred in the underlying mechanism (GAA)
 * @retval GLOBUS_AUTH_MEMORY_ALLOCATION_ERROR
 *         authorization handle memory allocation error
 * @retval GLOBUS_AUTH_INVALID_ARGUMENT
 *         a invalid argument was passed to the function
 *              
 * @note
 * An authorization handle created with this function should be 
 * freed with globus_authorization_handle_destroy
 */

globus_auth_result_t
globus_authorization_handle_init(
    globus_authorization_handle_t *     handle, 
    char *                              configfile,
    char *                              actions[],
    char *                              urlbase,
    char *                              service_type)
{
    int                                 status;
    int                                 i;
    
    *handle = (globus_authorization_handle_t)
        malloc(sizeof(globus_authorization_t));

    if (handle == NULL)
    {
        return (globus_result_set(
                    GLOBUS_AUTH_MEMORY_ALLOCATION_ERROR,
                    "failed to allocate memory for handle : globus_authorization_handle_init"
                ));
    }

    memset(*handle,0,sizeof(globus_authorization_t));    
    
    /* configfile contains callback routines */
    if (configfile == NULL)
    {
        /* Use default */
        configfile = GLOBUS_AUTH_DEFAULT_CONFIG_FILE;
    }
    
    status = gaa_initialize(&((*handle)->gaa),configfile);
    
    if(status != GAA_S_SUCCESS)
    {
        free(*handle);
        return(globus_result_set(
                   GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                   "initialization failed : %s (%s)",
                   gaacore_majstat_str(status),
                   gaa_get_err()));
    }
    
    if(urlbase != NULL)
    {
        (*handle)->gaa_cb_arg.urlbase = (char *)strdup(urlbase);
    }

    if(service_type != NULL)
    {
        (*handle)->gaa_cb_arg.service_type = (char *)strdup(service_type);
    }
    
    if(actions != NULL)
    {
        i=0;
        while(actions[i])
        {
            i++;
        }

        (*handle)->gaa_cb_arg.actions = (char **)
            malloc(sizeof(char *)*(i+1));
        
        i=0;

        while(actions[i])
        {
            (*handle)->gaa_cb_arg.actions[i] = (char *)strdup(actions[i]);
            i++;
        }

        (*handle)->gaa_cb_arg.actions[i] = NULL;
        
    }
    else
    {
        free(*handle);
        return(globus_result_set(
                   GLOBUS_AUTH_INVALID_ARGUMENT,
                   "You must specify a set of actions"));
    }
    
    (*handle)->gaa_sc = 0;
    (*handle)->gss_param = 0;
    (*handle)->policy_source = 0;
    
#ifdef DEBUG
    (*handle)->debug_answer = 0; 
#endif /* DEBUG */

    return(GLOBUS_SUCCESS);
}


/** globus_authorization_handle_destroy()
 *
 * Frees an authorization handle
 *
 * @param handle
 *        input authorization handle
 *
 * @retval GLOBUS_SUCCESS
 *         success
 * @retval GLOBUS_AUTH_BAD_HANDLE
 *         null authorization handle passed
 */


globus_auth_result_t
globus_authorization_handle_destroy(
    globus_authorization_handle_t *     handle)
{
    int                                 i;
    
    if (!(*handle))
    {
        return(globus_result_set(
                   GLOBUS_AUTH_BAD_HANDLE,
                   "null handle : globus_authorization_handle_destroy"
               )); 
    }
    
    if((*handle)->gaa)
    {
        gaa_cleanup(&((*handle)->gaa),0);
    }
    
    if ((*handle)->policy_source)
    {
        free((*handle)->policy_source);
    }
    
    if ((*handle)->gaa_sc)
    {
        gaa_free_sc((*handle)->gaa_sc);
    }

    if((*handle)->gaa_cb_arg.restrictions)
    {
        free((*handle)->gaa_cb_arg.restrictions);
    }

    if((*handle)->gaa_cb_arg.urlbase)
    {
        free((*handle)->gaa_cb_arg.urlbase);
    }

    if((*handle)->gaa_cb_arg.service_type)
    {
        free((*handle)->gaa_cb_arg.service_type);
    }
    
    if((*handle)->gaa_cb_arg.actions)
    {
        i = 0;

        while((*handle)->gaa_cb_arg.actions[i])
        {
            free((*handle)->gaa_cb_arg.actions[i]);
        }
        
        free((*handle)->gaa_cb_arg.actions);
    }

    if((*handle)->policy_display_string)
    {
        free((*handle)->policy_display_string);
    }
    
#ifdef DEBUG
    if ((*handle)->debug_answer)
    {
        gaa_free_answer((*handle)->debug_answer);
    }
    
#endif /* DEBUG */

    free(*handle);
    
    return GLOBUS_SUCCESS;
}

static gaa_gss_generic_param_t
globus_l_gss_param_from_ctx(gss_ctx_id_t context)
{
	gaa_gss_generic_param_s * gss_param = 0;
	if ((gss_param = (gaa_gss_generic_param_s *)malloc(sizeof(gaa_gss_generic_param_s))) == 0)
		return(0);
	gss_param->type = GAA_GSS_GENERIC_CTX;
	gss_param->param.ctx = context;
	return(gss_param);
}

static gaa_gss_generic_param_t
globus_l_gss_param_from_cred(gss_cred_id_t cred)
{
   gaa_gss_generic_param_s * gss_param = 0;
   if ((gss_param = (gaa_gss_generic_param_s *)malloc(sizeof(gaa_gss_generic_param_s))) == 0)
       return(0);
   gss_param->type = GAA_GSS_GENERIC_CRED;
   gss_param->param.cred = cred;
   return(gss_param);
}

static OM_uint32
globus_l_inquire_gss_param_by_oid(OM_uint32 *			minor_status,
				  const gaa_gss_generic_param_t	gss_param,
				  const gss_OID			desired_object,
				  gss_buffer_set_t *		data_set)
{
    if (gss_param->type == GAA_GSS_GENERIC_CTX)
        return(gss_inquire_sec_context_by_oid(minor_status,
					      gss_param->param.ctx,
					      desired_object,
					      data_set));
    else if (gss_param->type == GAA_GSS_GENERIC_CRED)
        return(gss_inquire_cred_by_oid(minor_status,
				       gss_param->param.cred,
				       desired_object,
				       data_set));
    else
        return(GSS_S_FAILURE);
}

/** globus_authorization_handle_set_gss_ctx()
 *
 * Gets credentials from the GSS security context and adds it to the 
 * authorization handle
 *
 * @param handle
 *        input authorization handle
 * @param context
 *        input GSS security context
 *
 * @retval GLOBUS_SUCCESS
 *         success
 * @retval GLOBUS_AUTH_BAD_HANDLE
 *         null authorization handle passed
 * @retval GLOBUS_AUTH_BAD_GSS_SEC_CONTEXT
 *         null security context passed
 * @retval GLOBUS_AUTH_INTERNAL_GAA_ERROR
 *         an internal error (in GAA) occurred
 * 
 */

globus_auth_result_t
globus_authorization_handle_set_gss_ctx(
    globus_authorization_handle_t handle,
    gss_ctx_id_t context)
{
    gaa_gss_generic_param_t gss_param = 0;
    if ((gss_param = globus_l_gss_param_from_ctx(context)) == 0)
	return(globus_result_set(GLOBUS_AUTH_BAD_GSS_SEC_CONTEXT,
				 "bad gss context"));
    return(globus_l_authorization_handle_set_gss_param(handle, gss_param));
} 

/** globus_authorization_handle_set_gss_cred()
 *
 * Gets credentials from the GSS security context and adds it to the 
 * authorization handle
 *
 * @param handle
 *        input authorization handle
 * @param cred
 *        input GSS security credential
 *
 * @retval GLOBUS_SUCCESS
 *         success
 * @retval GLOBUS_AUTH_BAD_HANDLE
 *         null authorization handle passed
 * @retval GLOBUS_AUTH_BAD_GSS_SEC_CONTEXT
 *         null credential passed
 * @retval GLOBUS_AUTH_INTERNAL_GAA_ERROR
 *         an internal error (in GAA) occurred
 * 
 */

globus_auth_result_t
globus_authorization_handle_set_gss_cred(
    globus_authorization_handle_t handle,
    gss_cred_id_t cred)
{
    gaa_gss_generic_param_t gss_param = 0;
    if ((gss_param = globus_l_gss_param_from_cred(cred)) == 0)
	return(globus_result_set(GLOBUS_AUTH_BAD_GSS_SEC_CONTEXT,
				 "bad gss cred"));
    return(globus_l_authorization_handle_set_gss_param(handle, gss_param));
} 

static globus_auth_result_t
globus_l_authorization_handle_set_gss_param(
    globus_authorization_handle_t handle,
    gaa_gss_generic_param_t gss_param)
{
    gaa_cred_ptr            cred = NULL;
    gaa_status              status;
    OM_uint32               maj_stat, 
                            min_stat;
    gss_buffer_set_t	    policy_extension = 0;
    gss_name_t		    signer_identity;
    gss_buffer_desc	    signer_namebuf = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc	    policy_buf;
    cas_policy *	    caspolicy = 0;
    globus_auth_result_t    result = GLOBUS_SUCCESS;
         
    if (!handle) 
    {
        return(globus_result_set(
                   GLOBUS_AUTH_BAD_HANDLE,
                   "null handle : globus_authorization_handle_set_gss_ctx"
               )); 
    }
    
    if(!gss_param) 
    {
        return(globus_result_set(
                   GLOBUS_AUTH_BAD_GSS_SEC_CONTEXT,
                   "null security context : globus_authorization_handle_set_gss_param"
               )); 
    }
    
        
    if (handle->gaa_sc)
    {
        gaa_free_sc(handle->gaa_sc);
        handle->gaa_sc = NULL;
    }
    
    status = gaa_new_sc(&handle->gaa_sc);
    
    if(status != GAA_S_SUCCESS)
    {
        return(globus_result_set(
                   GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                   " error creating GAA security context: %s (%s)",
                   gaacore_majstat_str(status),
                   gaa_get_err()));
    }

    /* XXX status set twice here? */
    status = gaa_new_cred(
        handle->gaa,
        handle->gaa_sc,
        &cred,
        "gss",     /*mech_type*/
        gss_param,       /*raw credentials*/
        GAA_IDENTITY, /*cred_type*/
        1,  /* Does it make sense to evaluate it here?*/
        &status);
    
    if (status != GAA_S_SUCCESS)
    {
        return(globus_result_set(
                   GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                   "failed to create GAA credential : %s (%s)",
                   gaacore_majstat_str(status),
                   gaa_get_err()));
    }

    if (gaa_add_cred(handle->gaa, handle->gaa_sc, cred)!=GAA_S_SUCCESS)
    {
	gaa_free_cred(cred);
        return(globus_result_set(
                   GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                   "failed to add GAA credential : %s (%s)",
                   gaacore_majstat_str(status),
                   gaa_get_err()));
    }
    handle->gss_param = gss_param; 
    handle->audit_identity = cred->principal->value;
    handle->authorization_identity = cred->principal->value;
    maj_stat = globus_l_inquire_gss_param_by_oid( 
        &min_stat,
        gss_param,
        (gss_OID) gss_cas_policy_extension,
        &policy_extension);
    
    if(maj_stat != GSS_S_COMPLETE)
    {
        result = globus_result_set(
	    GLOBUS_AUTH_INTERNAL_GSS_ERROR,
	    "failed to get cas policy extension from gss context");
	goto end;
    }

    /* pull out the cas rights from the cert */
    if ((policy_extension->count > 0) &&
	(policy_extension->elements->length > 0))
    {
	if ((maj_stat = gss_policy_verify(&min_stat, 0,
					 (gss_buffer_t)policy_extension->elements,
					 &policy_buf,
					 &signer_identity)) != GSS_S_COMPLETE)
	{
	    result = globus_result_set(
                GLOBUS_AUTH_INTERNAL_GSS_ERROR,
                "failed to verify cas policy extension");
	    goto end;
	}
	if ((maj_stat = gss_display_name(&min_stat,
					signer_identity,
					&signer_namebuf,
					0)) != GSS_S_COMPLETE)
	{
	    result = globus_result_set(
                GLOBUS_AUTH_INTERNAL_GSS_ERROR,
                "failed to display cas policy signer name");
	    goto end;
	}


	((char *)policy_buf.value)[policy_buf.length] = '\0';
	if ((handle->policy_display_string =
	     strdup((char *)policy_buf.value)) == 0)
 	  {
	    result = globus_result_set(
				       GLOBUS_AUTH_MEMORY_ALLOCATION_ERROR,
				       "failed to copy policy buffer");

	    goto end;
	  }
	
	if ((caspolicy =
	     globus_l_authorization_parse_policy_header(policy_buf.value)) == 0)
	{
	    result = globus_result_set(
                GLOBUS_AUTH_INTERNAL_GSS_ERROR,
                "failed to parse cas policy");
	    goto end;
	}

	if (caspolicy->rights)
	{
	    /* Okay, treat this as a CAS credential. */
	    if (caspolicy->target_subject == 0)
	    {
		result = globus_result_set(
		    GLOBUS_AUTH_AUTHORIZATION_FAILED,
		    "credential policy statement has no target user");
	    }
	    if (strcmp(caspolicy->target_subject,
		       handle->authorization_identity))
	    {
		result = globus_result_set(
		    GLOBUS_AUTH_AUTHORIZATION_FAILED,
		    "credential bearer is not the target user");
	    }
	    if (caspolicy->start_time)
		if ((handle->gaa_cb_arg.start_time =
		     (char *)strdup(caspolicy->start_time)) == 0)
		{
		    result = globus_result_set(
			GLOBUS_AUTH_MEMORY_ALLOCATION_ERROR,
			"failed to strdup policy start time");
		}
	    if (caspolicy->end_time)
		if ((handle->gaa_cb_arg.end_time =
		     (char *)strdup(caspolicy->end_time)) == 0)
		{
		    result = globus_result_set(
			GLOBUS_AUTH_MEMORY_ALLOCATION_ERROR,
			"failed to strdup policy end time");
		}

	    if ((handle->gaa_cb_arg.restrictions =
		 (char *)strdup(caspolicy->rights)) == 0)
	    {
		result = globus_result_set(
		    GLOBUS_AUTH_MEMORY_ALLOCATION_ERROR,
		    "failed to strdup policy rights");
	    }

	    handle->authorization_identity = signer_namebuf.value;
	}
    }
    
    /*establish the getpolicy callback*/
    status = gaa_set_getpolicy_callback(
        handle->gaa,                       /* the gaa ptr */ 
        gaa_simple_parse_restrictions,     /* name of getpolicy callback */
        &handle->gaa_cb_arg,               /* restrictions, actions, etc */
        0);
    

    if (status != GAA_S_SUCCESS)
    {
        result = globus_result_set(GLOBUS_AUTH_INTERNAL_GAA_ERROR,
				   "error in setting the getpolicy callback: %s (%s)",
				   gaacore_majstat_str(status),
				   gaa_get_err()); 
    }
    
 end:
    if (policy_extension)
	gss_release_buffer_set(&min_stat, &policy_extension);
    globus_l_authorization_cas_policy_free(caspolicy);
    return (result);
}

/** globus_authorization_handle_get_gss_ctx()
 *
 * Retrieves the GSS security context associated with the authorization
 * handle
 * 
 * @param handle
 *        input authorization handle
 * @param context
 *        output GSS security context
 * 
 * @retval GLOBUS_SUCCESS
 *         success
 * @retval GLOBUS_AUTH_NULL_HANDLE
 *         null authorization handle passed
 * @retval GLOBUS_AUTH_BAD_GSS_SEC_CONTEXT
 *        GSS  security context information not available  
 */
  
globus_auth_result_t
globus_authorization_handle_get_gss_ctx(
    globus_authorization_handle_t handle,
    gss_ctx_id_t * context) /* How do you make this look cleaner? */
{
    if (!handle) 
    {
        return(globus_result_set(
                   GLOBUS_AUTH_BAD_HANDLE,
                   "null handle : globus_authorization_handle_get_gss_ctx"
               )); 
    }

    if(!handle->gss_param ||
       (handle->gss_param->type != GAA_GSS_GENERIC_CTX) ||
       (handle->gss_param->param.ctx == 0))
    {
        return(globus_result_set(
                   GLOBUS_AUTH_BAD_GSS_SEC_CONTEXT,
                   "GSS security context not present : globus_authorization_handle_get_gss_ctx"
               )); 
    }
    
    *context = (handle->gss_param->param.ctx);  /* or get this out of the gaa_sc? */
    return GLOBUS_SUCCESS;
}

/** globus_authorization_handle_get_local_identity()
 *
 * Gets the local identity corresponding to the globus user's identity.
 * The mapping is stored in a gridmap file
 *
 * @param handle
 *        input authorization handle
 * @param local_identity
 *        output local identity
 * @param length
 *        input/output 
 *        indicates the size of local_identity
 *        The API fills in the actual size of the local identity
 *
 * @retval GLOBUS_SUCCESS
 *         success
 * @retval GLOBUS_AUTH_INTERNAL_GSS_ERROR
 *         an internal GSS error occurred
 */

globus_auth_result_t
globus_authorization_handle_get_local_identity(
    globus_authorization_handle_t handle,
    char *local_identity, int *length)
{

    OM_uint32           minor_status;
    OM_uint32           major_status;
    gss_name_t          name_subject;
    char               *char_subject;
    gss_buffer_desc     subject_desc_buf;

    if (handle == 0 || (handle->gss_param == 0))
	return(globus_result_set(GLOBUS_AUTH_BAD_HANDLE,
				 "bad auth handle"));

    if (handle->gss_param->type == GAA_GSS_GENERIC_CTX)
    {
	gss_inquire_context(
	    &minor_status,
	    handle->gss_param->param.ctx,
	    &name_subject,
	    NULL,
	    NULL,
	    NULL,
	    NULL,                                       
	    NULL,
	    NULL);
    }
    else if (handle->gss_param->type == GAA_GSS_GENERIC_CRED)
    {
	gss_inquire_cred(
	    &minor_status,
	    handle->gss_param->param.cred,
	    &name_subject,
	    NULL,
	    NULL,
	    NULL);
    }
    major_status = gss_export_name(&minor_status,name_subject,
                                   &subject_desc_buf);

    globus_gss_assist_gridmap(subject_desc_buf, char_subject);
    
    gss_release_buffer(&minor_status, &subject_desc_buf);
    gss_release_name(&minor_status, &name_subject);
    
    if (*length >= strlen(char_subject) + 1) 
    {
        strcpy(local_identity,char_subject);
    }
    
    return GLOBUS_SUCCESS;
}

/** globus_authorization_eval()
 * 
 * Checks that the requested action is allowed to the identity 
 * represented by the authorization handle
 *
 * @param handle
 *        input authorization handle
 * @param object
 *        the object for which authorization is sought
 * @param service_type
 *        the application type of which the object is a part
 *        (e.g - "file" for ftp servers, "script" for HTTP servers,etc)
 * @param action
 *        the action requested on the object
 *  
 * @retval GLOBUS_SUCCESS
 *         authorization request succeeded
 * @retval GLOBUS_AUTH_BAD_HANDLE
 *         null authorization handle passed
 * @retval GLOBUS_AUTH_INTERNAL_GAA_ERROR
 *         an internal GAA error occurred
 * @retval GLOBUS_AUTH_AUTHORIZATION_FAILED
 *         request was denied
 * @retval GLOBUS_AUTH_MAYBE
 *         request could not be evaluated
 * @retval GLOBUS_AUTH_UNKNOWN_ERROR
 *         an unknown error occurred
 */

globus_auth_result_t
globus_authorization_eval(
    globus_authorization_handle_t handle,
    char * object, /* "/homes/smith/myfile","/homes/directory", etc */
    char * service_type, /* e.g. "file" */
    char * action)      /* e.g. "read", "write", ... */
{
    gaa_list_ptr right_list = 0;
    gaa_request_right_ptr right = 0;
    gaa_answer_ptr answer = 0;
    int status;
    globus_auth_result_t ret_val;
    /*gaa_policy_ptr    policy;*/

    if (!handle) 
    {
        return(globus_result_set(
                   GLOBUS_AUTH_BAD_HANDLE,
                   "null handle : globus_authorization_eval"
               )); 
    }
        
    /*Check for null object, service type, action?*/
    
#ifdef DEBUG
    if (handle->debug_answer)
    {
        gaa_free_answer(handle->debug_answer);
    }
    
    handle->debug_answer = NULL;
    fprintf(stderr,"object=%s, service_type=%s, action=%s\n",
            object, service_type, action);
#endif /* DEBUG */

    /*Get policy info for the filename*/
    status = gaa_get_object_policy_info(object, handle->gaa,
                                        &handle->policy);

    if(status != GAA_S_SUCCESS)
    {
        return(globus_result_set(
                   GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                   "failed to get policy info for %s : %s (%s)", object,
                   gaacore_majstat_str(status),
                   gaa_get_err()));
    }

#ifdef GAA_DEBUG
    {
        char buffer[8192];
        
        /* Requires gaa debug library to be linked in */

        gaadebug_policy_string(handle->gaa, buffer, sizeof(buffer), handle->policy);

        fprintf(stderr, "%s\n", buffer);
    }
#endif /* GAA_DEBUG */

    /*Build the requested right*/
    right_list = gaa_new_req_rightlist();
    
    if(right_list == 0) 
    {
        return(globus_result_set(
                   GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                   "failed to create request rights list : %s (%s)",
                   gaacore_majstat_str(status),
                   gaa_get_err()));
    }
    
    status = gaa_new_request_right(handle->gaa,&right,
                                   service_type,action);
    
    if(status != GAA_S_SUCCESS)
    {
        return(globus_result_set(
                   GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                   "failed to create request right : %s (%s)",
                   gaacore_majstat_str(status),
                   gaa_get_err()));
    }

    /* add the filename in as an option
     * The option will be used by a condition evaluation callback
     * to check that the userid has permissions on the file
     * (using the access system call)
     */
    status = gaa_add_option(right,
                            "ObjectName",   
                            service_type,        
                            object,       
                            NULL);
    
    if(status != GAA_S_SUCCESS)
    {
        return(globus_result_set(
                   GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                   "failed to add request option : %s (%s)",
                   gaacore_majstat_str(status),
                   gaa_get_err()));
    }
    status = gaa_add_request_right(right_list,right);
    
    if(status != GAA_S_SUCCESS)
    {
        return(globus_result_set(
                   GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                   "failed to add request right : %s (%s)",
                   gaacore_majstat_str(status),
                   gaa_get_err()));
    }

    
    status = gaa_new_answer(&answer);
    
    if(status != GAA_S_SUCCESS)
    {
        return(globus_result_set(
                   GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                   "failed to create answer structure : %s (%s)",
                   gaacore_majstat_str(status),
                   gaa_get_err()));
    }

    status = gaa_check_authorization(handle->gaa,handle->gaa_sc,
                                     handle->policy,right_list,answer);
    
#ifdef GAA_DEBUG
    {
        char buffer[512];
        
        /* Requires gaa debug library to be linked in */

        gaadebug_answer_string(handle->gaa, buffer, sizeof(buffer), answer);

        fprintf(stderr, "%s\n", buffer);
    }
#endif /* GAA_DEBUG */

    switch (status)
    {
    case GAA_C_YES:
       ret_val = GLOBUS_SUCCESS;
       break;
    case GAA_C_NO:
    case GAA_S_NO_MATCHING_ENTRIES:
       ret_val = globus_result_set(
                    GLOBUS_AUTH_AUTHORIZATION_FAILED,
                    "authorization failed : %s (%s)",
                    gaacore_majstat_str(status),
                    gaa_get_err());
       break;
    case GAA_C_MAYBE:
       ret_val = globus_result_set(
                    GLOBUS_AUTH_MAYBE,
                    "unable to evaluate request : %s (%s)",
                    gaacore_majstat_str(status),
                    gaa_get_err());
        break;
    case GAA_S_INVALID_ARG:
    default:
        /*should this be GLOBUS_AUTH_INTERNAL_GAA_ERROR?*/
        ret_val = globus_result_set(
                    GLOBUS_AUTH_UNKNOWN_ERROR,
                    "authorization failed(unknown error): %s (%s)",
                    gaacore_majstat_str(status),
                    gaa_get_err());
        break;
    }

#ifdef DEBUG
    if (status != GAA_C_YES)
    {
        char string[256];
        
        globus_result_get_error_string(ret_val, string, sizeof(string));
        
        fprintf(stderr,
                "globus_authorization_eval returning error (status %d): %s\n",
                status, string);
    }
#endif /* DEBUG */

    gaa_list_free(right_list);
    right_list = NULL;    

    /* if(handle->policy) gaa_free_policy(handle->policy); */
    
    
#ifdef DEBUG
    handle->debug_answer = answer;
#else /* !DEBUG */
    gaa_free_answer(answer);    
    answer = NULL;
#endif /* !DEBUG */
    
    return ret_val;
}



/** globus_authorization_handle_set_policy_source()
 *
 * Stores infomation(filename) about the local policy database
 *
 * @param handle
 *        input authorization handle
 * @param policy_source
 *        input local policy database
 *
 * @retval GLOBUS_SUCCESS
 *         success
 * @retval GLOBUS_AUTH_BAD_HANDLE
 *         null authorization handle passed
 * @retval GLOBUS_AUTH_BAD_POLICY_SOURCE
 *         null policy source passed
 *         
 */
 

globus_auth_result_t
globus_authorization_handle_set_policy_source(
    globus_authorization_handle_t handle,
    char * policy_source)
{
    if (!handle) 
    {
        return(globus_result_set(
                   GLOBUS_AUTH_BAD_HANDLE,
                   "null handle : globus_authorization_handle_set_policy_source"
               )); 
    }
    
    if (!policy_source)
    {
        return(globus_result_set(
                   GLOBUS_AUTH_BAD_POLICY_SOURCE,
                   "null policy source :globus_authorization_handle_set_policy_source"
               )); 
    }
    
    handle->policy_source = (gaa_string_data)strdup(policy_source); 

#ifdef DEBUG
    fprintf(stderr,"Policy_source = %s\n",policy_source);
#endif /* DEBUG */

    return GLOBUS_SUCCESS;
}

/**globus_authorization_handle_get_policy_source()
 *
 *
 * Retreives the local policy database 
 *
 * @param handle
 *        input authorization handle
 * @param policy_source
 *        output policy database
 * @param length
 *        input/output 
 *        indicates the size of policy_source
 *        The API fills in the actual size of the policy source
 *
 * @retval GLOBUS_SUCCESS
 *         success
 * @retval GLOBUS_AUTH_BAD_HANDLE
 *         null authorization handle source passed
 * @retval GLOBUS_AUTH_BAD_POLICY_SOURCE
 *         policy source information not available
 * @retval GLOBUS_AUTH_INSUFFICIENT_BUFFER_SIZE
 *         size of policy_source not sufficient
 * 
 */


globus_auth_result_t
globus_authorization_handle_get_policy_source(
    globus_authorization_handle_t handle,
    char * policy_source,
    int * length)
{    
    if (!handle) 
    {
        return(globus_result_set(
                   GLOBUS_AUTH_BAD_HANDLE,
                   "null handle : globus_authorization_handle_get_policy_source"
               ));
    }
    
    if(!handle->policy_source)
    {
        return(globus_result_set(
                   GLOBUS_AUTH_BAD_POLICY_SOURCE,
                   "policy source not found: globus_authorization_handle_get_policy_source"
               ));
    }
    
    
    if ((*length) < strlen(handle->policy_source) + 1) 
    {
        (*length) = strlen(handle->policy_source) + 1;
        policy_source = 0;    
        return(globus_result_set(
        GLOBUS_AUTH_INSUFFICIENT_BUFFER_SIZE,
        "insufficient buffer size : globus_authorization_handle_get_policy_source"
        )) ;
    }
    
    strncpy(policy_source, handle->policy_source,*length);
    (*length) = strlen(handle->policy_source) + 1;    
    return GLOBUS_SUCCESS;
}

static cas_policy *
globus_l_authorization_cas_policy_new()
{
    cas_policy *cp;

    if ((cp = malloc(sizeof(cas_policy))) == 0)
	return(0);
    cp->target_subject = cp->start_time = cp->end_time = cp->rights = 0;
    return(cp);
}


static void
globus_l_authorization_cas_policy_free(cas_policy *cp)
{
    if (cp == 0)
	return;
  
    /* elements are not malloc'd */
    free(cp);
}

/** globus_l_authorization_parse_policy_header()
 * Parses a cas policy extension into a cas_policy structure.
 *
 * @param policy_string
 *	  input string to parse
 *
 * @retval <cas_policy *>
 *        parsed cas_policy structure
 * @retval 0
 *	  returns 0 on error
 *
 * @note
 *	  This function parses the header part of the CAS policy statement
 *        (target user and validity time) but leaves the list of rights as
 *        a string.
 */

#define DID_USER 1    
#define DID_STARTTIME 2
#define DID_ENDTIME 4
#define DID_ALL (DID_USER | DID_STARTTIME | DID_ENDTIME)

static cas_policy *
globus_l_authorization_parse_policy_header(char *		policy_string)
{
    int whatsdone = 0;
    struct parsed_line pline;
    char *nextline;
    cas_policy *caspolicy;


    nextline = policy_string;

    if ((caspolicy = globus_l_authorization_cas_policy_new()) == 0)
	return(0);

    while (nextline && ((whatsdone & DID_ALL) != DID_ALL))
    {
	nextline = globus_l_authorization_parse_policy_header_line(nextline,
								    &pline);
	if (pline.name == 0)
	    continue;
	else if (strcasecmp(pline.name, "user") == 0)
	{
	    if (whatsdone & DID_USER)
		/* must have exactly one target user */
		return(0);
	    caspolicy->target_subject = pline.value;
	    whatsdone |= DID_USER;
	}
	else if (strcasecmp(pline.name, "notbefore") == 0)
	{
	    if (whatsdone & DID_STARTTIME)
		/* must have exactly one start time */
		return(0);
	    if (pline.value)
		caspolicy->start_time = pline.value;
	    whatsdone |= DID_STARTTIME;
	}
	else if (strcasecmp(pline.name, "notafter") == 0)
	{
	    if (whatsdone & DID_ENDTIME)
		/* must have exactly one end time */
		return(0);
	    if (pline.value)
		caspolicy->end_time = pline.value;
	    whatsdone |= DID_ENDTIME;
	}
	else
	    break;
    }
    if ((whatsdone & DID_ALL) == DID_ALL)
    {
	caspolicy->rights = nextline;
	return(caspolicy);
    }
    else
    {
	globus_l_authorization_cas_policy_free(caspolicy);
	return(0);
    }
}


/** globus_l_authorization_parse_policy_header_line()
 *
 * Parses a line from a CAS policy statement into a {name, value} pair.
 *
 * @param string
 *	  input string
 * @param pline
 *	  output parsed name/value pair
 *        pline->name is a pointer to the first non-whitespace character
 *        in the line (or null if a newline is encountered before any
 *        non-whitespace character).
 *        pline->value is a pointer to the first character of the value
 *        (the first non-whitespace character after the first ":").
 *
 * @retval <string>
 *         a (char *) pointing to the character immediately following
 *	   the first newline in the input string.
 * @retval 0
 *         if the input string is the last line (i.e., if there is no newline,
 *         or the character immediately following the newline is null.
 *
 * @note
 *        This function inserts null characters into the input string.
 *        The separator character (":") between the name and value
 *        is nulled out to terminate pline.name.  The first whitespace
 *	  character after the last non-whitespace character in the line
 *        is nulled out to terminate pline.value.
 */
static char *
globus_l_authorization_parse_policy_header_line(char *		    string,
						struct parsed_line *pline)
{
    char *nextline = 0;
    char *s;
    char *eol;

    pline->name = pline->value = 0;

    /* Find end of line and nextline value, and null-terminate string */
    eol = string;
    while ((*eol != '\n') && (*eol != '\0'))
	eol++;
    if (*eol == '\n')
    {
	nextline = eol+1;
	if (*nextline == '\0')
	    nextline = 0;
	*eol = '\0';
    }

    /* Fill in pline->name */
    while (isspace(*string) && *string != '\0')
	string++;

    if (*string != '\0')
	pline->name = string;

    /* Null-terminate pline->nanme and find pline->value */
    for (s = pline->name; s && *s && ! pline->value; s++)
	if (*s == ':')
	{
	    *s++ = '\0';	/* null-terminate name */
	    while (*s && isspace(*s))
		s++;
	    pline->value = s;
	}
    
    if (pline->value && *pline->value == '\0')
	pline->value = 0;

    /* Null out whitespace after pline->value */
    if (pline->value)
	for (s = eol-1; s > pline->value && isspace(*s); s--)
	    *s = '\0';
    else if (pline->name)
	for (s = eol-1; s > pline->name && isspace(*s); s--)
	    *s = '\0';
    
    return(nextline);
}

char *
globus_auth_get_authorization_identity(globus_authorization_handle_t handle)
{
    if (handle == 0)
	return(0);
    else
	return(handle->authorization_identity);
}

char *
globus_auth_get_audit_identity(globus_authorization_handle_t handle)
{
    if (handle == 0)
	return(0);
    else
	return(handle->audit_identity);
}

char *
globus_auth_get_policy_string(globus_authorization_handle_t handle)
{
    return(handle->policy_display_string);
}

globus_auth_result_t
globus_auth_check_condition(globus_authorization_handle_t handle,
			    char *			  condtype,
			    char *			  condauth,
			    char *			  condval)
{
    gaa_status		    status = GAA_S_SUCCESS;
    gaa_condition *	    cond = 0;
    int 	 	    ynm = GAA_C_MAYBE;
    gaa_time_period	    vtp;

    if (handle == 0)
	return(globus_result_set(GLOBUS_AUTH_BAD_HANDLE,
				 "null auth handle"));
    if (handle->gaa == 0)
	return(globus_result_set(GLOBUS_AUTH_BAD_HANDLE,
				 "auth handle has null gaa pointer"));
    if (handle->gaa_sc == 0)
	return(globus_result_set(GLOBUS_AUTH_BAD_HANDLE,
				 "auth handle has null sc pointer"));
    if ((status = gaa_new_condition(&cond, condtype, condauth,
				    condval)) != GAA_S_SUCCESS)
        return(globus_result_set(
                   GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                   "failed to create condition : %s (%s)",
                   gaacore_majstat_str(status),
                   gaa_get_err()));
    if ((status = gaa_check_condition(handle->gaa, handle->gaa_sc, cond, &vtp,
				      &ynm, 0)) != GAA_S_SUCCESS)
	return(globus_result_set(
	    GLOBUS_AUTH_INTERNAL_GAA_ERROR,
	    "failed to check condition : %s (%s)",
	    gaacore_majstat_str(status),
	    gaa_get_err()));
    if (ynm == GAA_C_YES)
	return(GLOBUS_SUCCESS);
    else
	return(globus_result_set(GLOBUS_AUTH_AUTHORIZATION_FAILED,
				 "condition check returned %s",
				 gaacore_majstat_str(ynm)));
}

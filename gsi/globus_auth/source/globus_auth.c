#include "globus_auth.h"
#include "globus_auth_error.h"
#include <string.h>

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
        (*handle)->gaa_cb_arg.urlbase = strdup(urlbase);
    }

    if(service_type != NULL)
    {
        (*handle)->gaa_cb_arg.service_type = strdup(service_type);
    }
    
    if(actions != NULL)
    {
        i=0;
        while(actions[i])
        {
            i++;
        }

        (*handle)->gaa_cb_arg.actions = (char **)
            malloc(sizeof(char *)*i);
        
        i=0;

        while(actions[i])
        {
            (*handle)->gaa_cb_arg.actions[i] = strdup(actions[i]);
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
    (*handle)->gss_context = 0;
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

    
#ifdef DEBUG
    if ((*handle)->debug_answer)
    {
        gaa_free_answer((*handle)->debug_answer);
    }
    
#endif /* DEBUG */

    free(*handle);
    
    return GLOBUS_SUCCESS;
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
    gaa_cred_ptr            cred = NULL;
    gaa_status              status;
    OM_uint32               maj_stat, 
                            min_stat;
    gss_buffer_set_t        restrictions;
    int                     ii,len_so_far, old_len;
         
    if (!handle) 
    {
        return(globus_result_set(
                   GLOBUS_AUTH_BAD_HANDLE,
                   "null handle : globus_authorization_handle_set_gss_ctx"
               )); 
    }
    
    if(!context) 
    {
        return(globus_result_set(
                   GLOBUS_AUTH_BAD_GSS_SEC_CONTEXT,
                   "null security context : globus_authorization_handle_set_gss_ctx"
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
        context,       /*raw credentials*/
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
        return(globus_result_set(
                   GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                   "failed to add GAA credential : %s (%s)",
                   gaacore_majstat_str(status),
                   gaa_get_err()));
    }
    handle->gss_context = context; 
    maj_stat = gss_inquire_sec_context_by_oid( 
        &min_stat,
        context,
        (gss_OID) gss_restrictions_extension,
        &restrictions);
                            
    if(maj_stat != GSS_S_COMPLETE)
    {
        return(globus_result_set(
                GLOBUS_AUTH_INTERNAL_GSS_ERROR,
                "failed to get restrictions from gss context"));

    }

    len_so_far = 0;
    old_len = 0;
    
    /*go through the cert chain and pull out all restrictions*/

    for(ii = 0; ii < restrictions->count; ii++)
    {
        if(restrictions->elements[ii].length > 0)
        {
            /*the cert at this level contains restrictions*/
            old_len = len_so_far;
            len_so_far += restrictions->elements[ii].length;
            if(!handle->gaa_cb_arg.restrictions)
            {
                handle->gaa_cb_arg.restrictions =
                    (char *)malloc(len_so_far+1);
                memcpy(handle->gaa_cb_arg.restrictions,
                       (char *)restrictions->elements[ii].value,
                       len_so_far);
            
                handle->gaa_cb_arg.restrictions[len_so_far] = 0;
            }
            else
            {
		/* Can't handle multiple restrictions yet */
		gss_release_buffer_set(&min_stat, &restrictions);
		return(globus_result_set(GLOBUS_AUTH_UNIMPLEMENTED_REDELEGATION,
					 "support for restrictions in more than one cert in the chain is not implemented"));
           }
        }/*end if restrictions->elements[i].length*/
    }/*end for ii*/

    gss_release_buffer_set(&min_stat, &restrictions);
    
    /*establish the getpolicy callback*/
    status = gaa_set_getpolicy_callback(
        handle->gaa,                       /* the gaa ptr */ 
        gaa_simple_parse_restrictions,     /* name of getpolicy callback */
        &handle->gaa_cb_arg,               /* restrictions, actions, etc */
        0);
    

    if (status != GAA_S_SUCCESS)
    {
        return(globus_result_set(GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                                 "error in setting the getpolicy callback: %s (%s)",
                                 gaacore_majstat_str(status),
                                 gaa_get_err())); 
    }
    
    return GLOBUS_SUCCESS;
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

    if(!handle->gss_context) 
    {
        return(globus_result_set(
                   GLOBUS_AUTH_BAD_GSS_SEC_CONTEXT,
                   "GSS security context not present : globus_authorization_handle_get_gss_ctx"
               )); 
    }
    
    *context = (handle->gss_context);  /* or get this out of the gaa_sc? */
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
    
    gss_inquire_context(
        handle->gss_context,
        &minor_status,
        &name_subject,
        NULL,
        NULL,
        NULL,
        NULL,                                       
        NULL,
        NULL);

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
    int i = 0;
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
    int status;

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

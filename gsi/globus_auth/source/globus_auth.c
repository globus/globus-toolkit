#include "globus_auth.h"
#include "globus_auth_error.h"
#include "gaa_simple.h"

/** globus_authorization_handle_init()
 *
 * Creates a globus authorization handle and registers plugins.
 *
 * @param handle
 *        output authorization handle
 * @param configfile
 *        input configfile contains plugin information
 *
 * @retval GLOBUS_SUCCESS
 *         success
 * @retval GLOBUS_AUTH_INTERNAL_GAA_ERROR
 *         an error occurred in the underlying mechanism (GAA)
 * @retval GLOBUS_AUTH_MEMORY_ALLOCATION_ERROR
 *         authorization handle memory allocation error
 *              
 * @note
 * An authorization handle created with this function should be 
 * freed with globus_authorization_handle_destroy
 */

globus_auth_result_t
globus_authorization_handle_init(
    globus_authorization_handle_t *handle, 
    char * configfile)
{
    int status;

    if( ((*handle) = (globus_authorization_handle_t)
                malloc(sizeof(globus_authorization_t)))== 0)
        return (globus_result_set(
                GLOBUS_AUTH_MEMORY_ALLOCATION_ERROR,
                "failed to allocate memory for handle : globus_authorization_handle_init"
                ));
       
    /*configfile contains callback routines*/
    if((status = gaa_initialize(&((*handle)->gaa),configfile)) != GAA_S_SUCCESS)
    return(globus_result_set(
        GLOBUS_AUTH_INTERNAL_GAA_ERROR,
        "initialization failed : %s (%s)",
        gaacore_majstat_str(status),
        gaa_get_err()));

    (*handle)->gaa_sc = 0;
    (*handle)->gss_context = 0;
    (*handle)->policy_source = 0;
    #ifdef DEBUG
       (*handle)->debug_answer = 0; 
    #endif

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
    globus_authorization_handle_t *handle)
{
    if (!(*handle)) return(globus_result_set(
                            GLOBUS_AUTH_BAD_HANDLE,
                            "null handle : globus_authorization_handle_destroy"
                            )); 
    
    if((*handle)->gaa) gaa_cleanup(&((*handle)->gaa),0);
    (*handle)->gaa = NULL;
    /*globus_libc_free?*/
    if ((*handle)->policy_source) free((*handle)->policy_source);
    (*handle)->policy_source = NULL;
    if ((*handle)->gaa_sc) gaa_free_sc((*handle)->gaa_sc);
    (*handle)->gaa_sc = NULL;
    
    /*gss_delete_sec_context?*/
    (*handle)->gss_context = NULL;
    #ifdef DEBUG
        if ((*handle)->debug_answer) gaa_free_answer((*handle)->debug_answer);
        (*handle)->debug_answer = NULL;
    #endif
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
    gss_buffer_set_desc     restrictions;
    char *                  params;
    int                     ii,len_so_far, old_len;
         
    if (!handle) 
    return(globus_result_set(
        GLOBUS_AUTH_BAD_HANDLE,
        "null handle : globus_authorization_handle_set_gss_ctx"
        )); 
        
    if(!context) 
    return(globus_result_set(
        GLOBUS_AUTH_BAD_GSS_SEC_CONTEXT,
        "null security context : globus_authorization_handle_set_gss_ctx"
        )); 
        
    if (handle->gaa_sc){
        gaa_free_sc(handle->gaa_sc);
        handle->gaa_sc = NULL;
    }
    
    if((status = gaa_new_sc(&handle->gaa_sc)) != GAA_S_SUCCESS)
    return(globus_result_set(
        GLOBUS_AUTH_INTERNAL_GAA_ERROR,
        " error creating GAA security context: %s (%s)",
        gaacore_majstat_str(status),
        gaa_get_err()));

    if ( (status =gaa_new_cred(
        handle->gaa,
        handle->gaa_sc,
        &cred,
        "gss",     /*mech_type*/
        context,       /*raw credentials*/
        GAA_IDENTITY, /*cred_type*/
        1,  /* Does it make sense to evaluate it here?*/
        &status)) !=GAA_S_SUCCESS)
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
                   &min_stat, context,
                   gss_restrictions_extension,
                   &restrictions);
                            
    if(maj_stat != GSS_S_COMPLETE)
    {
        return(globus_result_set(
                GLOBUS_AUTH_INTERNAL_GSS_ERROR,
                "failed to get restrictions from gss context"));

    }
    params = NULL;
    len_so_far = 0;
    old_len = 0;
    
    /*go through the cert chain and pull out all restrictions*/
    for(ii = 0; ii < restrictions.count; ii++) {
        if(restrictions.elements[ii].length > 0) {
            /*the cert at this level contains restrictions*/
            old_len = len_so_far;
            len_so_far += restrictions.elements[ii].length;
            if(!params) {
                params = (char *)malloc(len_so_far+1);
                memcpy(params, (char *)restrictions.elements[ii].value,
                    len_so_far);
            
                params[len_so_far] = 0;
                gss_release_buffer(&min_stat, &restrictions.elements[ii]);
            }
            else{
                params = (char *)realloc(params,len_so_far+1);
                /*don't overwrite prreviously extracted restrictions*/
                memcpy(params+old_len, 
                    (char *)restrictions.elements[ii].value,
                    restrictions.elements[ii].length);
                params[len_so_far] = 0;
                gss_release_buffer(&min_stat, &restrictions.elements[ii]);
           }
        }/*end if restrictions.elements[i].length*/
    }/*end for ii*/

    
   /*establish the getpolicy callback*/
    if( (status = gaa_set_getpolicy_callback(handle->gaa,     /*the gaa ptr*/ 
                    gaasimple_parse_restrictions,          /*name of getpolicy callback*/
                    params,               /*restrictions (param to callback*/ 
                    0)) != GAA_S_SUCCESS)
       return(globus_result_set(GLOBUS_AUTH_INTERNAL_GAA_ERROR,
                "error in setting the getpolicy callback: %s (%s)",
                gaacore_majstat_str(status),
                gaa_get_err())); 

    
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
    return(globus_result_set(
        GLOBUS_AUTH_BAD_HANDLE,
        "null handle : globus_authorization_handle_get_gss_ctx"
        )); 

    if(!handle->gss_context)
    return(globus_result_set(
        GLOBUS_AUTH_BAD_GSS_SEC_CONTEXT,
        "GSS security context not present : globus_authorization_handle_get_gss_ctx"
        )); 
    
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

    major_status = gss_export_name(&minor_status,name_subject,&subject_desc_buf);
    globus_gss_assist_gridmap(subject_desc_buf, char_subject);
    
    gss_release_buffer(&minor_status, &subject_desc_buf);
    gss_release_name(&minor_status, &name_subject);
    
    if (*length >= strlen(char_subject) + 1) 
        strcpy(local_identity,char_subject);
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
    return(globus_result_set(
        GLOBUS_AUTH_BAD_HANDLE,
        "null handle : globus_authorization_eval"
        )); 
        
    /*Check for null object, service type, action?*/
    
    #ifdef DEBUG
        if (handle->debug_answer) gaa_free_answer(handle->debug_answer);
        handle->debug_answer = NULL;
        fprintf(stderr,"object=%s, service_type=%s, action=%s\n",
            object, service_type, action);
    #endif

    /*Get policy info for the filename*/
    if((status = gaa_get_object_policy_info(object, handle->gaa,
     &handle->policy))!= GAA_S_SUCCESS)
        return(globus_result_set(
            GLOBUS_AUTH_INTERNAL_GAA_ERROR,
            "failed to get policy info for %s : %s (%s)", object,
            gaacore_majstat_str(status),
            gaa_get_err()));

    /*Build the requested right*/
    if((right_list = gaa_new_req_rightlist()) == 0) 
        return(globus_result_set(
            GLOBUS_AUTH_INTERNAL_GAA_ERROR,
            "failed to create request rights list : %s (%s)",
            gaacore_majstat_str(status),
            gaa_get_err()));
    
    if((status = gaa_new_request_right(handle->gaa,&right,
        service_type,action)) != GAA_S_SUCCESS)
        return(globus_result_set(
            GLOBUS_AUTH_INTERNAL_GAA_ERROR,
            "failed to create request right : %s (%s)",
            gaacore_majstat_str(status),
            gaa_get_err()));

    /* add the filename in as an option
     * The option will be used by a condition evaluation callback
     * to check that the userid has permissions on the file
     * (using the access system call)
     */
    
    if((status = gaa_add_option(right,
                    "ObjectName",   
                    service_type,        
                    object,       
                    NULL)) != GAA_S_SUCCESS)
        return(globus_result_set(
            GLOBUS_AUTH_INTERNAL_GAA_ERROR,
            "failed to add request option : %s (%s)",
            gaacore_majstat_str(status),
            gaa_get_err()));
     

    if((status = gaa_add_request_right(right_list,right)) != GAA_S_SUCCESS)
        return(globus_result_set(
            GLOBUS_AUTH_INTERNAL_GAA_ERROR,
            "failed to add request right : %s (%s)",
            gaacore_majstat_str(status),
            gaa_get_err()));

    if((status = gaa_new_answer(&answer)) != GAA_S_SUCCESS)
        return(globus_result_set(
            GLOBUS_AUTH_INTERNAL_GAA_ERROR,
            "failed to create answer structure : %s (%s)",
            gaacore_majstat_str(status),
            gaa_get_err()));

    switch (status = gaa_check_authorization(handle->gaa,handle->gaa_sc,
                handle->policy,right_list,answer))
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
    gaa_list_free(right_list);
    right_list = NULL;    
    //if(handle->policy) gaa_free_policy(handle->policy);
    
    
    #ifdef DEBUG
        handle->debug_answer = answer;
    #else
        gaa_free_answer(answer);    
        answer = NULL;
    #endif
    
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

    if (!handle) return(globus_result_set(
                            GLOBUS_AUTH_BAD_HANDLE,
                            "null handle : globus_authorization_handle_set_policy_source"
                            )); 
    
    if (!policy_source) return(globus_result_set(
                                GLOBUS_AUTH_BAD_POLICY_SOURCE,
                                "null policy source :globus_authorization_handle_set_policy_source"
                                )); 

    handle->policy_source = (gaa_string_data)strdup(policy_source); 
    #ifdef DEBUG
        fprintf(stderr,"Policy_source = %s\n",policy_source);
    #endif
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
    return(globus_result_set(
        GLOBUS_AUTH_BAD_HANDLE,
        "null handle : globus_authorization_handle_get_policy_source"
        ));
    if(!handle->policy_source)
    return(globus_result_set(
        GLOBUS_AUTH_BAD_POLICY_SOURCE,
        "policy source not found: globus_authorization_handle_get_policy_source"
        ));
    
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

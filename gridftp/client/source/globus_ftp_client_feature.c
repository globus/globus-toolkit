#include "globus_i_ftp_client.h"

/*
 *
 * internal interface to 
 * globus_i_ftp_client_features_t 
 *
 */

globus_ftp_client_tristate_t 
globus_i_ftp_client_feature_get(
    globus_i_ftp_client_features_t *              features,
    globus_ftp_client_probed_feature_t            feature) 
{
  /* performance...
     if (features == NULL) {
    result = GLOBUS_I_FTP_CLIENT_ERROR_NULL_PARAMETER("feature_list");
    return globus_error_put(result);
  }
  */
  return features->list[feature];
}


void 
globus_i_ftp_client_feature_set(
    globus_i_ftp_client_features_t *             features,
    globus_ftp_client_probed_feature_t           feature,
    globus_ftp_client_tristate_t                 value)
{
  /* performance...
  if (features == NULL) {
    result = GLOBUS_I_FTP_CLIENT_ERROR_NULL_PARAMETER("feature_list");
    return globus_error_put(result);
    }*/

  features->list[feature]=value;
}

globus_i_ftp_client_features_t *
globus_i_ftp_client_features_init()
{
    int i;
    globus_i_ftp_client_features_t * features =
      (globus_i_ftp_client_features_t *)
      globus_malloc(sizeof(globus_i_ftp_client_features_t));
    for (i=0; i<GLOBUS_FTP_CLIENT_FEATURE_MAX; i++)
      globus_i_ftp_client_feature_set(
				      features,
				      i,
				      GLOBUS_FTP_CLIENT_MAYBE
				      );
    return features;
}

globus_result_t 
globus_i_ftp_client_features_destroy(
    globus_i_ftp_client_features_t *             features)
{
  globus_libc_free(features);
  return GLOBUS_SUCCESS;
}    


/**
 * @name features_init
 */
/*@{*/
/**
 * Initialize the feature set, to be later used by 
 * globus_ftp_client_feat(). Each feature gets initial
 * value GLOBUS_FTP_CLIENT_MAYBE.
 * @note Structure initialized by this function must be
 * destroyed using globus_ftp_client_features_destroy()
 * @return GLOBUS_SUCCESS on success, otherwise error.
 */
globus_result_t 
globus_ftp_client_features_init(
    globus_ftp_client_features_t *               u_features)
{
    globus_i_ftp_client_features_t * features  =  
      globus_i_ftp_client_features_init();
    if (features == GLOBUS_NULL) 
      return globus_error_put(GLOBUS_I_FTP_CLIENT_ERROR_OUT_OF_MEMORY());
    * u_features = features;
    return GLOBUS_SUCCESS;  
}
/**/
/*@}*/


/**
 * @name features_destroy
 */
/*@{*/
/**
 * Destroy the feature set.
 * @note Structure passed to this function must have been previously
 * initialized by globus_ftp_client_features_init().
 * @return GLOBUS_SUCCESS on success, otherwise error. 
 */
globus_result_t 
globus_ftp_client_features_destroy(
    globus_ftp_client_features_t *                  u_features)
{
  return globus_i_ftp_client_features_destroy(
      (globus_i_ftp_client_features_t *) * u_features);
}
/**/
/*@}*/


/* 
   callback parameter passed by globus_ftp_client_feat
   to the handle, for globus_l_ftp_client_feature_callback
*/
typedef struct globus_l_ftp_client_feature_callback_arg_s {
  /* read features from here*/
  globus_i_ftp_client_target_t *                 source;
  /* write features here */
  globus_ftp_client_features_t *                 user_features;
  /* afterwards call this*/
  globus_ftp_client_complete_callback_t          user_callback;
  void *                                         user_arg;
} globus_i_ftp_client_feature_callback_arg_t;


/*
   Callback passed by globus_ftp_client_feat
   to the handle.
   copying of the features must take place after the
   FTP FEAT operation. So it cannot be performed in 
   globus_ftp_client_feat
   (would be too early). Instead, globus_ftp_client_feat 
   passes a ref to this callback to the handle, so that
   after FTP operation complete, this function is called
   to copy the features to the user supplied structure.
   Afterwards it will invoke the user supplied callback.
   All the necessary references are passed to here from
   globus_ftp_client_feat through the argument i_arg 
   of type globus_i_ftp_client_feature_callback_arg_t* .
*/
void globus_l_ftp_client_feature_callback(
    void *					i_arg,
    globus_ftp_client_handle_t *		u_handle,
    globus_object_t *				error)
{
  globus_i_ftp_client_features_t *               features;
  globus_ftp_client_complete_callback_t          user_callback;
  void *                                         user_arg;
  int                                            i;
  globus_i_ftp_client_handle_t *                 handle;
  globus_i_ftp_client_feature_callback_arg_t * params =
     (globus_i_ftp_client_feature_callback_arg_t *) i_arg;


  /* these condidions have to be fulfilled,
     otherwise there's no way to proceed or even return error
  */
  globus_assert(params != GLOBUS_NULL);
  globus_assert(params->user_callback != GLOBUS_NULL);
  /* but this is allowed: params->user arg == null */


   if (error)
   {
        goto error_callback;
   }
   if (u_handle == GLOBUS_NULL) 
   {
      error = GLOBUS_I_FTP_CLIENT_ERROR_NULL_PARAMETER("handle");
      goto error_callback;
   }
  /* Check handle state: 
     is user handle non null, 
     is internal handle it points to non null,
     is handle magic number correct (ie internal handle correctly initialized)
  */
   if(GLOBUS_I_FTP_CLIENT_BAD_MAGIC(u_handle))
   { 
       error = GLOBUS_I_FTP_CLIENT_ERROR_INVALID_PARAMETER("u_handle");
       goto error_callback;
   } 

   handle = * u_handle;

   if (params->user_features == GLOBUS_NULL) 
   {
      error = GLOBUS_I_FTP_CLIENT_ERROR_INVALID_PARAMETER("i_arg");
      goto error_callback;
   }

   if (params->source == GLOBUS_NULL) 
   {
      error = GLOBUS_I_FTP_CLIENT_ERROR_INVALID_PARAMETER("i_arg");
      goto error_callback;
   }

   if (params->source->features == GLOBUS_NULL) 
   {
      error = GLOBUS_I_FTP_CLIENT_ERROR_INVALID_PARAMETER("i_arg");
      goto error_callback;
   }

   features = * (params->user_features);
   user_callback = params->user_callback;
   user_arg = params->user_arg;

   /*copy feature list*/
   for (i=0; 
	i<GLOBUS_FTP_CLIENT_FEATURE_MAX;
	i++)
     globus_i_ftp_client_feature_set(
				     features, 
				     i, 
				     globus_i_ftp_client_feature_get(
				        params->source->features, 
					i));

error_callback:
   /* params structure was initiated by globus_ftp_client_feat
    */
   globus_libc_free(params);
   (*user_callback) (
		     user_arg,
		     u_handle,
		     error
		    );
}
/*globus_l_ftp_client_feature_callback*/


/**
 * @name Feat
 */
/*@{*/
/**
 * Check the features supported by  the server (FTP FEAT command).  After
 * this  procedure  completes, the  features  set (parameter  u_features)
 * represents the features supported by the server. Prior to calling this
 * procedure,   the   structure   should   have   been   initialized   by
 * globus_ftp_client_features_init(); afterwards, it should be destroyed 
 * by globus_ftp_client_features_destroy(). After globus_ftp_client_feat()
 * returns,  each   feature  in   the  list  has   one  of   the  values:
 * GLOBUS_FTP_CLIENT_TRUE,           GLOBUS_FTP_CLIENT_FALSE,          or
 * GLOBUS_FTP_CLIENT_MAYBE. The  first two denote  the server supporting,
 * or not supporting, the given feature. The last one means that the test
 * has not  been performed. This is not necessarily caused by error; 
 * there might have been no reason to check for this particular feature.
 *
 * @param handle
 *        An FTP Client handle to use for the list operation.
 * @param url
 *	  The URL to list. The URL may be an ftp or gsiftp URL.
 * @param attr
 *	  Attributes for this file transfer.
 * @param u_features
 *        A pointer to a globus_ftp_client_features_t to be filled
 *        with the feature set supported by the server. 
 * @param complete_callback
 *        Callback to be invoked once the size check is completed.
 * @param callback_arg
 *	  Argument to be passed to the complete_callback.
 *
 * @return
 *        This function returns an error when any of these conditions are
 *        true:
 *        - handle is GLOBUS_NULL
 *        - source_url is GLOBUS_NULL
 *        - source_url cannot be parsed
 *        - source_url is not a ftp or gsiftp url
 *        - u_features is GLOBUS_NULL or badly initialized
 *        - complete_callback is GLOBUS_NULL
 *        - handle already has an operation in progress
 */
globus_result_t
globus_ftp_client_feat(
    globus_ftp_client_handle_t *                 u_handle,
    char *                                       url,
    globus_ftp_client_operationattr_t *          attr,
    globus_ftp_client_features_t *               u_features,
    globus_ftp_client_complete_callback_t        complete_callback,
    void *                                       callback_arg)
{
  globus_i_ftp_client_handle_t *          handle;
  globus_object_t *                       result;
  globus_bool_t				  registered;
  int                                     i;
  globus_i_ftp_client_feature_callback_arg_t * 
                                          internal_callback_arg;

  static char * myname = "globus_ftp_client_abort";

  if (u_features == GLOBUS_NULL) 
  {
      result = GLOBUS_I_FTP_CLIENT_ERROR_NULL_PARAMETER("u_features");
      goto error;
  }

  if (*u_features == GLOBUS_NULL) 
  {
      result = GLOBUS_I_FTP_CLIENT_ERROR_NULL_PARAMETER("internal feature list");
      goto error;
  }

  if (url == GLOBUS_NULL) 
  {
      result = GLOBUS_I_FTP_CLIENT_ERROR_NULL_PARAMETER("url");
      goto error;
  }

  if (u_handle == GLOBUS_NULL) 
  {
      result = GLOBUS_I_FTP_CLIENT_ERROR_NULL_PARAMETER("u_handle");
      goto error;
  }

  /* Check handle state: 
     is user handle non null, 
     is internal handle it points to non null,
     is handle magic number correct (ie internal handle correctly initialized)
  */
  if(GLOBUS_I_FTP_CLIENT_BAD_MAGIC(u_handle))
  {
      result = GLOBUS_I_FTP_CLIENT_ERROR_INVALID_PARAMETER("u_handle");
      goto error;
  }

  /* add reference to the handle to the shutdown count
   */
  globus_i_ftp_client_handle_is_active(u_handle);

  handle = * u_handle;

  globus_i_ftp_client_handle_lock(handle);

  if(handle->op != GLOBUS_FTP_CLIENT_IDLE)
  {
      result = GLOBUS_I_FTP_CLIENT_ERROR_OBJECT_IN_USE("handle");
      goto unlock_exit;
  }

  /* Setup handle for the FEAT*/
  handle->op = GLOBUS_FTP_CLIENT_FEAT;
  handle->state = GLOBUS_FTP_CLIENT_HANDLE_START;
  handle->source_url = globus_libc_strdup(url);

  /* copying of the features must take place after the
     FTP FEAT operation. So it cannot be performed here
     (it's too early). Instead, it will be done in the
     callback function globus_l_ftp_client_feature_callback.
     That function will in turn invoke the user callback.
  */
  /* this will be freed in globus_l_ftp_client_feature_callback()
   */
  internal_callback_arg = (globus_i_ftp_client_feature_callback_arg_t *)
    globus_malloc(sizeof(globus_i_ftp_client_feature_callback_arg_t));
  internal_callback_arg->user_features = u_features;
  internal_callback_arg->user_callback = complete_callback;
  internal_callback_arg->user_arg = callback_arg;

  handle->callback = globus_l_ftp_client_feature_callback;
  handle->callback_arg = internal_callback_arg;

  if(handle->source_url == GLOBUS_NULL)
  {
      result = GLOBUS_I_FTP_CLIENT_ERROR_OUT_OF_MEMORY();
      goto reset_handle_exit;
  }

  result = globus_i_ftp_client_target_find(handle,
					   url,
					   attr? * attr : GLOBUS_NULL,
					   &handle->source);
  if (result != GLOBUS_SUCCESS)
  {
    goto free_url_exit;
  }

  /* now as handle->source is identified, 
     save this information for callback
  */
  internal_callback_arg->source = handle->source;
  globus_assert( internal_callback_arg == handle->callback_arg );

  /* 
   * check our handle state before continuing, because we just unlocked.
   */
  if(handle->state == GLOBUS_FTP_CLIENT_HANDLE_ABORT)
  {
      result = GLOBUS_I_FTP_CLIENT_ERROR_OPERATION_ABORTED();
      
      goto abort;
  }
  else if(handle->state == GLOBUS_FTP_CLIENT_HANDLE_RESTART)
  {
      goto restart;
  }
   
  result = globus_i_ftp_client_target_activate(
					       handle, 
					       handle->source,
					       &registered);
  if(registered == GLOBUS_FALSE)
  {
	/* 
	 * A restart or abort happened during activation, before any
	 * callbacks were registered. We must deal with them here.
	 */
	globus_assert(handle->state == GLOBUS_FTP_CLIENT_HANDLE_ABORT ||
		      handle->state == GLOBUS_FTP_CLIENT_HANDLE_RESTART ||
		      result != GLOBUS_SUCCESS);

	if(handle->state == GLOBUS_FTP_CLIENT_HANDLE_ABORT)
	{
	    result = GLOBUS_I_FTP_CLIENT_ERROR_OPERATION_ABORTED();

	    goto abort;
	}
	else if (handle->state ==
		 GLOBUS_FTP_CLIENT_HANDLE_RESTART)
	{
	    goto restart;
	}
	else if(result != GLOBUS_SUCCESS)
	{
	    goto source_problem_exit;
	}
  }


  globus_i_ftp_client_handle_unlock(handle);

  return GLOBUS_SUCCESS;


    /* Error handling */

source_problem_exit:
    /* Release the target associated with this list. */
    if(handle->source != GLOBUS_NULL)
    {
	globus_i_ftp_client_target_release(handle,
					   handle->source);
    }

free_url_exit:
    globus_libc_free(handle->source_url);

reset_handle_exit:
  /* Reset the state of the handle. */
  handle->source_url = GLOBUS_NULL;
  handle->op = GLOBUS_FTP_CLIENT_IDLE;
  handle->state = GLOBUS_FTP_CLIENT_HANDLE_START;
  handle->callback = GLOBUS_NULL;
  handle->callback_arg = GLOBUS_NULL;
    
unlock_exit:
  /* Release the lock */
  globus_i_ftp_client_handle_unlock(handle);
  globus_i_ftp_client_handle_is_not_active(u_handle);
  
error:
  /* And return our error */
  return globus_error_put(result);

restart:
    globus_i_ftp_client_target_release(handle,
				       handle->source);

    result = globus_i_ftp_client_restart_register_oneshot(handle);

    if(!result)
    {
	globus_i_ftp_client_handle_unlock(handle);
	return GLOBUS_SUCCESS;
    }
    /* else fallthrough */
abort:
    if(handle->source)
    {
	globus_i_ftp_client_target_release(handle,
					   handle->source);
    }

    /* Reset the state of the handle. */
    globus_libc_free(handle->source_url);
    handle->source_url = GLOBUS_NULL;
    handle->op = GLOBUS_FTP_CLIENT_IDLE;
    handle->state = GLOBUS_FTP_CLIENT_HANDLE_START;
    handle->callback = GLOBUS_NULL;
    handle->callback_arg = GLOBUS_NULL;
    
    globus_i_ftp_client_handle_unlock(handle);
    globus_i_ftp_client_handle_is_not_active(u_handle);

    return globus_error_put(result);
}
/* globus_ftp_client_feat() */
/*@}*/



/**
 * @name is_feature_supported
 */
/*@{*/
/**
 * Check if the feature is supported by the server.
 * After the function completes, parameter answer contains
 * the state of the server support of the given function.
 * It can have one of the values: GLOBUS_FTP_CLIENT_TRUE,  
 * GLOBUS_FTP_CLIENT_FALSE, or GLOBUS_FTP_CLIENT_MAYBE. 
 *
 * @param u_features 
 *        list of features, as returned by globus_ftp_client_feat()
 * @param answer
 *        this variable will contain the answer
 * @param feature
 *        feature number, 0 <= feature < GLOBUS_FTP_CLIENT_FEATURE_MAX 
 * @return
 *      error when any of the parameters is null or badly initialized
 */
globus_result_t
globus_ftp_client_is_feature_supported(
    const globus_ftp_client_features_t *       u_features,
    globus_ftp_client_tristate_t *             answer,
    const globus_ftp_client_probed_feature_t   feature) 
{
  globus_object_t * result;
  globus_i_ftp_client_features_t * features;

  if (answer == GLOBUS_NULL) 
  {
      result = GLOBUS_I_FTP_CLIENT_ERROR_NULL_PARAMETER("answer");
      goto error;
  }
  if (u_features == GLOBUS_NULL) 
  {
      result = GLOBUS_I_FTP_CLIENT_ERROR_NULL_PARAMETER("feature_list");
      goto error;
  }
  if ( feature < 0 || GLOBUS_FTP_CLIENT_FEATURE_MAX <= feature)
  {
    result = GLOBUS_I_FTP_CLIENT_ERROR_INVALID_PARAMETER("feature");
  }

  features =  * u_features;

  if (features == GLOBUS_NULL) 
  {
      result = GLOBUS_I_FTP_CLIENT_ERROR_NULL_PARAMETER("internal feature list");
      goto error;
  }

  *answer = globus_i_ftp_client_feature_get(features, feature);

  return GLOBUS_SUCCESS;

 error:
  return globus_error_put(result);
}
/*globus_ftp_client_is_feature_supported()*/
/*@}*/




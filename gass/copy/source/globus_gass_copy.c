/**
 * @file globus_gass_copy.c
 *
 * Globus GASS copy library
 *
 * @see See the detailed description in globus_gass_copy.h
 */

#include "globus_gass_copy.h"

#define GLOBUS_I_GASS_COPY_DEBUG

#define globus_i_gass_copy_set_error(handle, error) \
{ \
    if(handle->err == GLOBUS_NULL) \
        handle->err = globus_object_copy(error); \
}

#define globus_i_gass_copy_set_error_from_result(handle, result) \
{ \
    if(handle->err == GLOBUS_NULL) \
    { \
        handle->err = globus_error_get(result); \
	result = globus_error_put(handle->err); \
    } \
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
#include "globus_i_gass_copy.h"


/* questions:
 * 
 * 1 how to manage error handling
 * 
 *   IO example
 *       err1 = globus_io_error_construct_null_parameter(
 *             GLOBUS_IO_MODULE,
 *             GLOBUS_NULL,
 *             "handle",
 *             1,
 *             myname);
 *       err = globus_io_error_construct_null_parameter(
 *             GLOBUS_IO_MODULE,
 *             err1,
 *             "handle",
 *             1,
 *             myname);
 *       return globus_error_put(err);
 *
 */

/******************************************************************************
                       Define module specific variables
******************************************************************************/

globus_module_descriptor_t globus_gass_copy_module = 
{
    "gass_copy_client",
    globus_i_gass_copy_activate,
    globus_i_gass_copy_deactivate,
    GLOBUS_NULL
};

/*
****************************************
  module activation
******************************************/
int
globus_i_gass_copy_activate(void)
{
    int rc;
    
    rc = globus_module_activate(GLOBUS_GASS_TRANSFER_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }

    rc = globus_module_activate(GLOBUS_IO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }
    rc = globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }

    return 0;
} /* globus_i_gass_copy_activate() */

/*****************************************
  module deactivation
******************************************/
int
globus_i_gass_copy_deactivate(void)
{
    int rc;
    /*
      rc = globus_module_deactivate(GLOBUS_FTP_CLIENT_MODULE); 

      if (rc != GLOBUS_SUCCESS)
      {
      return(rc);
      }
      */
    rc = globus_module_deactivate(GLOBUS_IO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }
    rc = globus_module_deactivate(GLOBUS_GASS_TRANSFER_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }
    
    return 0;
} /* globus_i_gass_copy_deactivate() */



/********************************************************************
 * generic callback to signal completion of asynchronous transfer
 ********************************************************************/
static
void
globus_l_gass_copy_monitor_callback(
    void * callback_arg,
    globus_gass_copy_handle_t * handle,
    globus_object_t * error)
{
    globus_i_gass_copy_monitor_t       *monitor;
    monitor = (globus_i_gass_copy_monitor_t*)callback_arg;

    globus_mutex_lock(&monitor->mutex);
    monitor->done = GLOBUS_TRUE;
    if(error != GLOBUS_NULL)
    {
	monitor->err = globus_object_copy(error);
	monitor->use_err = GLOBUS_TRUE;
    }
    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);

    return;
} /* globus_l_gass_copy_monitor_callback() */

#endif

/************************************************************
 * Handle initialization and destruction
 ************************************************************/

/**
 * Initialize a GASS copy handle
 *
 * A globus_gass_copy_handle must be initialized before any transfers may be associated with it.  This function
 * initializes a  globus_gass_copy_handle to be used for doing transfers, this includes initializing a globus_ftp_client_handle which will be
 * used for doing any ftp/gsiftp transfers. The same handle may be used to perform multiple, consecutive
 * transfers.  However, there can only be one transfer associated with a particular handle at any given time.  After all transfers to
 * be associated with this handle have completed, the handle should be destroyed by calling globus_gass_copy_handle_destroy().
 *
 * @param handle
 *        The handle to be initialized
 *
 *  @return
 *       This function returns GLOBUS_SUCCESS if successful, or a globus_result_t indicating the error that occurred.
 *
 * @see globus_gass_copy_handle_destroy() , globus_ftp_client_hande_init()
 */
globus_result_t
globus_gass_copy_handle_init(
    globus_gass_copy_handle_t * handle)
{
    globus_result_t result;
    globus_object_t * err;
    static char * myname="globus_gass_copy_handle_init";
    
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "copy_handle_init() was called.....\n");
#endif
    if(handle != GLOBUS_NULL)
    {
	result = globus_ftp_client_handle_init(&handle->ftp_handle);
	if(result != GLOBUS_SUCCESS)
	    return result;
    
	handle->state = GLOBUS_NULL;
	handle->status = GLOBUS_GASS_COPY_STATUS_NONE;
	handle->buffer_length = 1024*1024;
	handle->user_pointer = GLOBUS_NULL;
	handle->err = GLOBUS_NULL;

	return GLOBUS_SUCCESS;
    }
    else
    {
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: BAD_PARAMETER, handle is NULL",
	    myname);
	  
	return globus_error_put(err);
    }
}

/**
 *  Destroy a GASS copy handle
 *
 * Destroy a  gass_copy_handle, which was initialized using  globus_gass_copy_handle_init(), that will no longer be used for doing
 * transfers.  Once the handle is detroyed, no further transfers should be associated with it.
 *
 * @param handle
 *        The handle to be destroyed
 *
 *  @return
 *       This function returns GLOBUS_SUCCESS if successful, or a globus_result_t indicating the error that occurred.
 *
 * @see globus_gass_copy_handle_init(), globus_ftp_client_hande_destroy()
 */
globus_result_t
globus_gass_copy_handle_destroy(
    globus_gass_copy_handle_t * handle)
{
    globus_result_t result;
    globus_object_t * err;
    static char * myname="globus_gass_copy_handle_destroy";
    
    if(handle != GLOBUS_NULL)
    {
	result = globus_ftp_client_handle_destroy(&handle->ftp_handle);
	return result;
    }
    else
    {
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: BAD_PARAMETER, handle is NULL",
	    myname);
	  
	return globus_error_put(err);
    }
}

/**
 * Set the size of the buffer to be used for doing transfers
 *
 * This function allows the user to set the size of the buffer that will be used for doing transfers, if this function is not called
 * the buffer size will default to 1M.
 *
 * @param handle
 *        Set the buffer length for transfers associated with this handle.
 * @param length
 *       The length, in bytes, to make the buffer.
 *
 *  @return
 *       This function returns GLOBUS_SUCCESS if successful, or a globus_result_t indicating the error that occurred.
 */
globus_result_t
globus_gass_copy_set_buffer_length(
    globus_gass_copy_handle_t * handle,
    int length)
{
    globus_object_t * err;
    static char * myname="globus_gass_copy_set_buffer_length";
    if (handle)
    {
	handle->buffer_length = length;
	return GLOBUS_SUCCESS;
    }
    else
    {
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: BAD_PARAMETER, handle is NULL",
	    myname);

	return globus_error_put(err);
    }
} /* globus_gass_copy_set_buffer_length() */


/**
 * Initialize an attribute structure
 *
 * The globus_gass_copy_attr_t can be used to pass the globus_gass_copy library information about how a transfer should be performed.
 * It must first be initialized by calling this function. Then any or all of the following functions may be called to set attributes associated
 * with a particular protocol: globus_gass_copy_attr_set_ftp(), globus_gass_copy_attr_set_gass(), globus_gass_copy_attr_set_io().  Any
 * function which takes a globus_gass_copy_attr_t as an argument will also accept GLOBUS_NULL, in which case the appropriate set of
 * default attributes will be used.
 *
 * @param attr
 *      The attribute structure to be initialized
 *
 *  @return
 *       This function returns GLOBUS_SUCCESS if successful, or a globus_result_t indicating the error that occurred.
 *
 * @see globus_gass_copy_attr_set_ftp(), globus_gass_copy_attr_set_gass(), globus_gass_copy_attr_set_io().
 */
globus_result_t
globus_gass_copy_attr_init(
    globus_gass_copy_attr_t * attr)
{
    globus_object_t * err;
    static char * myname="globus_gass_copy_attr_init";
    if(attr!=GLOBUS_NULL)
    {
	attr->ftp_attr = GLOBUS_NULL;
	attr->io = GLOBUS_NULL;
	attr->gass_requestattr = GLOBUS_NULL;
	return GLOBUS_SUCCESS;
    }
    else
    {
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: BAD_PARAMETER, attr is NULL",
	    myname);
	return globus_error_put(err);
    }
}

/**
 * Set the attributes for ftp/gsiftp transfers
 *
 * In order to specify attributes for ftp/gsiftp transfers, a globus_ftp_client_attr_t should be initialized and its values set using the
 * appropriate globus_ftp_client_attr_* functions.  The globus_ftp_client_attr_t can then be passed to the globus_gass_copy_attr_t via
 * this function.
 *
 * @param attr
 *      A globus_gass_copy attribute structure 
 *@param ftp_attr
 *      The ftp/gsiftp attributes to be used
 *
 * @see globus_gass_copy_attr_init(), globus_gass_copy_attr_set_gass(), globus_gass_copy_attr_set_io(), globus_ftp_client_attr_*
 */
globus_result_t
globus_gass_copy_attr_set_ftp(
    globus_gass_copy_attr_t * attr,
    globus_ftp_client_attr_t * ftp_attr)
{
    globus_object_t * err;
    static char * myname="globus_gass_copy_attr_set_ftp";
    
    if(attr != GLOBUS_NULL)
    {
	attr->ftp_attr = ftp_attr;
	return GLOBUS_SUCCESS;
    }
    else
    {
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: BAD_PARAMETER, attr is NULL",
	    myname);
	return globus_error_put(err);
    }
}

/**
 * Set the attributes for file transfers
 *
 * In order to specify attributes for file transfers, a globus_io_attr_t should be initialized and its values set using the
 * appropriate globus_io_attr_* functions.  The globus_io_attr_t can then be passed to the globus_gass_copy_attr_t via
 * this function.
 *
 * @param attr
 *      A globus_gass_copy attribute structure 
 *@param io_attr
 *      The file attributes to be used
 *
 *  @return
 *       This function returns GLOBUS_SUCCESS if successful, or a globus_result_t indicating the error that occurred.
 *
 * @see globus_gass_copy_attr_init(), globus_gass_copy_attr_set_gass(), globus_gass_copy_attr_set_ftp(), globus_io_attr_*
 */
globus_result_t
globus_gass_copy_attr_set_io(
    globus_gass_copy_attr_t * attr,
    globus_io_attr_t * io_attr)
{
    globus_object_t * err;
    static char * myname="globus_gass_copy_attr_set_io";
    if(attr != GLOBUS_NULL)
    {
	attr->io = io_attr;
	return GLOBUS_SUCCESS;
    }
    else
    {
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: BAD_PARAMETER, attr is NULL",
	    myname);
	return globus_error_put(err);
    }
} /* globus_gass_copy_attr_set_io() */

/**
 * Set the attributes for http/https transfers
 *
 * In order to specify attributes for http/https transfers, a globus_gass_transfer_requestattr_t should be initialized and its values
 * set using the appropriate globus_gass_transfer_requestattr_* functions.  The globus_gass_transfer_requestattr_t can then be passed
 * to the globus_gass_copy_attr_t via this function.
 *
 * @param attr
 *      A globus_gass_copy attribute structure 
 *@param io_attr
 *      The http/https attributes to be used
 *
 *  @return
 *       This function returns GLOBUS_SUCCESS if successful, or a globus_result_t indicating the error that occurred.
 *
 * @see globus_gass_copy_attr_init(), globus_gass_copy_attr_set_io(), globus_gass_copy_attr_set_ftp(),
 *         globus_gass_transfer_requestattr_*
 */
globus_result_t
globus_gass_copy_attr_set_gass(
    globus_gass_copy_attr_t * attr,
    globus_gass_transfer_requestattr_t * gass_attr)
{
    globus_object_t * err;
    static char * myname="globus_gass_copy_attr_set_gass";
    if(attr != GLOBUS_NULL)
    {
	attr->gass_requestattr = gass_attr;
	return GLOBUS_SUCCESS;
    }
    else
    {
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: BAD_PARAMETER, attr is NULL",
	    myname);
	return globus_error_put(err);
    }
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
void
globus_l_gass_copy_gass_setup_callback(
    void * callback_arg,
    globus_gass_transfer_request_t request);

void
globus_l_gass_copy_read_from_queue(
    globus_gass_copy_handle_t * handle);

globus_result_t
globus_l_gass_copy_register_read(
    globus_gass_copy_handle_t * handle,
    globus_byte_t * buffer);

void
globus_l_gass_copy_gass_read_callback(
    void *                          callback_arg,
    globus_gass_transfer_request_t  request,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_bool_t                   last_data);

void
globus_l_gass_copy_io_read_callback(
    void *                          callback_arg,
    globus_io_handle_t *            io_handle,
    globus_result_t                 result,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes);

void
globus_l_gass_copy_ftp_read_callback(
    void *                          callback_arg,
    globus_ftp_client_handle_t *    handle,
    globus_object_t *               error,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_size_t                   offset,
    globus_bool_t		    eof);

globus_result_t
globus_l_gass_copy_io_setup_get(
    globus_gass_copy_handle_t * handle);

globus_result_t
globus_l_gass_copy_io_setup_put(
    globus_gass_copy_handle_t * handle);

globus_result_t
globus_l_gass_copy_ftp_setup_get(
    globus_gass_copy_handle_t * handle);

globus_result_t
globus_l_gass_copy_ftp_setup_put(
    globus_gass_copy_handle_t * handle);

void
globus_l_gass_copy_ftp_get_done_callback(
    void * callback_arg,
    globus_ftp_client_handle_t * handle,
    globus_object_t *	       error);

void
globus_l_gass_copy_ftp_put_done_callback(
    void * callback_arg,
    globus_ftp_client_handle_t * handle,
    globus_object_t *	       error);


void
globus_l_gass_copy_write_from_queue(
    globus_gass_copy_handle_t * handle);

globus_result_t
globus_l_gass_copy_register_write(
    globus_gass_copy_handle_t * handle,
    globus_i_gass_copy_buffer_t * buffer_entry);

void
globus_l_gass_copy_gass_write_callback(
    void *                          callback_arg,
    globus_gass_transfer_request_t  request,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_bool_t                   last_data);

void
globus_l_gass_copy_io_write_callback(
    void *                callback_arg,
    globus_io_handle_t *  io_handle, 
    globus_result_t       result,
    globus_byte_t *       bytes,
    globus_size_t         nbytes);

void
globus_l_gass_copy_ftp_write_callback(
    void *                       callback_arg,
    globus_ftp_client_handle_t * handle, 
    globus_object_t *            error,
    globus_byte_t *              bytes,
    globus_size_t                nbytes,
    globus_size_t                offset,
    globus_bool_t		 eof);
  
globus_result_t
globus_i_gass_copy_attr_duplicate(globus_gass_copy_attr_t ** attr);

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/**
 * Get the status of the current transfer
 */
globus_result_t
globus_gass_copy_get_status(
    globus_gass_copy_handle_t * handle,
    globus_gass_copy_status_t *status)
{
    globus_object_t * err;
    static char * myname="globus_gass_copy_get_status";
    if(handle != GLOBUS_NULL)
    {
	*status = handle->status;
	return GLOBUS_SUCCESS;
    }
    else
    {
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: BAD_PARAMETER, handle is NULL",
	    myname);
	
	return globus_error_put(err);
    }
} /* globus_gass_copy_get_status() */


#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * Classify the URL schema into the transfer method that will be used to do
 * the actual tranfer.
 *
 * @param url
 *        The URL for schema checking
 * @param type
 *        the filled in schema type of the URL param
 *
 * @return
 *         This function returns GLOBUS_SUCCESS or a result pointing to an
 *         object of one of the the following error types:
 * @retval GLOBUS_URL_ERROR_*
 *         one of the GLOBUS_URL_ERROR_ values
 */
globus_result_t
globus_gass_copy_get_url_mode(
    char * url,
    globus_gass_copy_url_mode_t * mode)
{
    globus_url_t url_info;
    int rc;
    globus_object_t * err;
    static char * myname="globus_gass_copy_get_url_mode";

    if ((rc = globus_url_parse(url, &url_info)) != GLOBUS_SUCCESS)
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "copy_url_mode(): globus_url_parse returned !GLOBUS_SUCCESS for url: %s\n", url);
#endif
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: globus_url_parse returned error code: %d for url: %s",
	    myname,
	    rc,
	    url);
	
	return globus_error_put(err);
    }
   
    if ( (url_info.scheme_type == GLOBUS_URL_SCHEME_FTP) ||
	 (url_info.scheme_type == GLOBUS_URL_SCHEME_GSIFTP) )
    {
	*mode = GLOBUS_GASS_COPY_URL_MODE_FTP;
    }
    else if ( (url_info.scheme_type == GLOBUS_URL_SCHEME_HTTP) ||
              (url_info.scheme_type == GLOBUS_URL_SCHEME_HTTPS) )
    {
	*mode = GLOBUS_GASS_COPY_URL_MODE_GASS;
    }
    else if ( (url_info.scheme_type == GLOBUS_URL_SCHEME_FILE))
    {
	*mode = GLOBUS_GASS_COPY_URL_MODE_IO;
    }
    else
    {
	*mode = GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED;
    }

    return GLOBUS_SUCCESS;
} /* globus_l_gass_copy_get_url_mode() */

/* if either source or detination are ftp urls, wait for their callbacks to be called before
   cleaning up and calling the user callback
   */
void
globus_l_gass_copy_wait_for_ftp_callbacks(
    globus_gass_copy_handle_t *handle)
{
    globus_i_gass_copy_monitor_t * source_monitor
	= &(handle->state->source.data.ftp.monitor);
    globus_i_gass_copy_monitor_t * dest_monitor
	= &(handle->state->dest.data.ftp.monitor);
    
    if(handle->state->source.mode == GLOBUS_GASS_COPY_URL_MODE_FTP)
    {
	globus_mutex_lock(&(source_monitor->mutex));
	while(!source_monitor->done)
	{
	    globus_cond_wait(&(source_monitor->cond), &(source_monitor->mutex));
	}
	globus_mutex_unlock(&(source_monitor->mutex));
    }

    if(handle->state->dest.mode == GLOBUS_GASS_COPY_URL_MODE_FTP)
    {
	globus_mutex_lock(&(dest_monitor->mutex));
	while(!dest_monitor->done)
	{
	    globus_cond_wait(&(dest_monitor->cond), &(dest_monitor->mutex));
	}
	globus_mutex_unlock(&(dest_monitor->mutex));
    }
}/* globus_l_gass_copy_wait_for_ftp_callbacks() */


/**
 * Populate the target transfer structures
 */
globus_result_t
globus_l_gass_copy_target_populate(
    globus_gass_copy_handle_t * handle,
    globus_i_gass_copy_target_t * target,
    globus_gass_copy_url_mode_t * url_mode,
    char * url,
    globus_gass_copy_attr_t * attr)
{
    globus_object_t * err;
    globus_gass_copy_attr_t * tmp_attr;
    static char * myname="globus_l_gass_copy_target_populate";
    /* initialize the target mutex */
    globus_mutex_init(&(target->mutex), GLOBUS_NULL);

    target->n_pending = 0;
    target->n_complete = 0;
    target->status = GLOBUS_I_GASS_COPY_TARGET_INITIAL;
    target->cancel = GLOBUS_I_GASS_COPY_CANCEL_FALSE;

    if(attr == GLOBUS_NULL)
    {
	target->free_attr = GLOBUS_TRUE;
	tmp_attr = (globus_gass_copy_attr_t *) globus_libc_malloc(sizeof(globus_gass_copy_attr_t));

	if(tmp_attr == GLOBUS_NULL)
	{
	    err = globus_error_construct_string(
		GLOBUS_GASS_COPY_MODULE,
		GLOBUS_NULL,
		"[%s]: failed malloc a globus_gass_copy_attr_t structure successfully",
		myname);
	    globus_i_gass_copy_set_error(handle, err);
	    return globus_error_put(handle->err);
	}
      
	globus_gass_copy_attr_init(tmp_attr);
  
	attr = tmp_attr;
    }
    else
	target->free_attr = GLOBUS_FALSE;

    target->mode = *url_mode;
    switch (target->mode)
    {
    case GLOBUS_GASS_COPY_URL_MODE_FTP:

	/* target->mode = *url_mode; */
	globus_mutex_init(&(target->data.ftp.monitor.mutex), GLOBUS_NULL);
	globus_cond_init(&(target->data.ftp.monitor.cond), GLOBUS_NULL);
	target->data.ftp.monitor.done = GLOBUS_FALSE;
	target->url = globus_libc_strdup(url);
	target->attr = *attr;
	/* FIXX n_simultaneous should be pulled from attributes, or something */
	target->n_simultaneous = 1;
	break;

    case GLOBUS_GASS_COPY_URL_MODE_GASS:

	/*target->mode = GLOBUS_I_GASS_COPY_TARGET_MODE_GASS; */
	target->url = globus_libc_strdup(url);
	target->attr = *attr;
	target->n_simultaneous = 1;
	break;

    case GLOBUS_GASS_COPY_URL_MODE_IO:

	/*target->mode = GLOBUS_I_GASS_COPY_TARGET_MODE_IO;*/
	target->url = globus_libc_strdup(url);
	target->attr = *attr;
	target->data.io.free_handle = GLOBUS_TRUE;
	target->data.io.seekable = GLOBUS_TRUE;
	target->n_simultaneous = 1;

	break;

    case GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED:
	/* something went horribly wrong */
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: %s: GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED",
	    myname,
	    url);
	globus_i_gass_copy_set_error(handle, err);
	return globus_error_put(handle->err);

	break;
    }

    /* setup the queue
     */
    if (globus_fifo_init(&(target->queue)) != GLOBUS_SUCCESS)
    {
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: failed to initialize fifo successfully",
	    myname);
	globus_i_gass_copy_set_error(handle, err);
	return globus_error_put(handle->err);
    }
    
    return GLOBUS_SUCCESS;
} /* globus_l_gass_copy_target_populate() */

globus_result_t
globus_l_gass_copy_io_target_populate(
    globus_gass_copy_handle_t * handle,
    globus_i_gass_copy_target_t * target,
    globus_io_handle_t * io_handle)
{
    globus_object_t * err;
    static char * myname="globus_l_gass_copy_io_target_populate";
    
    target->free_attr = GLOBUS_FALSE;
    /* initialize the target mutex */
    globus_mutex_init(&(target->mutex), GLOBUS_NULL);

    target->data.io.handle = io_handle;
    
    target->n_pending = 0;
    target->status = GLOBUS_I_GASS_COPY_TARGET_INITIAL;

    target->mode = GLOBUS_GASS_COPY_URL_MODE_IO;
   
    target->data.io.free_handle = GLOBUS_FALSE;
    if(globus_io_get_handle_type(io_handle) == GLOBUS_IO_HANDLE_TYPE_FILE)
	target->data.io.seekable = GLOBUS_TRUE;
    else
	target->data.io.seekable = GLOBUS_FALSE;
    target->n_simultaneous = 1;
    
    /* setup the queue
     */
    if (globus_fifo_init(&(target->queue)) != GLOBUS_SUCCESS)
    {
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: failed to initialize fifo successfully",
	    myname);
	globus_i_gass_copy_set_error(handle, err);
	return globus_error_put(handle->err);
    }
    
    return GLOBUS_SUCCESS;
} /* globus_l_gass_copy_io_target_populate() */


/**
 * Clean up the target transfer structures, freeing any memory that was allocated
 */
globus_result_t
globus_l_gass_copy_target_destroy(
    globus_i_gass_copy_target_t * target)
{
    globus_i_gass_copy_buffer_t *  buffer_entry;
    /* empty and free the queue */
    while(!globus_fifo_empty(&(target->queue)))
    {
	buffer_entry = globus_fifo_dequeue(&(target->queue));
	globus_libc_free(buffer_entry->bytes);
	globus_libc_free(buffer_entry);
    }
    globus_fifo_destroy(&(target->queue));
    /* clean up the mutex */
    globus_mutex_destroy(&(target->mutex));
    /* free up the attr, if we allocated it */
    if(target->free_attr == GLOBUS_TRUE)
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "target_destroy(): freeing the target attr\n");
#endif
	globus_libc_free(&(target->attr));
    }
  
    switch(target->mode)
    {
    case GLOBUS_GASS_COPY_URL_MODE_FTP:
	/* once parallel reads/writes are possible, will have to potentially free the attr,
	   if parallelism is turned off by the library */
	  
	globus_libc_free(&(target->url));
	   
	globus_mutex_destroy(&(target->data.ftp.monitor.mutex));
	globus_cond_destroy(&(target->data.ftp.monitor.cond));
	   	   
	break;

    case GLOBUS_GASS_COPY_URL_MODE_GASS:
	globus_libc_free(&(target->url));
	break;
	   
    case GLOBUS_GASS_COPY_URL_MODE_IO:
	if(target->data.io.free_handle == GLOBUS_TRUE)
	{
	    globus_libc_free(&(target->data.io.handle));
	    globus_libc_free(&(target->url));

	}
	break;
    }
    return GLOBUS_SUCCESS;
} /* gloubs_l_gass_copy_target_destroy() */

/**
 * instantiate state structure
 */
globus_result_t
globus_l_gass_copy_state_new(
    globus_gass_copy_handle_t *handle)
{
    globus_object_t * err;
    static char * myname="globus_l_gass_copy_state_new";
    
    globus_gass_copy_state_t ** tmp_state = &(handle->state);
    *tmp_state = (globus_gass_copy_state_t *)
	globus_libc_malloc(sizeof(globus_gass_copy_state_t));

    if(tmp_state == GLOBUS_NULL)
    {
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: failed to malloc a globus_gass_copy_state_t successfully",
	    myname);
	globus_i_gass_copy_set_error(handle, err);
	return globus_error_put(handle->err);
    }
    
    handle->status = GLOBUS_GASS_COPY_STATUS_INITIAL;
    handle->err = GLOBUS_SUCCESS;
 
    /* initialize the monitor */   
    globus_mutex_init(&((*tmp_state)->monitor.mutex), GLOBUS_NULL);
    globus_cond_init(&((*tmp_state)->monitor.cond), GLOBUS_NULL);
    (*tmp_state)->monitor.done = GLOBUS_FALSE;
      
    (*tmp_state)->monitor.err = GLOBUS_NULL;
    (*tmp_state)->monitor.use_err = GLOBUS_FALSE;
    
    globus_mutex_init(&((*tmp_state)->mutex), GLOBUS_NULL);

    return GLOBUS_SUCCESS;
} /* globus_l_gass_copy_state_new() */

/**
 * free state structure
 */
globus_result_t
globus_l_gass_copy_state_free(
    globus_gass_copy_state_t * state)
{
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "globus_l_gass_copy_state_free(): freeing up the state\n");
#endif
    /* clean  up the monitor */
    globus_mutex_destroy(&(state->monitor.mutex));
    globus_cond_destroy(&(state->monitor.cond));

    globus_mutex_destroy(&(state->mutex));
    /* FIXX-  put target_destroy() back in */  
    /* clean  up the source target */
    globus_l_gass_copy_target_destroy(&(state->source));
	
    /* clean  up the destination target */
    globus_l_gass_copy_target_destroy(&(state->dest));
  
    /* free up the state */
  
    globus_libc_free(state);
 
} /* globus_l_gass_copy_state_free() */


/**
 * Start the transfer.
 *
 * Based on the source and destination information in the state structure, start
 * the data transfer using the appropriate method - FTP, GASS, IO
 *
 * @param state
 *        structure containing all the information required to perform data
 *        transfer from a source to a destination.
 *
 * @return fuzzy description
 *
 * @retval GLOBUS_SUCCESS
 *         Descriptions
 * @retval GLOBUS_FAILRUE
 *
 * @see globus_gass_copy_xxx()
 */
globus_result_t
globus_l_gass_copy_transfer_start(
    globus_gass_copy_handle_t * handle)
{
    globus_gass_copy_state_t * state = handle->state;
    globus_result_t result = GLOBUS_SUCCESS;
    int rc;
    globus_object_t * err;
    static char * myname="globus_l_gass_copy_transfer_start";

#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "made it to globus_l_gass_copy_transfer_start()\n");
#endif
    
    if (   (state->source.mode
	    == GLOBUS_GASS_COPY_URL_MODE_FTP)
	   && (   (   (state->dest.mode
		       == GLOBUS_GASS_COPY_URL_MODE_GASS) )
		  || (   (state->dest.mode
			  == GLOBUS_GASS_COPY_URL_MODE_IO)
			 && (!state->dest.data.io.seekable) ) ) )
    {
	/*
	 * If the source stream is ftp, this means it is capable
	 * of supporting multiple data channels and handing back
	 * data block in an arbitrary order.
	 *
	 * If the destination stream can only handle sequential
	 * writes of the data, then disable the multiple data
	 * channel support in ftp
	 */

	/*
	if ((result = globus_i_gass_copy_attr_duplicate(&(state->source.attr)))
            != GLOBUS_SUCCESS)
        {
	    handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	    return result;
        }
	*/
        /* probably change these with a globus_ftp_attr_parallelism*?? call
         */
	/*
	  state->source.attr.parallelism_info.mode =
	  GLOBUS_GSIFTP_CONTROL_PARALLELISM_NONE;
	  state->source.attr.striping_info.mode =
	  GLOBUS_GSIFTP_CONTROL_STRIPING_NONE;
	  */
	/*
	 * ftp -> gass_transfer:
	 *     turn off both parallel & striping
	 * ftp -> io:
	 *     globus_io_file_seek() can be used to deal with out of
	 *     order blocks
	 * gass_transfer, io -> *
	 *     The source data is serialized anyway, so do don't need
	 *     to worry about the destination.  An ftp destination can
	 *     use parallelism and/or striping if desired
	 */
    }
 
    /* depending on the mode, call the appropriate routine to start the
     * transfer
     */
    switch (state->source.mode)
    {
    case GLOBUS_GASS_COPY_URL_MODE_FTP:

	state->source.data.ftp.n_channels = 0;
	state->source.data.ftp.n_reads_posted = 0;

        result = globus_l_gass_copy_ftp_setup_get(handle);

	break;

    case GLOBUS_GASS_COPY_URL_MODE_GASS:
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "transfer_start(): about to call globus_gass_transfer_register_get()\n");
#endif
	rc = globus_gass_transfer_register_get(
	    &(state->source.data.gass.request),
	    (state->source.attr.gass_requestattr),
	    state->source.url,
	    globus_l_gass_copy_gass_setup_callback,
	    (void *) handle);
/*
  FIXX - what happens if this is a referral?
  */
	if (rc != GLOBUS_SUCCESS)
	{
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	    fprintf(stderr, "transfer_start(): globus_gass_transfer_register_get returned !GLOBUS_SUCCESS\n");
#endif	    
	    err = globus_error_construct_string(
		GLOBUS_GASS_COPY_MODULE,
		GLOBUS_NULL,
		"[%s]: %s globus_gass_transfer_register_get returned an error code of: %d",
		myname,
		state->source.url,
		rc);
	    globus_i_gass_copy_set_error(handle, err);
	    
	    result = globus_error_put(handle->err);
	}
	break;

    case GLOBUS_GASS_COPY_URL_MODE_IO:

	result = globus_l_gass_copy_io_setup_get(handle);

	break;
    }

    if(result != GLOBUS_SUCCESS)
    {
	globus_i_gass_copy_set_error_from_result(handle, result);
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	return result;
    }
    
    /* wait for ok from the source */
    globus_mutex_lock(&(state->monitor.mutex));
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "transfer_start(): about to cond_wait() while source is setup\n");
#endif
    while(state->source.status == GLOBUS_I_GASS_COPY_TARGET_INITIAL)
    {
        globus_cond_wait(&state->monitor.cond,
			 &state->monitor.mutex);	
    }
    globus_mutex_unlock(&state->monitor.mutex);

    if(handle->err)
    {
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	return globus_error_put(handle->err);
    }
    
    handle->status = GLOBUS_GASS_COPY_STATUS_SOURCE_READY;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "transfer_start(): source is ready\n");
#endif
    /*
     * Now get the destination side ready
     */
    switch (state->dest.mode)
    {
    case GLOBUS_GASS_COPY_URL_MODE_FTP:

	state->dest.data.ftp.n_channels = 0;
	state->dest.data.ftp.n_reads_posted = 0;

	result = globus_l_gass_copy_ftp_setup_put(handle);
	break;

    case GLOBUS_GASS_COPY_URL_MODE_GASS:
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "transfer_start(): about to call globus_gass_transfer_register_put()\n");
#endif
        rc = globus_gass_transfer_register_put(
	    &(state->dest.data.gass.request),
	    (state->dest.attr.gass_requestattr),
	    state->dest.url,
	    GLOBUS_NULL,
	    globus_l_gass_copy_gass_setup_callback,
	    (void *) handle);

	if (rc != GLOBUS_SUCCESS)
	{
	    err = globus_error_construct_string(
		GLOBUS_GASS_COPY_MODULE,
		GLOBUS_NULL,
		"[%s]: %s globus_gass_transfer_register_put returned an error code of: %d",
		myname,
		state->dest.url,
		rc);
	    globus_i_gass_copy_set_error(handle, err);
	    
	    result = globus_error_put(handle->err);
	}
	  
	
	break;

    case GLOBUS_GASS_COPY_URL_MODE_IO:
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "transfer_start(): about to call globus_l_gass_copy_io_setup_put()\n");
#endif
	result = globus_l_gass_copy_io_setup_put(handle);

	break;
    }

    if(result != GLOBUS_SUCCESS)
    {
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE; 
    
	globus_i_gass_copy_set_error_from_result(handle, result);

#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "transfer_start(): error with setting up the dest\n");
#endif

	/* FIXX - need to clean up the source side since it was already opened.....
	 *  prolly need to call user's callback here.
	 globus_gass_copy_cancel(handle);
	 */
	return result;
    }
    /* wait for ok from the dest */
    globus_mutex_lock(&(state->monitor.mutex));

#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "transfer_start(): about to cond_wait() while dest is setup\n");
#endif
    
    while(state->dest.status == GLOBUS_I_GASS_COPY_TARGET_INITIAL)
    {
        globus_cond_wait(&state->monitor.cond,
			 &state->monitor.mutex);
    }
    globus_mutex_unlock(&state->monitor.mutex);

    if(handle->err)
    {
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	/* FIXX - need to clean up the source side since it was already opened.....
	 *  prolly need to call user's callback here.
	 globus_gass_copy_cancel(handle);
	 */
	return globus_error_put(handle->err);
    }
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "transfer_start(): dest is ready, let's get goin'\n");
#endif
    /* both sides are ready, start the transfer */
    state->n_buffers = 0;
    state->max_buffers = state->source.n_simultaneous +
	state->dest.n_simultaneous;
    handle->status = GLOBUS_GASS_COPY_STATUS_TRANSFER_IN_PROGRESS;

    globus_l_gass_copy_read_from_queue(handle); /*start reading */
    return(GLOBUS_SUCCESS);
} /* globus_l_gass_copy_transfer_start() */

void
globus_l_gass_copy_read_from_queue(
    globus_gass_copy_handle_t * handle)
{
    globus_gass_copy_state_t * state = handle->state;
    globus_i_gass_copy_buffer_t *  buffer_entry;
    globus_byte_t * buffer;
    globus_result_t result = GLOBUS_SUCCESS;
    globus_object_t * err;
    static char * myname="globus_l_gass_copy_read_from_queue";
    
    globus_mutex_lock(&(state->source.mutex));
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "read_from_queue(): n_pending= %d  n_simultaneous= %d\n", state->source.n_pending, state->source.n_simultaneous);
#endif

    /* if the source is READY (and not DONE, FAILURE, or CANCELED), see if we should register a read
     */
    if(state->source.status == GLOBUS_I_GASS_COPY_TARGET_READY)
    {
	
	/*  FIXX --
	 *  this needs to be a while loop, so that ftp can take advantage of
	 *  multiple channels
	 */
	/* if there aren't too many reads pending, register one */
	if((state->source.n_pending < state->source.n_simultaneous) &&
	   !state->source.cancel)
	{
	    if ((buffer_entry = globus_fifo_dequeue(&(state->source.queue)))
		!= GLOBUS_NULL)
	    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
		fprintf(stderr, "read_from_queue: about to register_read() with buffer from fifo\n");
#endif
		state->source.n_pending++;
		result = globus_l_gass_copy_register_read(
		    handle,
		    buffer_entry->bytes);
		globus_libc_free(buffer_entry);

	    }/* if (buffer_entry != GLOBUS_NULL) */
	    else /* there are no available buffers to read into, if  there's room create one */
	    {
		globus_mutex_lock(&(state->mutex));
		{ /* lock state to check/modify n_buffers and max_buffers */
		    if(state->n_buffers < state->max_buffers)
		    {		
			state->n_buffers++;
			/* allocate a buffer to read into*/
		
			buffer = globus_libc_malloc(handle->buffer_length);
			if(buffer == GLOBUS_NULL)
			{
			    /* out of memory error */
			    err = globus_error_construct_string(
				GLOBUS_GASS_COPY_MODULE,
				GLOBUS_NULL,
				"[%s]: failed to malloc buffer of size %d",
				myname,
				handle->buffer_length);
			    globus_i_gass_copy_set_error(handle, err);
			    result = globus_error_put(handle->err);
			}
			else
			{
			    state->source.n_pending++;
			    result = globus_l_gass_copy_register_read(
				handle,
				buffer);
			}
		    }/* if(state->n_buffers < state->max_buffers) */
		}
		globus_mutex_unlock(&(state->mutex));
	    }/* else (no available buffers in fifo, create a new one, maybe*/

	    if (result != GLOBUS_SUCCESS)
	    {
		state->source.cancel = GLOBUS_I_GASS_COPY_CANCEL_TRUE;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
		fprintf(stderr, "read_from_queue(): there was an ERROR trying to register a read\n");
#endif
	    }
	}/* if(state->source.n_pending < state->source.n_simultaneous) */
    } /* if(state->source.status == GLOBUS_I_GASS_COPY_TARGET_READY) */
    globus_mutex_unlock(&(state->source.mutex));

    if(result != GLOBUS_SUCCESS)
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "read_from_queue():  gonna call globus_gass_copy_cancel()\n");
#endif
	/* FIXX -- call globus_gass_copy_cancel() */
    }
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "read_from_queue(): returning\n");
#endif
   
} /* globus_l_gass_copy_read_from_queue() */


/**
 * register read
 *
 * Based on the mod of the source, register a read using the appropriate
 * data transfer method.
 *
 * @param state
 *        structure containing all the information required to perform data
 *        transfer from a source to a destination.
 * @param buffer
 *        The buffer to be used to transfer the data.
 *
 * @return fuzzy description
 *
 * @retval GLOBUS_SUCCESS
 *         Descriptions
 * @retval GLOBUS_FAILRUE
 *
 * @see globus_gass_copy_xxx()
 */
globus_result_t
globus_l_gass_copy_register_read(
    globus_gass_copy_handle_t * handle,
    globus_byte_t * buffer)
{
    globus_gass_copy_state_t * state = handle->state;
    globus_result_t result;
    int rc;
    globus_object_t * err;
    static char * myname="globus_l_gass_copy_register_read";
    
    switch (state->source.mode)
    {
    case GLOBUS_GASS_COPY_URL_MODE_FTP:
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "register_read():  calling globus_ftp_client_register_read()\n");
#endif	  
 	result = globus_ftp_client_register_read(
	    /*state->source.data.ftp.handle,*/
	    &(handle->ftp_handle),
	    buffer,
	    handle->buffer_length,
	    globus_l_gass_copy_ftp_read_callback,
	    (void *) handle);
	    
	break;

    case GLOBUS_GASS_COPY_URL_MODE_GASS:
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "register_read():  calling globus_gass_transfer_receive_bytes()\n");
#endif
	rc = globus_gass_transfer_receive_bytes(
	    state->source.data.gass.request,
	    buffer,
	    handle->buffer_length,
	    handle->buffer_length,
	    globus_l_gass_copy_gass_read_callback,
	    (void *) handle);

	if (rc != GLOBUS_SUCCESS)
	{
	    /* figure out what the error is, and pass it back through the result */
	    err = globus_error_construct_string(
		GLOBUS_GASS_COPY_MODULE,
		GLOBUS_NULL,
		"[%s]: globus_gass_transfer_receive_bytes returned error code: %d",
		myname,
		rc);
	    globus_i_gass_copy_set_error(handle, err);
	    result = globus_error_put(handle->err);
	}
	else result = GLOBUS_SUCCESS;
	
	break;

    case GLOBUS_GASS_COPY_URL_MODE_IO:

	result = globus_io_register_read(
	    state->source.data.io.handle,
	    buffer,
	    handle->buffer_length,
	    handle->buffer_length,
	    globus_l_gass_copy_io_read_callback,
	    (void *) handle);

	
	break;
    }

    return result;
    
} /* globus_l_gass_copy_register_read */

/*****************************************************************
 * setup callbacks
 *****************************************************************/


/**
 * GASS setup callback.
 *
 * This function is called after the connection attempt to the data source has
 * completed or failed.
 *
 * @param state
 *        structure containing all the information required to perform data
 *        transfer from a source to a destination.
 *
 * @return fuzzy description
 *
 * @retval GLOBUS_SUCCESS
 *         Descriptions
 * @retval GLOBUS_FAILURE
 *
 * @see globus_gass_copy_destroy()
 */

void
globus_l_gass_copy_gass_setup_callback(
    void * callback_arg,
    globus_gass_transfer_request_t  request)
{
    globus_gass_transfer_referral_t  referral;
    int rc;
    globus_object_t * err;
    char * current_url;
    char * denial_message;
    int denial_reason;
    static char * myname="globus_l_gass_copy_gass_setup_callback";

    globus_gass_copy_handle_t *  handle
	= (globus_gass_copy_handle_t *) callback_arg;
    globus_gass_copy_state_t * state = handle->state;
	

    globus_gass_transfer_request_status_t status;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "globus_l_gass_copy_gass_setup_callback() called\n");
#endif   
    status = globus_gass_transfer_request_get_status(request);

    switch(status)
    {
    case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "request status == GLOBUS_GASS_TRANSFER_REQUEST_REFERRED\n");
#endif
	globus_gass_transfer_request_get_referral(request, &referral);
	globus_gass_transfer_request_destroy(request);

	if (handle->status == GLOBUS_GASS_COPY_STATUS_INITIAL)
	{
	    /* first setup the source with the register get
	     */
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	    fprintf(stderr, "REQUEST_REFERRED:  STATE_INITIAL\n");
#endif
	    current_url = globus_libc_strdup(state->source.url);
	    state->source.url =
		globus_gass_transfer_referral_get_url(&referral, 0);
	       
#ifdef GLOBUS_I_GASS_COPY_DEBUG              
	    fprintf(stderr, "REQUEST_REFERRED: about to globus_gass_transfer_register_get() again with: %s\n",state->source.url);
#endif
	    if ( (rc = globus_gass_transfer_register_get(
		&(state->source.data.gass.request),
		(state->source.attr.gass_requestattr),
		state->source.url,
		globus_l_gass_copy_gass_setup_callback,
		(void *) handle)) != GLOBUS_SUCCESS )
	    {/* there was an error */
		globus_mutex_lock(&state->monitor.mutex);
#ifdef GLOBUS_I_GASS_COPY_DEBUG	   
		fprintf(stderr, "gass_setup_callback(): transfer_register_get() returned: %d\n", rc);
		if(rc==GLOBUS_GASS_ERROR_BAD_URL)
		    fprintf(stderr, "rc == GLOBUS_GASS_ERROR_BAD_URL\n");
#endif
		err = globus_error_construct_string(
		    GLOBUS_GASS_COPY_MODULE,
		    GLOBUS_NULL,
		    "[%s]: the original source url: %s  was referred to: %s, for which globus_gass_transfer_register_get returned an error code of: %d",
		    myname,
		    current_url,
		    state->source.url,
		    rc);
		globus_i_gass_copy_set_error(handle, err);
		globus_libc_free(current_url);
		globus_gass_transfer_referral_destroy(&referral);
		goto wakeup_state;
	    }
	    globus_gass_transfer_referral_destroy(&referral);
	}
	else
	{
	    /* if the state is not INITIAL then assume the source is ready
	     * and that we are now setting up the destination with the register put
	     */
	    current_url = globus_libc_strdup(state->dest.url);
	    state->dest.url =
		globus_gass_transfer_referral_get_url(&referral, 0);

	    globus_gass_transfer_referral_destroy(&referral);

	    if ( (rc = globus_gass_transfer_register_put(
		&request,
		(state->dest.attr.gass_requestattr),
		state->dest.url,
		GLOBUS_NULL,
		globus_l_gass_copy_gass_setup_callback,
		(void *) handle)) != GLOBUS_SUCCESS )
	    { /* there was an error */
		globus_mutex_lock(&state->monitor.mutex);
		err = globus_error_construct_string(
		    GLOBUS_GASS_COPY_MODULE,
		    GLOBUS_NULL,
		    "[%s]: the original destination url: %s was referred to: %s, for which globus_gass_transfer_register_get returned an error code of: %d",
		    myname,
		    current_url,
		    state->dest.url,
		    rc);
		globus_i_gass_copy_set_error(handle, err);
		globus_libc_free(current_url);
		globus_gass_transfer_referral_destroy(&referral);
		goto wakeup_state;
	    }
	    globus_gass_transfer_referral_destroy(&referral);
	}
	globus_libc_free(current_url);
	break;

    case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "request status == GLOBUS_GASS_TRANSFER_REQUEST_PENDING, should signal the monitor\n");
#endif
	if (handle->status == GLOBUS_GASS_COPY_STATUS_INITIAL)
	{
	    globus_mutex_lock(&state->monitor.mutex);
	    state->source.status = GLOBUS_I_GASS_COPY_TARGET_READY;
	    globus_cond_signal(&state->monitor.cond);
	    globus_mutex_unlock(&state->monitor.mutex);
	}
	else
	{
	    globus_mutex_lock(&state->monitor.mutex);
	    state->dest.status = GLOBUS_I_GASS_COPY_TARGET_READY;
	    globus_cond_signal(&state->monitor.cond);
	    globus_mutex_unlock(&state->monitor.mutex);
	}
	break;

    case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "request status == GLOBUS_GASS_TRANSFER_REQUEST_DONE\n");
#endif
	globus_mutex_lock(&state->monitor.mutex);
	if (handle->status == GLOBUS_GASS_COPY_STATUS_INITIAL)
	    current_url = state->source.url;
	else
	    current_url = state->dest.url;
	   
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: we're just getting set up, but the status of url %s is GLOBUS_GASS_TRANSFER_REQUEST_DONE",
	    myname,
	    current_url);
	globus_i_gass_copy_set_error(handle, err);
	   
	goto wakeup_state;
	break;

    case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "request status == GLOBUS_GASS_TRANSFER_REQUEST_DENIED\n");
#endif
	globus_mutex_lock(&state->monitor.mutex);
	if (handle->status == GLOBUS_GASS_COPY_STATUS_INITIAL)
	    current_url = state->source.url;
	else
	    current_url = state->dest.url;

	denial_reason = globus_gass_transfer_request_get_denial_reason(request);
	denial_message = globus_gass_transfer_request_get_denial_message(request);
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]:  url: %s request was DENIED, for reason: %d, %s",
	    myname,
	    current_url,
	    denial_reason,
	    denial_message);
	globus_i_gass_copy_set_error(handle, err);
	   
	goto wakeup_state;
	break;

    case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "request status == GLOBUS_GASS_TRANSFER_REQUEST_FAILED\n");
#endif
	globus_mutex_lock(&state->monitor.mutex);
	if (handle->status == GLOBUS_GASS_COPY_STATUS_INITIAL)
	    current_url = state->source.url;
	else
	    current_url = state->dest.url;

	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]:  url: %s request FAILED",
	    myname,
	    current_url);
	globus_i_gass_copy_set_error(handle, err);

	goto wakeup_state;
	break;
    } /* switch */
    return;

wakeup_state:
    /* 
     * assume mutex has already been locked by above calls
     */
    globus_gass_transfer_request_destroy(request);
    state->monitor.done = 1;
    globus_cond_signal(&state->monitor.cond);
    globus_mutex_unlock(&state->monitor.mutex);

    return;
} /* globus_l_gass_copy_gass_setup_callback() */

globus_result_t
globus_l_gass_copy_io_setup_get(
    globus_gass_copy_handle_t * handle)
{
    globus_gass_copy_state_t * state = handle->state;
    globus_url_t parsed_url;
    globus_result_t result = GLOBUS_SUCCESS;
    globus_object_t * err;
    static char * myname="globus_l_gass_copy_io_setup_get";
    
    if (state->source.data.io.free_handle)
    {
	globus_url_parse(state->source.url, &parsed_url);
	state->source.data.io.handle =(globus_io_handle_t *)
	    globus_libc_malloc(sizeof(globus_io_handle_t));
      
	if(state->source.data.io.handle == GLOBUS_NULL)
	{
	    err = globus_error_construct_string(
		GLOBUS_GASS_COPY_MODULE,
		GLOBUS_NULL,
		"[%s]: failed to malloc a globus_io_handle_t successfully",
		myname);
	    globus_i_gass_copy_set_error(handle, err);
	    return globus_error_put(handle->err);
	}
	result = globus_io_file_open(
	    parsed_url.url_path,
	    GLOBUS_IO_FILE_RDONLY,
	    GLOBUS_IO_FILE_IRUSR,
	    state->source.attr.io,
	    state->source.data.io.handle);

	if(result==GLOBUS_SUCCESS)
	{
	    state->source.status = GLOBUS_I_GASS_COPY_TARGET_READY;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	    fprintf(stderr, "io_setup_get(): SUCCESS opening %s\n",parsed_url.url_path);
	}
	else
	{
	    fprintf(stderr, "io_setup_get(): FAILURE opening %s\n",parsed_url.url_path);
#endif
	}
    }
    else
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "io_setup_get(): handle should already have been  opened by the user\n");
#endif
        state->source.status = GLOBUS_I_GASS_COPY_TARGET_READY;
        result=GLOBUS_SUCCESS;
    }

    return result;
} /* globus_l_gass_copy_io_setup_get() */

globus_result_t
globus_l_gass_copy_io_setup_put(
    globus_gass_copy_handle_t * handle)
{
    globus_gass_copy_state_t * state = handle->state;
    globus_url_t parsed_url;
    globus_result_t result = GLOBUS_SUCCESS;
    globus_object_t * err;
    static char * myname="globus_l_gass_copy_io_setup_put";
    if (state->dest.data.io.free_handle)
    {
        globus_url_parse(state->dest.url, &parsed_url);
        state->dest.data.io.handle = (globus_io_handle_t *)
            globus_libc_malloc(sizeof(globus_io_handle_t));
	if(state->dest.data.io.handle == GLOBUS_NULL)
	{
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	    fprintf(stderr, "io_setup_put(): error mallocing io_handle_t\n");
#endif
	    err = globus_error_construct_string(
		GLOBUS_GASS_COPY_MODULE,
		GLOBUS_NULL,
		"[%s]: failed to malloc a globus_io_handle_t successfully",
		myname);
	    globus_i_gass_copy_set_error(handle, err);
	    return globus_error_put(handle->err);
	}

        result = globus_io_file_open(
	    parsed_url.url_path,
	    (GLOBUS_IO_FILE_WRONLY|GLOBUS_IO_FILE_CREAT|GLOBUS_IO_FILE_TRUNC),
	    (GLOBUS_IO_FILE_IRWXU|GLOBUS_IO_FILE_IRWXG|GLOBUS_IO_FILE_IRWXO),
	    state->dest.attr.io,
	    state->dest.data.io.handle);

	if(result==GLOBUS_SUCCESS)
	{
	    state->dest.status = GLOBUS_I_GASS_COPY_TARGET_READY;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	    fprintf(stderr, "io_setup_put(): SUCCESS opening %s\n",parsed_url.url_path);
	}
	else
	{
	    fprintf(stderr, "io_setup_put(): FAILURE opening %s\n",parsed_url.url_path);
#endif
	}
    }
    else
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "io_setup_put(): handle should already have been  opened by the user\n");
#endif   
	state->dest.status = GLOBUS_I_GASS_COPY_TARGET_READY;
	result=GLOBUS_SUCCESS;
    }

    return result;
} /* globus_l_gass_copy_io_setup_put() */


globus_result_t
globus_l_gass_copy_ftp_setup_get(
    globus_gass_copy_handle_t * handle)
{
    globus_gass_copy_state_t * state = handle->state;
    globus_result_t result;

    result = globus_ftp_client_get(
	&(handle->ftp_handle),
	state->source.url,
	state->source.attr.ftp_attr,
	GLOBUS_NULL,
	globus_l_gass_copy_ftp_get_done_callback,
	(void *) handle);
    


    if(result==GLOBUS_SUCCESS)
    {
	state->source.status = GLOBUS_I_GASS_COPY_TARGET_READY;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "ftp_setup_get(): SUCCESS opening %s\n",state->source.url);
    }
    else
    {
	fprintf(stderr, "ftp_setup_get(): FAILURE opening %s\n",state->source.url);
#endif
    }

    return result;
    
} /* globus_l_gass_copy_ftp_setup_get() */

globus_result_t
globus_l_gass_copy_ftp_setup_put(
    globus_gass_copy_handle_t * handle)
{
    globus_gass_copy_state_t * state = handle->state;
    globus_result_t result;

    result = globus_ftp_client_put(
	&(handle->ftp_handle),
	state->dest.url,
	state->dest.attr.ftp_attr,
	GLOBUS_NULL,
	globus_l_gass_copy_ftp_put_done_callback,
	(void *) handle);
    
    if(result==GLOBUS_SUCCESS)
    {
	state->dest.status = GLOBUS_I_GASS_COPY_TARGET_READY;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "ftp_setup_put(): SUCCESS opening %s\n",state->dest.url);
    }
    else
    {
	fprintf(stderr, "ftp_setup_put(): FAILURE opening %s\n",state->dest.url);
#endif
    }

    return result;
  
} /* globus_l_gass_copy_ftp_setup_put() */



void
globus_l_gass_copy_ftp_transfer_callback(
    void *			       user_arg,
    globus_ftp_client_handle_t *       handle,
    globus_object_t *		       error)
{
    globus_gass_copy_handle_t * copy_handle
	= (globus_gass_copy_handle_t *) user_arg;

#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "ftp_transfer_callback(): called\n");
#endif

    if(error != GLOBUS_SUCCESS)
    {
	/* do some error handling */
	/*
	  copy_handle->err = globus_copy_error(error);
	  */
	copy_handle->err = error;

#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "ftp_transfer_callback(): !GLOBUS_SUCESS, error= %d\n", error);
    }
    else
    {
	fprintf(stderr, "ftp_transfer_callback(): GLOBUS_SUCCESS\n");
#endif
    }
    
    globus_l_gass_copy_state_free(copy_handle->state);
    copy_handle->state = GLOBUS_NULL;

#ifdef GLOBUS_I_GASS_COPY_DEBUG
    if(copy_handle->state == GLOBUS_NULL)
	fprintf(stderr, "copy_handle->state == GLOBUS_NULL\n");
    fprintf(stderr, "ftp_transfer_callback(): about to call user callback\n");
#endif
    if(copy_handle->user_callback != GLOBUS_NULL)
	copy_handle->user_callback(
	    copy_handle->callback_arg,
	    copy_handle,
	    copy_handle->err);
    
} /* globus_l_gass_copy_ftp_transfer_callback() */

void
globus_l_gass_copy_ftp_get_done_callback(
    void * callback_arg,
    globus_ftp_client_handle_t * handle,
    globus_object_t *	       error)
{
    globus_gass_copy_handle_t * copy_handle
	= (globus_gass_copy_handle_t *) callback_arg;
    globus_i_gass_copy_monitor_t * source_monitor
	= &(copy_handle->state->source.data.ftp.monitor);
    
    globus_mutex_lock(&(source_monitor->mutex));
    if (error != GLOBUS_SUCCESS)
    {
	/* FIXX - do some error handling */
	globus_i_gass_copy_set_error(copy_handle, error);
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "ftp_get_done_callback(): !!!GLOBUS_SUCCESS\n");
    }
    else
    {
	fprintf(stderr, "ftp_get_done_callback(): called with GLOBUS_SUCCESS\n");
#endif
    }

    source_monitor->done = GLOBUS_TRUE;
    globus_cond_signal(&(source_monitor->cond));
    globus_mutex_unlock(&(source_monitor->mutex));
    
    /*  FIXX -  not sure what should happen here
	globus_mutex_lock(&state->monitor.mutex);
	done = 1;
	globus_cond_signal(&state->monitor.cond);
	globus_mutex_unlock(&state->monitor.mutex);
	*/
} /* globus_l_gass_copy_ftp_get_done_callback() */

void
globus_l_gass_copy_ftp_put_done_callback(
    void * callback_arg,
    globus_ftp_client_handle_t * handle,
    globus_object_t *	       error)
{
    globus_gass_copy_handle_t * copy_handle
	= (globus_gass_copy_handle_t *) callback_arg;
    globus_i_gass_copy_monitor_t * dest_monitor
	= &(copy_handle->state->dest.data.ftp.monitor);
    
    globus_mutex_lock(&(dest_monitor->mutex));
    if (error != GLOBUS_SUCCESS)
    {
	globus_i_gass_copy_set_error(copy_handle, error);
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "ftp_put_done_callback(): !!!GLOBUS_SUCCESS\n");
    }
    else
    {
	fprintf(stderr, "ftp_put_done_callback(): called with GLOBUS_SUCCESS\n");
#endif
    }

    dest_monitor->done = GLOBUS_TRUE;
    globus_cond_signal(&(dest_monitor->cond));
    globus_mutex_unlock(&(dest_monitor->mutex));
    
    /*  FIXX -  not sure what should happen here
	globus_mutex_lock(&state->monitor.mutex);
	state->monitor.done = 1;
	globus_cond_signal(&state->monitor.cond);
	globus_mutex_unlock(&state->monitor.mutex);
	*/
} /* globus_l_gass_copy_ftp_put_done_callback() */


/*****************************************************************
 * read callbacks
 *****************************************************************/

void
globus_l_gass_copy_generic_read_callback(
    globus_gass_copy_handle_t *    handle,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_size_t                   offset,
    globus_bool_t                   last_data)
{
    globus_gass_copy_state_t *    state = handle->state;
    globus_i_gass_copy_buffer_t *  buffer_entry;
    globus_object_t * err;
    static char * myname="globus_l_gass_copy_generic_read_callback";
    
#ifdef GLOBUS_I_GASS_COPY_DEBUG   
    fprintf(stderr, "generic_read_callback(): read %d bytes\n", nbytes);
#endif   
    globus_mutex_lock(&(state->source.mutex));
    state->source.n_pending--;
    if(state->source.cancel == GLOBUS_I_GASS_COPY_CANCEL_TRUE)
    {
	/*  move this to the cancel function 
	    state->source.cancel = GLOBUS_I_GASS_COPY_CANCEL_CALLED;
	    */
	globus_mutex_unlock(&(state->source.mutex));
#ifdef GLOBUS_I_GASS_COPY_DEBUG   
	fprintf(stderr, "generic_read_callback(): there was an error, call cancel\n");
#endif
	/* FIXX -- globus_gass_copy_cancel() */
	return;
    }
    globus_mutex_unlock(&(state->source.mutex));

    /* if this buffer has anything in it, or itwill be the last write (eof)
     * put it in the write queue
     */
    
    if(nbytes >0 || last_data)
    {
	buffer_entry = (globus_i_gass_copy_buffer_t *)
	    globus_libc_malloc(sizeof(globus_i_gass_copy_buffer_t));

	if(buffer_entry == GLOBUS_NULL)
	{
	    /* out of memory error */
	    err = globus_error_construct_string(
		GLOBUS_GASS_COPY_MODULE,
		GLOBUS_NULL,
		"[%s]: failed to malloc a buffer structure successfully",
		myname);
	    globus_i_gass_copy_set_error(handle, err);

#ifdef GLOBUS_I_GASS_COPY_DEBUG
	    fprintf(stderr, "generic_read_callback():  out of memory error, gonna call globus_gass_copy_cancel()\n");
#endif
	    /* FIXX -- call globus_gass_copy_cancel() */
	    return;
	}
      
	buffer_entry->bytes  = bytes;
	buffer_entry->nbytes = nbytes;
	buffer_entry->offset = offset;
	buffer_entry->last_data = last_data;
      
	globus_mutex_lock(&(state->dest.mutex));
	{
	    /* put this read buffer entry onto the write queue */
	    globus_fifo_enqueue( &(state->dest.queue), buffer_entry);
	}
	globus_mutex_unlock(&(state->dest.mutex));

    } /* if(nbytes >0) */
    
    /* start the next write if there isn't already one outstanding */
    if(handle->state)
	globus_l_gass_copy_write_from_queue(handle);
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    else
	fprintf(stderr, "generic_read_callback(): handle->state == GLOBUS_NULL\n");
#endif

    /* if we haven't read everything from the source, read again */
    if(handle->state)
	globus_l_gass_copy_read_from_queue(handle);
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    else
	fprintf(stderr, "generic_read_callback(): handle->state == GLOBUS_NULL\n");
#endif

} /* globus_l_gass_copy_generic_read_callback() */


void
globus_l_gass_copy_ftp_read_callback(
    void *                          callback_arg,
    globus_ftp_client_handle_t *    handle,
    globus_object_t *               error,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_size_t                   offset,
    globus_bool_t		    eof)
{
    globus_gass_copy_handle_t * copy_handle
	= (globus_gass_copy_handle_t *) callback_arg;
    globus_gass_copy_state_t * state
        = copy_handle->state;
 
    globus_bool_t last_data;

#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "ftp_read_callback(): has been called\n");
#endif

    if(error == GLOBUS_SUCCESS) /* no error occured */
    {
	last_data = eof;
	if(eof)
	{    
	    globus_mutex_lock(&(state->source.mutex));
	    {
		state->source.status = GLOBUS_I_GASS_COPY_TARGET_DONE;
	    }
	    globus_mutex_unlock(&(state->source.mutex));
	    if((copy_handle->status != GLOBUS_GASS_COPY_STATUS_FAILURE) &&
	       (copy_handle->status < GLOBUS_GASS_COPY_STATUS_READ_COMPLETE))
		copy_handle->status = GLOBUS_GASS_COPY_STATUS_READ_COMPLETE;
	}
    }
    else /* there was an error */
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "ftp_read_callback: was passed an ERROR\n");
#endif
	globus_mutex_lock(&(state->source.mutex));
	{
	    if(!state->source.cancel) /* cancel has not been set already */
	    {
		globus_i_gass_copy_set_error(copy_handle, error);
		state->source.cancel = GLOBUS_I_GASS_COPY_CANCEL_TRUE;
		copy_handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	    }
	    else
	    {
		state->source.n_pending--;
		globus_mutex_unlock(&(state->source.mutex));
		return;
	    }
	    
	}
	globus_mutex_unlock(&(state->source.mutex));
    } /* else (there was an error) */

    
    globus_l_gass_copy_generic_read_callback(
        copy_handle,
        bytes,
        nbytes,
        offset,
	last_data);
} /* globus_l_gass_copy_ftp_read_callback() */

void
globus_l_gass_copy_gass_read_callback(
    void *                          callback_arg,
    globus_gass_transfer_request_t  request,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_bool_t                   last_data)
{
    globus_size_t offset;
    int req_status;
    globus_object_t * err;
    static char * myname="globus_l_gass_copy_gass_read_callback";
    
    globus_gass_copy_handle_t * handle
	= (globus_gass_copy_handle_t *) callback_arg;
    globus_gass_copy_state_t * state = handle->state;
    req_status = globus_gass_transfer_request_get_status(request);
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "globus_l_gass_copy_gass_read_callback(): req_status= %d\n", req_status);
#endif

    if(req_status == GLOBUS_GASS_TRANSFER_REQUEST_DONE ||
       req_status == GLOBUS_GASS_TRANSFER_REQUEST_PENDING)
    { /* all is well */
	if(last_data)
	{ /* this was the last read.  set READ_COMPLETE and free the request */

	    globus_mutex_lock(&(state->source.mutex));
	    {
		state->source.status = GLOBUS_I_GASS_COPY_TARGET_DONE;
	    }
	    globus_mutex_unlock(&(state->source.mutex));
	    handle->status = GLOBUS_GASS_COPY_STATUS_READ_COMPLETE;

/*	req_status = globus_gass_transfer_request_get_status(request); */
	    if(req_status == GLOBUS_GASS_TRANSFER_REQUEST_DONE)
	    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
		fprintf(stderr, "gass_read_callback(): GLOBUS_GASS_TRANSFER_REQUEST_DONE\n");
#endif
		globus_gass_transfer_request_destroy(request);
	    }
	    else
	    {
		/* there's an error, tell someone who cares */
#ifdef GLOBUS_I_GASS_COPY_DEBUG
		fprintf(stderr, "gass_read_callback(): this was last_data, but status !=GLOBUS_GASS_TRANSFER_REQUEST_DONE\n");
#endif
	    }
	}/* if(last_data) */

    } /* all is well */
    else
    { /* all is NOT well, deal with error */
	globus_mutex_lock(&(state->source.mutex));
	{
	    if(!state->source.cancel) /* cancel has not been set already */
	    {
		err = globus_error_construct_string(
		    GLOBUS_GASS_COPY_MODULE,
		    GLOBUS_NULL,
		    "[%s]: gass_transfer_request_status: %d",
		    myname,
		    req_status);
		globus_i_gass_copy_set_error(handle, err);
		state->source.cancel = GLOBUS_I_GASS_COPY_CANCEL_TRUE;
		handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	    }
	    else
	    {
		state->source.n_pending--;
		globus_mutex_unlock(&(state->source.mutex));
		return;
	    }
	}
	globus_mutex_unlock(&(state->source.mutex));
    } /* else (there was an error) */

    offset = state->source.n_complete * handle->buffer_length;
    globus_l_gass_copy_generic_read_callback(
        handle,
        bytes,
        nbytes,
        offset,
	last_data);
    state->source.n_complete++;
} /* globus_l_gass_copy_gass_read_callback() */

void
globus_l_gass_copy_io_read_callback(
    void *                          callback_arg,
    globus_io_handle_t *            io_handle,
    globus_result_t                 result,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes)
{
    globus_size_t offset;
    globus_object_t * err = GLOBUS_NULL;
    globus_bool_t last_data=GLOBUS_FALSE;
    globus_gass_copy_handle_t * handle
	= (globus_gass_copy_handle_t *) callback_arg;
    globus_gass_copy_state_t * state = handle->state;
   
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    if(result== GLOBUS_SUCCESS)
	fprintf(stderr, "io_read_callback(): result == GLOBUS_SUCCESS\n");
    else
	fprintf(stderr, "io_read_callback(): result != GLOBUS_SUCCESS\n");
    
    fprintf(stderr, "io_read_callback(): %d bytes READ\n", nbytes);
#endif
    
    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);
	last_data=globus_io_eof(err);
      
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "io_read_callback(): last_data == %d\n", last_data);
#endif
	if(last_data)
	{ /* this was the last read.  set READ_COMPLETE */
	    int rc;
	    globus_mutex_lock(&(state->source.mutex));
	    {
		state->source.status = GLOBUS_I_GASS_COPY_TARGET_DONE;
	    }
	    globus_mutex_unlock(&(state->source.mutex));
	    handle->status = GLOBUS_GASS_COPY_STATUS_READ_COMPLETE;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	    fprintf(stderr, "io_read_callback(): this was the last READ, source.status == GLOBUS_I_GASS_COPY_TARGET_DONE\n");
#endif
	    if(state->source.data.io.free_handle)
	    {
		globus_io_close(io_handle);
#ifdef GLOBUS_I_GASS_COPY_DEBUG
		fprintf(stderr, "io_read_callback(): handle closed\n");
#endif
		/*   thinking that this should go in the globus_l_gass_copy_state_free()
		     globus_libc_free(handle);
		     */
	    }	    	    
	}/* if(last_data) */
	else  /* there was an error */
	{
	    globus_mutex_lock(&(state->source.mutex));
	    {
		if(!state->source.cancel) /* cancel has not been set already */
		{
		    globus_i_gass_copy_set_error(handle, err);
		    state->source.cancel = GLOBUS_I_GASS_COPY_CANCEL_TRUE;
		    handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
		}
		else
		{
		    state->source.n_pending--;
		    globus_mutex_unlock(&(state->source.mutex));
		    return;
		}
		
	    }
	    globus_mutex_unlock(&(state->source.mutex));
	} /* else (there was an error) */
    }
    
    offset = state->source.n_complete * handle->buffer_length;
    globus_l_gass_copy_generic_read_callback(
        handle,
        bytes,
        nbytes,
        offset,
	last_data);
    state->source.n_complete++;
} /* globus_l_gass_copy_io_read_callback() */


/*****************************************************************
 * write callbacks
 *****************************************************************/

void
globus_l_gass_copy_generic_write_callback(
    globus_gass_copy_handle_t *    handle,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_size_t                   offset)
{
    globus_gass_copy_state_t * state = handle->state;
    globus_i_gass_copy_buffer_t *  buffer_entry;
    globus_object_t * err;
    static char * myname="globus_l_gass_copy_generic_write_callback";
    
    globus_mutex_lock(&(state->dest.mutex));
    state->dest.n_pending--;
    if(state->dest.cancel == GLOBUS_I_GASS_COPY_CANCEL_TRUE)
    {
	globus_mutex_unlock(&(state->dest.mutex));
#ifdef GLOBUS_I_GASS_COPY_DEBUG   
	fprintf(stderr, "generic_write_callback(): there was an error, call cancel\n");
#endif
	/* globus_gass_copy_cancel() */
	return;
    }
    
    globus_mutex_unlock(&(state->dest.mutex));

#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "generic_write_callback(): wrote %d bytes\n", nbytes);
#endif
    /* push the buffer on the read queue and start another read */
    
    buffer_entry = (globus_i_gass_copy_buffer_t *)
	globus_libc_malloc(sizeof(globus_i_gass_copy_buffer_t));

    if(buffer_entry == GLOBUS_NULL)
    {
	/* out of memory error */
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: failed to malloc a buffer structure successfully",
	    myname);
	globus_i_gass_copy_set_error(handle, err);
	
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "generic_write_callback():  out of memory error, gonna call globus_gass_copy_cancel()\n");
#endif
	/* FIXX -- call globus_gass_copy_cancel() */
	return;
    }
      
    
    buffer_entry->bytes  = bytes;
    globus_mutex_lock(&(state->source.mutex));
    globus_fifo_enqueue( &(state->source.queue), buffer_entry);
    globus_mutex_unlock(&(state->source.mutex));
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "generic_write_callback(): calling read_from_queue()\n");
#endif
    if(handle->state)
	globus_l_gass_copy_read_from_queue(handle);
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    else
	fprintf(stderr, "generic_write_callback(): handle->state == GLOBUS_NULL\n");
#endif
	
	
    /* if there are more writes to do, register the next write */
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "generic_write_callback(): calling write_from_queue()\n");
#endif
    if(handle->state)
	globus_l_gass_copy_write_from_queue(handle);
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    else
	fprintf(stderr, "generic_write_callback(): handle->state == GLOBUS_NULL\n");
#endif

} /* globus_l_gass_copy_generic_write_callback() */

void
globus_l_gass_copy_write_from_queue(
    globus_gass_copy_handle_t * handle)
{
    globus_gass_copy_state_t * state = handle->state;
    globus_i_gass_copy_buffer_t *  buffer_entry;
    globus_result_t result = GLOBUS_SUCCESS;
    globus_object_t * err;
    static char * myname="globus_l_gass_copy_write_from_queue";
  
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "globus_l_gass_copy_write_from_queue(): called\n");
#endif
   
    globus_mutex_lock(&(state->dest.mutex));

    /* if the dest is READY (and not DONE), see if we should register a write
     */
    if(state->dest.status == GLOBUS_I_GASS_COPY_TARGET_READY)
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "write_from_queue(): dest.status == TARGET_READY, n_pending= %d,  n_simultaneous= %d\n", state->dest.n_pending, state->dest.n_simultaneous);
#endif
  
	/*  FIXX --
	 *  this needs to be a while loop, so that ftp can take advantage of
	 *  multiple channels
	 */
	/*
	 * if there aren't too many writes pending.  check the write queue,
	 * and if there is one then register the first one to write.
	 */
	if((state->dest.n_pending < state->dest.n_simultaneous) &&
	   !state->dest.cancel)
	{
	    if ((buffer_entry = globus_fifo_dequeue(&(state->dest.queue)))
		!= GLOBUS_NULL)
	    {
		state->dest.n_pending++;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
		fprintf(stderr, "write_from_queue(): about to call register_write()\n");
#endif
		result = globus_l_gass_copy_register_write(
		    handle,
		    buffer_entry);
	    
	    }/* if (buffer_entry != GLOBUS_NULL) */

	    if (result != GLOBUS_SUCCESS)
	    {
		state->dest.cancel = GLOBUS_I_GASS_COPY_CANCEL_TRUE;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
		fprintf(stderr, "write_from_queue(): there was an ERROR trying to register a write\n");
#endif
	    }
	}  /* if (dest n_pending < n_simultaneous) */ 
    } /* if (dest _TARGET_READY) */

    if(result != GLOBUS_SUCCESS)
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "read_from_queue():  gonna call globus_gass_copy_cancel()\n");
#endif
	globus_mutex_unlock(&(state->dest.mutex));
	/* FIXX -- call globus_gass_copy_cancel() */
    }
    
/* if there are no writes to do, and no writes pending, clean up and call user's callback */
    if(state->source.status == GLOBUS_I_GASS_COPY_TARGET_DONE &&
       state->dest.status == GLOBUS_I_GASS_COPY_TARGET_DONE  )
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "write_from_queue(): source and dest status == TARGET_DONE\n");
#endif      
	if(state->dest.n_pending == 0 && state->source.n_pending == 0 )
	{ /* our work here is done */
	    handle->status =   GLOBUS_GASS_COPY_STATUS_DONE;	  
	}	
    }

    globus_mutex_unlock(&(state->dest.mutex));
    if(handle->status == GLOBUS_GASS_COPY_STATUS_DONE)
    {
	/* make sure we get the ftp callbacks, if any */
	globus_l_gass_copy_wait_for_ftp_callbacks(handle);
	/* do cleanup */
	
	globus_l_gass_copy_state_free(handle->state);
 
	handle->state = GLOBUS_NULL;

#ifdef GLOBUS_I_GASS_COPY_DEBUG
	if(handle->state == GLOBUS_NULL)
	    fprintf(stderr, "  handle->state == GLOBUS_NULL\n");
	fprintf(stderr, "write_from_queue(): about to call user callback\n");
#endif
	if(handle->user_callback != GLOBUS_NULL)
	    handle->user_callback(
		handle->callback_arg,
		handle,
		handle->err);
	/* if an error object was created, free it */
	if(handle->err != GLOBUS_NULL)
	    globus_libc_free(handle->err);
    }
} /* globus_l_gass_copy_write_from_queue() */

globus_result_t
globus_l_gass_copy_register_write(
    globus_gass_copy_handle_t * handle,
    globus_i_gass_copy_buffer_t * buffer_entry)
{
    globus_result_t result =GLOBUS_SUCCESS;
    globus_gass_copy_state_t * state = handle->state;
    int rc;
    globus_object_t * err;
    static char * myname="globus_l_gass_copy_register_write";
    
    switch (state->dest.mode)
    {
    case GLOBUS_GASS_COPY_URL_MODE_FTP:
	/* check the offset to see if its what we are expecting */
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "register_write():  calling globus_ftp_client_register_write()\n");
	fprintf(stderr, "                            nbytes= %d, offset= %d, last_data= %d\n", buffer_entry->nbytes,
		buffer_entry->offset,
		buffer_entry->last_data);
#endif	  
	result = globus_ftp_client_register_write(
	    &(handle->ftp_handle),
	    buffer_entry->bytes,
	    buffer_entry->nbytes,
	    buffer_entry->offset,
	    buffer_entry->last_data,
	    globus_l_gass_copy_ftp_write_callback,
	    (void *) handle);
	
	break;

    case GLOBUS_GASS_COPY_URL_MODE_GASS:
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "register_write(): send_bytes -- %d bytes (last_data==%d)\n", buffer_entry->nbytes, buffer_entry->last_data);
#endif
	/* check the offset to see if its what we are expecting */
	rc = globus_gass_transfer_send_bytes(
	    state->dest.data.gass.request,
	    buffer_entry->bytes,
	    buffer_entry->nbytes,
	    buffer_entry->last_data,
	    globus_l_gass_copy_gass_write_callback,
	    (void *) handle);

	if (rc != GLOBUS_SUCCESS)
	{
	    /* figure out what the error is, and pass it back through the result */
	    err = globus_error_construct_string(
		GLOBUS_GASS_COPY_MODULE,
		GLOBUS_NULL,
		"[%s]: globus_gass_transfer_send_bytes returned error code: %d",
		myname,
		rc);
	    globus_i_gass_copy_set_error(handle, err);
	    result = globus_error_put(handle->err);
	}
	else result = GLOBUS_SUCCESS;
	
	break;

    case GLOBUS_GASS_COPY_URL_MODE_IO:

	if (state->dest.data.io.seekable &&
	    state->source.mode == GLOBUS_GASS_COPY_URL_MODE_FTP)
	{
	    result = globus_io_file_seek(
		state->dest.data.io.handle,
		buffer_entry->offset,
		GLOBUS_IO_SEEK_SET);
	}

	if(result == GLOBUS_SUCCESS)
	{
	    result = globus_io_register_write(
		state->dest.data.io.handle,
		buffer_entry->bytes,
		buffer_entry->nbytes,
		globus_l_gass_copy_io_write_callback,
		(void *) handle);
	}
	
	break;
    }/* switch (state->dest.mode) */

    globus_libc_free(buffer_entry);

    return result;
}/* globus_l_gass_copy_register_write() */

void
globus_l_gass_copy_ftp_write_callback(
    void *                       callback_arg,
    globus_ftp_client_handle_t * handle, 
    globus_object_t *            error,
    globus_byte_t *              bytes,
    globus_size_t                nbytes,
    globus_size_t                offset,
    globus_bool_t		 eof)
{
    globus_gass_copy_handle_t * copy_handle
	= (globus_gass_copy_handle_t *) callback_arg;
    globus_gass_copy_state_t * state
        = copy_handle->state;

    globus_bool_t last_data;

#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "ftp_write_callback():  has been called, nbytes: %d\n", nbytes);
#endif

    if(error == GLOBUS_SUCCESS) /* no error occured */
    {
	last_data = eof;
	if(eof)
	{    
	    globus_mutex_lock(&(state->dest.mutex));
	    {
		state->dest.status = GLOBUS_I_GASS_COPY_TARGET_DONE;
	    }
	    globus_mutex_unlock(&(state->dest.mutex));
	    if((copy_handle->status != GLOBUS_GASS_COPY_STATUS_FAILURE) &&
	       (copy_handle->status < GLOBUS_GASS_COPY_STATUS_WRITE_COMPLETE))
		copy_handle->status = GLOBUS_GASS_COPY_STATUS_WRITE_COMPLETE;
	}
    }
    else /* there was an error */
    {
	globus_mutex_lock(&(state->dest.mutex));
	{
	    if(!state->dest.cancel) /* cancel has not been set already */
	    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
		fprintf(stderr, "ftp_write_callback(): there was an ERROR, throw cancel flag\n");
#endif
		globus_i_gass_copy_set_error(copy_handle, error);
		state->dest.cancel = GLOBUS_I_GASS_COPY_CANCEL_TRUE;
		copy_handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	    }
	    else
	    {
		state->dest.n_pending--;
		globus_mutex_unlock(&(state->dest.mutex));
		return;
	    }
	    
	}
	globus_mutex_unlock(&(state->dest.mutex));
    } /* else (there was an error) */
    
    globus_l_gass_copy_generic_write_callback(
        copy_handle,
        bytes,
        nbytes,
        offset);
} /* globus_l_gass_copy_ftp_write_callback() */


void
globus_l_gass_copy_gass_write_callback(
    void *                          callback_arg,
    globus_gass_transfer_request_t  request,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_bool_t                   last_data)
{
    int req_status;
    globus_object_t * err;
    static char * myname="globus_l_gass_copy_gass_write_callback";
    
    globus_gass_copy_handle_t * handle
	= (globus_gass_copy_handle_t *) callback_arg;
    globus_gass_copy_state_t * state = handle->state;
    
    req_status = globus_gass_transfer_request_get_status(request);
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "gass_write_callback(): last_data== %d, req_status= %d\n", last_data, req_status);
#endif

    if(req_status == GLOBUS_GASS_TRANSFER_REQUEST_DONE ||
       req_status == GLOBUS_GASS_TRANSFER_REQUEST_PENDING)
    { /* all is well */
	if(last_data)
	{ /* this was the last write.  set WRITE_COMPLETE and free the request */
	    int rc;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	    fprintf(stderr, "gass_write_callback(): THIS WAS THE LAST WRITE\n");
#endif
	    globus_mutex_lock(&(state->dest.mutex));
	    {
		state->dest.status = GLOBUS_I_GASS_COPY_TARGET_DONE;
	    }
	    globus_mutex_unlock(&(state->dest.mutex));
	    handle->status = GLOBUS_GASS_COPY_STATUS_WRITE_COMPLETE;
	
/*	rc = globus_gass_transfer_request_get_status(request); */
	    if(req_status == GLOBUS_GASS_TRANSFER_REQUEST_DONE)
	    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
		fprintf(stderr, "gass_write_callback(): GLOBUS_GASS_TRANSFER_REQUEST_DONE\n");
#endif
		globus_gass_transfer_request_destroy(request);
	    }
	    else
	    {
		/* there's an error, tell someone who cares */
#ifdef GLOBUS_I_GASS_COPY_DEBUG
		fprintf(stderr, "gass_write_callback(): this was last_data, but status !=GLOBUS_GASS_TRANSFER_REQUEST_DONE\n");
#endif
	    }
	} /* if (last_data) */
    } /*all is well */
    else
    { /* all is NOT well, deal with error */
	globus_mutex_lock(&(state->dest.mutex));
	{
	    if(!state->dest.cancel) /* cancel has not been set already */
	    {
		err = globus_error_construct_string(
		    GLOBUS_GASS_COPY_MODULE,
		    GLOBUS_NULL,
		    "[%s]: gass_transfer_request_status: %d",
		    myname,
		    req_status);
		globus_i_gass_copy_set_error(handle, err);
		state->dest.cancel = GLOBUS_I_GASS_COPY_CANCEL_TRUE;
		handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	    }
	    else
	    {
		state->dest.n_pending--;
		globus_mutex_unlock(&(state->dest.mutex));
		return;
	    }
	}
	globus_mutex_unlock(&(state->dest.mutex));
    } /* else (there was an error) */
	
    globus_l_gass_copy_generic_write_callback(
        handle,
        bytes,
        nbytes,
        0);
} /* globus_l_gass_copy_gass_write_callback() */
   
void
globus_l_gass_copy_io_write_callback(
    void *                callback_arg,
    globus_io_handle_t *  io_handle, 
    globus_result_t       result,
    globus_byte_t *       bytes,
    globus_size_t         nbytes)
{
    globus_gass_copy_handle_t * handle
	= (globus_gass_copy_handle_t *) callback_arg;
    globus_gass_copy_state_t * state = handle->state;


    if(result==GLOBUS_SUCCESS)
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "io_write_callback(): result == GLOBUS_SUCCESS\n");
#endif

	globus_mutex_lock(&(state->source.mutex));
	{    
	    if(state->source.status == GLOBUS_I_GASS_COPY_TARGET_DONE &&
	       state->source.n_pending == 0)
	    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
		fprintf(stderr, "io_write_callback(): THIS WAS THE LAST WRITE\n");
#endif
		globus_mutex_lock(&(state->dest.mutex));
		{
		    state->dest.status = GLOBUS_I_GASS_COPY_TARGET_DONE;
		}
		globus_mutex_unlock(&(state->dest.mutex));
		handle->status = GLOBUS_GASS_COPY_STATUS_WRITE_COMPLETE;

		if(state->dest.data.io.free_handle)
		{
		    globus_io_close(io_handle);
#ifdef GLOBUS_I_GASS_COPY_DEBUG
		    fprintf(stderr, "io_write_callback(): handle closed\n");
#endif
		}
	
	  
	    } /* end if last write */
	}
	globus_mutex_unlock(&(state->source.mutex));
    }
    else /* there was an error */
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "io_write_callback(): result != GLOBUS_SUCCESS\n");
#endif
	globus_mutex_lock(&(state->dest.mutex));
	{
	    if(!state->dest.cancel) /* cancel has not been set already */
	    {
		globus_i_gass_copy_set_error_from_result(handle, result);
		state->dest.cancel = GLOBUS_I_GASS_COPY_CANCEL_TRUE;
		handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	    }
	    else
	    {
		state->dest.n_pending--;
		globus_mutex_unlock(&(state->dest.mutex));
		return;
	    }
	}
	globus_mutex_unlock(&(state->dest.mutex));
    } /* else (there was an error) */
    
    globus_l_gass_copy_generic_write_callback(
        handle,
        bytes,
        nbytes,
        0);
} /* globus_l_gass_copy_io_write_callback() */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/************************************************************
 * Transfer functions (synchronous)
 ************************************************************/

/**
 * Transfer data from source URL to destination URL (blocking)
 *
 * @param handle
 *        The handle to perform the copy operation
 * @param source_url
 *        transfer data from this URL
 * @param source_attr
 *        Attributes describing how the transfer form the source should be done
 * @param dest_url
 *        transfer data to this URL
 * @param dest_attr
 *        Attributes describing how the transfer to the destination should be
 *        done
 *
 * @return
 *         This function returns GLOBUS_SUCCESS if the transfer was completed
 *         successfully, or a result pointing to an
 *         object of one of the the following error types:
 * @retval GLOBUS_GASS_COPY_ERROR_TYPE_NULL_PARAMETER
 *         The handle was equal to GLOBUS_NULL, so the transfer could not 
 *         processed.
 * @retval GLOBUS_GASS_COPY_ERROR_TYPE_next_error
 *         next error description
 *
 * @see globus_gass_copy_url_to_handle() globus_gass_copy_handle_to_url()
 */
globus_result_t
globus_gass_copy_url_to_url(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    globus_gass_copy_attr_t * source_attr,
    char * dest_url,
    globus_gass_copy_attr_t * dest_attr)
{
    globus_result_t result;
    globus_i_gass_copy_monitor_t        monitor;
    globus_object_t * err;
    int bad_param;
    static char * myname="globus_gass_copy_url_to_url";

    if(handle == GLOBUS_NULL)
    {
	bad_param = 1;
	goto error_exit;
    }
    if(source_url == GLOBUS_NULL)
    {
	bad_param = 2;
	goto error_exit;
    }
    if(dest_url == GLOBUS_NULL)
    {
	bad_param = 4;
	goto error_exit;    
    }
    
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;    
    monitor.err = GLOBUS_NULL;
    monitor.use_err = GLOBUS_FALSE;
           
    result = globus_gass_copy_register_url_to_url(
	handle,
	source_url,
	source_attr,
	dest_url,
	dest_attr,
	globus_l_gass_copy_monitor_callback,
	(void *) &monitor);

    if(result != GLOBUS_SUCCESS)
    {
	globus_mutex_destroy(&monitor.mutex);
	globus_cond_destroy(&monitor.cond);
	return(result);
    }
    /* wait on cond_wait() for completion */
    globus_mutex_lock(&monitor.mutex);
   
    while(!monitor.done)
    {
        globus_cond_wait(&monitor.cond, &monitor.mutex);
    }

    globus_mutex_unlock(&monitor.mutex);

    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    /* do some error checking
     */
    if(monitor.use_err)
    {
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	return globus_error_put(monitor.err);
    }
    else
    {
	return GLOBUS_SUCCESS;
    }
  
error_exit:
    if(handle)
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
    err = globus_error_construct_string(
	GLOBUS_GASS_COPY_MODULE,
	GLOBUS_NULL,
	"[%s]: BAD_PARAMETER, argument %d cannot be NULL",
	myname,
	bad_param);
    return globus_error_put(err);
     
} /* globus_gass_copy_url_to_url() */



/*****************************************************************
 * copy url to handle
 *****************************************************************/

/**
 * Transfer data from source URL to an IO handle (blocking)
 *
 * @param handle
 *        The handle to perform the copy operation
 * @param source_url
 *        transfer data from this URL
 * @param source_attr
 *        Attributes describing how the transfer form the source should be done
 * @param dest_handle
 *        transfer data to this IO handle
 * 
 *
 * @return
 *         This function returns GLOBUS_SUCCESS if the transfer was completed
 *         successfully, or a result pointing to an
 *         object of one of the the following error types:
 * @retval GLOBUS_GASS_COPY_ERROR_TYPE_NULL_PARAMETER
 *         The handle was equal to GLOBUS_NULL, so the transfer could not 
 *         processed.
 * @retval GLOBUS_GASS_COPY_ERROR_TYPE_next_error
 *         next error description
 *
 * @see globus_gass_copy_url_to_url() globus_gass_copy_handle_to_url()
 */
globus_result_t
globus_gass_copy_url_to_handle(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    globus_gass_copy_attr_t * source_attr,
    globus_io_handle_t * dest_handle)
{
    globus_result_t result;
    globus_i_gass_copy_monitor_t        monitor;
    globus_object_t * err;
    int bad_param;
    static char * myname="globus_gass_copy_url_to_handle";

    /* Check arguments for validity */
    if(handle == GLOBUS_NULL)
    {
	bad_param=1;
	goto error_exit;
    }
    if(source_url == GLOBUS_NULL)
    {
	bad_param=2;
	goto error_exit;
    }
    if(dest_handle == GLOBUS_NULL)
    {
	bad_param=4;
	goto error_exit;
    }
  
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.err = GLOBUS_NULL;
    monitor.use_err = GLOBUS_FALSE;
         
    result = globus_gass_copy_register_url_to_handle(
	handle,
	source_url,
	source_attr,
	dest_handle,
	globus_l_gass_copy_monitor_callback,
	(void *) &monitor);

    if(result != GLOBUS_SUCCESS)
    {
	globus_mutex_destroy(&monitor.mutex);
	globus_cond_destroy(&monitor.cond);
	return(result);
    }
  
    /* wait on cond_wait() for completion */
    globus_mutex_lock(&monitor.mutex);
  
    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
  
    globus_mutex_unlock(&monitor.mutex);

    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    /* do some error checking
     */
    
    if(monitor.use_err)
    {
	return globus_error_put(monitor.err);
    }
    else
    {
	return GLOBUS_SUCCESS;
    }
    
error_exit:
    if(handle)
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
    err = globus_error_construct_string(
	GLOBUS_GASS_COPY_MODULE,
	GLOBUS_NULL,
	"[%s]: BAD_PARAMETER, argument %d cannot be NULL",
	myname,
	bad_param);
    return globus_error_put(err);
    
} /* globus_gass_copy_url_to_handle() */


/**
 * Transfer data from an IO handle to destination URL  (blocking)
 *
 * @param handle
 *        The handle to perform the copy operation
 * @param source_handle
 *        transfer data from this IO handle
 * @param dest_url
 *        transfer data to this URL
 * @param dest_attr
 *        Attributes describing how the transfer to the destination should be done
 * 
 *
 * @return
 *         This function returns GLOBUS_SUCCESS if the transfer was completed
 *         successfully, or a result pointing to an
 *         object of one of the the following error types:
 * @retval GLOBUS_GASS_COPY_ERROR_TYPE_NULL_PARAMETER
 *         The handle was equal to GLOBUS_NULL, so the transfer could not 
 *         processed.
 * @retval GLOBUS_GASS_COPY_ERROR_TYPE_next_error
 *         next error description
 *
 * @see globus_gass_copy_url_to_url() globus_gass_copy_url_to_handle()
 */

globus_result_t
globus_gass_copy_handle_to_url(
    globus_gass_copy_handle_t * handle,
    globus_io_handle_t * source_handle,
    char * dest_url,
    globus_gass_copy_attr_t * dest_attr)
{
    globus_result_t result;
    globus_i_gass_copy_monitor_t        monitor;
    globus_object_t * err;
    int bad_param;
    static char * myname="globus_gass_copy_handle_to_url";

    /* Check arguments for validity */
    if(handle == GLOBUS_NULL)
    {
	bad_param=1;
	goto error_exit;
    }
    if(source_handle == GLOBUS_NULL)
    {
	bad_param=2;
	goto error_exit;
    }
    if(dest_url == GLOBUS_NULL)
    {
	bad_param=3;
	goto error_exit;
    }
    
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.err = GLOBUS_NULL;
    monitor.use_err = GLOBUS_FALSE;
    
    result = globus_gass_copy_register_handle_to_url(
	handle,
	source_handle,
	dest_url,
	dest_attr,    
	globus_l_gass_copy_monitor_callback,
	(void *) &monitor);

    if(result != GLOBUS_SUCCESS)
    {
	globus_mutex_destroy(&monitor.mutex);
	globus_cond_destroy(&monitor.cond);
	return(result);
    }
    /* wait on cond_wait() for completion */
    globus_mutex_lock(&monitor.mutex);
  
    while(!monitor.done)
    {
	globus_cond_wait(&monitor.cond, &monitor.mutex);
    }
  
    globus_mutex_unlock(&monitor.mutex);

    globus_mutex_destroy(&monitor.mutex);
    globus_cond_destroy(&monitor.cond);
    /* do some error checking
     */
    
    if(monitor.use_err)
    {
	return globus_error_put(monitor.err);
    }
    else
    {
	return GLOBUS_SUCCESS;
    }
    
error_exit:
    if(handle)
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
    err = globus_error_construct_string(
	GLOBUS_GASS_COPY_MODULE,
	GLOBUS_NULL,
	"[%s]: BAD_PARAMETER, argument %d cannot be NULL",
	myname,
	bad_param);
    return globus_error_put(err);
  
} /* globus_gass_copy_handle_to_url() */

/************************************************************
 * Transfer functions (asynchronous)
 ************************************************************/

/**
 * Transfer data from source URL to destination URL (non-blocking)
 *
 * This functions initiates a transfer from source URL to destination URL,
 * then returns immediately.
 *
 * When the transfer is completed or if the
 * transfer is aborted, the callback_func will be invoked with the final
 * status of the transfer.
 *
 * @param handle
 *        The handle to perform the copy operation
 * @param source_url
 *        transfer data from this URL
 * @param source_attr
 *        Attributes describing how the transfer form the source should be done
 * @param dest_url
 *        transfer data to this URL
 * @param dest_attr
 *        Attributes describing how the transfer to the destination should be
 *        done
 * @param callback_func
 *        Callback to be invoked once the transfer is completed.
 * @param callback_arg
 *        Argument to be passed to the callback_func.
 *
 * @return
 *         This function returns GLOBUS_SUCCESS if the transfer was initiated
 *         successfully, or a result pointing to an
 *         object of one of the the following error types:
 * @retval GLOBUS_GASS_COPY_ERROR_TYPE_NULL_PARAMETER
 *         The handle was equal to GLOBUS_NULL, so the transfer could not 
 *         processed.
 * @retval GLOBUS_GASS_COPY_ERROR_TYPE_next_error
 *         next error description
 *
 * @see globus_gass_copy_register_url_to_handle() globus_gass_copy_register_handle_to_url()
 */
globus_result_t
globus_gass_copy_register_url_to_url(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    globus_gass_copy_attr_t * source_attr,
    char * dest_url,
    globus_gass_copy_attr_t * dest_attr,
    globus_gass_copy_callback_t callback_func,
    void * callback_arg)
{
    globus_object_t * err = GLOBUS_ERROR_NO_INFO;
    globus_result_t result;
    globus_gass_copy_state_t * state;
    globus_gass_copy_url_mode_t source_url_mode;
    globus_gass_copy_url_mode_t dest_url_mode;
    int bad_param;
    static char * myname="globus_gass_copy_register_url_to_url";

    /* Check arguments for validity */
    if(handle == GLOBUS_NULL)
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "register_url_to_url(): handle was GLOBUS_NULL\n");
#endif
	bad_param = 1;
	goto error_exit;
    }
    if(source_url == GLOBUS_NULL)
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "register_url_to_url(): source_url  was GLOBUS_NULL\n");
#endif
	bad_param = 2;
	goto error_exit;
    }
    if(dest_url == GLOBUS_NULL)
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "register_url_to_url(): dest_url was GLOBUS_NULL\n");
#endif
	bad_param = 4;
	goto error_exit;    
    }
    
    result = globus_gass_copy_get_url_mode(
	source_url,
	&source_url_mode);
    if(result != GLOBUS_SUCCESS)
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "register_url_to_url(): copy_url_mode returned ! GLOBUS_SUCCESS for source_url\n");
#endif
	goto error_result_exit;
    }
    
    result = globus_gass_copy_get_url_mode(
	dest_url,
	&dest_url_mode);
    if(result != GLOBUS_SUCCESS)
    {
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "register_url_to_url(): copy_url_mode returned ! GLOBUS_SUCCESS for dest_url\n");
#endif	
	goto error_result_exit;
    }
    
    if (   (source_url_mode == GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED)
	   || (dest_url_mode == GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED) )
    {
	char src_msg[256];
	char dest_msg[256];
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	fprintf(stderr, "register_url_to_url(): source or dest is URL_MODE_UNSUPPORTED\n");
#endif
	if(source_url_mode == GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED)
	    sprintf(src_msg, "  %s,  GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED.",source_url);
	if(dest_url_mode == GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED)
	    sprintf(src_msg, "  %s,  GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED.",dest_url);
	
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: %s%s",
	    myname,
	    src_msg,
	    dest_msg);
	globus_i_gass_copy_set_error(handle, err);
	return globus_error_put(handle->err);
    }
    
    /* Initialize the state for this transfer */
    result = globus_l_gass_copy_state_new(handle);
    if(result != GLOBUS_SUCCESS) goto error_result_exit;
    
    state = handle->state;
    /*store the user's callback and argument */
    handle->user_callback = callback_func;
    handle->callback_arg = callback_arg;

    result = globus_l_gass_copy_target_populate(
	handle,
	&(state->source),
	&source_url_mode,
	source_url,
	source_attr);

    if(result != GLOBUS_SUCCESS) goto error_result_exit;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "source target populated\n");
#endif
    result = globus_l_gass_copy_target_populate(
	handle,
	&(state->dest),
	&dest_url_mode,
	dest_url,
	dest_attr);
    
    if(result != GLOBUS_SUCCESS) goto error_result_exit;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "dest target populated\n");
#endif
	
    if (   (source_url_mode == GLOBUS_GASS_COPY_URL_MODE_FTP)
	   && (dest_url_mode == GLOBUS_GASS_COPY_URL_MODE_FTP) )
    {
	
#ifdef GLOBUS_I_GASS_COPY_DEBUG
        fprintf(stderr, "calling globus_ftp_client_third_party_transfer()\n");
#endif
        result = globus_ftp_client_third_party_transfer(
	    &(handle->ftp_handle),
	    source_url,
	    state->source.attr.ftp_attr,
	    dest_url,
	    state->dest.attr.ftp_attr,
	    GLOBUS_NULL,
	    globus_l_gass_copy_ftp_transfer_callback,
	    (void *) handle);

	if (result != GLOBUS_SUCCESS)
	{
	    /* do some error handling */
#ifdef GLOBUS_I_GASS_COPY_DEBUG
	    fprintf(stderr, "third_party_transfer() was not GLOBUS_SUCCESS! it returned %d\n", result);
#endif
	    goto error_result_exit;
#ifdef GLOBUS_I_GASS_COPY_DEBUG	    
	}
	else
	{
	    fprintf(stderr, "third_party_transfer() returned GLOBUS_SUCCESS\n");
#endif
	}
    }
    else
    {
        /* At least one of the urls is not ftp, so we have to do the copy ourselves */

	result = globus_l_gass_copy_transfer_start(handle);
	if (result != GLOBUS_SUCCESS)
	{
	    goto error_result_exit;
	}
    }

    return GLOBUS_SUCCESS;

error_exit:
    if(handle)
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
    err = globus_error_construct_string(
	GLOBUS_GASS_COPY_MODULE,
	GLOBUS_NULL,
	"[%s]: BAD_PARAMETER, argument %d cannot be NULL",
	myname,
	bad_param);
    return globus_error_put(err);
 
error_result_exit:
    handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
    return result;
}/* globus_gass_copy_register_url_to_url() */

/**
 * Transfer data from source URL to an IO handle (non-blocking)
 *
 * This functions initiates a transfer from source URL to an IO handle,
 * then returns immediately.
 *
 * When the transfer is completed or if the
 * transfer is aborted, the callback_func will be invoked with the final
 * status of the transfer.
 *
 * @param handle
 *        The handle to perform the copy operation
 * @param source_url
 *        transfer data from this URL
 * @param source_attr
 *        Attributes describing how the transfer form the source should be done
 * @param dest_handle
 *        transfer data to this IO handle
 * @param callback_func
 *        Callback to be invoked once the transfer is completed.
 * @param callback_arg
 *        Argument to be passed to the callback_func.
 * 
 *
 * @return
 *         This function returns GLOBUS_SUCCESS if the transfer was initiated
 *         successfully, or a result pointing to an
 *         object of one of the the following error types:
 * @retval GLOBUS_GASS_COPY_ERROR_TYPE_NULL_PARAMETER
 *         The handle was equal to GLOBUS_NULL, so the transfer could not 
 *         processed.
 * @retval GLOBUS_GASS_COPY_ERROR_TYPE_next_error
 *         next error description
 *
 * @see globus_gass_copy_register_url_to_url() globus_gass_copy_register_handle_to_url()
 */

globus_result_t
globus_gass_copy_register_url_to_handle(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    globus_gass_copy_attr_t * source_attr,
    globus_io_handle_t * dest_handle,
    globus_gass_copy_callback_t callback_func,
    void * callback_arg)
{
    globus_object_t * err = GLOBUS_ERROR_NO_INFO;
    globus_result_t result;
    globus_gass_copy_state_t * state;
    globus_gass_copy_url_mode_t source_url_mode;
    int bad_param;
    static char * myname="globus_gass_copy_register_url_to_handle";
    
    /* Check arguments for validity */
    if(handle == GLOBUS_NULL)
    {
	bad_param=1;
	goto error_exit;
    }
    if(source_url == GLOBUS_NULL)
    {
	bad_param=2;
	goto error_exit;
    }
    if(dest_handle == GLOBUS_NULL)
    {
	bad_param=4;
	goto error_exit;
    }
    
    result = globus_gass_copy_get_url_mode(
	source_url,
	&source_url_mode);

    if(result != GLOBUS_SUCCESS) goto error_result_exit;
    
    if ( source_url_mode == GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED)      
    {
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: %s,  GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED",
	    myname,
	    source_url);
	globus_i_gass_copy_set_error(handle, err);
	return globus_error_put(handle->err);
    }

    /* Initialize the state for this transfer */
    result = globus_l_gass_copy_state_new(handle);
    if(result != GLOBUS_SUCCESS) goto error_result_exit;
    
    state = handle->state;
    /*store the user's callback and argument */
    handle->user_callback = callback_func;
    handle->callback_arg = callback_arg;

    result = globus_l_gass_copy_target_populate(
	handle,
	&(state->source),
	&source_url_mode,
	source_url,
	source_attr);
    if(result != GLOBUS_SUCCESS) goto error_result_exit;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "source target populated\n");
#endif
    result = globus_l_gass_copy_io_target_populate(
	handle,
	&(state->dest),
	dest_handle);
    if(result != GLOBUS_SUCCESS) goto error_result_exit;
    
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "dest target populated\n");
#endif
    
    result = globus_l_gass_copy_transfer_start(handle);
    if (result != GLOBUS_SUCCESS)
    {
	goto error_result_exit;
    }
    
    return GLOBUS_SUCCESS;

error_exit:
    if(handle)
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
    err = globus_error_construct_string(
	GLOBUS_GASS_COPY_MODULE,
	GLOBUS_NULL,
	"[%s]: BAD_PARAMETER, argument %d cannot be NULL",
	myname,
	bad_param);
    return globus_error_put(err);

error_result_exit:
    handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
    return result;
} /* globus_gass_copy_register_url_to_handle() */


/**
 * Transfer data from an IO handle to destination URL  (non-blocking)
 *
 * This functions initiates a transfer from an IO handle to destination URL,
 * then returns immediately.
 *
 * When the transfer is completed or if the
 * transfer is aborted, the callback_func will be invoked with the final
 * status of the transfer.
 *
 * @param handle
 *        The handle to perform the copy operation
 * @param source_handle
 *        transfer data from this IO handle
 * @param dest_url
 *        transfer data to this URL
 * @param dest_attr
 *        Attributes describing how the transfer to the destination should be done
 * @param callback_func
 *        Callback to be invoked once the transfer is completed.
 * @param callback_arg
 *        Argument to be passed to the callback_func.
 * 
 *
 * @return
 *         This function returns GLOBUS_SUCCESS if the transfer was initiated
 *         successfully, or a result pointing to an
 *         object of one of the the following error types:
 * @retval GLOBUS_GASS_COPY_ERROR_TYPE_NULL_PARAMETER
 *         The handle was equal to GLOBUS_NULL, so the transfer could not 
 *         processed.
 * @retval GLOBUS_GASS_COPY_ERROR_TYPE_next_error
 *         next error description
 *
 * @see globus_gass_copy_register_url_to_url() globus_gass_copy_register_url_to_handle()
 */
globus_result_t
globus_gass_copy_register_handle_to_url(
    globus_gass_copy_handle_t * handle,
    globus_io_handle_t * source_handle,
    char * dest_url,
    globus_gass_copy_attr_t * dest_attr,
    globus_gass_copy_callback_t callback_func,
    void * callback_arg)
{
    globus_object_t * err = GLOBUS_ERROR_NO_INFO;
    globus_result_t result;
    globus_gass_copy_state_t * state;
    globus_gass_copy_url_mode_t dest_url_mode;
    int bad_param;
    static char * myname="globus_gass_copy_register_handle_to_url";

    /* Check arguments for validity */
    if(handle == GLOBUS_NULL)
    {
	bad_param=1;
	goto error_exit;
    }
    if(source_handle == GLOBUS_NULL)
    {
	bad_param=2;
	goto error_exit;
    }
    if(dest_url == GLOBUS_NULL)
    {
	bad_param=3;
	goto error_exit;
    }
    
    result = globus_gass_copy_get_url_mode(
	dest_url,
	&dest_url_mode);
    if(result != GLOBUS_SUCCESS) goto error_result_exit;
    
    if ( dest_url_mode == GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED)      
    {
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: %s,  GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED",
	    myname,
	    dest_url);
	globus_i_gass_copy_set_error(handle, err);
	return globus_error_put(handle->err);
    }

    /* Initialize the state for this transfer */
    result = globus_l_gass_copy_state_new(handle);
    if(result != GLOBUS_SUCCESS) goto error_result_exit;
    
    state = handle->state;
    /*store the user's callback and argument */
    handle->user_callback = callback_func;
    handle->callback_arg = callback_arg;

    result = globus_l_gass_copy_io_target_populate(
	handle,
	&(state->source),
	source_handle);
    if(result != GLOBUS_SUCCESS) goto error_result_exit;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "source target populated\n");
#endif
    result = globus_l_gass_copy_target_populate(
	handle,
	&(state->dest),
	&dest_url_mode,
	dest_url,
	dest_attr);
    
    if(result != GLOBUS_SUCCESS) goto error_result_exit;
#ifdef GLOBUS_I_GASS_COPY_DEBUG
    fprintf(stderr, "dest target populated\n");
#endif
    result = globus_l_gass_copy_transfer_start(handle);
    if (result != GLOBUS_SUCCESS)
    {
	goto error_result_exit;
    }

    return GLOBUS_SUCCESS;

error_exit:
    if(handle)
	handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
    err = globus_error_construct_string(
	GLOBUS_GASS_COPY_MODULE,
	GLOBUS_NULL,
	"[%s]: BAD_PARAMETER, argument %d cannot be NULL",
	myname,
	bad_param);
    return globus_error_put(err);
error_result_exit:
    handle->status = GLOBUS_GASS_COPY_STATUS_FAILURE;
    return result;
} /* globus_gass_copy_register_handle_to_url */

/************************************************************
 * Caching url state
 ************************************************************/

/**
 * Cache connections to an FTP or GSIFTP server.
 *
 * Explicitly cache connections to URL server. When
 * an URL is cached, the connection
 * to the URL server will not be closed after a file transfer completes.
 *
 * @param handle
 *        Handle which will contain a cached connection to the URL server.
 * @param url
 *        The URL of the FTP or GSIFTP server to cache.
 */
globus_result_t
globus_gass_copy_cache_url_state(
    globus_gass_copy_handle_t * handle,
    char * url)
{
    globus_result_t result;
    globus_url_t url_info;
    globus_object_t * err;
    static char * myname="globus_gass_copy_cache_url_state";

    if(handle != GLOBUS_NULL)
    {
	globus_url_parse(url, &url_info);
	if (   (strcmp(url_info.scheme, "ftp") == 0)
	       || (strcmp(url_info.scheme, "gsiftp") == 0)    )
	{
	    result = globus_ftp_client_handle_cache_url_state(
		&handle->ftp_handle,
		url);
	}
	else
	{
	    err = globus_error_construct_string(
		GLOBUS_GASS_COPY_MODULE,
		GLOBUS_NULL,
		"[%s]: BAD_URL_SCHEME, url: %s, only ftp or gsiftp can be cached",
		myname,
		url);
	    return globus_error_put(err);
	}
    }
    else
    { /* handle == GLOBUS_NULL */
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: BAD_PARAMETER, handle is NULL",
	    myname);
	return globus_error_put(err);
    }
    
    return result;

} /* globus_gass_copy_cache_url_state() */

/**
 * Remove a cached connection to an FTP or GSIFTP server.
 *
 * Explicitly remove a cached connection to an FTP or GSIFTP server.
 * If an idle connection to an FTP server exists, it will be closed.
 *
 * @param handle
 *        Handle which contains a cached connection to the URL server.
 * @param url
 *        The URL of the FTP or GSIFTP server to remove.
 */
globus_result_t
globus_gass_copy_flush_url_state(
    globus_gass_copy_handle_t * handle,
    char * url)
{
    globus_result_t result;
    globus_url_t url_info;
    globus_object_t * err;
    static char * myname="globus_gass_copy_flush_url_state";

    if(handle != GLOBUS_NULL)
    {
	globus_url_parse(url, &url_info);
	if (   (strcmp(url_info.scheme, "ftp") == 0)
	       || (strcmp(url_info.scheme, "gsiftp") == 0)    )
	{
	    result = globus_ftp_client_handle_flush_url_state(
		&handle->ftp_handle,
		url);
	}
	else
	{
	    err = globus_error_construct_string(
		GLOBUS_GASS_COPY_MODULE,
		GLOBUS_NULL,
		"[%s]: BAD_URL_SCHEME, url: %s, only ftp or gsiftp can be cached",
		myname,
		url);
	    return globus_error_put(err);
	}
    }
    else
    { /* handle == GLOBUS_NULL */
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: BAD_PARAMETER, handle is NULL",
	    myname);
	return globus_error_put(err);
    }
    
    return result;
} /* globus_gass_copy_flush_url_state() */


/************************************************************
 * User pointers on handles
 ************************************************************/

/**
 * Set a pointer in the handle to point at user-allocated memory.
 */
globus_result_t
globus_gass_copy_set_user_pointer(
    globus_gass_copy_handle_t * handle,
    void * user_pointer)
{
    globus_object_t *err;
    static char * myname="globus_gass_copy_set_user_pointer";
    
    if(handle)
    {
	handle->user_pointer = user_pointer;
	return GLOBUS_SUCCESS;
    }
    else
    {
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: BAD_PARAMETER, handle is NULL",
	    myname);
	return globus_error_put(err);
    }
} /* globus_gass_copy_set_user_pointer() */

/**
 * Get the pointer in the handle that points to user-allocated memory.
 */
globus_result_t
globus_gass_copy_get_user_pointer(
    globus_gass_copy_handle_t * handle,
    void * user_data)
{
    globus_object_t *err;
    static char * myname="globus_gass_copy_get_user_pointer";
    
    if (handle)
    {
	user_data = handle->user_pointer;
	return GLOBUS_SUCCESS;
    }
    else
    {
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: BAD_PARAMETER, handle is NULL",
	    myname);
	return globus_error_put(err);
    }
}

/**
 * Cancel the current transfer associated with this handle, *NOT YET IMPLEMENTED*
 */
globus_result_t
globus_gass_copy_cancel(
     globus_gass_copy_handle_t * handle,
     globus_gass_copy_callback_t cancel_callback,
     void * cancel_callback_arg)
{
/*
  store the cancel_callback and cancel_callback_arg in the handle.

  if it's a third_party_transfer(), call the ftp_client cancel with a gass_l_gass_copy callback, which calls the user's cancel_callback.

  or
  
  call a cancel_target() function for both source and dest.  which should each call a register_fail (or somesuch)  for the
  underlying protocol.

  add a cancel_complete bool to the target structure.

  make a cancel_struct_t which contains the handle and a flag saying whether it was called from the soure or dest?  so that the
  globus_l_gass_copy_cancel_callback (probably need a protocol specific (because of different footprints) and a generic one)
  knows which one to set as complete.  then checks to see if the other is also complete.  if not, end.
  if so, call the copy_state_free(), the cancel_callback(), and the user_callback().  free th error object after calling user_callback.

  */
  
}

/************************************************************
 * Attributes
 ************************************************************/
#ifdef USE_FTP
/**
 * Set TCP buffer/window size
 */
globus_result_t
globus_gass_copy_attr_set_tcpbuffer(
    globus_gass_copy_attr_t * attr,
    globus_ftp_control_tcpbuffer_t * tcpbuffer_info)
{

/* how should we set errors */

    if (attr == GLOBUS_NULL)
        return GLOBUS_GASS_COPY_ERROR_NULL_ATTR;

    if (attr == GLOBUS_NULL)
        return GLOBUS_GASS_COPY_ERROR_NULL_TCPBUFFER;

/* or */

    if (attr == GLOBUS_NULL)
    {
        return globus_error_put(
           globus_gass_copy_error_construct_null_parameter(
              GLOBUS_GASS_COPY_MODULE,
              GLOBUS_NULL,
              "attr",
              1,
              "globus_gass_copy_attr_set_tcpbuffer");
    }

    if (tcpbuffer_info == GLOBUS_NULL)
    {
        return globus_error_put(
           globus_gass_copy_error_construct_null_parameter(
              GLOBUS_GASS_COPY_MODULE,
              GLOBUS_NULL,
              "tcpbuffer_info",
              2,
              "globus_gass_copy_attr_set_tcpbuffer");
    }

    attr->tcpbuffer_info = *tcpbuffer_info;
}

/**
 * Set parallelism info
 */
globus_result_t
globus_gass_copy_attr_set_parallelism(
    globus_gass_copy_attr_t * attr,
    globus_ftp_control_parallelism_t * parallelism_info)
{
    attr->parallel_info = *parallel_info;
}

/**
 * Set striping info
 */
globus_result_t
globus_gass_copy_attr_set_striping(
    globus_gass_copy_attr_t * attr,
    globus_ftp_control_striping_t * striping_info)
{
    attr->striping_info = *striping_info;
}

/**
 * Set authorization info
 */
globus_result_t
globus_gass_copy_attr_set_authorization(
    globus_gass_copy_attr_t * attr,
    globus_io_authorization_t * authorization_info)
{
    attr->authorization_info = *authorization_info;
}
    
/**
 * Set secure channel info
 */
globus_result_t
globus_gass_copy_attr_set_secure_channel(
    globus_gass_copy_attr_t * attr,
    globus_io_secure_channel_t * secure_channel_info)
{
    attr->secure_channel_info = *secure_channel_info;
}

#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Duplicate the passed in attribute structure. 
 */
globus_result_t
globus_i_gass_copy_attr_duplicate(globus_gass_copy_attr_t ** attr)
{
    globus_gass_copy_attr_t * new_attr;
    globus_object_t * err;
    static char * myname="globus_i_gass_copy_attr_duplicate";
    
    if ( (attr == GLOBUS_NULL) || (*attr == GLOBUS_NULL) )
    {
	err = globus_error_construct_string(
	    GLOBUS_GASS_COPY_MODULE,
	    GLOBUS_NULL,
	    "[%s]: BAD_PARAMETER, attr==GLOBUS_NULL, or *attr==GLOBUS_NULL",
	    myname);
	  
	return globus_error_put(err);
    }

    new_attr = (globus_gass_copy_attr_t *)
	globus_libc_malloc(sizeof(globus_gass_copy_attr_t));
    new_attr = *attr;
    *attr = new_attr;

    return GLOBUS_SUCCESS;
} /* globus_i_gass_copy_attr_duplicate */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */
/************************************************************
 * Example
 ************************************************************

globus_gass_copy_t handle;
globus_gass_copy_init(&handle);
globus_gass_copy_cache_url_state(
    &handle,
    "gsiftp://pitcairn.mcs.anl.gov/");
globus_gass_copy_url_to_url(
    &handle,
    "gsiftp://pitcairn.mcs.anl.gov/tmp/foo",
    "gsiftp://lemon.mcs.anl.gov/tmp/foo");
globus_gass_copy_url_to_url(
    &handle,
    "gsiftp://pitcairn.mcs.anl.gov/tmp/foo",
    "gsiftp://tuva.mcs.anl.gov/tmp/foo");
globus_gass_copy_url_to_url(
    &handle,
    "gsiftp://pitcairn.mcs.anl.gov/tmp/foo",
    "http://tuva.mcs.anl.gov/tmp/foo");
globus_gass_copy_url_to_iohandle(
    &handle,
    "gsiftp://pitcairn.mcs.anl.gov/tmp/foo",
    io_handle);
globus_gass_copy_destroy(&handle);

*/

/************************************************************
 * Example Attributes
 ************************************************************

globus_io_authorization_t a;
globus_io_authorization_t b;

a.mode = GLOBUS_IO_AUTHORIZATION_MODE_IDENTITY;
strcpy(a.data.identity.subject, "foo");

globus_gass_copy_attr_set_authorization(attr, &a); 
globus_gass_copy_attr_get_authorization(attr, &b);

b.mode = ...

globus_gass_copy_attr_set_authorization(attr2, &b);

typedef struct globus_gass_copy_attr_s
{
    globus_io_authorization_t a;
    ...
} globus_gass_copy_attr_t;

*/

/*
globus_gass_copy_t handle;
globus_gass_copy_init(&handle);

globus_gass_copy_attribute_setup_ftp(handle, ftp_attr);
globus_gass_copy_attribute_setup_io(handle, io_attr);
globus_gass_copy_attribute_setup_gass(handle, io_attr);

globus_gass_copy_cache_url_state(
    &handle,
    "gsiftp://pitcairn.mcs.anl.gov/");
globus_gass_copy_url_to_url(
    &handle,
    "gsiftp://pitcairn.mcs.anl.gov/tmp/foo",
    "gsiftp://lemon.mcs.anl.gov/tmp/foo");

**/

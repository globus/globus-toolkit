/**
 * @file globus_gass_copy.c
 *
 * Short description
 *
 * Long description
 */

#include "globus_gass_copy.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
#include "globus_i_gass_copy.h"
#endif

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

/************************************************************
 * Handle initialization and destruction
 ************************************************************/

/**
 * Initialize the GASS copy handle
 *
 * Initialize the handle via globus_ftp_client_init()
 *
 * @param handle
 *        The handle to be initialized
 *
 * @return fuzzy description
 *
 * @retval GLOBUS_SUCCESS
 *         Descriptions
 * @retval GLOBUS_FAILRUE
 *
 * @see globus_gass_copy_destroy() globus_ftp_client_init()
 */
globus_result_t
globus_gass_copy_init(
    globus_gass_copy_handle_t * handle)
{
    globus_ftp_client_init(&handle->ftp_handle);
}

/**
 *  Destroy the GASS copy handle
 */
globus_result_t
globus_gass_copy_destroy(
    globus_gass_copy_handle_t * handle)
{
    globus_ftp_client_destroy(&handle->ftp_handle);
}

/************************************************************
 * Transfer functions (synchronous)
 ************************************************************/

/**
 * Transfer data from source URL to destination URL
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
 *         This function returns GLOBUS_SUCCESS or a result pointing to an
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
    globus_l_gass_copy_url_scheme(
	source_url,
	&source_url_scheme);
    globus_l_gass_copy_url_scheme(
	dest_url,
	&dest_url_scheme);

    if (   (source_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED)
        || (dest_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED) )
    {
        return GLOBUS_FAILURE;
	/* return error */
    }
    
    globus_i_gass_copy_state_t * state;

    /* Initialize the state for this transfer */
    globus_l_gass_copy_state_new(&state);

    /* initialize the monitor */
    globus_mutex_init(&state->monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&state->monitor.cond, GLOBUS_NULL);
    state->monitor.done = GLOBUS_FALSE;
    state->monitor.err = GLOBUS_NULL;
    state->monitor.use_err = GLOBUS_FALSE;
    
    state->handle = handle;

    /* comes from source_attr, or defaults */
    state->buffer_length = something;
	
    if (   (source_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_FTP)
	&& (dest_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_FTP) )
    {
	/* use source_attr to create source_ftp_client_attr */
	
	/* use dest_attr to create dest_ftp_client_attr */
	
	globus_ftp_client_thirdparty_transfer(
	    handle->ftp_handle,
	    source_url,
	    source_ftp_client_attr,
	    dest_url,
	    dest_ftp_client_attr,
	    globus_l_gass_copy_ftp_transfer_callback,
	    &state->monitor);
    }
    else
    {
        /* Both urls are not ftp, so we have to do the copy ourselves */

	globus_l_gass_copy_target_populate(
            state->source,
            source_url_scheme
	    source_url,
	    source_attr);

	globus_l_gass_copy_target_populate(
            state->dest,
            dest_url_scheme
	    dest_url,
	    dest_attr);

	globus_l_gass_copy_transfer_start(state);
    }
    
    /* wait on cond_wait() for completion */
    globus_mutex_lock(&state->monitor.mutex);
   
    while(!state->monitor.done)
    {
        globus_cond_wait(&state->monitor.cond, &state->monitor.mutex);
    }

    globus_mutex_unlock(&state->monitor.mutex);

    if(state->monitor.use_err)
    {
        return globus_error_put(state->monitor.err);
    }
    else
    {
        return GLOBUS_SUCCESS;
    }
} /* globus_gass_copy_url_to_url() */

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
globus_l_gass_copy_url_scheme(
    char * url,
    globus_i_gass_copy_url_scheme_t * type)
{
    globus_url_t url_info;

    if ((rc = globus_url_parse(url, &url_info)) != GLOBUS_SUCCESS)
    {
        return rc;
    }

    if ( (url_info.schema_type == GLOBUS_URL_SCHEME_FTP) ||
         (url_info.schema_type == GLOBUS_URL_SCHEME_GSIFTP) )
    {
       *type = GLOBUS_I_GASS_COPY_URL_SCHEME_FTP;
    }
    else if ( (url_info.schema_type == GLOBUS_URL_SCHEME_HTTP) ||
              (url_info.schema_type == GLOBUS_URL_SCHEME_HTTPS) )
    {
       *type = GLOBUS_I_GASS_COPY_URL_SCHEME_HTTP;
    }
    else if ( (url_info.schema_type == GLOBUS_URL_SCHEME_FILE)
    {
       *type = GLOBUS_I_GASS_COPY_URL_SCHEME_FILE;
    }
    else
    {
       *type = GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED;
    }

    return GLOBUS_SUCCESS;
} /* globus_l_gass_copy_url_scheme() */

/**
 * instantiate state structure
 */
globus_result_t
globus_l_gass_copy_state_new(
    globus_gass_copy_handle_t *handle,
    globus_i_gass_copy_target_mode_t * mode,
    char * url,
    globus_gass_copy_attr_t * attr,
    globus_i_gass_copy_state_t ** state)
{
    *state = (globus_i_gass_copy_state_t *)
         globus_libc_malloc(sizeof(globus_i_gass_copy_state_t));
    (*state)->handle = handle;
    (*state)->number = GLOBUS_I_GASS_COPY_STATE_INITIAL;
} /* globus_l_gass_copy_state_new() */

/**
 * free state structure
 */
globus_result_t
globus_l_gass_copy_state_free(
    globus_i_gass_copy_state_t * state)
{
} /* globus_l_gass_copy_state_free() */

/**
 * Populate the target transfer structures
 */
globus_result_t
globus_l_gass_copy_target_populate(
    globus_i_gass_copy_target_t * target,
    globus_i_gass_copy_url_scheme_t * url_scheme,
    char * url,
    globus_gass_copy_attr_t * attr)
{
    switch (url_scheme)
    {
        case GLOBUS_I_GASS_COPY_URL_SCHEME_FTP:

             target->mode = GLOBUS_I_GASS_COPY_TARGET_MODE_FTP;
             target->url = globus_libc_strdup(url);
             target->attr = *attr;
             break;

        case GLOBUS_I_GASS_COPY_URL_SCHEME_HTTP:

             target->mode = GLOBUS_I_GASS_COPY_TARGET_MODE_GASS;
             target->url = globus_libc_strdup(url);
             target->attr = *attr;
             break;

        case GLOBUS_I_GASS_COPY_URL_SCHEME_FILE:

             target->mode = GLOBUS_I_GASS_COPY_TARGET_MODE_IO;
             target->url = globus_libc_strdup(url);
             target->attr = *attr;
             target->data.io.free_handle = GLOBUS_TRUE;
             target->data.io.seekable = GLOBUS_TRUE;

             break;

        case GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED:
             /* something went horribly wrong */
             break;
    }
    return GLOBUS_SUCCESS;
} /* globus_l_gass_copy_target_populate() */

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
    globus_i_gass_copy_state_t * state)
{
    globus_result_t result;

    if (   (state->source.mode
	    == GLOBUS_I_GASS_COPY_TARGET_MODE_FTP)
	&& (   (   (state->dest.mode
		    == GLOBUS_I_GASS_COPY_TARGET_MODE_GASS) )
	    || (   (state->dest.mode
		    == GLOBUS_I_GASS_COPY_TARGET_MODE_IO)
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

	if ((result = globus_gass_copy_attr_duplicate(&(state->source.attr)))
            != GLOBUS_SUCCESS)
        {
           return result;
        }

        /* probably change these with a globus_ftp_attr_parallelism*?? call
         */
        state->source.attr.parallelism_info.mode =
            GLOBUS_GSIFTP_CONTROL_PARALLELISM_NONE;
        state->source.attr.striping_info.mode =
            GLOBUS_GSIFTP_CONTROL_STRIPING_NONE;
	
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

    if (globus_fifo_init(&(state->dest.write_queue)) != GLOBUS_SUCCESS)
    {
        return(GLOBUS_FAILURE);
    }

    /* depending on the mode, call the appropriate routine to start the
     * transfer
     */
    switch (state->source.mode)
    {
      case GLOBUS_I_GASS_COPY_TARGET_MODE_FTP:

	state->source.data.ftp.n_channels = 0;
	state->source.data.ftp.n_reads_posted = 0;

        /* This register_get function calls the callback function only
         * after the transfer has completed.  So we need to call the ftp_setup
         * callback function by hand.
	globus_ftp_client_get(
	    handle->ftp_handle,
	    state->source.url,
	    state->source.attr.ftp,
	    globus_l_gass_copy_ftp_get_done_callback,
	    (void *) state);

        globus_l_gass_copy_ftp_setup_callback(state);

	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_GASS:

	globus_gass_transfer_register_get(
	    state->source.data.gass.request,
	    state->source.attr.gass,
	    state->source.url,
	    globus_l_gass_copy_gass_setup_callback,
	    (void *) state);

	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_IO:

	globus_l_gass_copy_io_setup_get_callback(state);

	break;
    }

    /* wait for ok from the source */
    state->number = SOURCE_READY;

    /*
     * Now get the destination side ready
     */
    switch (state->dest.mode)
    {
      case GLOBUS_I_GASS_COPY_TARGET_MODE_FTP:

	state->dest.data.ftp.n_channels = 0;
	state->dest.data.ftp.n_reads_posted = 0;

        /* This register_get function calls the callback function only
         * after the transfer has completed.  So we need to call the ftp_setup
         * callback function by hand.
	globus_ftp_client_put(
	    handle->ftp_handle,
	    state->dest.url,
	    state->dest.attr.ftp,
	    globus_l_gass_copy_ftp_put_done_callback,
	    (void *) state);

	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_GASS:

	globus_gass_transfer_register_put(
	    state->dest.data.gass.request,
	    state->dest.attr.gass,
	    state->dest.url,
	    globus_l_gass_copy_gass_setup_callback,
	    (void *) state);

	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_IO:

	globus_l_gass_copy_io_setup_put_callback(state);

	break;
    }

    /* wait for ok from the dest */

    return(GLOBUS_SUCCESS);
} /* globus_l_gass_copy_transfer_start() */


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
void
globus_l_gass_copy_register_read(
    globus_i_gass_copy_state_t * state,
    globus_byte_t * buffer)
{
    globus_mutex_lock(&(state->source.mutex));

    if (!buffer)
    {
	/*
	 * allocate read buffer of some length
	 * attr should allow user to set the buffer size
	 */
	buffer = malloc(state->buffer_length);
    }

    switch (state->source.mode)
    {
      case GLOBUS_I_GASS_COPY_TARGET_MODE_FTP:
	globus_ftp_client_register_read(
	    state->source.data.ftp.handle,
	    buffer,
	    state->buffer_length,
	    globus_l_gass_copy_ftp_read_callback,
	    (void *) state);
	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_GASS:
	globus_gass_transfer_receive_bytes(
	    state->source.data.gass.request,
	    buffer,
	    state->buffer_length,
	    state->buffer_length,
	    globus_l_gass_copy_gass_read_callback,
	    (void *) state);
	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_IO:
	globus_io_register_read(
	    state->source.data.io.handle,
	    buffer
	    state->buffer_length,
	    state->buffer_length,
	    globus_l_gass_copy_io_read_callback,
	    (void *) state);
	break;
    }
    
    globus_mutex_unlock(&(state->source.mutex));
} /* globus_l_gass_copy_register_read */

/*****************************************************************
 * setup callbacks
 *****************************************************************/

void
globus_l_gass_copy_generic_setup_callback(
    globus_i_gass_copy_state_t *  state)
{
    /* how to handle multiple buffers? for loop around register_read */
    
    globus_l_gass_copy_register_read(
	state,
	(globus_byte_t *) GLOBUS_NULL); /* malloc new buffer */

} /* globus_l_gass_copy_generic_setup_callback() */

void
globus_l_gass_copy_ftp_setup_callback(
    globus_i_gass_copy_state_t * state)
{
    globus_l_gass_copy_generic_setup_callback(state);
} /* globus_l_gass_copy_ftp_setup_callback() */

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
globus_result_t
void
globus_l_gass_copy_gass_setup_callback(
    void * callback_arg,
    globus_gass_transfer_request_t * request)
{
    globus_i_gass_copy_state_t * state
	= (globus_i_gass_copy_state_t *) callback_arg;

    globus_gass_transfer_request_status_t status;

    status = globus_gass_transfer_request_get_status(request);

    switch(status)
    {
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
        
           globus_gass_transfer_referral_t             referral;
           int rc;

           globus_gass_transfer_request_get_referral(request, &referral);
           globus_gass_transfer_request_destroy(request);

           if (state->number == INITIAL)
           {
               /* first setup the source with the register get
                */
               state->source.url =
                   globus_gass_transfer_referral_get_url(&referral, 0);

               globus_gass_transfer_referral_destroy(&referral);

               if ( (rc = globus_gass_transfer_register_get(
                     &request,
                     state->source.attr.gass,
                     state->source.url,
                     globus_l_gass_copy_gass_setup_callback,
                     (void *) state)) != GLOBUS_SUCCESS )
               {
                   globus_mutex_lock(&state->monitor.mutex);
                   state->err = rc;
                   goto wakeup_state;
               }
           }
           else
           {
               /* if the state is not INITIAL then assume the source is ready
                * so now setup the destination with the register put
                */

               state->dest.url =
                   globus_gass_transfer_referral_get_url(&referral, 0);

               globus_gass_transfer_referral_destroy(&referral);

               if ( (rc = globus_gass_transfer_register_get(
                     &request,
                     state->dest.attr.gass,
                     state->dest.url,
                     globus_l_gass_copy_gass_setup_callback,
                     (void *) state)) != GLOBUS_SUCCESS )
               {
                   globus_mutex_lock(&state->monitor.mutex);
                   state->err = rc;
                   goto wakeup_state;
               }
           }

           break;

      case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:

           if (state->number == INITIAL)
               globus_l_gass_copy_generic_setup_callback(state);
           else
               state->dest.ready = GLOBUS_TRUE;

           break;

      case GLOBUS_GASS_TRANSFER_REQUEST_DONE:

           globus_mutex_lock(&state->monitor.mutex);
           goto wakeup_state;
           break;

      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:

           globus_mutex_lock(&state->monitor.mutex);
           state->err = globus_gass_transfer_request_get_denial_reason(request);
           /* globus_gass_transfer_request_get_denial_message(request)); */
           goto wakeup_state;
           break;

      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:

           globus_mutex_lock(&state->monitor.mutex);
           /* needs real error */
           state->err = GLOBUS_GASS_TRANSFER_REQUEST_FAILED;
           goto wakeup_state;
           break;
    } /* switch */
    return;

  wakeup_state:
    /* 
     * assume mutex has already been locked by above calls
     */
    globus_gass_transfer_request_destroy(request);
    done = 1;
    globus_cond_signal(&state->monitor.cond);
    globus_mutex_unlock(&state->monitor.mutex);

    return;
} /* globus_l_gass_copy_gass_setup_callback() */

void
globus_l_gass_copy_io_setup_get_callback(
    globus_i_gass_copy_state_t * state)
{
    globus_url_t parsed_url;

    if (state->source.free_handle)
    {
        globus_url_parse(state->source.url, &parsed_url);
        state->source.data.io.handle =
            globus_libc_malloc(sizeof(globus_io_handle_t));

        globus_io_file_open(
                 parsed_url.path,
                 GLOBUS_IO_FILE_RDONLY,
                 GLOBUS_IO_FILE_IRUSR,
                 state->source.attr.io,
                 state->source.data.io.handle);
    }

    globus_l_gass_copy_generic_setup_callback(state);

} /* globus_l_gass_copy_io_setup_get_callback() */

void
globus_l_gass_copy_io_setup_put_callback(
    globus_i_gass_copy_state_t * state)
{
    globus_url_t parsed_url;

    if (state->dest.free_handle)
    {
        globus_url_parse(state->dest.url, &parsed_url);
        state->dest.data.io.handle =
            globus_libc_malloc(sizeof(globus_io_handle_t));

        globus_io_file_open(
                 parsed_url.path,
                 GLOBUS_IO_FILE_RDONLY,
                 GLOBUS_IO_FILE_IRUSR,
                 state->dest.attr.io,
                 state->dest.data.io.handle);
    }

    state->dest.ready = GLOBUS_TRUE;

} /* globus_l_gass_copy_io_setup_put_callback() */

void
globus_l_gass_copy_ftp_get_done_callback(
    void * callback_arg,
    globus_ftp_client_handle * handle)
{
    globus_i_gass_copy_state_t * state
	= (globus_i_gass_copy_state_t *) callback_arg;

    globus_mutex_lock(&state->monitor.mutex);
    done = 1;
    globus_cond_signal(&state->monitor.cond);
    globus_mutex_unlock(&state->monitor.mutex);

} /* globus_l_gass_copy_ftp_get_done_callback() */

void
globus_l_gass_copy_ftp_put_done_callback(
    void * callback_arg,
    globus_ftp_client_handle * handle)
{
    globus_i_gass_copy_state_t * state
	= (globus_i_gass_copy_state_t *) callback_arg;

    globus_mutex_lock(&state->monitor.mutex);
    done = 1;
    globus_cond_signal(&state->monitor.cond);
    globus_mutex_unlock(&state->monitor.mutex);

} /* globus_l_gass_copy_ftp_put_done_callback() */


/*****************************************************************
 * read callbacks
 *****************************************************************/

void
globus_l_gass_copy_generic_read_callback(
    globus_i_gass_copy_state_t *    state,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_size_t                   offset)
{
    globus_gass_copy_buffer_t *  buffer_entry;

    globus_mutex_lock(&(state->dest.mutex));

    buffer_entry = (globus_i_gass_copy_buffer_t *)
         globus_libc_malloc(sizeof(globus_i_gass_copy_buffer_t));
    buffer_entry.bytes  = bytes;
    buffer_entry.nbytes = nbytes;
    buffer_entry.offset = offset;

    /* put this read buffer entry onto the write queue */
    globus_fifo_enqueue( state->dest.write_queue, buffer_entry);

    /* start the next write if there isn't already one outstanding */
    globus_i_gass_copy_write_from_queue(state);

    globus_mutex_unlock(&(state->dest.mutex));

} /* globus_l_gass_copy_generic_read_callback() */


void
globus_l_gass_copy_ftp_read_callback(
    void *                          callback_arg,
    globus_ftp_handle_t *           handle,
    globus_result_t                 result,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_size_t                   offset)
{
    globus_i_gass_copy_state_t * state
	= (globus_i_gass_copy_state_t *) callback_arg;

    globus_l_gass_copy_generic_read_callback(
        state,
        bytes,
        nbytes,
        offset);
} /* globus_l_gass_copy_ftp_read_callback() */

void
globus_l_gass_copy_gass_read_callback(
    void *                          callback_arg,
    globus_gass_transfer_request_t  request,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_bool_t                   last_data)
{
    globus_i_gass_copy_state_t * state
	= (globus_i_gass_copy_state_t *) callback_arg;

    globus_l_gass_copy_generic_read_callback(
        state,
        bytes,
        nbytes,
        0);
} /* globus_l_gass_copy_gass_read_callback() */

void
globus_l_gass_copy_io_read_callback(
    void *                          callback_arg,
    globus_io_handle_t *            handle,
    globus_result_t                 result,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes)
{
    globus_i_gass_copy_state_t * state
	= (globus_i_gass_copy_state_t *) callback_arg;

    globus_l_gass_copy_generic_read_callback(
        state,
        bytes,
        nbytes,
        0);
} /* globus_l_gass_copy_io_read_callback() */


/*****************************************************************
 * write callbacks
 *****************************************************************/

void
globus_l_gass_copy_generic_write_callback(
    globus_i_gass_copy_state_t *    state,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_size_t                   offset)
{
    globus_mutex_lock(&(state->dest.mutex));

    state->writes_pending--;
    
    /* register the next io write */
    globus_l_gass_copy_write_from_queue(state);

    globus_mutex_unlock(&(state->dest.mutex));

    /* register a new read using this buffer */
    globus_l_gass_copy_register_read(
	state,
	bytes);

} /* globus_l_gass_copy_generic_write_callback() */

void
globus_l_gass_copy_write_from_queue(
    globus_i_gass_copy_state_t * state)
{
    globus_gass_copy_buffer_t *  buffer_entry;

    while ((state->writes_pending < state->dest.simultaneous_writes) &&
           state->dest.ready)
    {
	/*
	 * There is not a write pending.  So check the write queue,
	 * and if there is one then register the first one to write.
	 */
	if ((buffer_entry = globus_fifo_dequeue(state->dest.write_queue))
              != GLOBUS_NULL)
	{
	    switch (state->dest.mode)
	    {
	      case GLOBUS_I_GASS_COPY_TARGET_MODE_FTP:
		/* check the offset to see if its what we are expecting */
		globus_ftp_client_register_write(
		    state->dest.data.ftp.handle,
		    buffer_entry->bytes,
		    buffer_entry->nbytes,
		    globus_l_gass_copy_ftp_write_callback,
		    (void *) state);
		break;

	      case GLOBUS_I_GASS_COPY_TARGET_MODE_GASS:
		/* check the offset to see if its what we are expecting */
		globus_gass_transfer_send_bytes(
		    state->dest.data.gass.request,
		    buffer_entry->bytes,
		    buffer_entry->nbytes,
		    state->buffer_length,
		    globus_l_gass_copy_gass_write_callback,
		    (void *) state);
		break;

	      case GLOBUS_I_GASS_COPY_TARGET_MODE_IO:
		if (state->dest.data.io.seekable)
		{
		    globus_io_file_seek(
			state->dest.data.io.handle,
			buffer_entry->offset,
			GLOBUS_IO_SEEK_SET);
		}
	
		globus_io_register_write(
		    state->dest.data.io.handle,
		    buffer_entry->bytes
		    buffer_entry->nbytes,
		    globus_l_gass_copy_io_write_callback,
		    (void *) state);

		break;
	    }
	}

        globus_libc_free(buffer_entry);

	state->writes_pending++;
    }
    
    /* i dont think we want this unlock here ???
     * globus_mutex_unlock(&(state->dest.mutex));
     */

} /* globus_l_gass_copy_write_from_queue() */

void
globus_l_gass_copy_ftp_write_callback(
    void *                callback_arg,
    globus_ftp_handle_t * handle, 
    globus_result_t       result,
    globus_byte_t *       bytes,
    globus_size_t         nbytes)
{
    globus_i_gass_copy_state_t * state
	= (globus_i_gass_copy_state_t *) callback_arg;

    globus_l_gass_copy_generic_write_callback(
        state,
        bytes,
        nbytes,
        0);
} /* globus_l_gass_copy_ftp_write_callback() */
   
void
globus_l_gass_copy_gass_write_callback(
    void *                          callback_arg,
    globus_gass_transfer_request_t  request,
    globus_byte_t *                 bytes,
    globus_size_t                   nbytes,
    globus_bool_t                   last_data)
{
    globus_i_gass_copy_state_t * state
	= (globus_i_gass_copy_state_t *) callback_arg;

    globus_l_gass_copy_generic_write_callback(
        state,
        bytes,
        nbytes,
        0);
} /* globus_l_gass_copy_gass_write_callback() */
   
void
globus_l_gass_copy_io_write_callback(
    void *                callback_arg,
    globus_io_handle_t *  handle, 
    globus_result_t       result,
    globus_byte_t *       bytes,
    globus_size_t         nbytes)
{
    globus_i_gass_copy_state_t * state
	= (globus_i_gass_copy_state_t *) callback_arg;

    globus_l_gass_copy_generic_write_callback(
        state,
        bytes,
        nbytes,
        0);
} /* globus_l_gass_copy_io_write_callback() */
   

/*****************************************************************
 * copy url to handle
 *****************************************************************/

globus_result_t
globus_gass_copy_url_to_handle(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    globus_gass_copy_attr_t * source_attr,
    globus_io_handle_t * dest_handle)
{
}

globus_result_t
globus_gass_copy_handle_to_url(
    globus_gass_copy_handle_t * handle,
    globus_io_handle_t * source_handle,
    char * dest_url,
    globus_gass_copy_attr_t * dest_attr)
{
}

/************************************************************
 * Transfer functions (asynchronous)
 ************************************************************/

globus_result_t
globus_gass_copy_register_url_to_url(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    globus_gass_copy_attr_t * dest_attr,
    char * dest_url,
    globus_gass_copy_attr_t * source_attr,
    globus_gass_copy_callback_t callback_func,
    void * callback_arg)
{
}

globus_result_t
globus_gass_copy_register_url_to_handle(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    globus_gass_copy_attr_t * source_attr,
    globus_io_handle_t * dest_handle,
    globus_gass_copy_callback_t callback_func,
    void * callback_arg)
{
}

globus_result_t
globus_gass_copy_register_handle_to_url(
    globus_gass_copy_handle_t * handle,
    globus_io_handle_t * source_handle,
    char * dest_url,
    globus_gass_copy_attr_t * dest_attr,
    globus_gass_copy_callback_t callback_func,
    void * callback_arg)
{
}

/************************************************************
 * Caching url state
 ************************************************************/

globus_result_t
globus_gass_copy_cache_url_state(
    globus_gass_copy_handle_t * handle,
    char * url)
{
    globus_url_t source_url_info;
    globus_url_parse(source_url, &source_url_info);
    if (   (strcmp(source_url_info.schema, "ftp") == 0)
	|| (strcmp(source_url_info.schema, "gsiftp") == 0)    )
    {
	globus_ftp_client_cache_url_state(
	    &handle->ftp_handle,
	    url);
    }
} /* globus_gass_copy_cache_url_state() */

globus_result_t
globus_gass_copy_flush_url_state(
    globus_gass_copy_handle_t * handle,
    char * url)
{
    globus_url_t source_url_info;
    globus_url_parse(source_url, &source_url_info);
    if (   (strcmp(source_url_info.schema, "ftp") == 0)
	|| (strcmp(source_url_info.schema, "gsiftp") == 0)    )
    {
	globus_ftp_client_flush_url_state(
	    &handle->ftp_handle,
	    url);
    }
} /* globus_gass_copy_flush_url_state() */
    
/************************************************************
 * User pointers on handles
 ************************************************************/

globus_result_t
globus_gass_copy_set_user_pointer(
    globus_gass_copy_handle_t * handle,
    void * user_pointer)
{
}

void *
globus_gass_copy_get_user_pointer(
    globus_gass_copy_handle_t * handle)
{
}

    
/************************************************************
 * Attributes
 ************************************************************/

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

/**
 * Duplicate the passed in attribute structure. 
 */
globus_result_t
globus_i_gass_copy_attr_duplicate(globus_gass_copy_attr_t ** attr)

    globus_gass_copy_attr_t * new_attr;

    if (attr == GLOBUS_NULL) || (*attr == GLOBUS_NULL)
    {
        return globus_error_put(
           globus_gass_copy_error_construct_null_parameter(
              GLOBUS_GASS_COPY_MODULE,
              GLOBUS_NULL,
              "attr",
              1,
              "globus_gass_copy_attr_duplicate");
    }

    new_attr = (globus_i_gass_copy_attr_t *)
         globus_libc_malloc(sizeof(globus_i_gass_copy_attr_t));
    new_attr = *attr;
    *attr = new_attr;

    return GLOBUS_SUCCESS;
}

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

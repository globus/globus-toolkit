/**
 * @file globus_gass_copy.c
 *
 * Short description
 *
 * Long description
 */


/************************************************************
 * Handle initialization and destruction
 ************************************************************/

/**
 * Short description
 *
 * Long descriptioin
 *
 * @param param
 *        Description
 * @param param
 *        Description
 *
 * @return fuzzy description
 *
 * @retval GLOBUS_SUCCESS
 *         Descriptions
 * @retval GLOBUS_FAILRUE
 *
 * @see globus_gass_copy_destroy()
 */
globus_result_t
globus_gass_copy_init(
    globus_gass_copy_handle_t * handle)
{
    globus_gsiftp_client_init(&handle->gsiftp_handle);
}

globus_result_t
globus_gass_copy_destroy(
    globus_gass_copy_handle_t * handle)
{
    globus_gsiftp_client_destroy(&handle->gsiftp_handle);
}

/************************************************************
 * Transfer functions (synchronous)
 ************************************************************/

globus_result_t
globus_gass_copy_url_to_url(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    globus_gass_copy_attr_t * source_attr,
    char * dest_url,
    globus_gass_copy_attr_t * dest_attr)
{
    globus_i_gass_copy_url_scheme(
	source_url,
	&source_url_scheme);
    globus_i_gass_copy_url_scheme(
	source_url,
	&source_url_scheme);

    /* setup a monitor to wait for completion */
    
    if (   (source_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED)
        || (dest_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED) )
    {
	/* return error */
    }
    
    if (   (source_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_FTP)
	&& (dest_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_FTP) )
    {
	/* use source_attr to create source_gsiftp_client_attr */
	
	/* use source_attr to create dest_gsiftp_client_attr */
	
	globus_gsiftp_client_register_transfer(
	    handle->gsiftp_handle,
	    source_url,
	    source_gsiftp_client_attr,
	    dest_url,
	    dest_gsiftp_client_attr,
	    globus_i_gass_copy_gsiftp_transfer_callback,
	    callback_arg);
    }
    else
    {
	/* Both urls are not ftp, so we have to do the copy ourselves */
	globus_i_gass_copy_state_t * state;

	/* Initialize the state for this transfer */
	globus_i_gass_copy_state_new(&state);

	state->handle = handle;

	/* comes from source_attr, or defaults */
	state->buffer_length = something;
	
	/* Populate the transfer_source structures */
	switch (source_url_scheme)
	{
	  case GLOBUS_I_GASS_COPY_URL_SCHEME_FTP:
	    globus_i_gass_copy_state_source(
		state,
		GLOBUS_I_GASS_COPY_TARGET_MODE_FTP,
		source_url,
		source_attr);
	    break;

	  case GLOBUS_I_GASS_COPY_URL_SCHEME_HTTP:
	    globus_i_gass_copy_state_source(
		state,
		GLOBUS_I_GASS_COPY_TARGET_MODE_GASS,
		source_url,
		source_attr);
	    transfer_source.url = globus_libc_strdup(source_url);
	    break;

	  case GLOBUS_I_GASS_COPY_URL_SCHEME_FILE:
	    globus_i_gass_copy_state_source(
		state,
		GLOBUS_I_GASS_COPY_TARGET_MODE_IO,
		source_url,
		source_attr);
	    globus_url_parse(source_url, &parsed_url);
	    state->source.data.io.handle
		= malloc(sizeof(globus_io_handle_t));
	    globus_io_file_open(
		parsed_url.path,
		/* other args */,
		state->source.data.io.handle);
	    state->source.data.io.free_handle = GLOBUS_TRUE;
	    state->source.data.io.seekable = GLOBUS_TRUE;
	    break;

	  case GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED:
	    /* something went horribly wrong */
	    break;
	}
	
	/* similar sort of switch for the destination */

	globus_i_gass_copy_transfer_start(
	    transfer_source,
	    transfer_dest,
	    callback_func, /* signals completion */
	    callback_arg);

    }
    
    /* wait on cond_wait() for completion */
}

globus_result_t
globus_i_gass_copy_url_scheme(
    char * url,
    globus_i_gass_copy_url_scheme_t * type)
{
}

globus_result_t
globus_i_gass_copy_state_new(
    globus_gass_copy_handle_t *handle,
    globus_i_gass_copy_target_mode_t * mode,
    char * url,
    globus_gass_copy_attr_t * attr,
    globus_i_gass_copy_state_t ** state)
{
    *state = malloc(...);
    (*state)->handle = handle;
    (*state)->number = GLOBUS_I_GASS_COPY_STATE_INITIAL;
}

globus_result_t
globus_i_gass_copy_state_source(
    globus_i_gass_copy_state_t *state,
    globus_i_gass_copy_target_mode_t * mode,
    char * url,
    globus_gass_copy_attr_t * attr)
{
    state->source.mode = mode;
    state->source.url = globus_libc_strdup(url);
    state->source.attr = *attr;
}

globus_result_t
globus_i_gass_copy_state_dest(
    globus_i_gass_copy_state_t *state,
    globus_i_gass_copy_target_mode_t * mode,
    char * url,
    globus_gass_copy_attr_t * attr)
{
    state->dest.mode = mode;
    state->dest.url = globus_libc_strdup(url);
    state->dest.attr = *attr;
}

globus_result_t
globus_i_gass_copy_state_free(
    globus_i_gass_copy_state_t * transfer_state)
{
}

globus_result_t
globus_i_gass_copy_transfer_start(
    globus_i_gass_copy_state_t * state,
    globus_gass_copy_callback_t callback_func,
    void * callback_arg)
{
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

	globus_gass_copy_attr_parallelism(&(state->source.attr),
					  /* no parallelism */);
	globus_gass_copy_attr_striping(&(state->source.attr),
				       /* no striping */);
	
	/*
	 * ftp -> gass_transfer:
	 *     turn off both parallel & striping
	 * ftp -> io:
	 *     globus_io_file_seek() can be used to deal with out of
	 *     order blocks
	 * gass_transfer, io -> *
	 *     The source data is serialized anyway, so do don't need
	 *     to worry about the destination.  An ftp destination can
	 *     uses parallelism and/or striping if desired
	 */
    }

    switch (state->source.mode)
    {
      case GLOBUS_I_GASS_COPY_TARGET_MODE_FTP:

	state->source.data.ftp.n_channels = 0;
	state->source.data.ftp.n_reads_posted = 0;

	/* Setup the ftp get */
	globus_gsiftp_client_register_get(
	    handle->gsiftp_handle,
	    state->source.url,
	    attr,
	    globus_i_gass_copy_ftp_setup_callback,
	    (void *) state);

	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_GASS:

	/* Setup the gass get */
	globus_gass_transfer_register_get(
	    state->source.data.gass.request,
	    request_attr,
	    state->source.url,
	    globus_i_gass_copy_gass_setup_callback,
	    (void *) state);

	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_IO:

	globus_i_gass_copy_io_setup_callback(
	    (void *) state);

	break;
    }
}

/*****************************************************************
 * setup callbacks
 *****************************************************************/

void
globus_i_gass_copy_generic_setup_callback(
    void * callback_arg,
    ...)
{
    globus_i_gass_copy_state_t * state
	= (globus_i_gass_copy_state_t *) callback_arg;

    /* how to handle multiple buffers? for loop around register_read */
    
    globus_i_gass_copy_register_read(
	state,
	(globus_byte_t *) GLOBUS_NULL); /* malloc new buffer */

}

void
globus_i_gass_copy_ftp_setup_callback(
    void * callback_arg,
    globus_gass_transfer_request_t * request)
{
}

void
globus_i_gass_copy_gass_setup_callback(
    void * callback_arg,
    globus_gass_transfer_request_t * request)
{
}

void
globus_i_gass_copy_io_setup_callback(
    void * callback_arg,
    globus_gass_transfer_request_t * request)
{
}


/*****************************************************************
 * read callbacks
 *****************************************************************/

void
globus_i_gass_copy_generic_read_callback(
    void * callback_arg,
    ...)
{
    globus_i_gass_copy_state_t * state
	= (globus_i_gass_copy_state_t *) callback_arg;

    globus_mutex_lock(&(state->dest.mutex));

    /* put this buffer onto the write queue */
    enqueue({buffer, offset, size},
	    state->dest.write_queue);

    /* start the next write if there isn't already one outstanding */
    globus_i_gass_copy_generic_write_from_queue(state);

    globus_mutex_unlock(&(state->dest.mutex));
}

void
globus_i_gass_copy_ftp_read_callback(
    void * callback_arg,
    ...)
{
    globus_i_gass_copy_generic_read_callback(callback_arg, ...);
}

void
globus_i_gass_copy_gass_read_callback(
    void * callback_arg,
    ...)
{
    globus_i_gass_copy_generic_read_callback(callback_arg, ...);
}

void
globus_i_gass_copy_io_read_callback(
    void * callback_arg,
    ...)
{
    globus_i_gass_copy_generic_read_callback(callback_arg, ...);
}

void
globus_i_gass_copy_register_read(
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
	globus_gsiftp_client_data_register_read(
	    handle->gsiftp_handle,
	    buffer,
	    state->buffer_length,
	    globus_i_gass_copy_gsiftp_read_callback,
	    (void *) state);
	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_GASS:
	globus_gass_transfer_receive_bytes(
	    state->source.data.gass.request,
	    buffer,
	    state->buffer_length,
	    state->buffer_length,
	    globus_i_gass_copy_gass_read_callback,
	    (void *) state);
	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_IO:
	globus_io_register_read(
	    io_handle,
	    buffer
	    state->buffer_length,
	    state->buffer_length,
	    globus_i_gass_copy_io_read_callback,
	    (void *) state);
	break;
    }
    
    globus_mutex_unlock(&(state->source.mutex));
}

void
globus_i_gass_copy_register_write(
    globus_i_gass_copy_state_t * state,
    globus_byte_t * buffer,
    size_t offset,
    size_t size)
{
    globus_mutex_lock(&(state->dest.mutex));

    enqueue({buffer, offset, size},
	    state->dest.write_queue);

    globus_i_gass_copy_register_write_from_queue(state);
    
    globus_mutex_unlock(&(state->dest.mutex));
}

/*****************************************************************
 * write callbacks
 *****************************************************************/

void
globus_i_gass_copy_generic_write_callback(
    void * callback_arg
    buffer,
    offset,
    size)
{
    globus_i_gass_copy_state_t * state
	= (globus_i_gass_copy_state_t *) callback_arg;

    globus_mutex_lock(&(state->dest.mutex));

    state->dest.writes_pending--;
    
    /* register the next io write */
    globus_i_gass_copy_write_from_queue(state);

    globus_mutex_unlock(&(state->dest.mutex));

    /* register a new read using this buffer */
    globus_i_gass_copy_register_read(
	state,
	buffer);
}

void
globus_i_gass_copy_register_write_from_queue(
    globus_i_gass_copy_state_t * state)
{

    while (state->dest.writes_pending < state->dest.simultaneous_writes)
    {
	/*
	 * There is not a write pending.  So check the write queue,
	 * and if there is one then register the first one to write.
	 */
	if ((buffer = dequeue(state->dest.write_queue)) != GLOBUS_NULL)
	{
	    switch (state->dest.mode)
	    {
	      case GLOBUS_I_GASS_COPY_TARGET_MODE_FTP:
		/* check the offset to see if its what we are expecting */
		globus_gsiftp_client_data_register_write(
		    handle->gsiftp_handle,
		    buffer,
		    size,
		    globus_i_gass_copy_gsiftp_write_callback,
		    (void *) state);
		break;

	      case GLOBUS_I_GASS_COPY_TARGET_MODE_GASS:
		/* check the offset to see if its what we are expecting */
		globus_gass_transfer_send_bytes(
		    state->dest.data.gass.request,
		    buffer,
		    size,
		    state->buffer_length,
		    globus_i_gass_copy_gass_read_callback,
		    (void *) state);
		break;

	      case GLOBUS_I_GASS_COPY_TARGET_MODE_IO:
		if (state->dest.data.io.seekable)
		{
		    globus_io_file_seek(
			state->dest.data.io.handle,
			offset,
			GLOBUS_IO_SEEK_SET);
		}
	
		globus_io_register_write(
		    state->dest.data.io.handle,
		    buffer
		    size,
		    globus_i_gass_copy_io_write_callback,
		    (void *) state);

		break;
	    }
	}

	state->dest.writes_pending++;
    }
    
    globus_mutex_unlock(&(state->dest.mutex));
}

void
globus_i_gass_copy_ftp_write_callback(
    void * callback_arg
    /* other args */)
{
    globus_i_gass_copy_generic_write_callback(callback_arg, /* ... */);
}
   
void
globus_i_gass_copy_gass_write_callback(
    void * callback_arg
    /* other args */)
{
    globus_i_gass_copy_generic_write_callback(callback_arg, /* ... */);
}
   
void
globus_i_gass_copy_io_write_callback(
    void * callback_arg
    /* other args */)
{
    globus_i_gass_copy_generic_write_callback(callback_arg, /* ... */);
}
   

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
	globus_gsiftp_client_cache_url_state(
	    &handle->gsiftp_handle,
	    url);
    }
}

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
	globus_gsiftp_client_flush_url_state(
	    &handle->gsiftp_handle,
	    url);
    }
}
    
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
    globus_gsiftp_control_tcpbuffer_t * tcpbuffer_info)
{
}

globus_result_t
globus_gass_copy_attr_set_parallelism(
    globus_gass_copy_attr_t * attr,
    globus_gsiftp_control_parallelism_t * parallelism_info)
{
}

globus_result_t
globus_gass_copy_attr_set_striping(
    globus_gass_copy_attr_t * attr,
    globus_gsiftp_control_striping_t * striping_info)
{
}

globus_result_t
globus_gass_copy_attr_set_authorization(
    globus_gass_copy_attr_t * attr,
    globus_io_authorization_t * authorization_info)
{
}
    
globus_result_t
globus_gass_copy_attr_set_secure_channel(
    globus_gass_copy_attr_t * attr,
    globus_io_secure_channel_t * secure_channel_info)
{
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

/**
 * @file globus_gass_copy.c
 *
 * Short description
 *
 * Long description
 */

#include "globus_gass_copy.h"

#define GLOBUS_GASS_COPY_DEBUG

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


/********************************************************************
 * generic callback to signal completion of asynchronous transfer
 ********************************************************************/
static
void
globus_l_gass_copy_monitor_callback(
    void * callback_arg,
    globus_gass_copy_handle_t * handle,
    globus_object_t * result)
{
    globus_i_gass_copy_monitor_t       *monitor;
    monitor = (globus_i_gass_copy_monitor_t*)callback_arg;

    globus_mutex_lock(&monitor->mutex);
    monitor->done = GLOBUS_TRUE;
    globus_cond_signal(&monitor->cond);
    globus_mutex_lock(&monitor->mutex);

    return;
} /* globus_l_gass_copy_monitor_callback() */


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
    
  globus_ftp_client_handle_init(&handle->ftp_handle);
     
  handle->state = GLOBUS_NULL;
  handle->status = GLOBUS_GASS_COPY_STATUS_NONE;
}

/**
 *  Destroy the GASS copy handle
 */
globus_result_t
globus_gass_copy_destroy(
    globus_gass_copy_handle_t * handle)
{
  
  globus_ftp_client_handle_destroy(&handle->ftp_handle);
    
}

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

void
globus_l_gass_copy_io_setup_get(
    globus_gass_copy_state_t * state);

void
globus_l_gass_copy_io_setup_put(
    globus_gass_copy_state_t * state);

void
globus_l_gass_copy_ftp_setup_get(
    globus_gass_copy_handle_t * handle);

void
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
    globus_i_gass_copy_monitor_t        monitor;

    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    /*
    monitor.err = GLOBUS_NULL;
    monitor.use_err = GLOBUS_FALSE;
           */
    globus_gass_copy_register_url_to_url(
	handle,
	source_url,
	source_attr,
	dest_url,
	dest_attr,
	globus_l_gass_copy_monitor_callback,
	(void *) &monitor);
    
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
    /*
    if(monitor.use_err)
    {
        return globus_error_put(monitor.err);
    }
    else
    {
        return GLOBUS_SUCCESS;
    }
    */
    
} /* globus_gass_copy_url_to_url() */


/**
 * get the status of the current transfer
 */
globus_gass_copy_status_t
globus_gass_copy_get_status(
    globus_gass_copy_handle_t * handle)
{
    return (handle->status);
} /* globus_gass_copy_get_status() */


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
    int rc;

    if ((rc = globus_url_parse(url, &url_info)) != GLOBUS_SUCCESS)
    {
      /* return rc; */
    }
    /*  FIXX  - need to get the GSIFTP back in there
     */
      if ( (url_info.scheme_type == GLOBUS_URL_SCHEME_FTP) ||
	   (url_info.scheme_type == GLOBUS_URL_SCHEME_GSIFTP) )
	/*	 
    if ( (url_info.scheme_type == GLOBUS_URL_SCHEME_FTP)  )
	*/
    {
       *type = GLOBUS_I_GASS_COPY_URL_SCHEME_FTP;
    }
    else if ( (url_info.scheme_type == GLOBUS_URL_SCHEME_HTTP) ||
              (url_info.scheme_type == GLOBUS_URL_SCHEME_HTTPS) )
    {
       *type = GLOBUS_I_GASS_COPY_URL_SCHEME_HTTP;
    }
    else if ( (url_info.scheme_type == GLOBUS_URL_SCHEME_FILE))
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
 * Populate the target transfer structures
 */
globus_result_t
globus_l_gass_copy_target_populate(
    globus_i_gass_copy_target_t * target,
    globus_i_gass_copy_url_scheme_t * url_scheme,
    char * url,
    globus_gass_copy_attr_t * attr)
{
    globus_gass_copy_attr_t * tmp_attr;
  /* initialize the target mutex */
    globus_mutex_init(&(target->mutex), GLOBUS_NULL);

    target->n_pending = 0;
    target->n_complete = 0;
    target->status = GLOBUS_I_GASS_COPY_TARGET_INITIAL;

    if(attr == GLOBUS_NULL)
    {
      target->free_attr = GLOBUS_TRUE;
      tmp_attr = (globus_gass_copy_attr_t *) globus_libc_malloc(sizeof(globus_gass_copy_attr_t));
      
      tmp_attr->ftp_attr = GLOBUS_NULL;
      tmp_attr->io = GLOBUS_NULL;
      tmp_attr->gass_requestattr = GLOBUS_NULL;
      attr = tmp_attr;
    }
    else
      target->free_attr = GLOBUS_FALSE;

    switch (*url_scheme)
    {
        case GLOBUS_I_GASS_COPY_URL_SCHEME_FTP:

             target->mode = GLOBUS_I_GASS_COPY_TARGET_MODE_FTP;
             target->url = globus_libc_strdup(url);
             target->attr = *attr;
	     /* FIXX n_simultaneous should be pulled from attributes, or something */
	     target->n_simultaneous = 1;
             break;

        case GLOBUS_I_GASS_COPY_URL_SCHEME_HTTP:

             target->mode = GLOBUS_I_GASS_COPY_TARGET_MODE_GASS;
             target->url = globus_libc_strdup(url);
             target->attr = *attr;
	     target->n_simultaneous = 1;
             break;

        case GLOBUS_I_GASS_COPY_URL_SCHEME_FILE:

             target->mode = GLOBUS_I_GASS_COPY_TARGET_MODE_IO;
             target->url = globus_libc_strdup(url);
             target->attr = *attr;
             target->data.io.free_handle = GLOBUS_TRUE;
             target->data.io.seekable = GLOBUS_TRUE;
	     target->n_simultaneous = 1;

             break;

        case GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED:
             /* something went horribly wrong */
             break;
    }
    return GLOBUS_SUCCESS;
} /* globus_l_gass_copy_target_populate() */

globus_result_t
globus_l_gass_copy_io_target_populate(
    globus_i_gass_copy_target_t * target,
    globus_io_handle_t * handle)
{
    target->free_attr = GLOBUS_FALSE;
  /* initialize the target mutex */
    globus_mutex_init(&(target->mutex), GLOBUS_NULL);

    target->data.io.handle = handle;
    
    target->n_pending = 0;
    target->status = GLOBUS_I_GASS_COPY_TARGET_INITIAL;

    target->mode = GLOBUS_I_GASS_COPY_TARGET_MODE_IO;
   
    target->data.io.free_handle = GLOBUS_FALSE;
    if(globus_io_get_handle_type(handle) == GLOBUS_IO_HANDLE_TYPE_FILE)
      target->data.io.seekable = GLOBUS_TRUE;
    else
      target->data.io.seekable = GLOBUS_FALSE;
    target->n_simultaneous = 1;
    
     
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
    globus_libc_free(&(target->attr));

  switch(target->mode)
  {
      case GLOBUS_I_GASS_COPY_TARGET_MODE_FTP:
	   /* FIXX -- free the url*/
	   break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_GASS:
	   /* FIXX -- free the url*/
	   break;
	   
      case GLOBUS_I_GASS_COPY_TARGET_MODE_IO:
	   if(target->data.io.free_handle == GLOBUS_TRUE)
	   {
	     globus_libc_free(&(target->data.io.handle));
	     /* FIXX -- free the url*/
	   }
	   break;
  }
} /* gloubs_l_gass_copy_target_destroy() */

/**
 * instantiate state structure
 */
globus_result_t
globus_l_gass_copy_state_new(
    globus_gass_copy_handle_t *handle
/*
     globus_i_gass_copy_target_mode_t * mode,
     char * url,
     globus_gass_copy_attr_t * attr,

    globus_gass_copy_state_t ** state
*/
    )
{ 
  globus_gass_copy_state_t ** tmp_state = &(handle->state);
  *tmp_state = (globus_gass_copy_state_t *)
         globus_libc_malloc(sizeof(globus_gass_copy_state_t));
  /* do we need this?   i don't think so...*/
  /*  (*tmp_state)->handle = handle;  */
  
    handle->status = GLOBUS_GASS_COPY_STATUS_INITIAL;
    handle->err = GLOBUS_SUCCESS;

     /* comes from source_attr, or defaults */
    /* FIXX - set buffer_length properly */
    (*tmp_state)->buffer_length = 1024 *1024;
    
     /* initialize the monitor */   
    globus_mutex_init(&((*tmp_state)->monitor.mutex), GLOBUS_NULL);
    globus_cond_init(&((*tmp_state)->monitor.cond), GLOBUS_NULL);
    (*tmp_state)->monitor.done = GLOBUS_FALSE;
    /*   
    state->monitor.err = GLOBUS_NULL;
    state->monitor.use_err = GLOBUS_FALSE;
    */
     globus_mutex_init(&((*tmp_state)->mutex), GLOBUS_NULL);
} /* globus_l_gass_copy_state_new() */

/**
 * free state structure
 */
globus_result_t
globus_l_gass_copy_state_free(
    globus_gass_copy_state_t * state)
{
#ifdef GLOBUS_GASS_COPY_DEBUG
  printf("globus_l_gass_copy_state_free(): freeing up the state\n");
#endif
  /* clean  up the monitor */
  globus_mutex_destroy(&(state->monitor.mutex));
  globus_cond_destroy(&(state->monitor.cond));

  globus_mutex_destroy(&(state->mutex));
  /* FIXX-  put target_destroy() back in */  
  /* clean  up the source target */
/*  globus_l_gass_copy_target_destroy(&(state->source)); */
  /* clean  up the destination target */
/*  globus_l_gass_copy_target_destroy(&(state->dest)); */
  
  /* free up the state and set it to NULL */
  
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
  globus_result_t result;

#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("made it to globus_l_gass_copy_transfer_start()\n");
#endif
    
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
	if ((result = globus_i_gass_copy_attr_duplicate(&(state->source.attr)))
            != GLOBUS_SUCCESS)
        {
           return result;
        }

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
    /* setup read queue
            */
    if (globus_fifo_init(&(state->source.queue)) != GLOBUS_SUCCESS)
    {
      /* FIXX -- do error handling properly 
	 return(GLOBUS_FAILURE);
      */
    }
    /* setup write queue
            */
    if (globus_fifo_init(&(state->dest.queue)) != GLOBUS_SUCCESS)
    {
      /* FIXX -- do error handling properly
	 return(GLOBUS_FAILURE);
      */
    }

    /* depending on the mode, call the appropriate routine to start the
     * transfer
     */
    switch (state->source.mode)
    {
      case GLOBUS_I_GASS_COPY_TARGET_MODE_FTP:

	state->source.data.ftp.n_channels = 0;
	state->source.data.ftp.n_reads_posted = 0;

        globus_l_gass_copy_ftp_setup_get(handle);

	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_GASS:
#ifdef GLOBUS_GASS_COPY_DEBUG
	  printf("transfer_start(): about to call globus_gass_transfer_register_get()\n");
#endif
	globus_gass_transfer_register_get(
	    &(state->source.data.gass.request),
	    (state->source.attr.gass_requestattr),
	    state->source.url,
	    globus_l_gass_copy_gass_setup_callback,
	    (void *) handle);

	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_IO:

	globus_l_gass_copy_io_setup_get(state);

	break;
    }

    /* wait for ok from the source */
    globus_mutex_lock(&(state->monitor.mutex));
#ifdef GLOBUS_GASS_COPY_DEBUG
 printf("transfer_start(): about to cond_wait() while source is setup\n");
#endif
    while(state->source.status == GLOBUS_I_GASS_COPY_TARGET_INITIAL)
    {
        globus_cond_wait(&state->monitor.cond,
			 &state->monitor.mutex);
	/* FIXX -- do error handling properly 
	if(state->err) return(GLOBUS_FAILURE);
	*/
    }
    globus_mutex_unlock(&state->monitor.mutex);    
    handle->status = GLOBUS_GASS_COPY_STATUS_SOURCE_READY;
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("transfer_start(): source is ready\n");
#endif
    /*
     * Now get the destination side ready
     */
    switch (state->dest.mode)
    {
      case GLOBUS_I_GASS_COPY_TARGET_MODE_FTP:

	state->dest.data.ftp.n_channels = 0;
	state->dest.data.ftp.n_reads_posted = 0;

	globus_l_gass_copy_ftp_setup_put(handle);
        
	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_GASS:
#ifdef GLOBUS_GASS_COPY_DEBUG
	  printf("transfer_start(): about to call globus_gass_transfer_register_put()\n");
#endif
        globus_gass_transfer_register_put(
	    &(state->dest.data.gass.request),
	    (state->dest.attr.gass_requestattr),
	    state->dest.url,
	    GLOBUS_NULL,
	    globus_l_gass_copy_gass_setup_callback,
	    (void *) handle);

	break;

       case GLOBUS_I_GASS_COPY_TARGET_MODE_IO:

	 globus_l_gass_copy_io_setup_put(state);

	 break;
    }

    /* wait for ok from the dest */
    globus_mutex_lock(&(state->monitor.mutex));
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("transfer_start(): about to cond_wait() while dest is setup\n");
#endif
    while(state->dest.status == GLOBUS_I_GASS_COPY_TARGET_INITIAL)
    {
        globus_cond_wait(&state->monitor.cond,
			 &state->monitor.mutex);
	/* FIXX -- do error handling properly 
	if(state->err) return(GLOBUS_FAILURE);
	*/
    }
    globus_mutex_unlock(&state->monitor.mutex);
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("transfer_start(): dest is ready, let's get goin'\n");
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
    
    globus_mutex_lock(&(state->source.mutex));
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("read_from_queue(): n_pending= %d  n_simultaneous= %d\n", state->source.n_pending, state->source.n_simultaneous);
#endif

    /* if the source is READY (and not DONE), see if we should register a read
     */
    if(state->source.status == GLOBUS_I_GASS_COPY_TARGET_READY)
    {
	
      /*  FIXX --
       *  this needs to be a while loop, so that ftp can take advantage of
       *  multiple channels
       */
      /* if there aren't too many reads pending, register one */
	if(state->source.n_pending < state->source.n_simultaneous)
	{
	  if ((buffer_entry = globus_fifo_dequeue(&(state->source.queue)))
              != GLOBUS_NULL)
	  {
#ifdef GLOBUS_GASS_COPY_DEBUG
	    printf("read_from_queue: about to register_read() with buffer from fifo\n");
#endif
	    state->source.n_pending++;
	    globus_l_gass_copy_register_read(
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
		
		buffer = globus_libc_malloc(state->buffer_length);
		state->source.n_pending++;
		globus_l_gass_copy_register_read(
		     handle,
		     buffer);
	      }
	    }
	    globus_mutex_unlock(&(state->mutex));
	  }/* else (no available buffers in fifo, create a new one, maybe*/
	}/* if(state->source.n_pending < state->source.n_simultaneous) */
    } /* if(state->source.status == GLOBUS_I_GASS_COPY_TARGET_READY) */
    globus_mutex_unlock(&(state->source.mutex));
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("read_from_queue(): returning\n");
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
    switch (state->source.mode)
    {
      case GLOBUS_I_GASS_COPY_TARGET_MODE_FTP:
#ifdef GLOBUS_GASS_COPY_DEBUG
	printf("register_read():  calling globus_ftp_client_register_read()\n");
#endif	  
 	globus_ftp_client_register_read(
	    /*state->source.data.ftp.handle,*/
	    &(handle->ftp_handle),
	    buffer,
	    state->buffer_length,
	    globus_l_gass_copy_ftp_read_callback,
	    (void *) handle);
	    
	  break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_GASS:
#ifdef GLOBUS_GASS_COPY_DEBUG
	printf("register_read():  calling globus_gass_transfer_receive_bytes()\n");
#endif
	globus_gass_transfer_receive_bytes(
	    state->source.data.gass.request,
	    buffer,
	    state->buffer_length,
	    state->buffer_length,
	    globus_l_gass_copy_gass_read_callback,
	    (void *) handle);
	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_IO:

	globus_io_register_read(
	    state->source.data.io.handle,
	    buffer,
	    state->buffer_length,
	    state->buffer_length,
	    globus_l_gass_copy_io_read_callback,
	    (void *) handle);

	
	break;
    }
    
} /* globus_l_gass_copy_register_read */

/*****************************************************************
 * setup callbacks
 *****************************************************************/

void
globus_l_gass_copy_generic_setup_callback(
    globus_gass_copy_handle_t *  handle)
{
    /* how to handle multiple buffers? for loop around register_read */
    
    globus_l_gass_copy_register_read(
	handle,
	(globus_byte_t *) GLOBUS_NULL); /* malloc new buffer */

} /* globus_l_gass_copy_generic_setup_callback() */

void
globus_l_gass_copy_ftp_setup_callback(
    globus_gass_copy_handle_t * handle)
{
    globus_l_gass_copy_generic_setup_callback(handle);
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

void
globus_l_gass_copy_gass_setup_callback(
    void * callback_arg,
    globus_gass_transfer_request_t  request)
{
    globus_gass_transfer_referral_t  referral;
    int rc;

    globus_gass_copy_handle_t *  handle
      = (globus_gass_copy_handle_t *) callback_arg;
    globus_gass_copy_state_t * state = handle->state;
	

    globus_gass_transfer_request_status_t status;
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("globus_l_gass_copy_gass_setup_callback() called\n");
#endif   
    status = globus_gass_transfer_request_get_status(request);

    switch(status)
    {
      case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
#ifdef GLOBUS_GASS_COPY_DEBUG
	  printf("request status == GLOBUS_GASS_TRANSFER_REQUEST_REFERRED\n");
#endif
           globus_gass_transfer_request_get_referral(request, &referral);
           globus_gass_transfer_request_destroy(request);

           if (handle->status == GLOBUS_GASS_COPY_STATUS_INITIAL)
           {
               /* first setup the source with the register get
                */
#ifdef GLOBUS_GASS_COPY_DEBUG
	       printf("REQUEST_REFERRED:  STATE_INITIAL\n");
#endif
               state->source.url =
                   globus_gass_transfer_referral_get_url(&referral, 0);
	       
#ifdef GLOBUS_GASS_COPY_DEBUG              
	       printf("REQUEST_REFERRED: about to globus_gass_transfer_register_get() again with: %s\n",state->source.url);
#endif
               if ( (rc = globus_gass_transfer_register_get(
                     &(state->source.data.gass.request),
                     (state->source.attr.gass_requestattr),
                     state->source.url,
                     globus_l_gass_copy_gass_setup_callback,
                     (void *) handle)) != GLOBUS_SUCCESS )
               {
                   globus_mutex_lock(&state->monitor.mutex);
#ifdef GLOBUS_GASS_COPY_DEBUG	   
		   printf("gass_setup_callback(): transfer_register_get() returned: %d\n", rc);
		   if(rc==GLOBUS_GASS_ERROR_BAD_URL)
		       printf("rc == GLOBUS_GASS_ERROR_BAD_URL\n");
#endif
                   handle->err = rc;
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
               {
                   globus_mutex_lock(&state->monitor.mutex);
                   handle->err = rc;
                   goto wakeup_state;
               }
           }

           break;

      case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
#ifdef GLOBUS_GASS_COPY_DEBUG
	  printf("request status == GLOBUS_GASS_TRANSFER_REQUEST_PENDING, should signal the monitor\n");
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
#ifdef GLOBUS_GASS_COPY_DEBUG
	  printf("request status == GLOBUS_GASS_TRANSFER_REQUEST_DONE\n");
#endif
           globus_mutex_lock(&state->monitor.mutex);
           goto wakeup_state;
           break;

      case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
#ifdef GLOBUS_GASS_COPY_DEBUG
	  printf("request status == GLOBUS_GASS_TRANSFER_REQUEST_DENIED\n");
#endif
           globus_mutex_lock(&state->monitor.mutex);
           handle->err = globus_gass_transfer_request_get_denial_reason(request);
           /* globus_gass_transfer_request_get_denial_message(request)); */
           goto wakeup_state;
           break;

      case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
#ifdef GLOBUS_GASS_COPY_DEBUG
	  printf("request status == GLOBUS_GASS_TRANSFER_REQUEST_FAILED\n");
#endif
           globus_mutex_lock(&state->monitor.mutex);
           /* needs real error */
           handle->err = GLOBUS_GASS_TRANSFER_REQUEST_FAILED;
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

void
globus_l_gass_copy_io_setup_get(
    globus_gass_copy_state_t * state)
{
    globus_url_t parsed_url;
    globus_result_t rc;
    
    if (state->source.data.io.free_handle)
    {
        globus_url_parse(state->source.url, &parsed_url);
        state->source.data.io.handle =(globus_io_handle_t *)
            globus_libc_malloc(sizeof(globus_io_handle_t));

        rc = globus_io_file_open(
                 parsed_url.url_path,
                 GLOBUS_IO_FILE_RDONLY,
                 GLOBUS_IO_FILE_IRUSR,
                 state->source.attr.io,
                 state->source.data.io.handle);
#ifdef GLOBUS_GASS_COPY_DEBUG
	if(rc==GLOBUS_SUCCESS)
	  printf("io_setup_get(): SUCCESS opening %s\n",parsed_url.url_path);
	else
	  printf("io_setup_get(): FAILURE opening %s\n",parsed_url.url_path);
#endif
    }
#ifdef GLOBUS_GASS_COPY_DEBUG
    else
      printf("io_setup_get(): handle should already have been  opened by the user\n");
#endif
    state->source.status = GLOBUS_I_GASS_COPY_TARGET_READY;
} /* globus_l_gass_copy_io_setup_get() */

void
globus_l_gass_copy_io_setup_put(
    globus_gass_copy_state_t * state)
{
    globus_url_t parsed_url;
    globus_result_t rc;
    
    if (state->dest.data.io.free_handle)
    {
        globus_url_parse(state->dest.url, &parsed_url);
        state->dest.data.io.handle = (globus_io_handle_t *)
            globus_libc_malloc(sizeof(globus_io_handle_t));

        rc = globus_io_file_open(
                 parsed_url.url_path,
                 (GLOBUS_IO_FILE_WRONLY | GLOBUS_IO_FILE_CREAT),
                 (GLOBUS_IO_FILE_IRUSR | GLOBUS_IO_FILE_IWUSR),
                 state->dest.attr.io,
                 state->dest.data.io.handle);
#ifdef GLOBUS_GASS_COPY_DEBUG
	if(rc==GLOBUS_SUCCESS)
	  printf("io_setup_put(): SUCCESS opening %s\n",parsed_url.url_path);
	else
	  printf("io_setup_put(): FAILURE opening %s\n",parsed_url.url_path);
#endif
    }
#ifdef GLOBUS_GASS_COPY_DEBUG
    else
      printf("io_setup_put(): handle should already have been  opened by the user\n");
#endif   
    state->dest.status = GLOBUS_I_GASS_COPY_TARGET_READY;

} /* globus_l_gass_copy_io_setup_put() */


void
globus_l_gass_copy_ftp_setup_get(
    globus_gass_copy_handle_t * handle)
{
    globus_gass_copy_state_t * state = handle->state;
    globus_result_t rc;

    rc = globus_ftp_client_get(
		   &(handle->ftp_handle),
		   state->source.url,
		   state->source.attr.ftp_attr,
		   GLOBUS_NULL,
		   globus_l_gass_copy_ftp_get_done_callback,
		   (void *) handle);
    

#ifdef GLOBUS_GASS_COPY_DEBUG
    if(rc==GLOBUS_SUCCESS)
      printf("ftp_setup_get(): SUCCESS opening %s\n",state->source.url);
    else
      printf("ftp_setup_get(): FAILURE opening %s\n",state->source.url);
#endif

    state->source.status = GLOBUS_I_GASS_COPY_TARGET_READY;
} /* globus_l_gass_copy_ftp_setup_get() */

void
globus_l_gass_copy_ftp_setup_put(
    globus_gass_copy_handle_t * handle)
{
    globus_gass_copy_state_t * state = handle->state;
    globus_result_t rc;

    rc = globus_ftp_client_put(
		   &(handle->ftp_handle),
		   state->dest.url,
		   state->dest.attr.ftp_attr,
		   GLOBUS_NULL,
		   globus_l_gass_copy_ftp_get_done_callback,
		   (void *) handle);
    

#ifdef GLOBUS_GASS_COPY_DEBUG
    if(rc==GLOBUS_SUCCESS)
      printf("ftp_setup_put(): SUCCESS opening %s\n",state->dest.url);
    else
      printf("ftp_setup_put(): FAILURE opening %s\n",state->dest.url);
#endif

    state->dest.status = GLOBUS_I_GASS_COPY_TARGET_READY;
} /* globus_l_gass_copy_ftp_setup_put() */



void
globus_l_gass_copy_ftp_transfer_callback(
    void *			       user_arg,
    globus_ftp_client_handle_t *       handle,
    globus_object_t *		       error)
{
    globus_gass_copy_handle_t * copy_handle
	= (globus_gass_copy_handle_t *) user_arg;

    globus_l_gass_copy_state_free(copy_handle->state);
      copy_handle->state = GLOBUS_NULL;

#ifdef GLOBUS_GASS_COPY_DEBUG
      if(copy_handle->state == GLOBUS_NULL)
	printf("copy_handle->state == GLOBUS_NULL\n");
      printf("globus_l_gass_copy_ftp_transfer_callback(): about to call user callback\n");
#endif 
      copy_handle->user_callback(
	       copy_handle->callback_arg,
	       copy_handle,
	       copy_handle->result);
    
} /* globus_l_gass_copy_ftp_transfer_callback() */

void
globus_l_gass_copy_ftp_get_done_callback(
    void * callback_arg,
    globus_ftp_client_handle_t * handle,
    globus_object_t *	       error)
{
    globus_gass_copy_handle_t * copy_handle
	= (globus_gass_copy_handle_t *) callback_arg;
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
#ifdef GLOBUS_GASS_COPY_DEBUG   
    printf("generic_read_callback(): read %d bytes\n", nbytes);
#endif   
    globus_mutex_lock(&(state->source.mutex));
    state->source.n_pending--;
    globus_mutex_unlock(&(state->source.mutex));

    /* if this buffer has anything in it,
     * put it in the write queue
     */
    
    if(nbytes >0)
    {
      buffer_entry = (globus_i_gass_copy_buffer_t *)
	globus_libc_malloc(sizeof(globus_i_gass_copy_buffer_t));
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
#ifdef GLOBUS_GASS_COPY_DEBUG
    else
      printf("generic_read_callback(): handle->state == GLOBUS_NULL\n");
#endif

  /* if we haven't read everything from the source, read again */
    if(handle->state)
      globus_l_gass_copy_read_from_queue(handle);
#ifdef GLOBUS_GASS_COPY_DEBUG
    else
      printf("generic_read_callback(): handle->state == GLOBUS_NULL\n");
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

#ifdef GLOBUS_GASS_COPY_DEBUG
	printf("ftp_read_callback(): has been called\n");
#endif    
   
    last_data = eof;
    if(eof)
    {    
      globus_mutex_lock(&(state->source.mutex));
      {
	state->source.status = GLOBUS_I_GASS_COPY_TARGET_DONE;
      }
      globus_mutex_unlock(&(state->source.mutex));
      if(copy_handle->status < GLOBUS_GASS_COPY_STATUS_READ_COMPLETE)
	copy_handle->status = GLOBUS_GASS_COPY_STATUS_READ_COMPLETE;
    }
    
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
    globus_gass_copy_handle_t * handle
	= (globus_gass_copy_handle_t *) callback_arg;
    globus_gass_copy_state_t * state = handle->state;
    req_status = globus_gass_transfer_request_get_status(request);
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("globus_l_gass_copy_gass_read_callback(): req_status= %d\n", req_status);
#endif
    if(last_data)
    { /* this was the last read.  set READ_COMPLETE and free the request */
	int rc;
	globus_mutex_lock(&(state->source.mutex));
	{
	  state->source.status = GLOBUS_I_GASS_COPY_TARGET_DONE;
	}
	globus_mutex_unlock(&(state->source.mutex));
	handle->status = GLOBUS_GASS_COPY_STATUS_READ_COMPLETE;

	rc = globus_gass_transfer_request_get_status(request);
	if(rc == GLOBUS_GASS_TRANSFER_REQUEST_DONE)
	{
#ifdef GLOBUS_GASS_COPY_DEBUG
	  printf("gass_read_callback(): GLOBUS_GASS_TRANSFER_REQUEST_DONE\n");
#endif
	  globus_gass_transfer_request_destroy(request);
	}
	else
	{
	    /* there's an error, tell someone who cares */
#ifdef GLOBUS_GASS_COPY_DEBUG
	  printf("gass_read_callback(): this was last_data, but status !=GLOBUS_GASS_TRANSFER_REQUEST_DONE\n");
#endif
	}
    }/* if(last_data) */
    
    offset = state->source.n_complete * state->buffer_length;
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
    globus_object_t * err;
    globus_bool_t last_data=GLOBUS_FALSE;
    globus_gass_copy_handle_t * handle
	= (globus_gass_copy_handle_t *) callback_arg;
    globus_gass_copy_state_t * state = handle->state;
   
#ifdef GLOBUS_GASS_COPY_DEBUG
    if(result== GLOBUS_SUCCESS)
      printf("io_read_callback(): result == GLOBUS_SUCCESS\n");
    else
      printf("io_read_callback(): result != GLOBUS_SUCCESS\n");
    
    printf("io_read_callback(): %d bytes READ\n", nbytes);
#endif
    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);
	last_data=globus_io_eof(err);
    }   
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("io_read_callback(): last_data == %d\n", last_data);
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
#ifdef GLOBUS_GASS_COPY_DEBUG
	printf("io_read_callback(): this was the last READ, source.status == GLOBUS_I_GASS_COPY_TARGET_DONE\n");
#endif
	if(state->source.data.io.free_handle)
	{
	  globus_io_close(io_handle);
#ifdef GLOBUS_GASS_COPY_DEBUG
	  printf("io_read_callback(): handle closed\n");
#endif
	  /*   thinking that this should go in the globus_l_gass_copy_state_free()
	       globus_libc_free(handle);
	  */
	}
	
	
    }/* if(last_data) */

    offset = state->source.n_complete * state->buffer_length;
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
    
    globus_mutex_lock(&(state->dest.mutex));
    state->dest.n_pending--;
    globus_mutex_unlock(&(state->dest.mutex));
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("generic_write_callback(): wrote %d bytes\n", nbytes);
#endif
    /* push the buffer on the read queue and start another read */
    
    buffer_entry = (globus_i_gass_copy_buffer_t *)
      globus_libc_malloc(sizeof(globus_i_gass_copy_buffer_t));
    buffer_entry->bytes  = bytes;
    globus_mutex_lock(&(state->source.mutex));
    globus_fifo_enqueue( &(state->source.queue), buffer_entry);
    globus_mutex_unlock(&(state->source.mutex));
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("generic_write_callback(): calling read_from_queue()\n");
#endif
    if(handle->state)
      globus_l_gass_copy_read_from_queue(handle);
#ifdef GLOBUS_GASS_COPY_DEBUG
    else
      printf("generic_write_callback(): handle->state == GLOBUS_NULL\n");
#endif
	
	
     /* if there are more writes to do, register the next write */
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("generic_write_callback(): calling write_from_queue()\n");
#endif
    if(handle->state)
      globus_l_gass_copy_write_from_queue(handle);
#ifdef GLOBUS_GASS_COPY_DEBUG
    else
      printf("generic_write_callback(): handle->state == GLOBUS_NULL\n");
#endif

} /* globus_l_gass_copy_generic_write_callback() */

void
globus_l_gass_copy_write_from_queue(
    globus_gass_copy_handle_t * handle)
{
    globus_gass_copy_state_t * state = handle->state;
    globus_i_gass_copy_buffer_t *  buffer_entry;
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("globus_l_gass_copy_write_from_queue(): called\n");
#endif
   
    globus_mutex_lock(&(state->dest.mutex));

    /* if the dest is READY (and not DONE), see if we should register a write
     */
    if(state->dest.status == GLOBUS_I_GASS_COPY_TARGET_READY)
    {

      /*  FIXX --
       *  this needs to be a while loop, so that ftp can take advantage of
       *  multiple channels
       */
      /*
       * if there aren't too many writes pending.  check the write queue,
       * and if there is one then register the first one to write.
       */
      if(state->dest.n_pending < state->dest.n_simultaneous)
	{
	  if ((buffer_entry = globus_fifo_dequeue(&(state->dest.queue)))
              != GLOBUS_NULL)
	  {
	    state->dest.n_pending++;
#ifdef GLOBUS_GASS_COPY_DEBUG
	    printf("write_from_queue(): about to call register_write()\n");
#endif
	    globus_l_gass_copy_register_write(
		handle,
		buffer_entry);
	    /* globus_mutex_unlock(&(state->dest.mutex)); */
	    
	  }/* if (buffer_entry != GLOBUS_NULL) */
	     
	}/* if (dest _TARGET_READY) */
    } /* if (dest n_pending < n_simultaneous) */

/* if there are no writes to do, and no writes pending, clean up and call user's callback */
    if(state->source.status == GLOBUS_I_GASS_COPY_TARGET_DONE &&
       state->dest.status == GLOBUS_I_GASS_COPY_TARGET_DONE  )
    {
#ifdef GLOBUS_GASS_COPY_DEBUG
	    printf("write_from_queue(): source and dest status == TARGET_DONE\n");
#endif      
	if(state->dest.n_pending == 0 && state->source.n_pending == 0 )
	  { /* our work here is done */
	  handle->status =   GLOBUS_GASS_COPY_STATUS_DONE;	  
	}	
    }

    globus_mutex_unlock(&(state->dest.mutex));
    if(handle->status == GLOBUS_GASS_COPY_STATUS_DONE)
    {
      /* do cleanup */
      globus_l_gass_copy_state_free(handle->state);
      handle->state = GLOBUS_NULL;

#ifdef GLOBUS_GASS_COPY_DEBUG
      if(handle->state == GLOBUS_NULL)
	printf("  handle->state == GLOBUS_NULL\n");
      printf("write_from_queue(): about to call user callback\n");
#endif 
      handle->user_callback(
	       handle->callback_arg,
	       handle,
	       handle->result);
    }
} /* globus_l_gass_copy_write_from_queue() */

globus_result_t
globus_l_gass_copy_register_write(
    globus_gass_copy_handle_t * handle,
    globus_i_gass_copy_buffer_t * buffer_entry)
{
    globus_gass_copy_state_t * state = handle->state;
    switch (state->dest.mode)
    {
      case GLOBUS_I_GASS_COPY_TARGET_MODE_FTP:
	/* check the offset to see if its what we are expecting */
	  
	globus_ftp_client_register_write(
	    state->dest.data.ftp.handle,
	    buffer_entry->bytes,
	    buffer_entry->nbytes,
	    buffer_entry->offset,
	    buffer_entry->last_data,
	    globus_l_gass_copy_ftp_write_callback,
	    (void *) handle);
	    
	  break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_GASS:
#ifdef GLOBUS_GASS_COPY_DEBUG
	printf("register_write(): send_bytes -- %d bytes (last_data==%d)\n", buffer_entry->nbytes, buffer_entry->last_data);
#endif
	/* check the offset to see if its what we are expecting */
	globus_gass_transfer_send_bytes(
	    state->dest.data.gass.request,
	    buffer_entry->bytes,
	    buffer_entry->nbytes,
	    buffer_entry->last_data,
	    globus_l_gass_copy_gass_write_callback,
	    (void *) handle);
	break;

      case GLOBUS_I_GASS_COPY_TARGET_MODE_IO:

	if (state->dest.data.io.seekable &&
	    state->source.mode == GLOBUS_I_GASS_COPY_TARGET_MODE_FTP)
	{
	    globus_io_file_seek(
		state->dest.data.io.handle,
		buffer_entry->offset,
		GLOBUS_IO_SEEK_SET);
	}
	
	globus_io_register_write(
	    state->dest.data.io.handle,
	    buffer_entry->bytes,
	    buffer_entry->nbytes,
	    globus_l_gass_copy_io_write_callback,
	    (void *) handle);
	
	break;
    }/* switch (state->dest.mode) */

    globus_libc_free(buffer_entry);
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
    last_data = eof;
    if(eof)
    {    
      globus_mutex_lock(&(state->dest.mutex));
      {
	state->dest.status = GLOBUS_I_GASS_COPY_TARGET_DONE;
      }
      globus_mutex_unlock(&(state->dest.mutex));
      if(copy_handle->status < GLOBUS_GASS_COPY_STATUS_WRITE_COMPLETE)
	copy_handle->status = GLOBUS_GASS_COPY_STATUS_WRITE_COMPLETE;
    }
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
    globus_gass_copy_handle_t * handle
	= (globus_gass_copy_handle_t *) callback_arg;
    globus_gass_copy_state_t * state = handle->state;
    req_status = globus_gass_transfer_request_get_status(request);
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("gass_write_callback(): last_data== %d, req_status= %d\n", last_data, req_status);
#endif
    if(last_data)
    { /* this was the last write.  set WRITE_COMPLETE and free the request */
        int rc;
#ifdef GLOBUS_GASS_COPY_DEBUG
	printf("gass_write_callback(): THIS WAS THE LAST WRITE\n");
#endif
	globus_mutex_lock(&(state->dest.mutex));
	{
	  state->dest.status = GLOBUS_I_GASS_COPY_TARGET_DONE;
	}
	globus_mutex_unlock(&(state->dest.mutex));
	handle->status = GLOBUS_GASS_COPY_STATUS_WRITE_COMPLETE;
	rc = globus_gass_transfer_request_get_status(request);
	if(rc == GLOBUS_GASS_TRANSFER_REQUEST_DONE)
	{
#ifdef GLOBUS_GASS_COPY_DEBUG
	  printf("gass_write_callback(): GLOBUS_GASS_TRANSFER_REQUEST_DONE\n");
#endif
	  globus_gass_transfer_request_destroy(request);
	}
	else
	{
	    /* there's an error, tell someone who cares */
#ifdef GLOBUS_GASS_COPY_DEBUG
	  printf("gass_write_callback(): this was last_data, but status !=GLOBUS_GASS_TRANSFER_REQUEST_DONE\n");

	  if(req_status == GLOBUS_GASS_TRANSFER_REQUEST_FAILED)
	    printf("   in fact, req_status == GLOBUS_GASS_TRANSFER_REQUEST_FAILED\n");
#endif
	}
    } /* if (last_data) */
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

#ifdef GLOBUS_GASS_COPY_DEBUG
    if(result==GLOBUS_SUCCESS)
      printf("io_write_callback(): result == GLOBUS_SUCCESS\n");
    else
      printf("io_write_callback(): result != GLOBUS_SUCCESS\n");
#endif
    globus_mutex_lock(&(state->source.mutex));
    {    
      if(state->source.status == GLOBUS_I_GASS_COPY_TARGET_DONE &&
	 state->source.n_pending == 0)
	{
#ifdef GLOBUS_GASS_COPY_DEBUG
	  printf("io_write_callback(): THIS WAS THE LAST WRITE\n");
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
#ifdef GLOBUS_GASS_COPY_DEBUG
	    printf("io_write_callback(): handle closed\n");
#endif
	    /*   thinking that this should go in the globus_l_gass_copy_state_free()
	            globus_libc_free(handle);	  
	        */
	  }
	
	  
	} /* end if last write */
    }
    globus_mutex_unlock(&(state->source.mutex));
    
    globus_l_gass_copy_generic_write_callback(
        handle,
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
  globus_i_gass_copy_monitor_t        monitor;

  globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
  globus_cond_init(&monitor.cond, GLOBUS_NULL);
  monitor.done = GLOBUS_FALSE;

  globus_gass_copy_register_url_to_handle(
      handle,
      source_url,
      source_attr,
      dest_handle,
      globus_l_gass_copy_monitor_callback,
      (void *) &monitor);
  
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
    /*
    if(monitor.use_err)
    {
        return globus_error_put(monitor.err);
    }
    else
    {
        return GLOBUS_SUCCESS;
    }
    */
} /* globus_gass_copy_url_to_handle() */

globus_result_t
globus_gass_copy_handle_to_url(
    globus_gass_copy_handle_t * handle,
    globus_io_handle_t * source_handle,
    char * dest_url,
    globus_gass_copy_attr_t * dest_attr)
{
    globus_i_gass_copy_monitor_t        monitor;

  globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
  globus_cond_init(&monitor.cond, GLOBUS_NULL);
  monitor.done = GLOBUS_FALSE;

  globus_gass_copy_register_handle_to_url(
      handle,
      source_handle,
      dest_url,
      dest_attr,    
      globus_l_gass_copy_monitor_callback,
      (void *) &monitor);
  
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
    /*
    if(monitor.use_err)
    {
        return globus_error_put(monitor.err);
    }
    else
    {
        return GLOBUS_SUCCESS;
    }
    */
} /* globus_gass_copy_handle_to_url() */

/************************************************************
 * Transfer functions (asynchronous)
 ************************************************************/

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
    globus_gass_copy_state_t * state;
    globus_i_gass_copy_url_scheme_t source_url_scheme;
    globus_i_gass_copy_url_scheme_t dest_url_scheme;
    
    globus_l_gass_copy_url_scheme(
	source_url,
	&source_url_scheme);
    globus_l_gass_copy_url_scheme(
	dest_url,
	&dest_url_scheme);

    if (   (source_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED)
        || (dest_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED) )
    {
      /* FIXX -- do error handling properly 
	 return GLOBUS_FAILURE;
      */
	/* return error */
    }
    
    

    /* Initialize the state for this transfer */
    globus_l_gass_copy_state_new(handle);

    state = handle->state;
    /*store the user's callback and argument */
    handle->user_callback = callback_func;
    handle->callback_arg = callback_arg;

    globus_l_gass_copy_target_populate(
            &(state->source),
            &source_url_scheme,
	    source_url,
	    source_attr);
#ifdef GLOBUS_GASS_COPY_DEBUG
	printf("source target populated\n");
#endif
	globus_l_gass_copy_target_populate(
            &(state->dest),
            &dest_url_scheme,
	    dest_url,
	    dest_attr);
#ifdef GLOBUS_GASS_COPY_DEBUG
	printf("dest target populated\n");
#endif
	
    if (   (source_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_FTP)
	&& (dest_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_FTP) )
    {
	/* use source_attr to create source_ftp_client_attr */
	
	/* use dest_attr to create dest_ftp_client_attr */
	
#ifdef GLOBUS_GASS_COPY_DEBUG
        printf("calling globus_ftp_client_third_party_transfer()\n");
#endif
        globus_ftp_client_third_party_transfer(
	    &(handle->ftp_handle),
	    source_url,
	    state->source.attr.ftp_attr,
	    dest_url,
	    state->dest.attr.ftp_attr,
	    GLOBUS_NULL,
	    globus_l_gass_copy_ftp_transfer_callback,
	    (void *) handle);
	    
    }
    else
    {
        /* At least one of the urls is not ftp, so we have to do the copy ourselves */

	globus_l_gass_copy_transfer_start(handle);
    }
    
   
}/* globus_gass_copy_register_url_to_url() */

globus_result_t
globus_gass_copy_register_url_to_handle(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    globus_gass_copy_attr_t * source_attr,
    globus_io_handle_t * dest_handle,
    globus_gass_copy_callback_t callback_func,
    void * callback_arg)
{
    globus_gass_copy_state_t * state;
    globus_i_gass_copy_url_scheme_t source_url_scheme;

    globus_l_gass_copy_url_scheme(
	source_url,
	&source_url_scheme);

    if ( source_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED)      
    {
      /* FIXX -- do error handling properly 
	 return GLOBUS_FAILURE;
      */
	/* return error */
    }

     /* Initialize the state for this transfer */
    globus_l_gass_copy_state_new(handle);
    
    state = handle->state;
    /*store the user's callback and argument */
    handle->user_callback = callback_func;
    handle->callback_arg = callback_arg;

    globus_l_gass_copy_target_populate(
            &(state->source),
            &source_url_scheme,
	    source_url,
	    source_attr);
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("source target populated\n");
#endif
    globus_l_gass_copy_io_target_populate(
            &(state->dest),
	    dest_handle);
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("dest target populated\n");
#endif
    globus_l_gass_copy_transfer_start(handle);
    
} /* globus_gass_copy_register_url_to_handle() */

globus_result_t
globus_gass_copy_register_handle_to_url(
    globus_gass_copy_handle_t * handle,
    globus_io_handle_t * source_handle,
    char * dest_url,
    globus_gass_copy_attr_t * dest_attr,
    globus_gass_copy_callback_t callback_func,
    void * callback_arg)
{
  globus_gass_copy_state_t * state;
    globus_i_gass_copy_url_scheme_t dest_url_scheme;

    globus_l_gass_copy_url_scheme(
	dest_url,
	&dest_url_scheme);

    if ( dest_url_scheme == GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED)      
    {
      /* FIXX -- do error handling properly 
	 return GLOBUS_FAILURE;
      */
	/* return error */
    }

     /* Initialize the state for this transfer */
    globus_l_gass_copy_state_new(handle);

    state = handle->state;
    /*store the user's callback and argument */
    handle->user_callback = callback_func;
    handle->callback_arg = callback_arg;

    globus_l_gass_copy_io_target_populate(
            &(state->source),
	    source_handle);
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("source target populated\n");
#endif
    globus_l_gass_copy_target_populate(
            &(state->dest),
            &dest_url_scheme,
	    dest_url,
	    dest_attr);
#ifdef GLOBUS_GASS_COPY_DEBUG
    printf("dest target populated\n");
#endif
    globus_l_gass_copy_transfer_start(handle);
}

/************************************************************
 * Caching url state
 ************************************************************/

#ifdef USE_FTP
globus_result_t
globus_gass_copy_cache_url_state(
    globus_gass_copy_handle_t * handle,
    char * url)
{
    globus_url_t source_url_info;
    globus_url_parse(source_url, &source_url_info);
    if (   (strcmp(source_url_info.scheme, "ftp") == 0)
	|| (strcmp(source_url_info.scheme, "gsiftp") == 0)    )
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
    if (   (strcmp(source_url_info.scheme, "ftp") == 0)
	|| (strcmp(source_url_info.scheme, "gsiftp") == 0)    )
    {
	globus_ftp_client_flush_url_state(
	    &handle->ftp_handle,
	    url);
    }
} /* globus_gass_copy_flush_url_state() */

#endif

/************************************************************
 * User pointers on handles
 ************************************************************/

globus_result_t
globus_gass_copy_set_user_pointer(
    globus_gass_copy_handle_t * handle,
    void * user_pointer)
{
  handle->user_pointer = user_pointer;
}

void *
globus_gass_copy_get_user_pointer(
    globus_gass_copy_handle_t * handle)
{
  return(handle->user_pointer);
}

/**
 * cancel the current transfer
 */
globus_result_t
globus_gass_copy_cancel(
     globus_gass_copy_handle_t * handle)
{

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

/**
 * Duplicate the passed in attribute structure. 
 */
globus_result_t
globus_i_gass_copy_attr_duplicate(globus_gass_copy_attr_t ** attr)
{
    globus_gass_copy_attr_t * new_attr;

    if ( (attr == GLOBUS_NULL) || (*attr == GLOBUS_NULL) )
    {
	/*
        return globus_error_put(
           globus_gass_copy_error_construct_null_parameter(
              GLOBUS_GASS_COPY_MODULE,
              GLOBUS_NULL,
              "attr",
              1,
              "globus_gass_copy_attr_duplicate"));
	  */
    }

    new_attr = (globus_gass_copy_attr_t *)
         globus_libc_malloc(sizeof(globus_gass_copy_attr_t));
    new_attr = *attr;
    *attr = new_attr;

    return GLOBUS_SUCCESS;
} /* globus_i_gass_copy_attr_duplicate */

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


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
    globus_url_parse(source_url, &source_url_info);
    globus_url_parse(dest_url, &dest_url_info);

    if (   (   (strcmp(source_url_info->scheme, "ftp") == 0)
	    || (strcmp(source_url_info->scheme, "gsiftp") == 0) )
        && (   (strcmp(dest_url_info->scheme, "ftp") == 0)
	    || (strcmp(dest_url_info->scheme, "gsiftp") == 0) ) )
    {
	globus_gsiftp_client_transfer(
	    handle->gsiftp_handle,
	    source_url,
	    dest_url);
    }
    else
    {
	/* Both urls are not ftp, so we have to do the copy ourselves */

	/* Populate the transfer_source and transfer_dest structures */
	if (   (strcmp(source_url_info->scheme, "ftp") == 0)
	    || (strcmp(source_url_info->scheme, "gsiftp") == 0) )
	{
	    transfer_source.mode = GLOBUS_I_GASS_COPY_MODE_FTP;
	    transfer_source.url = globus_libc_strdup(source_url);
	}
    }

}

globus_result_t
globus_i_gass_copy_doit(
    globus_i_gass_copy_transferinfo_t * source,
    globus_i_gass_copy_transferinfo_t * dest)
{
    if (transfer_source.mode == GLOBUS_I_GASS_COPY_MODE_FTP)
    {
	globus_gsiftp_client_get(
	    handle->gsiftp_handle,
	    source->url);

	/* Later call... */
	globus_gsiftp_client_data_read(
	    handle->gsiftp_handle,
	    buffer,
	    length,
	    ...);
    }
}


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
}

globus_result_t
globus_gass_copy_flush_url_state(
    globus_gass_copy_handle_t * handle,
    char * url)
{
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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_ftp_client.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

#define GLOBUS_L_FTP_CLIENT_EXIST_BUFFER_LENGTH 256

/* Module specific data types */
typedef enum
{
    GLOBUS_FTP_CLIENT_EXIST_MDTM,
    GLOBUS_FTP_CLIENT_EXIST_SIZE,
    GLOBUS_FTP_CLIENT_EXIST_MLST,
    GLOBUS_FTP_CLIENT_EXIST_STAT,
    GLOBUS_FTP_CLIENT_EXIST_NLST
}
globus_l_ftp_client_existence_state_t;

typedef struct
{
    char *					url_string;
    globus_url_t				parsed_url;
    globus_byte_t *				buffer;
    globus_ftp_client_operationattr_t 		attr;
    globus_size_t				buffer_length;
    globus_bool_t				exists;
    globus_abstime_t				modification_time;
    globus_off_t				size;
    globus_object_t *				error;
    globus_ftp_client_complete_callback_t	callback;
    void *					callback_arg;
    globus_l_ftp_client_existence_state_t	state;
}
globus_l_ftp_client_existence_info_t;

/* Module specific prototypes */
static
globus_result_t
globus_l_ftp_client_existence_info_init(
    globus_l_ftp_client_existence_info_t **	existence_info,
    const char *				url,
    globus_ftp_client_operationattr_t *		attr,
    globus_ftp_client_complete_callback_t	complete_callback,
    void *					callback_arg);

static
globus_result_t
globus_l_ftp_client_existence_info_destroy(
    globus_l_ftp_client_existence_info_t **	existence_info);

static
void
globus_l_ftp_client_exist_callback(
    void *					user_arg,
    globus_ftp_client_handle_t *		handle,
    globus_object_t *				error);

static
void
globus_l_ftp_client_exist_data_callback(
    void *					user_arg,
    globus_ftp_client_handle_t *		handle,
    globus_object_t *				error,
    globus_byte_t *				buffer,
    globus_size_t				length,
    globus_off_t				offset,
    globus_bool_t				eof);

#endif

/**
 * @name File or Directory Existence
 */
/* @{ */
/**
 * Check for the existence of a file or directory on an FTP server.
 * @ingroup globus_ftp_client_operations
 *
 * This function attempts to determine whether the specified URL points to
 * a valid file or directory. The @a complete_callback will be invoked
 * with the result of the existence check passed as a globus error object,
 * or GLOBUS_SUCCESS.
 *
 * @param handle
 *        An FTP Client handle to use for the existence check operation.
 * @param url
 *        The URL of the directory or file to check. The URL may be an
 *        ftp or gsiftp URL.
 * @param attr
 *        Attributes to use for this operation.
 * @param complete_callback
 *        Callback to be invoked once the existence operation is completed.
 * @param callback_arg
 *        Argument to be passed to the complete_callback.
 * @return
 *        This function returns an error when any of these conditions are
 *        true:
 *        - handle is GLOBUS_NULL
 *        - url is GLOBUS_NULL
 *        - url cannot be parsed
 *        - url is not a ftp or gsiftp url
 *        - complete_callback is GLOBUS_NULL
 *        - handle already has an operation in progress
 */
globus_result_t
globus_ftp_client_exists(
    globus_ftp_client_handle_t *		u_handle,
    const char *				url,
    globus_ftp_client_operationattr_t *		attr,
    globus_ftp_client_complete_callback_t	complete_callback,
    void *					callback_arg)
{
    globus_result_t result;
    globus_l_ftp_client_existence_info_t *	existence_info;

    result = globus_l_ftp_client_existence_info_init(&existence_info,
	                                             url,
						     attr,
						     complete_callback,
						     callback_arg);
    if(result != GLOBUS_SUCCESS)
    {
	goto result_exit;
    }

    result = globus_ftp_client_modification_time(u_handle,
	    url,
	    attr,
	    &existence_info->modification_time,
	    globus_l_ftp_client_exist_callback,
	    existence_info);

    if(result != GLOBUS_SUCCESS)
    {
	goto info_destroy_exit;
    }
    return GLOBUS_SUCCESS;

  info_destroy_exit:
    globus_l_ftp_client_existence_info_destroy(&existence_info);
  result_exit:
    return result;
}
/* globus_ftp_client_exists() */
/* @} */

/* Local/internal functions */
#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
static
globus_result_t
globus_l_ftp_client_existence_info_init(
    globus_l_ftp_client_existence_info_t **	existence_info,
    const char *				url,
    globus_ftp_client_operationattr_t *		attr,
    globus_ftp_client_complete_callback_t	complete_callback,
    void *					callback_arg)
{
    globus_object_t *				err = GLOBUS_SUCCESS;
    globus_result_t				result;
    int						rc;
    static char *myname = "globus_l_ftp_client_existence_info_init";

    *existence_info =
	globus_libc_calloc(1, sizeof(globus_l_ftp_client_existence_info_t));

    if(*existence_info == GLOBUS_NULL)
    {
	err = GLOBUS_I_FTP_CLIENT_ERROR_OUT_OF_MEMORY();

	goto error_exit;
    }

    rc = globus_url_parse(url, &(*existence_info)->parsed_url);

    if(rc != GLOBUS_SUCCESS)
    {
	err = GLOBUS_I_FTP_CLIENT_ERROR_INVALID_PARAMETER("url");

	goto free_info_exit;
    }

    (*existence_info)->url_string = globus_libc_strdup(url);

    if((*existence_info)->url_string == GLOBUS_NULL)
    {
	err = GLOBUS_I_FTP_CLIENT_ERROR_OUT_OF_MEMORY();

	goto free_parsed_url_exit;
    }


    result = globus_ftp_client_operationattr_copy(
	    &(*existence_info)->attr,
	    attr);

    if(result != GLOBUS_SUCCESS)
    {
	err = globus_error_get(result);

	goto free_url_string_exit;
    }

    (*existence_info)->callback = complete_callback;
    (*existence_info)->callback_arg = callback_arg;
    (*existence_info)->buffer =
	globus_libc_malloc(GLOBUS_L_FTP_CLIENT_EXIST_BUFFER_LENGTH);

    if((*existence_info)->buffer == GLOBUS_NULL)
    {
	err = GLOBUS_I_FTP_CLIENT_ERROR_OUT_OF_MEMORY();

	goto free_attr_exit;
    }

    (*existence_info)->buffer_length = GLOBUS_L_FTP_CLIENT_EXIST_BUFFER_LENGTH;

    return GLOBUS_SUCCESS;

free_attr_exit:
    globus_ftp_client_operationattr_destroy(&(*existence_info)->attr);
free_url_string_exit:
    globus_libc_free((*existence_info)->url_string);
free_parsed_url_exit:
    globus_url_destroy(&(*existence_info)->parsed_url);
free_info_exit:
    globus_libc_free(*existence_info);
error_exit:
    return globus_error_put(err);
}
/* globus_l_ftp_client_existence_info_init() */

static
globus_result_t
globus_l_ftp_client_existence_info_destroy(
    globus_l_ftp_client_existence_info_t **	existence_info)
{
    globus_libc_free((*existence_info)->url_string);
    globus_url_destroy(&(*existence_info)->parsed_url);
    globus_libc_free((*existence_info)->buffer);
    if((*existence_info)->error)
    {
	globus_object_free((*existence_info)->error);
    }
    globus_ftp_client_operationattr_destroy(&(*existence_info)->attr);

    globus_libc_free(*existence_info);

    *existence_info = GLOBUS_NULL;

    return GLOBUS_SUCCESS;
}
/* globus_l_ftp_client_existence_info_destroy() */

static
void
globus_l_ftp_client_exist_callback(
    void *					user_arg,
    globus_ftp_client_handle_t *		handle,
    globus_object_t *				error)
{
    globus_l_ftp_client_existence_info_t *	info;
    globus_result_t				result;
    globus_bool_t				myerr = GLOBUS_FALSE;
    globus_bool_t				try_again = GLOBUS_FALSE;

    info = user_arg;

    switch(info->state)
    {
	case GLOBUS_FTP_CLIENT_EXIST_MDTM:
	    if(error == GLOBUS_SUCCESS)
	    {
		info->exists = GLOBUS_TRUE;
	    }
	    else
	    {
		result = globus_ftp_client_size(
			handle,
			info->url_string,
			&info->attr,
			&info->size,
			globus_l_ftp_client_exist_callback,
			info);

		if(result != GLOBUS_SUCCESS)
		{
		    error = globus_error_get(result);
		    myerr = GLOBUS_TRUE;
		}
		else
		{
		    info->state = GLOBUS_FTP_CLIENT_EXIST_SIZE;
		    try_again = GLOBUS_TRUE;
		}
	    }
	    break;
	case GLOBUS_FTP_CLIENT_EXIST_SIZE:
	    if(error == GLOBUS_SUCCESS)
	    {
		info->exists = GLOBUS_TRUE;
	    }
	    else
	    {
		result = globus_ftp_client_verbose_list(
			handle,
			info->url_string,
			&info->attr,
			globus_l_ftp_client_exist_callback,
			info);

		if(result != GLOBUS_SUCCESS)
		{
		    error = globus_error_get(result);
		    myerr = GLOBUS_TRUE;
		}
		else
		{
		    result = globus_ftp_client_register_read(
			handle,
			info->buffer,
			info->buffer_length,
			globus_l_ftp_client_exist_data_callback,
			info);
		    if(result != GLOBUS_SUCCESS)
		    {
			error = globus_error_get(result);
			myerr = GLOBUS_TRUE;
		    }
		    else
		    {
			info->state = GLOBUS_FTP_CLIENT_EXIST_NLST;
			try_again = GLOBUS_TRUE;
		    }
		}
	    }
	    break;
	case GLOBUS_FTP_CLIENT_EXIST_MLST:
	case GLOBUS_FTP_CLIENT_EXIST_STAT:
	case GLOBUS_FTP_CLIENT_EXIST_NLST:
	    try_again = GLOBUS_FALSE;
	    break;
    }
    if(!try_again)
    {
	if(error == GLOBUS_SUCCESS && !info->exists)
	{
	    error = GLOBUS_I_FTP_CLIENT_ERROR_NO_SUCH_FILE(info->url_string);

	    myerr = GLOBUS_TRUE;
	}
	info->callback(info->callback_arg, handle, error);

	globus_l_ftp_client_existence_info_destroy(&info);

	if(myerr)
	{
	    globus_object_free(error);
	}
    }
}
/* globus_l_ftp_client_exist_callback() */

static
void
globus_l_ftp_client_exist_data_callback(
    void *					user_arg,
    globus_ftp_client_handle_t *		handle,
    globus_object_t *				error,
    globus_byte_t *				buffer,
    globus_size_t				length,
    globus_off_t				offset,
    globus_bool_t				eof)
{
    globus_l_ftp_client_existence_info_t *	info;
    globus_result_t				result;

    info = user_arg;

    if(error != GLOBUS_SUCCESS && !info->error)
    {
	info->error = globus_object_copy(error);
    }
    if(!error)
    {
	if(length > 0)
	{
	    info->exists = GLOBUS_TRUE;
	}
    }
    if(! eof)
    {
	result =
	    globus_ftp_client_register_read(
		    handle,
		    info->buffer,
		    info->buffer_length,
		    globus_l_ftp_client_exist_data_callback,
		    info);

	if(result != GLOBUS_SUCCESS && !info->error)
	{
	    info->error = globus_error_get(result);
	}
    }
}
/* globus_l_ftp_client_exist_data_callback() */
#endif

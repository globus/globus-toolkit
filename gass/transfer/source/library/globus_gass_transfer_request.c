/******************************************************************************
globus_gass_transfer_request.c
 
Description:
    This module implements the request structure accessors for the
    GASS transfer library
 
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/
#include "globus_i_gass_transfer.h"

/* Request Accessors */

globus_gass_transfer_request_type_t
globus_gass_transfer_request_get_type(
    globus_gass_transfer_request_t		request)
{
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL)
    {
	return GLOBUS_GASS_TRANSFER_REQUEST_TYPE_INVALID;
    }
    else
    {
	return req->type;
    }
}
/* globus_gass_transfer_request_get_type() */

int
globus_gass_transfer_request_set_type(
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_request_type_t		type)
{
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL||
       req->type != GLOBUS_GASS_TRANSFER_REQUEST_TYPE_INVALID)
    {
	return GLOBUS_GASS_ERROR_INVALID_USE;
    }
    else
    {
	req->type = type;
	return GLOBUS_SUCCESS;
    }
}
/* globus_gass_transfer_request_set_type() */

void *
globus_gass_transfer_request_get_user_pointer(
    globus_gass_transfer_request_t		request)
{
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL||
       req->type != GLOBUS_GASS_TRANSFER_REQUEST_TYPE_INVALID)
    {
	return GLOBUS_NULL;
    }
    else
    {
	return req->user_pointer;
    }
}
/* globus_gass_transfer_request_get_user_pointer() */

int
globus_gass_transfer_request_set_user_pointer(
    globus_gass_transfer_request_t		request,
    void *					user_pointer)
{
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_INVALID_USE;
    }
    else
    {
	req->user_pointer = user_pointer;
	return GLOBUS_SUCCESS;
    }
}
/* globus_gass_transfer_request_set_user_pointer() */

globus_gass_transfer_request_status_t
globus_gass_transfer_request_get_status(
    globus_gass_transfer_request_t		request)
{
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req != GLOBUS_NULL)
    {
	switch(req->status)
	{
	  case GLOBUS_GASS_TRANSFER_REQUEST_STARTING3:
	  case GLOBUS_GASS_TRANSFER_REQUEST_PENDING:
	  case GLOBUS_GASS_TRANSFER_REQUEST_ACTING:
	  case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_PENDING:
	  case GLOBUS_GASS_TRANSFER_REQUEST_ACCEPTING:
	    return GLOBUS_GASS_TRANSFER_REQUEST_PENDING;
	  case GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING:
	  case GLOBUS_GASS_TRANSFER_REQUEST_FAILING:
	  case GLOBUS_GASS_TRANSFER_REQUEST_FAILED:
	  case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL1:
	  case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL2:
	  case GLOBUS_GASS_TRANSFER_REQUEST_SERVER_FAIL3:
	  case GLOBUS_GASS_TRANSFER_REQUEST_USER_FAIL:
	    return GLOBUS_GASS_TRANSFER_REQUEST_FAILED;
	  case GLOBUS_GASS_TRANSFER_REQUEST_FINISHING:
	    return GLOBUS_GASS_TRANSFER_REQUEST_DONE;
	  case GLOBUS_GASS_TRANSFER_REQUEST_STARTING2:
	    return GLOBUS_GASS_TRANSFER_REQUEST_STARTING;
	  case GLOBUS_GASS_TRANSFER_REQUEST_REFERRED:
	  case GLOBUS_GASS_TRANSFER_REQUEST_DENIED:
	  case GLOBUS_GASS_TRANSFER_REQUEST_DONE:
	  case GLOBUS_GASS_TRANSFER_REQUEST_STARTING:
	  case GLOBUS_GASS_TRANSFER_REQUEST_INVALID:
	    return req->status;
	}
    }
    return GLOBUS_GASS_TRANSFER_REQUEST_INVALID;
}
/* globus_gass_transfer_request_get_status() */

int
globus_gass_transfer_request_get_referral(
    globus_gass_transfer_request_t		request,
    globus_gass_transfer_referral_t *		referral)
{
    globus_gass_transfer_request_struct_t *	req;

    /* Sanity check of arguments */
    if(referral == GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_NULL_POINTER;
    }
    /* Check for illegal handle */
    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_INVALID_USE;
    }
    else if(req->referral_count == 0)
    {
	referral->url = GLOBUS_NULL;
	referral->count = 0;

	return GLOBUS_SUCCESS;
    }
    else
    {
	globus_size_t				i;

	referral->url =
	    globus_malloc(sizeof(char *) * req->referral_count);

	for(i = 0; i < req->referral_count; i++)
	{
	    referral->url[i] = globus_libc_strdup(req->referral_url[i]);
	}
	referral->count = req->referral_count;

	return GLOBUS_SUCCESS;
    }
}
/* globus_gass_transfer_request_get_referral() */

char *
globus_gass_transfer_request_get_url(
    globus_gass_transfer_request_t		request)
{
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL)
    {
	return GLOBUS_NULL;
    }
    else
    {
	return req->url;
    }
}

int
globus_gass_transfer_request_set_url(
    globus_gass_transfer_request_t		request,
    char *					url)
{
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL ||
       req->url != GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_INVALID_USE;
    }
    else
    {
	req->url = url;
	return GLOBUS_SUCCESS;
    }
}
void
globus_gass_transfer_request_set_length(
    globus_gass_transfer_request_t		request,
    globus_size_t				length)
{
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL)
    {
	return ;
    }
    else
    {
	req->length = length;
    }
}
globus_size_t
globus_gass_transfer_request_get_length(
    globus_gass_transfer_request_t		request)
{
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL)
    {
	return GLOBUS_GASS_LENGTH_UNKNOWN;
    }
    else
    {
	return req->length;
    }
}
int
globus_gass_transfer_request_get_denial_reason(
    globus_gass_transfer_request_t 		request)
{
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL)
    {
	return 0;
    }
    else
    {
	return req->denial_reason;
    }
}

char *
globus_gass_transfer_request_get_denial_message(
    globus_gass_transfer_request_t		request)
{
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL)
    {
	return GLOBUS_NULL;
    }
    else
    {
	return globus_libc_strdup(req->denial_message);
    }
}

char *
globus_gass_transfer_request_get_subject(
    globus_gass_transfer_request_t		request)
{
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL)
    {
	return GLOBUS_NULL;
    }
    else
    {
	return req->subject;
    }
}
/* globus_gass_transfer_request_get_subject() */

int
globus_gass_transfer_request_set_subject(
    globus_gass_transfer_request_t		request,
    char *					subject)
{
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_INVALID_USE;
    }
    else if(req->subject != GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_INVALID_USE;
    }
    else
    {
	req->subject = subject;
	return GLOBUS_SUCCESS;
    }
}
/* globus_gass_transfer_request_set_subject() */
void
globus_i_gass_transfer_request_init(
    globus_gass_transfer_request_t *            request,
    globus_gass_transfer_requestattr_t *        attr,
    char *                                      url,
    globus_gass_transfer_request_type_t         type,
    globus_gass_transfer_callback_t             callback,
    void *                                      user_arg)
{
    globus_gass_transfer_request_struct_t *	req;

    req = globus_malloc(sizeof(globus_gass_transfer_request_struct_t));
    if(req == GLOBUS_NULL)
    {
	goto error_exit;
    }

    if(url)
    {
	req->url = globus_libc_strdup(url);
        if(req->url == GLOBUS_NULL)
        {
	    goto free_req;
        }
    }
    else
    {
	req->url = GLOBUS_NULL;
    }
    req->type			= type;
    req->status			= GLOBUS_GASS_TRANSFER_REQUEST_STARTING;
    req->referral_url		= GLOBUS_NULL;
    req->referral_count		= GLOBUS_NULL;
    req->callback		= callback;
    req->callback_arg		= user_arg;
    req->proto			= GLOBUS_NULL;
    req->subject		= GLOBUS_NULL;
    req->denial_reason		= 0;
    req->denial_message		= GLOBUS_NULL;
    req->handled_length		= 0;
    req->posted_length		= 0;
    req->fail_callback		= GLOBUS_NULL;
    req->client_side		= GLOBUS_FALSE;
    req->user_pointer		= GLOBUS_NULL;

    globus_fifo_init(&req->pending_data);
    if(attr)
    {
	req->attr = globus_object_copy(*attr);
	if(req->attr == GLOBUS_NULL)
	{
	    goto free_fifo;
	}
    }
    else
    {
	req->attr = GLOBUS_NULL;
    }

    *request = globus_handle_table_insert(&globus_i_gass_transfer_request_handles,
					  (void *) req,
					  2);
    globus_list_insert(&globus_i_gass_transfer_requests,
		       (void *) (*request));
    
    return;

  free_fifo:
    globus_fifo_destroy(&req->pending_data);
    globus_free(req->url);
  free_req:
    globus_free(req);
  error_exit:
    *request = GLOBUS_HANDLE_TABLE_NO_HANDLE;
    return;
}
/* globus_i_gass_transfer_request_init() */

int
globus_i_gass_transfer_request_destroy(
    globus_gass_transfer_request_t		request)
{
    globus_bool_t				referenced;
    globus_gass_transfer_request_struct_t *	req;

    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL)
    {
	return GLOBUS_GASS_ERROR_INVALID_USE;
    }

    referenced =
	globus_handle_table_decrement_reference(&globus_i_gass_transfer_request_handles,
						request);
    if(!referenced)
    {
	int					i;
	globus_list_t *				tmp;

	tmp = globus_list_search(globus_i_gass_transfer_requests,
				 (void *) request);
	
	globus_list_remove(&globus_i_gass_transfer_requests,
			   tmp);

	globus_cond_signal(&globus_i_gass_transfer_shutdown_cond);
	
	if(req->attr)
	{
		globus_object_free(req->attr);
	}
	globus_fifo_destroy(&req->pending_data);
	globus_free(req->url);

	/* free referral */
	for(i = 0; i < req->referral_count; i++)
	{
	    globus_free(req->referral_url[i]);
	}
	if(req->referral_url)
	{
	    globus_free(req->referral_url);
	}
	req->referral_url = GLOBUS_NULL;
	req->referral_count = 0;

	/* free deny message */
	if(req->denial_message)
	{
	    globus_free(req->denial_message);
	}


	globus_free(req);
	request = GLOBUS_HANDLE_TABLE_NO_HANDLE;

	return GLOBUS_SUCCESS;
    }
    else
    {
	return GLOBUS_SUCCESS;
    }
}
/* globus_gass_transfer_request_destroy() */
int
globus_gass_transfer_request_destroy(
    globus_gass_transfer_request_t		request)
{
    globus_gass_transfer_request_struct_t *	req;
    int						rc;

    globus_i_gass_transfer_lock();
    req =
	globus_handle_table_lookup(&globus_i_gass_transfer_request_handles,
				   request);
    if(req == GLOBUS_NULL)
    {
	rc = GLOBUS_GASS_ERROR_INVALID_USE;
	goto finish;
    }
    if(req->status != GLOBUS_GASS_TRANSFER_REQUEST_FAILED &&
       req->status != GLOBUS_GASS_TRANSFER_REQUEST_DONE &&
       req->status != GLOBUS_GASS_TRANSFER_REQUEST_FINISHING &&
       req->status != GLOBUS_GASS_TRANSFER_REQUEST_REFERRED &&
       req->status != GLOBUS_GASS_TRANSFER_REQUEST_ACTING_TO_FAILING &&
       req->status != GLOBUS_GASS_TRANSFER_REQUEST_DENIED)
    {
	rc = GLOBUS_GASS_ERROR_INVALID_USE;
	goto finish;
    }

    rc =  globus_i_gass_transfer_request_destroy(request);

 finish:
    globus_i_gass_transfer_unlock();
    return rc;
}
/* globus_gass_transfer_request_destroy() */


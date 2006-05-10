/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_i_gram_protocol.h"
#include <string.h>

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
static
globus_size_t
globus_l_gram_protocol_quote_string(
    const char *			in,
    globus_byte_t *			bufp);

static
int
globus_l_gram_protocol_unquote_string(
    const globus_byte_t *		inbuf,
    globus_size_t			insize,
    char *				out);
#endif

/**
 * @defgroup globus_gram_protocol_pack Message Packing
 * @ingroup globus_gram_protocol_functions
 */

/**
 * @defgroup globus_gram_protocol_unpack Message Unpacking
 * @ingroup globus_gram_protocol_functions
 */

/**
 * Pack a GRAM Job Request
 * @ingroup globus_gram_protocol_pack 
 *
 * Encodes the parameters of a job request in a GRAM protocol message.
 * The resulting message may be sent with globus_gram_protocol_post()
 * or framed with globus_gram_protocol_frame_request() and sent by the
 * application.
 *
 * @param job_state_mask
 *        The bitwise-or of the job states which the client would like
 *        to register for job state change callbacks.
 * @param callback_url
 *        A callback contact string which will be contacted when a
 *        job state change which matches the @a job_state_mask occurs.
 *        This may be NULL, if the client does not wish to register
 *        a callback contact with this job request.
 * @param rsl
 *        An RSL string which contains the job request. This will
 *        be parsed and validated on the server side.
 * @param query
 *        An output variable which will be populated with a new
 *        string containing the packed job request message. The caller
 *        must free this memory by calling globus_libc_free();
 * @param querysize
 *        An output variable which will be populated with the length
 *        of the job request message returned in @a query.
 */
int
globus_gram_protocol_pack_job_request(
    int					job_state_mask,
    const char *			callback_url,
    const char *			rsl,
    globus_byte_t **			query,
    globus_size_t *			querysize)
{
    int					len;

    *query = globus_libc_malloc(
			strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE) +
			strlen(GLOBUS_GRAM_HTTP_PACK_JOB_STATE_MASK_LINE) +
			strlen(GLOBUS_GRAM_HTTP_PACK_CALLBACK_URL_LINE) +
			((callback_url) ? strlen(callback_url) : 2)
			+ 2*strlen(rsl) + 16);

    len = globus_libc_sprintf((char *) *query,
			      GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
			      GLOBUS_GRAM_HTTP_PACK_JOB_STATE_MASK_LINE
			      GLOBUS_GRAM_HTTP_PACK_CALLBACK_URL_LINE
			      "rsl: ",
			      GLOBUS_GRAM_PROTOCOL_VERSION,
			      job_state_mask,
			      (callback_url) ? callback_url : "\"\"" );

    len += globus_l_gram_protocol_quote_string(rsl, (*query)+len );

    globus_libc_sprintf((char *)(*query)+len,
			"%s",
			CRLF);
    *querysize = (globus_size_t)(len+3);

    return GLOBUS_SUCCESS;
}
/* globus_gram_protocol_pack_job_request() */


/**
 * Unpack a job request
 * @ingroup globus_gram_protocol_unpack
 *
 * Extracts the parameters of a job request from a GRAM message. The
 * parameters to this function mirror those of
 * globus_gram_protocol_pack_job_request().
 *
 * @param query
 *        The job request.
 * @param querysize
 *        The length of the job request string.
 * @param job_state_mask
 *        A pointer to an integer to be populated with the job state
 *        mask in the job request.
 * @param callback_url
 *        A pointer to be populated with a copy of the URL of the callback
 *        contact to be registered for this job request. The caller must
 *        free this memory by calling globus_libc_free().
 * @param description
 *        A pointer to be populated with a copy of the job description RSL
 *        for this job request. The caller must
 *        free this memory by calling globus_libc_free().
 */
int
globus_gram_protocol_unpack_job_request(
    const globus_byte_t *		query,
    globus_size_t			querysize,
    int  *				job_state_mask,
    char **				callback_url,
    char **				description)
{
    int					protocol_version;
    int					rc;
    globus_size_t			rsl_count;
    char *				q = (char *) query;
    char *				p;

    p = strstr(q, CRLF"rsl: ");
    if (!p)
	return GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

    p+=strlen(CRLF"rsl: ");
    rsl_count = querysize - (globus_size_t)(p-q);

    *callback_url = globus_libc_malloc(p-q);
    *description  = globus_libc_malloc(rsl_count);

    globus_libc_lock();
    rc = sscanf( q,
		 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
		 GLOBUS_GRAM_HTTP_PACK_JOB_STATE_MASK_LINE
		 GLOBUS_GRAM_HTTP_PACK_CALLBACK_URL_LINE,
		 &protocol_version,
		 job_state_mask,
		 *callback_url );
    globus_libc_unlock();
    if (rc != 3)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
	goto globus_gram_protocol_unpack_job_request_done;
    }
    if (protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH;
	goto globus_gram_protocol_unpack_job_request_done;
    }
    if (strcmp(*callback_url, "\"\"")==0)
    {
	globus_libc_free(*callback_url);
	*callback_url = GLOBUS_NULL;
    }

    rc = globus_l_gram_protocol_unquote_string(
	          (globus_byte_t*) p,
		  rsl_count-3,        /* CR LF + null */
		  *description );

globus_gram_protocol_unpack_job_request_done:
    if (rc != GLOBUS_SUCCESS)
    {
	globus_libc_free(*callback_url);
	globus_libc_free(*description);
	*callback_url = GLOBUS_NULL;
	*description = GLOBUS_NULL;
    }
    return rc;
}
/* globus_gram_protocol_unpack_job_request() */

/**
 * Pack a GRAM reply message 
 * @ingroup globus_gram_protocol_pack
 *
 * Encodes the parameters of a reply to a job request in a GRAM protocol
 * message.  The resulting message may be sent with
 * globus_gram_protocol_post() or framed with
 * globus_gram_protocol_frame_request() and sent by the application.
 *
 * @param status
 *        The job's failure code if the job failed, or 0, if the job
 *        request was processed successfully.
 * @param job_contact
 *        A string containing the job's contact string, which may
 *        be used to contact the job manager to query or cancel the job.
 *        This may be NULL, if the job request was not successfull.
 * @param reply
 *        A pointer which will be set to point to a newly allocated
 *        reply string. The string must be freed by the caller with
 *        globus_libc_free()
 * @param replysize
 *        The length of the reply string.
 *
 * @retval GLOBUS_SUCCESS
 *         The reply was successfully constructed.
 * @retval GLOBUS_GRAM_PROTOCOL_MALLOC_FAILED
 *         Memory for the reply string could not be allocated.
 */
int
globus_gram_protocol_pack_job_request_reply(
    int					status,
    const char *			job_contact,    /* may be null */
    globus_byte_t **			reply,
    globus_size_t *			replysize )
{
    *reply = globus_libc_malloc(
		       strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE) +
		       strlen(GLOBUS_GRAM_HTTP_PACK_STATUS_LINE) +
		       strlen(GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE) +
		       ((job_contact) ? strlen(job_contact) + 3 : 3));
    if(*reply == GLOBUS_NULL)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }

    if (job_contact)
	globus_libc_sprintf( (char *) *reply,
			     GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
			     GLOBUS_GRAM_HTTP_PACK_STATUS_LINE
			     GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE,
			     GLOBUS_GRAM_PROTOCOL_VERSION,
			     status,
			     job_contact );
    else
	globus_libc_sprintf( (char *) *reply,
			     GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
			     GLOBUS_GRAM_HTTP_PACK_STATUS_LINE,
			     GLOBUS_GRAM_PROTOCOL_VERSION,
			     status );

    *replysize = (globus_size_t)(strlen((char *) *reply) + 1);
    return GLOBUS_SUCCESS;
}
/* globus_gram_protocol_pack_job_request_reply() */

/**
 * Unpack a reply to a GRAM job request
 * @ingroup globus_gram_protocol_unpack
 *
 * Extracts the parameters of a reply to a job request from a GRAM message.
 * The parameters to this function mirror those of
 * globus_gram_protocol_pack_job_request_reply().
 *
 * @param reply
 *        The job request reply.
 * @param replysize
 *        The length of the reply string.
 * @param status
 *        A pointer to an integer to be populated with the failure code
 *        associated with the job request. This may be GLOBUS_SUCCESS,
 *        if the job request was successful.
 * @param job_contact
 *        A pointer to a string to be populated with the job's contact
 *        string.  This may set to NULL if the job request failed. If
 *        non-NULL upon return, the caller must free this string using
 *        globus_libc_free().
 *
 * @retval GLOBUS_SUCCESS
 *         The reply was successfully unpacked.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *         Memory for the @a job_contact string could not be allocated.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED
 *         The reply message couldn't be parsed.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH
 *         The reply message was in an incompatible version of the
 *         GRAM protocol.
 */
int
globus_gram_protocol_unpack_job_request_reply(
    const globus_byte_t *		reply,
    globus_size_t			replysize,
    int *				status,
    char **				job_contact )
{
    int					rc;
    int					protocol_version;
    char *				p;

    p = strstr((char *)reply, CRLF "job-manager-url:");
    if (p)
    {
	*job_contact = globus_libc_malloc(
	    replysize - strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE));
	if(*job_contact == GLOBUS_NULL)
	{
	    return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
	}

	p+=2;  /* crlf */
    }

    globus_libc_lock();
    rc = sscanf( (char *) reply,
		 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
		 GLOBUS_GRAM_HTTP_PACK_STATUS_LINE,
		 &protocol_version,
		 status );
    globus_libc_unlock();
    if (rc != 2 )
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
	goto globus_gram_protocol_unpack_job_request_done;
    }
    if (protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH;
	goto globus_gram_protocol_unpack_job_request_done;
    }
    rc = GLOBUS_SUCCESS;
    if (p)
    {
	globus_libc_lock();
	rc = sscanf( p,
		     GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE,
		     *job_contact );
	globus_libc_unlock();
	if (rc != 1)
	    rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
	else
	    rc = GLOBUS_SUCCESS;
    }

globus_gram_protocol_unpack_job_request_done:

    if (rc != GLOBUS_SUCCESS)
    {
	globus_libc_free(*job_contact);
	*job_contact = NULL;
    }

    return rc;
}
/* globus_gram_protocol_unpack_job_request_reply() */


/**
 * Pack a GRAM Job Manager Query
 * @ingroup globus_gram_protocol_pack 
 *
 * Encodes the parameters of a job status request, or other GRAM query
 * in a GRAM protocol message.  The resulting message may be sent with
 * globus_gram_protocol_post() or framed with
 * globus_gram_protocol_frame_request() and sent by the
 * application.
 *
 * @param status_request
 *        A string containing the type of query. This may be "status",
 *        "register", "unregister", "signal", or "cancel".
 * @param query
 *        An output variable which will be populated with a new
 *        string containing the packed job query message.
 * @param querysize
 *        An output variable which will be populated with the length
 *        of the job query message returned in @a query.
 */
int
globus_gram_protocol_pack_status_request(
    const char *			status_request,
    globus_byte_t **			query,
    globus_size_t *			querysize)
{
    globus_size_t			len;

    *query = globus_libc_malloc(
		       strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE) +
		       strlen(GLOBUS_GRAM_HTTP_PACK_CLIENT_REQUEST_LINE) +
		       2*strlen(status_request));
    if(*query == GLOBUS_NULL)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }

    len = globus_libc_sprintf( (char *) *query,
			       GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE,
			       GLOBUS_GRAM_PROTOCOL_VERSION );

    len += globus_l_gram_protocol_quote_string( status_request,
					    (*query) + len );

    globus_libc_sprintf( (char *)(*query)+len, CRLF);

    *querysize = (globus_size_t)(strlen((char*)*query) + 1);

    return GLOBUS_SUCCESS;
}
/* globus_gram_protocol_pack_status_request() */

/**
 * Unpack a GRAM query
 * @ingroup globus_gram_protocol_unpack
 *
 * Extracts the parameters of a query from a GRAM message.
 * The parameters to this function mirror those of
 * globus_gram_protocol_pack_status_request().
 *
 * @param query
 *        The GRAM query.
 * @param querysize
 *        The length of the query string.
 * @param status_request
 *        A pointer to a string to be populated with the query 
 *        string.  The caller must free this string using
 *        globus_libc_free().
 *
 * @retval GLOBUS_SUCCESS
 *         The reply was successfully unpacked.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *         Memory for the @a job_contact string could not be allocated.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED
 *         The reply message couldn't be parsed.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH
 *         The reply message was in an incompatible version of the
 *         GRAM protocol.
 */
int
globus_gram_protocol_unpack_status_request(
    const globus_byte_t *		query,
    globus_size_t			querysize,
    char **				status_request)
{
    int					rc;
    int					protocol_version;
    char *				p;
    globus_size_t			msgsize;

    p = strstr((char *) query, CRLF);
    if (!p)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
	goto error_exit;
    }

    p+=2;
    msgsize = querysize - (globus_size_t)(p-(char *)query);
    *status_request = globus_libc_malloc(msgsize);
    rc = GLOBUS_SUCCESS;

    globus_libc_lock();
    rc = sscanf((char *) query,
		 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE,
		 &protocol_version);
    globus_libc_unlock();
    if (rc != 1)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
	goto error_exit;
    }
    else if (protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH;
	goto error_exit;
    }

    rc = globus_l_gram_protocol_unquote_string(
	          (globus_byte_t*) p,
		  msgsize,
		  *status_request);

error_exit:
    if (rc != GLOBUS_SUCCESS)
    {
	globus_libc_free(*status_request);
	*status_request = GLOBUS_NULL;
    }

    return rc;
}
/* globus_gram_protocol_unpack_status_request() */

/**
 * Pack a GRAM reply message 
 * @ingroup globus_gram_protocol_pack
 *
 * Encodes the parameters of a reply to a job manager query in a GRAM
 * protocol message.  The resulting message may be sent with
 * globus_gram_protocol_reply().
 * globus_gram_protocol_frame_reply() and sent by the application.
 *
 * @param job_status
 *        The job's current @ref globus_gram_protocol_job_state_t "job
 *        state".
 * @param failure_code
 *        The error code generated by the query. This may be GLOBUS_SUCCESS
 *        if the query succeeded.
 * @param job_failure_code
 *        The error code associated with the job if it has failed. This may
 *        be GLOBUS_SUCCESS if the job has not failed.
 * @param reply
 *        A pointer which will be set to point to a newly allocated
 *        reply string. The string must be freed by the caller with
 *        globus_libc_free()
 * @param replysize
 *        The length of the reply string.
 *
 * @retval GLOBUS_SUCCESS
 *         The reply was successfully constructed.
 * @retval GLOBUS_GRAM_PROTOCOL_MALLOC_FAILED
 *         Memory for the reply string could not be allocated.
 */
int
globus_gram_protocol_pack_status_reply(
    int					job_status,
    int					failure_code,
    int					job_failure_code,
    globus_byte_t **			reply,
    globus_size_t *			replysize)
{
    *reply = globus_libc_malloc(
			strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE) +
			strlen(GLOBUS_GRAM_HTTP_PACK_STATUS_LINE) +
			strlen(GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE) +
			strlen(GLOBUS_GRAM_HTTP_PACK_JOB_FAILURE_CODE_LINE)
			+ 4 );
    if(*reply == GLOBUS_NULL)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }

    globus_libc_sprintf((char *)*reply,
			GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
			GLOBUS_GRAM_HTTP_PACK_STATUS_LINE
			GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE
			GLOBUS_GRAM_HTTP_PACK_JOB_FAILURE_CODE_LINE,
			GLOBUS_GRAM_PROTOCOL_VERSION,
			job_status,
			failure_code,
			job_failure_code);

    *replysize = (globus_size_t)(strlen((char *)*reply) + 1);

    return GLOBUS_SUCCESS;
}
/* globus_gram_protocol_pack_status_reply() */

/**
 * Unpack a reply to a GRAM status request
 * @ingroup globus_gram_protocol_unpack
 *
 * Extracts the parameters of a reply to a status request from a GRAM message.
 * The parameters to this function mirror those of
 * globus_gram_protocol_pack_status_reply().
 *
 * @param reply
 *        The job request reply.
 * @param replysize
 *        The length of the reply string.
 * @param job_status
 *        A pointer to an integer to be populated with thejob's current @ref
 *        globus_gram_protocol_job_state_t "job state".
 * @param failure_code
 *        A pointer to an integer to be populated with the failure code
 *        associated with the status request. This may be GLOBUS_SUCCESS,
 *        if the job request was successful.
 * @param job_failure_code
 *        A pointer to an integer to be populated with the failure code
 *        for the job, if the @a job_status is
 *        GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED.
 *
 * @retval GLOBUS_SUCCESS
 *         The reply was successfully unpacked.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED
 *         The reply message couldn't be parsed.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH
 *         The reply message was in an incompatible version of the
 *         GRAM protocol.
 */
int
globus_gram_protocol_unpack_status_reply(
    const globus_byte_t *		reply,
    globus_size_t			replysize,
    int *				job_status,
    int *				failure_code,
    int *				job_failure_code)
{
    int					protocol_version;
    int					rc;

    globus_libc_unlock();
    rc = sscanf( (char *) reply,
		 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
		 GLOBUS_GRAM_HTTP_PACK_STATUS_LINE
		 GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE
		 GLOBUS_GRAM_HTTP_PACK_JOB_FAILURE_CODE_LINE,
		 &protocol_version,
		 job_status,
		 failure_code,
		 job_failure_code );
    globus_libc_unlock();
    if (rc == 3)
    {
	*job_failure_code = 0;
    }
    if (rc != 3 && rc != 4)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
    }
    else if (protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH;
    }

    return GLOBUS_SUCCESS;
}
/* globus_gram_protocol_unpack_status_reply() */

/**
 * Pack a status update message
 * @ingroup globus_gram_protocol_pack
 *
 * Encodes the current status of a job in a GRAM protocol message.
 * The resulting message may be sent with globus_gram_protocol_post()
 * or framed with globus_gram_protocol_frame_request() and sent by the
 * application. Status messages are sent by the job manager when the
 * job's state changes.
 *
 * @param job_contact
 *        The contact string associated with this job manager.
 * @param status
 *        The job's current @ref globus_gram_protocol_job_state_t "job
 *        state".
 * @param failure_code
 *        The error associated with this job request, if the @a status
 *        value is GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED.
 * @param reply
 *        An output variable which will be populated with a new
 *        string containing the packed status message. The caller
 *        must free this memory by calling globus_libc_free();
 * @param replysize
 *        An output variable which will be populated with the length
 *        of the job request message returned in @a reply.
 */
int
globus_gram_protocol_pack_status_update_message(
    char *				job_contact,
    int					status,
    int					failure_code,
    globus_byte_t **			reply,
    globus_size_t *			replysize)
{
    *reply = globus_libc_malloc(
	strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE) +
	strlen(GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE) +
	strlen(GLOBUS_GRAM_HTTP_PACK_STATUS_LINE) +
	strlen(GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE) +
	strlen(job_contact) + 5 );
    if(*reply == GLOBUS_NULL)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }

    globus_libc_sprintf( (char *) *reply,
			 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
			 GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE
			 GLOBUS_GRAM_HTTP_PACK_STATUS_LINE
			 GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE,
			 GLOBUS_GRAM_PROTOCOL_VERSION,
			 job_contact,
			 status,
			 failure_code );

    *replysize = (globus_size_t)(strlen((char *)*reply) + 1);

    return GLOBUS_SUCCESS;
}
/* globus_gram_protocol_pack_status_update_message() */


/**
 * Unpack a status update message
 * @ingroup globus_gram_protocol_unpack
 *
 * Extracts the parameters of a status update from a GRAM message.
 * The parameters to this function mirror those of
 * globus_gram_protocol_pack_status_update_message().
 *
 * @param reply
 *        The status update message.
 * @param replysize
 *        The length of the message.
 * @param job_contact
 *        An output variable which will be populated with a new
 *        string containing the job contact string. The caller
 *        must free this memory by calling globus_libc_free().
 * @param status
 *        A pointer to an integer to be populated with the job's current @ref
 *        globus_gram_protocol_job_state_t "job state".
 * @param failure_code
 *        A pointer to an integer to be populated with the failure code
 *        for the job, if the @a job_status is
 *        GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED.
 *
 * @retval GLOBUS_SUCCESS
 *         The message was successfully unpacked.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED
 *         The message couldn't be parsed.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *         Memory for the @a job_contact string could not be allocated.
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH
 *         The status message was in an incompatible version of the
 *         GRAM protocol.
 */
int
globus_gram_protocol_unpack_status_update_message(
    const globus_byte_t *		reply,
    globus_size_t			replysize,
    char **				job_contact,
    int *				status,
    int *				failure_code)
{
    int   protocol_version;
    int   rc;

    *job_contact = globus_libc_malloc(replysize);
    if(*job_contact == GLOBUS_NULL)
    {
	return GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }

    globus_libc_lock();
    rc = sscanf( (char *) reply,
		 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
		 GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE
		 GLOBUS_GRAM_HTTP_PACK_STATUS_LINE
		 GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE,
		 &protocol_version,
		 *job_contact,
		 status,
		 failure_code );
    globus_libc_unlock();
    if (rc != 4)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
    }
    else if (protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        return GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH;
    }

    return GLOBUS_SUCCESS;
}
/* globus_gram_protocol_unpack_status_update_message() */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/* assumes bufp has sufficient memory */
static
globus_size_t
globus_l_gram_protocol_quote_string(
    const char *			in,
    globus_byte_t *			bufp)
{
    char *				out = (char *) bufp;

    *out++='"';			/* Start the quoted string */
    while (*in)
    {
	if (*in == '"' || *in == '\\')   /* need escaping */
	    *out++ = '\\';
	*out++ = *in++;
    }
    *out++ = '"';		/* End the quoted string. */
    *out   = '\0';

    return (globus_size_t)(out - (char *)bufp);
}
/* globus_l_gram_protocol_quote_string() */


/*
 *
 * TODO: Add unquoting for the % HEX HEX mechanism.
 * assumes enough mem alloc'd
 */
static
int
globus_l_gram_protocol_unquote_string(
    const globus_byte_t *		inbuf,
    globus_size_t			insize,
    char *				out)
{
    globus_bool_t  in_quote = GLOBUS_FALSE;
    globus_bool_t  done     = GLOBUS_FALSE;
    char *         in       = (char *) inbuf;

    if (*in == '"')
    {
	in_quote = GLOBUS_TRUE;
	++in;
    }
    while (!done && ((globus_size_t)(in - (char *)inbuf) < insize))
    {
	if (!*in)
	{
	    done = GLOBUS_TRUE;
	    continue;
	}
	if (in_quote)
	{
	    if (*in == '"')  /* done */
	    {
		++in;
		in_quote = GLOBUS_FALSE;
		done = GLOBUS_TRUE;
		continue;
	    }
	    else if (*in == '\\')   /* escaped characeter, do next instead */
		*out++ = *(++in);
	    else
		*out++ = *in;
	}
	else   /* no quote */
	{
	    if (*in == '\r')	/* end of the line. */
	    {
	        if (*(++in) != '\n')
		{
		    /* Malformed line */
		    return GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
		}
	    }
	    /* TODO: Recognize % HEX HEX here. */
	    *out++ = *in;
	}
	++in;
    }   /* while */

    if (in_quote)
	return GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

    *out  = '\0';
    return GLOBUS_SUCCESS;
}
/* globus_l_gram_protocol_unquote_string() */
#endif

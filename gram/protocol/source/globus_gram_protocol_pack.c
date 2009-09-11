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
    const char *                        in,
    globus_byte_t *                     bufp);

static
int
globus_l_gram_protocol_unquote_string(
    const globus_byte_t *               inbuf,
    globus_size_t                       insize,
    char *                              out);

static
void
globus_l_gram_protocol_extension_destroy(
    void *                              datum);

static
int
globus_l_gram_protocol_get_int_attribute(
    globus_hashtable_t *                extensions,
    const char *                        attribute_name,
    int *                               value);

static
int
globus_l_gram_protocol_get_string_attribute(
    globus_hashtable_t *                extensions,
    const char *                        attribute_name,
    char **                             value);
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
    int                                 job_state_mask,
    const char *                        callback_url,
    const char *                        rsl,
    globus_byte_t **                    query,
    globus_size_t *                     querysize)
{
    int                                 len;

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
 *        free this memory by calling free().
 * @param description
 *        A pointer to be populated with a copy of the job description RSL
 *        for this job request. The caller must
 *        free this memory by calling free().
 */
int
globus_gram_protocol_unpack_job_request(
    const globus_byte_t *               query,
    globus_size_t                       querysize,
    int  *                              job_state_mask,
    char **                             callback_url,
    char **                             description)
{
    int                                 protocol_version;
    int                                 rc;
    globus_hashtable_t                  attributes;

    if (query == NULL || job_state_mask == NULL || callback_url == NULL ||
        description == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto bad_param;
    }

    *job_state_mask = 0;
    *callback_url = NULL;
    *description = NULL;

    rc = globus_gram_protocol_unpack_message(
            (const char *) query,
            querysize,
            &attributes);
    if (rc != GLOBUS_SUCCESS)
    {
        goto parse_error;
    }

    rc = globus_l_gram_protocol_get_int_attribute(
            &attributes,
            GLOBUS_GRAM_ATTR_PROTOCOL_VERSION,
            &protocol_version);

    if (rc != GLOBUS_SUCCESS)
    {
        goto version_error;
    }

    if (protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH;

        goto version_mismatch;
    }

    rc = globus_l_gram_protocol_get_int_attribute(
            &attributes,
            GLOBUS_GRAM_ATTR_JOB_STATE_MASK,
            job_state_mask);
    if (rc != GLOBUS_SUCCESS)
    {
        goto job_state_mask_failed;
    }

    rc = globus_l_gram_protocol_get_string_attribute(
            &attributes,
            GLOBUS_GRAM_ATTR_CALLBACK_URL,
            callback_url);
    if (rc != GLOBUS_SUCCESS)
    {
        goto callback_url_failed;
    }

    if (*callback_url[0] == '\0')
    {
        free(*callback_url);
        *callback_url = NULL;
    }

    rc = globus_l_gram_protocol_get_string_attribute(
            &attributes,
            GLOBUS_GRAM_ATTR_RSL,
            description);

    if (rc != GLOBUS_SUCCESS)
    {
        if (*callback_url)
        {
            free(*callback_url);
            *callback_url = NULL;
        }
    }
callback_url_failed:
job_state_mask_failed:
version_mismatch:
version_error:
    globus_gram_protocol_hash_destroy(&attributes);
parse_error:
bad_param:
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
    int                                 status,
    const char *                        job_contact,    /* may be null */
    globus_byte_t **                    reply,
    globus_size_t *                     replysize )
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
    const globus_byte_t *               reply,
    globus_size_t                       replysize,
    int *                               status,
    char **                             job_contact )
{
    int                                 rc = GLOBUS_SUCCESS;
    int                                 protocol_version;
    globus_hashtable_t                  message_attributes;

    if (reply == NULL || status == NULL || job_contact == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto bad_param;
    }
    *status = 0;
    *job_contact = NULL;

    rc = globus_gram_protocol_unpack_message(
            (const char *) reply,
            replysize,
            &message_attributes);
    if (rc != GLOBUS_SUCCESS)
    {
        goto parse_error;
    }

    rc = globus_l_gram_protocol_get_int_attribute(
            &message_attributes,
            GLOBUS_GRAM_ATTR_PROTOCOL_VERSION,
            &protocol_version);
    if (rc != GLOBUS_SUCCESS)
    {
        goto version_error;
    }
    if (protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH;

        goto version_mismatch;
    }

    rc = globus_l_gram_protocol_get_int_attribute(
            &message_attributes,
            GLOBUS_GRAM_ATTR_STATUS,
            status);
    if (rc != GLOBUS_SUCCESS)
    {
        goto status_failed;
    }

    /* Only if the job is successfully created */
    rc = globus_l_gram_protocol_get_string_attribute(
            &message_attributes,
            GLOBUS_GRAM_ATTR_JOB_MANAGER_URL,
            job_contact);
    if (rc != GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED)
    {
        rc = GLOBUS_SUCCESS;
    }

status_failed:
version_mismatch:
version_error:
    globus_gram_protocol_hash_destroy(&message_attributes);
parse_error:
bad_param:
    return rc;
}
/* globus_gram_protocol_unpack_job_request_reply() */

int
globus_gram_protocol_pack_job_request_reply_with_extensions(
    int					status,
    const char *			job_contact,    /* may be null */
    globus_hashtable_t *                extensions,
    globus_byte_t **			reply,
    globus_size_t *			replysize)
{
    globus_gram_protocol_extension_t * entry;
    size_t                              len = 0;
    int                                 chrs;
    int                                 rc = GLOBUS_SUCCESS;

    if (reply != NULL)
    {
        *reply = NULL;
    }

    if (replysize != NULL)
    {
        *replysize = 0;
    }
    if (extensions == NULL || reply == NULL || replysize == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto bad_param;
    }

    for (entry = globus_hashtable_first(extensions);
         entry != NULL;
         entry = globus_hashtable_next(extensions))
    {
        if (entry->attribute == NULL || entry->value == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_PACK_FAILED;

            goto bad_attr;
        }
        len += strlen(entry->attribute) + (2*strlen(entry->value)) + 4;
    }
    len += strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE) +
           strlen(GLOBUS_GRAM_HTTP_PACK_STATUS_LINE) +
           (job_contact
            ? strlen(GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE)
            : 0) +
           (job_contact
            ? strlen(job_contact) : 0) +
           4;

    *reply = malloc(len);
    if(*reply == GLOBUS_NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto reply_malloc_failed;
    }

    if (job_contact)
    {
        chrs = sprintf((char *)*reply,
                GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
                GLOBUS_GRAM_HTTP_PACK_STATUS_LINE
                GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE,
                GLOBUS_GRAM_PROTOCOL_VERSION,
                status,
                job_contact);
    }
    else
    {
        chrs = sprintf((char *)*reply,
                GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
                GLOBUS_GRAM_HTTP_PACK_STATUS_LINE,
                GLOBUS_GRAM_PROTOCOL_VERSION,
                status);
    }

    for (entry = globus_hashtable_first(extensions);
         entry != NULL;
         entry = globus_hashtable_next(extensions))
    {
        chrs += sprintf(((char *) *reply) + chrs,
                "%s: ",
                entry->attribute);

        chrs += globus_l_gram_protocol_quote_string(
                entry->value,
                *reply + chrs);

        chrs += sprintf(((char *) *reply) + chrs, "\r\n");
    }

    *replysize = (globus_size_t)(strlen((char *)*reply) + 1);

reply_malloc_failed:
bad_attr:
bad_param:
    return rc;
}
/* globus_gram_protocol_pack_job_request_reply_with_extensions() */

int
globus_gram_protocol_unpack_job_request_reply_with_extensions(
    const globus_byte_t *		reply,
    globus_size_t			replysize,
    int *				status,
    char **				job_contact,
    globus_hashtable_t *                extensions)
{
    globus_gram_protocol_extension_t * entry = NULL;
    int                                 rc;

    if (reply == NULL || status == NULL || job_contact == NULL || 
            extensions == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto bad_param;
    }
    *status = 0;
    *job_contact = NULL;
    *extensions = NULL;

    rc = globus_gram_protocol_unpack_message(
            (char *) reply,
            replysize,
            extensions);

    if (rc != GLOBUS_SUCCESS)
    {
        goto parse_error;
    }

    /* Check that required attributes are present */
    entry = globus_hashtable_lookup(
            extensions,
            "protocol-version");
    if (entry == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

        goto verify_error;
    }
    if (strtol(entry->value, NULL, 10) != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH;

        goto verify_error;
    }

    entry = globus_hashtable_lookup(
            extensions,
            "status");
    if (entry == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
        
        goto verify_error;
    }
    *status = atoi(entry->value);

    entry = globus_hashtable_lookup(
            extensions,
            "job-manager-url");
    if (entry == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

        goto verify_error;
    }
    *job_contact = strdup(entry->value);
    if (*job_contact == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto copy_contact_failed;
    }

    rc = GLOBUS_SUCCESS;

    if (rc != GLOBUS_SUCCESS)
    {
copy_contact_failed:
verify_error:
        globus_gram_protocol_hash_destroy(extensions);
    }
parse_error:
bad_param:

    return rc;
}

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
    const char *                        status_request,
    globus_byte_t **                    query,
    globus_size_t *                     querysize)
{
    globus_size_t                       len;

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
    const globus_byte_t *               query,
    globus_size_t                       querysize,
    char **                             status_request)
{
    int                                 rc;
    int                                 protocol_version;
    char *                              p;
    globus_size_t                       msgsize;

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
    int                                 job_status,
    int                                 failure_code,
    int                                 job_failure_code,
    globus_byte_t **                    reply,
    globus_size_t *                     replysize)
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
    const globus_byte_t *               reply,
    globus_size_t                       replysize,
    int *                               job_status,
    int *                               failure_code,
    int *                               job_failure_code)
{
    int                                 protocol_version;
    int                                 rc;

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
 * Pack a GRAM reply message with extensions
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
 * @param extensions
 *        Hashtable of globus_gram_protocol_extension_t * values
 *        containing extension attribute-value pairs.
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
globus_gram_protocol_pack_status_reply_with_extensions(
    int                                 job_status,
    int                                 failure_code,
    int                                 job_failure_code,
    globus_hashtable_t *                extensions,
    globus_byte_t **                    reply,
    globus_size_t *                     replysize)
{
    globus_gram_protocol_extension_t * entry;
    size_t                              len = 0;
    int                                 chrs;
    int                                 rc = GLOBUS_SUCCESS;

    if (reply != NULL)
    {
        *reply = NULL;
    }

    if (replysize != NULL)
    {
        *replysize = 0;
    }
    if (extensions == NULL || reply == NULL || replysize == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto bad_param;
    }

    for (entry = globus_hashtable_first(extensions);
         entry != NULL;
         entry = globus_hashtable_next(extensions))
    {
        if (entry->attribute == NULL || entry->value == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_PACK_FAILED;

            goto bad_attr;
        }
        len += strlen(entry->attribute) + (2*strlen(entry->value)) + 4;
    }
    len += strlen(GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE) +
           strlen(GLOBUS_GRAM_HTTP_PACK_STATUS_LINE) +
           strlen(GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE) +
           strlen(GLOBUS_GRAM_HTTP_PACK_JOB_FAILURE_CODE_LINE)
           + 4;

    *reply = malloc(len);
    if(*reply == GLOBUS_NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto reply_malloc_failed;
    }

    chrs = sprintf((char *)*reply,
            GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
            GLOBUS_GRAM_HTTP_PACK_STATUS_LINE
            GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE
            GLOBUS_GRAM_HTTP_PACK_JOB_FAILURE_CODE_LINE,
            GLOBUS_GRAM_PROTOCOL_VERSION,
            job_status,
            failure_code,
            job_failure_code);

    for (entry = globus_hashtable_first(extensions);
         entry != NULL;
         entry = globus_hashtable_next(extensions))
    {
        chrs += sprintf(((char *) *reply) + chrs,
                "%s: ",
                entry->attribute);

        chrs += globus_l_gram_protocol_quote_string(
                entry->value,
                *reply + chrs);

        chrs += sprintf(((char *) *reply) + chrs, "\r\n");
    }

    *replysize = (globus_size_t)(strlen((char *)*reply) + 1);

reply_malloc_failed:
bad_attr:
bad_param:
    return rc;
}
/* globus_gram_protocol_pack_status_reply_with_extensions() */

/**
 * Unpack a reply to a GRAM status request with extensions
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
globus_gram_protocol_unpack_status_reply_with_extensions(
    const globus_byte_t *               reply,
    globus_size_t                       replysize,
    globus_hashtable_t *                extensions)
{
    int                                 rc;
    globus_gram_protocol_extension_t * entry = NULL;

    if (reply == NULL || extensions == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto bad_param;
    }

    rc = globus_gram_protocol_unpack_message(
            (const char *) reply,
            replysize,
            extensions);

    if (rc != GLOBUS_SUCCESS)
    {
        goto parse_error;
    }
    
    /* Check that required attributes are present */
    entry = globus_hashtable_lookup(
            extensions,
            "protocol-version");
    if (entry == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

        goto verify_error;
    }
    if (strtol(entry->value, NULL, 10) != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH;

        goto verify_error;
    }

    entry = globus_hashtable_lookup(
            extensions,
            "status");
    if (entry == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;
        
        goto verify_error;
    }

    entry = globus_hashtable_lookup(
            extensions,
            "failure-code");
    if (entry == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

        goto verify_error;
    }

    entry = globus_hashtable_lookup(
            extensions,
            "job-failure-code");
    if (entry == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

        goto verify_error;
    }

    rc = GLOBUS_SUCCESS;

    if (rc != GLOBUS_SUCCESS)
    {
verify_error:
        entry = NULL;
        globus_gram_protocol_hash_destroy(extensions);
    }
parse_error:
bad_param:

    return rc;
}
/* globus_gram_protocol_unpack_status_reply_with_extensions() */

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
    char *                              job_contact,
    int                                 status,
    int                                 failure_code,
    globus_byte_t **                    reply,
    globus_size_t *                     replysize)
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
 * Pack a status update message with arbitrary extensions
 * @ingroup globus_gram_protocol_pack
 *
 * Encodes the current status of a job in a GRAM protocol message.
 * The resulting message may be sent with globus_gram_protocol_post()
 * or framed with globus_gram_protocol_frame_request() and sent by the
 * application. Status messages are sent by the job manager when the
 * job's state changes. This version is generates messages which begin like
 * those generated by globus_gram_protocol_pack_status_update_message() but
 * includes additional application-defined extension attribute-value pairs.
 *
 * @param job_contact
 *        The contact string associated with this job manager.
 * @param status
 *        The job's current @ref globus_gram_protocol_job_state_t "job
 *        state".
 * @param failure_code
 *        The error associated with this job request, if the @a status
 *        value is GLOBUS_GRAM_PROTOCOL_JOB_STATE_FAILED.
 * @param extensions
 *        Hashtable of globus_gram_protocol_extension_t * values
 *        containing extension attribute-value pairs.
 * @param reply
 *        An output variable which will be populated with a new
 *        string containing the packed status message. The caller
 *        must free this memory by calling globus_libc_free();
 * @param replysize
 *        An output variable which will be populated with the length
 *        of the job request message returned in @a reply.
 */
int
globus_gram_protocol_pack_status_update_message_with_extensions(
    char *                              job_contact,
    int                                 status,
    int                                 failure_code,
    globus_hashtable_t *                extensions,
    globus_byte_t **                    reply,
    globus_size_t *                     replysize)
{
    globus_gram_protocol_extension_t * entry;
    size_t                              len = 0;
    size_t                              chrs = 0;
    char *                              tmp;
    int                                 rc = GLOBUS_SUCCESS;

    if (job_contact == NULL || extensions == NULL ||
        reply == NULL || replysize == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto null_param;
    }

    for (entry = globus_hashtable_first(extensions);
         entry != NULL;
         entry = globus_hashtable_next(extensions))
    {
        if (entry->attribute == NULL || entry->value == NULL)
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_PACK_FAILED;

            goto bad_attr;
        }
        len += strlen(entry->attribute) + (2*strlen(entry->value)) + 4;
    }

    tmp = globus_common_create_string(
                 GLOBUS_GRAM_HTTP_PACK_PROTOCOL_VERSION_LINE
                 GLOBUS_GRAM_HTTP_PACK_JOB_MANAGER_URL_LINE
                 GLOBUS_GRAM_HTTP_PACK_STATUS_LINE
                 GLOBUS_GRAM_HTTP_PACK_FAILURE_CODE_LINE,
                 GLOBUS_GRAM_PROTOCOL_VERSION,
                 job_contact,
                 status,
                 failure_code);
    if (tmp == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto tmp_malloc_failed;
    }

    chrs = strlen(tmp);
    len += chrs + 1;
    *reply = (globus_byte_t *) tmp;
    tmp = realloc(tmp, len);
    if (tmp == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
        free(*reply);
        *reply = NULL;

        goto reply_realloc_failed;
    }
    *reply = (globus_byte_t *) tmp;

    for (entry = globus_hashtable_first(extensions);
         entry != NULL;
         entry = globus_hashtable_next(extensions))
    {
        chrs += sprintf(((char *) *reply) + chrs,
                "%s: ",
                entry->attribute);

        chrs += globus_l_gram_protocol_quote_string(
                entry->value,
                *reply + chrs);

        chrs += sprintf(((char *) *reply) + chrs, "\r\n");
    }

    *replysize = (globus_size_t)(strlen(tmp) + 1);

reply_realloc_failed:
tmp_malloc_failed:
bad_attr:
null_param:

    return rc;
}

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
    const globus_byte_t *               reply,
    globus_size_t                       replysize,
    char **                             job_contact,
    int *                               status,
    int *                               failure_code)
{
    int                                 rc = GLOBUS_SUCCESS;
    globus_hashtable_t                  extensions;

    if (reply == NULL || job_contact == NULL || status == NULL ||
        failure_code == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto bad_param;
    }
    *job_contact = NULL;
    *status = 0;
    *failure_code = 0;

    rc = globus_gram_protocol_unpack_status_update_message_with_extensions(
            reply,
            replysize,
            &extensions);

    if (rc != GLOBUS_SUCCESS)
    {
        goto parse_error;
    }

    rc = globus_l_gram_protocol_get_string_attribute(
            &extensions,
            GLOBUS_GRAM_ATTR_JOB_MANAGER_URL,
            job_contact);
    if (rc != GLOBUS_SUCCESS)
    {
        goto job_manager_url_error;
    }

    rc = globus_l_gram_protocol_get_int_attribute(
            &extensions,
            GLOBUS_GRAM_ATTR_STATUS,
            status);
    if (rc != GLOBUS_SUCCESS)
    {
        goto status_error;
    }

    rc = globus_l_gram_protocol_get_int_attribute(
            &extensions,
            GLOBUS_GRAM_ATTR_FAILURE_CODE,
            failure_code);
    if (rc != GLOBUS_SUCCESS)
    {
status_error:
        free(*job_contact);
        *job_contact = NULL;
    }
job_manager_url_error:
    globus_gram_protocol_hash_destroy(&extensions);
parse_error:
bad_param:
    return rc;
}
/* globus_gram_protocol_unpack_status_update_message() */

/**
 * Unpack a status update message to a hashtable
 * @ingroup globus_gram_protocol_unpack
 *
 * Extracts the parameters of a status update from a GRAM message into a
 * hashtable of globus_gram_protocol_extension_t values. The hashtable will be
 * initialized by this function and all of the attributes of the job in the
 * status message will be included in it. If this function returns
 * GLOBUS_SUCCESS, the caller is responsible for freeing
 * the hashtable and its values.
 *
 * @param reply
 *        The status update message.
 * @param replysize
 *        The length of the message.
 * @param message_hash
 *        An output variable which will be initialized to a hashtable
 *        containing the message attributes. The caller must destroy this
 *        hashtable calling globus_gram_protocol_hash_destroy()
 *
 * @retval GLOBUS_SUCCESS
 *         Sucess
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED
 *         Unpack failed
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED
 *         Malloc failed
 * @retval GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH
 *         Version mismatch
 */
int
globus_gram_protocol_unpack_status_update_message_with_extensions(
    const globus_byte_t *               reply,
    globus_size_t                       replysize,
    globus_hashtable_t *                extensions)
{
    int                                 protocol_version;
    int                                 rc = GLOBUS_SUCCESS;
    globus_gram_protocol_extension_t *  entry;
    int                                 failure_code;
    char *                              failure_type = NULL;
    char *                              failure_message = NULL;
    char *                              failure_source = NULL;
    char *                              failure_destination = NULL;
    char *                              extended_error = NULL;

    if (reply == NULL || extensions == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto bad_param;
    }

    rc = globus_gram_protocol_unpack_message(
            (const char *) reply,
            replysize,
            extensions);
    if (rc != GLOBUS_SUCCESS)
    {
        goto parse_error;
    }

    rc = globus_l_gram_protocol_get_int_attribute(
            extensions,
            GLOBUS_GRAM_ATTR_PROTOCOL_VERSION,
            &protocol_version);
    if (rc != GLOBUS_SUCCESS)
    {
        goto version_missing_error;
    }

    if (protocol_version != GLOBUS_GRAM_PROTOCOL_VERSION)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_VERSION_MISMATCH;

        goto version_error;
    }

    entry = globus_hashtable_lookup(
            extensions,
            GLOBUS_GRAM_ATTR_JOB_MANAGER_URL);
    if (entry == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

        goto job_manager_url_error;
    }

    entry = globus_hashtable_lookup(
            extensions,
            GLOBUS_GRAM_ATTR_STATUS);
    if (entry == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

        goto status_error;
    }

    rc = globus_l_gram_protocol_get_int_attribute(
            extensions,
            GLOBUS_GRAM_ATTR_FAILURE_CODE,
            &failure_code);
    if (rc != GLOBUS_SUCCESS)
    {
        goto failure_code_error;
    }

    rc = globus_l_gram_protocol_get_string_attribute(
            extensions,
            "gt3-failure-type",
            &failure_type);
    if (rc != GLOBUS_SUCCESS)
    {
        if (rc != GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED)
        {
            goto failure_type_error;
        }
        rc = GLOBUS_SUCCESS;
    }

    rc = globus_l_gram_protocol_get_string_attribute(
            extensions,
            "gt3-failure-message",
            &failure_message);
    if (rc != GLOBUS_SUCCESS)
    {
        if (rc != GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED)
        {
            goto failure_message_error;
        }
        rc = GLOBUS_SUCCESS;
    }

    rc = globus_l_gram_protocol_get_string_attribute(
            extensions,
            "gt3-failure-source",
            &failure_source);
    if (rc != GLOBUS_SUCCESS)
    {
        if (rc != GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED)
        {
            goto failure_source_error;
        }
        rc = GLOBUS_SUCCESS;
    }

    rc = globus_l_gram_protocol_get_string_attribute(
            extensions,
            "gt3-failure-destination",
            &failure_destination);

    if (rc != GLOBUS_SUCCESS)
    {
        if (rc != GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED)
        {
            goto failure_destination_error;
        }
        rc = GLOBUS_SUCCESS;
    }

    if (failure_code == GLOBUS_GRAM_PROTOCOL_ERROR_STAGE_IN_FAILED ||
        failure_code == GLOBUS_GRAM_PROTOCOL_ERROR_STAGING_EXECUTABLE ||
        failure_code == GLOBUS_GRAM_PROTOCOL_ERROR_STAGING_STDIN)
    {
        if (failure_type && 
                (strcmp(failure_type, "executable") == 0 ||
                 strcmp(failure_type, "stdin") == 0))
        {
            extended_error = globus_common_create_string(
                    "the job manager could not stage in %s "
                    "from %s",
                    failure_type,
                    failure_source ? failure_source : "UNKNOWN");
        }
        else
        {
            extended_error = globus_common_create_string(
                    "the job manager could not stage in a file "
                    "from %s to %s%s%s",
                    failure_source ? failure_source : "UNKNOWN",
                    failure_destination ? failure_destination : "UNKNOWN",
                    (failure_message && *failure_message) ? ": " : "",
                    (failure_message && *failure_message)
                        ? failure_message : "");
        }
        if (extended_error)
        {
            globus_i_gram_protocol_error_hack_replace_message(
                    failure_code,
                    extended_error);
            free(extended_error);
        }
    }

    if (failure_destination)
    {
        free(failure_destination);
    }
failure_destination_error:
    if (failure_source)
    {
        free(failure_source);
    }
failure_source_error:
    if (failure_message)
    {
        free(failure_message);
    }
failure_message_error:
    if (failure_type)
    {
        free(failure_type);
    }
failure_type_error:
failure_code_error:
status_error:
job_manager_url_error:
version_error:
version_missing_error:
    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_protocol_hash_destroy(extensions);
        *extensions = NULL;
    }
parse_error:
bad_param:
    return rc;
}
/* globus_gram_protocol_unpack_status_update_message_with_extensions() */

static
void
globus_l_gram_protocol_extension_destroy(
    void *                              datum)
{
    globus_gram_protocol_extension_t * entry = datum;

    if (entry)
    {
        if (entry->attribute)
        {
            free(entry->attribute);
        }
        if (entry->value)
        {
            free(entry->value);
        }
        free(entry);
    }
}

/**
 * Destroy message attribute hash
 * @ingroup globus_gram_protocol_unpack
 * 
 * @param message_hash
 *     Hashtable of globus_gram_protocol_extension_t * values to destroy
 */
void
globus_gram_protocol_hash_destroy(
    globus_hashtable_t *                message_hash)
{
    if (message_hash != NULL)
    {
        globus_hashtable_destroy_all(
                message_hash,
                globus_l_gram_protocol_extension_destroy);
        *message_hash = NULL;
    }
}
/* globus_gram_protocol_hash_destroy() */


/**
 * Create a GRAM5 protocol extension entry
 * @ingroup globus_gram_protocol_extensions
 *
 * Allocates a new GRAM5 protocol extension entry containing an attribute-value
 * pair. The @a attribute parameter is copied into the extension, and the
 * @a format parameter is a printf-style format string used to construct the
 * value of the extension.
 * 
 * The caller is responsible for freeing the extension when done with it. The
 * quoting rules described in @ref globus_gram_protocol must be implemented
 * by the caller in the format string.
 * 
 * @param attribute
 *     Name of the extension attribute
 * @param format
 *     Printf-style format string used along with the varargs to construct
 *     the extension's value string.
 *
 * @retval
 *     A new GRAM5 extension structure, or NULL if a malloc error occurred.
 */
globus_gram_protocol_extension_t *
globus_gram_protocol_create_extension(
    const char *                        attribute,
    const char *                        format,
    ...)
{
    globus_gram_protocol_extension_t *  extension;
    va_list                             ap;
    size_t                              vlen;

    if (attribute == NULL || format == NULL)
    {
        extension = NULL;

        goto bad_param;
    }
    extension = malloc(sizeof(globus_gram_protocol_extension_t));
    if (extension == NULL)
    {
        goto malloc_extension_failed;
    }
    extension->attribute = strdup(attribute);
    if (extension->attribute == NULL)
    {
        goto malloc_attribute_failed;
    }

    va_start(ap, format);
    vlen = vsnprintf(NULL, 0, format, ap);
    va_end(ap);

    extension->value = malloc(vlen + 1);
    if (extension->value == NULL)
    {
        goto malloc_value_failed;
    }

    va_start(ap, format);
    vsnprintf(extension->value, vlen + 1, format, ap);
    va_end(ap);

    return extension;

malloc_value_failed:
    free(extension->attribute);
malloc_attribute_failed:
    free(extension);
    extension = NULL;
malloc_extension_failed:
bad_param:
    return extension;
}
/* globus_gram_protocol_create_extension() */

int
globus_gram_protocol_unpack_message(
    const char *                        message,
    size_t                              message_length,
    globus_hashtable_t *                message_attributes)
{
    globus_gram_protocol_extension_t *  extension;
    const char                          *attr_start, *value_start;
    size_t                              attr_len, value_len;
    const char *                        p;
    char *                              q;
    int                                 rc = GLOBUS_SUCCESS;
    int                                 i;

    if (message == NULL || message_attributes == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto bad_param;
    }
    rc = globus_hashtable_init(
            message_attributes,
            17,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
    if (rc != GLOBUS_SUCCESS)
    {
        goto hashtable_init_failed;
    }
    p = message;

    while (*p != 0)
    {
        attr_start = p;
        /* Pull out attribute start and length */
        while (*p != ':' && *p != '\0')
        {
            p++;
        }

        if (*p != ':')
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

            goto parse_error;
        }

        attr_len = p - attr_start;
        p++;

        if (*p != ' ')
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

            goto parse_error;
        }
        p++;

        if (*p == '"')
        {
            globus_bool_t               escaped = GLOBUS_FALSE;

            p++;

            value_start = p;
            while (*p != 0)
            {
                if (escaped)
                {
                    escaped = GLOBUS_FALSE;
                }
                else if (*p == '"')
                {
                    break;
                }
                else if (*p == '\\')
                {
                    escaped = GLOBUS_TRUE;
                }
                p++;
            }
            value_len = p - value_start;
            p++;
        }
        else
        {
            value_start = p;
            while (*p != '\r' && *p != 0)
            {
                p++;
            }
            value_len = p - value_start;
        }
        if (*(p++) != '\r')
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

            goto parse_error;
        }
        if (*(p++) != '\n')
        {
            rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

            goto parse_error;
        }
        extension = malloc(sizeof(globus_gram_protocol_extension_t));

        extension->attribute = malloc(attr_len+1);
        sprintf(extension->attribute, "%.*s", (int) attr_len, attr_start);
        q = extension->value = malloc(value_len+1);

        for (i = 0; i < value_len; i++)
        {
            if (value_start[i] != '\\')
            {
                *(q++) = value_start[i];
            }
            else
            {
                *(q++) = value_start[++i];
            }
        }
        *q = '\0';

        globus_hashtable_insert(
                message_attributes,
                extension->attribute,
                extension);
    }
parse_error:
    if (rc != GLOBUS_SUCCESS)
    {
        globus_gram_protocol_hash_destroy(message_attributes);
    }
hashtable_init_failed:
bad_param:
    return rc;
}
/* globus_gram_protocol_unpack_message() */

int
globus_gram_protocol_pack_version_request(
    char **                             request,
    size_t *                            requestsize)
{
    int                                 rc = GLOBUS_SUCCESS;

    if (request == NULL || requestsize == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_NULL_PARAMETER;

        goto bad_param;
    }
    *request = globus_common_create_string("command: version\r\n");
    if (*request == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto malloc_failed;
    }
    *requestsize = strlen(*request) + 1;

malloc_failed:
bad_param:
    return rc;
}
/* globus_gram_protocol_pack_version_request() */


#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/* assumes bufp has sufficient memory */
static
globus_size_t
globus_l_gram_protocol_quote_string(
    const char *                        in,
    globus_byte_t *                     bufp)
{
    char *                              out = (char *) bufp;

    *out++='"';                 /* Start the quoted string */
    while (*in)
    {
        if (*in == '"' || *in == '\\')   /* need escaping */
            *out++ = '\\';
        *out++ = *in++;
    }
    *out++ = '"';               /* End the quoted string. */
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
    const globus_byte_t *               inbuf,
    globus_size_t                       insize,
    char *                              out)
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
            if (*in == '\r')    /* end of the line. */
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

static
int
globus_l_gram_protocol_get_int_attribute(
    globus_hashtable_t *                extensions,
    const char *                        attribute_name,
    int *                               value)
{
    globus_gram_protocol_extension_t *  extension;
    int                                 rc = GLOBUS_SUCCESS;

    extension = globus_hashtable_lookup(extensions, (void *) attribute_name);
    if (extension == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

        goto unpack_failed;
    }

    *value = atoi(extension->value);

unpack_failed:
    return rc;
}
/* globus_l_gram_protocol_get_int_attribute() */

static
int
globus_l_gram_protocol_get_string_attribute(
    globus_hashtable_t *                extensions,
    const char *                        attribute_name,
    char **                             value)
{
    globus_gram_protocol_extension_t *  extension;
    int                                 rc = GLOBUS_SUCCESS;

    extension = globus_hashtable_lookup(extensions, (void *) attribute_name);
    if (extension == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_HTTP_UNPACK_FAILED;

        goto unpack_failed;
    }

    *value = strdup(extension->value);

    if (*value == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;
    }

unpack_failed:
    return rc;
}
/* globus_l_gram_protocol_get_string_attribute() */

#endif

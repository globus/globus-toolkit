#include "globus_i_xio_http.h"

/**
 * @defgroup globus_i_xio_http_server Internal Server Implementation
 */
static
void
globus_l_xio_http_accept_callback(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg);

static
void
globus_l_xio_http_server_read_request_callback(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg);

static
globus_result_t
globus_l_xio_http_server_parse_request(
    globus_i_xio_http_handle_t *        http_handle,
    globus_bool_t *                     done);

static
void
globus_l_xio_http_server_call_ready_callback(
    globus_i_xio_http_handle_t *        http_handle,
    globus_result_t                     result);

/**
 * Accept an HTTP request
 * @ingroup globus_i_xio_http_server
 *
 * Passes the request to the transport driver. In the callback, 
 * the request target information will be generated.
 *
 * @param driver_server
 *     Void * pointing to a server structure. Not used yet.
 * @param driver_attr
 *     Void * pointing to a driver-specific target attribute structure. Target
 *     attributes are not implemented in the HTTP driver, so this is ignored.
 * @param accept_op
 *     Operation associated with the accept.
 *
 * @return
 * This function passes the accept to the underlying transport driver,
 * so will return whatever value that driver returns.
 */
globus_result_t
globus_i_xio_http_accept(
    void *                              driver_server,
    void *                              driver_attr,
    globus_xio_operation_t              accept_op)
{
    return globus_xio_driver_pass_accept(accept_op,
            globus_l_xio_http_accept_callback, NULL);
}
/* globus_i_xio_http_accept() */

/**
 * Accept callback
 * @ingroup globus_i_xio_http_server
 *
 * Callback function called when the transport completes accepting
 * a connection for the request. Generates a new target to associate with
 * the result of this accept. This target will be passed to
 * globus_xio_open() or globus_xio_register_open() to begin processing the
 * request.
 *
 * @param op
 *     XIO Data structure passed through to globus_xio_driver_finished_accept().
 * @param result
 *     Result from the transport's attempt to accept a new connection.
 * @param user_arg
 *     Not used.
 *
 * @return void
 *
 * @todo When implemented in the XIO driver framework, parse the request
 * header before returning from this, so the target is populated with
 * meaningful information for the user. This will help enable persistent
 * connections.
 */
static
void
globus_l_xio_http_accept_callback(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_xio_http_target_t *        target_info = NULL;
    GlobusXIOName(globus_l_xio_http_accept_callback);
    
    if (result == GLOBUS_SUCCESS)
    {
        target_info = globus_i_xio_http_target_new();

        if (target_info == NULL)
        {
            result = GlobusXIOErrorMemory("target");
        }
    }

    globus_xio_driver_finished_accept(op, target_info, result);
}
/* globus_l_xio_http_accept_callback() */

/**
 * Server-side connection open callback
 * @ingroup globus_i_xio_http_server
 *
 * Called as a result of open at the transport level. If this was successful,
 * we will read the HTTP request from the client and call the user with
 * the request information.
 *
 * If this function is successful, the open will remain unfinished until the
 * request read is finished. If an error happens, this function will close the 
 * handle internally and call globus_xio_driver_finished_open() to propagate
 * the error.
 *
 * @param op
 *     Operation associated with the open.
 * @param result
 *     Result from the transport's attempt to open the new connection.
 * @param user_arg
 *     Void * pointing to a #globus_i_xio_http_handle_t associated with
 *     this open.
 *
 * @return void
 */
void
globus_i_xio_http_server_open_callback(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{
    globus_i_xio_http_handle_t *        http_handle = user_arg;
    globus_xio_driver_handle_t          handle;
    globus_bool_t                       pass_close_on_error = GLOBUS_TRUE;
    globus_result_t                     result2;
    GlobusXIOName(globus_i_xio_http_server_open_callback);

    handle = http_handle->handle;
    if (result != GLOBUS_SUCCESS)
    {
        pass_close_on_error = GLOBUS_FALSE;

        goto error_exit;
    }
    http_handle->read_buffer.iov_len = GLOBUS_XIO_HTTP_CHUNK_SIZE;
    http_handle->read_buffer.iov_base = globus_libc_malloc(
                                GLOBUS_XIO_HTTP_CHUNK_SIZE);
    if (http_handle->read_buffer.iov_base == NULL)
    {
        result = GlobusXIOErrorMemory("read_buffer");

        goto error_exit;
    }

    result = globus_xio_driver_pass_read(
            op,
            &http_handle->read_buffer,
            1,
            1,
            globus_l_xio_http_server_read_request_callback,
            http_handle);

    if (result != GLOBUS_SUCCESS)
    {
        goto free_buffer_exit;
    }

    return;

free_buffer_exit:
    globus_libc_free(http_handle->read_buffer.iov_base);
    http_handle->read_buffer.iov_base = NULL;
    http_handle->read_buffer.iov_len = 0;

error_exit:
    if (pass_close_on_error)
    {
        result2 = globus_xio_driver_operation_create(
                &http_handle->close_operation,
                http_handle->handle);

        if (result2 != GLOBUS_SUCCESS)
        {
            /*
             * We can't close the transport, we'll make the best of the
             * situation. Resetting this flag makes the lower code destroy
             * the handle.
             */
            pass_close_on_error = GLOBUS_FALSE;

            goto destroy_handle_exit;
        }

        result2 = globus_xio_driver_pass_close(
                http_handle->close_operation,
                globus_i_xio_http_close_callback,
                http_handle);

        if (result2 != GLOBUS_SUCCESS)
        {
            pass_close_on_error = GLOBUS_FALSE;
        }
    }

destroy_handle_exit:
    if (!pass_close_on_error)
    {
        globus_i_xio_http_handle_destroy(http_handle);
        globus_libc_free(http_handle);
        http_handle = NULL;
    }
    globus_xio_driver_finished_open(
            handle,
            http_handle,
            op,
            result);
}
/* globus_i_xio_http_server_open_callback() */

/**
 * Read request callback
 * @ingroup globus_i_xio_http_server
 *
 * Called when part of the request has been read by the transport driver.
 * If all of the request headers are present, or some error occurs at the
 * transport layer, or the request isn't well-formed, then the request ready
 * callback set in the handle's open attribute will be called. If the header
 * information isn't all present, then another read will be passed
 * to the transport.
 *
 * @param op
 *     XIO operation associated with the request read.
 * @param result
 *     Transport-level result of reading the request.
 * @param nbytes
 *     Amount of data read by the transport.
 * @param user_arg
 *     Void * pointing to the #globus_i_xio_http_handle_t associated
 *     with this request.
 *
 * @return void
 */
static
void
globus_l_xio_http_server_read_request_callback(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    globus_i_xio_http_handle_t *        http_handle = user_arg;
    globus_bool_t                       eof = GLOBUS_FALSE;
    globus_bool_t                       done;
    globus_bool_t                       copy_residue = GLOBUS_FALSE;
    GlobusXIOName(globus_l_xio_http_server_read_request_callback);

    if (result != GLOBUS_SUCCESS)
    {
        if (globus_xio_error_is_eof(result))
        {
            eof = GLOBUS_TRUE;
        }
        else
        {
            goto error_exit;
        }
    }

    globus_assert(!http_handle->parsed_headers);

    /* Haven't parsed request and headers yet */
    http_handle->read_buffer_valid += nbytes;

    result = globus_l_xio_http_server_parse_request(http_handle, &done);
    if (result == GLOBUS_SUCCESS && !done)
    {
        goto reregister_read;
    }
    else if (result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    /* Determine whether we should expect an entity along with the
     * request
     */
    if ((http_handle->request_info.http_version == GLOBUS_XIO_HTTP_VERSION_1_1)
            && (http_handle->request_info.headers.transfer_encoding
            == GLOBUS_XIO_HTTP_TRANSFER_ENCODING_CHUNKED))
    {
        http_handle->request_info.headers.entity_needed = GLOBUS_TRUE;
    }
    else if (http_handle->response_info.headers.content_length_set)
    {
        http_handle->request_info.headers.entity_needed = GLOBUS_TRUE;
    }

    http_handle->parsed_headers = GLOBUS_TRUE;

    globus_xio_driver_finished_open(
            http_handle->handle,
            http_handle,
            op,
            result);

    if (http_handle->user_read_operation != NULL)
    {
        copy_residue = GLOBUS_TRUE;
    }

    globus_l_xio_http_server_call_ready_callback(http_handle, result);

    if (copy_residue)
    {
        /* User registered a read before we parsed everything, handle
         * residue.
         */
        globus_i_xio_http_copy_residue(http_handle);
    }

    return;
reregister_read:
    if (eof)
    {
        /* Header block wasn't complete before eof */
        goto error_exit;
    }
    result = globus_i_xio_http_clean_read_buffer(http_handle);

    if (result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    result = globus_xio_driver_pass_read(
            op,
            &http_handle->read_iovec,
            1,
            1,
            globus_l_xio_http_server_read_request_callback,
            http_handle);

    if (result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }

    return;
error_exit:
    if (http_handle->user_read_operation != NULL)
    {
        copy_residue = GLOBUS_TRUE;
    }

    globus_xio_driver_finished_open(
            http_handle->handle,
            http_handle,
            op,
            result);

    globus_l_xio_http_server_call_ready_callback(http_handle, result);

    if (copy_residue)
    {
        /* User registered a read before we parsed everything, handle
         * residue.
         */
        globus_i_xio_http_copy_residue(http_handle);
    }
}
/* globus_l_xio_http_server_read_request_callback() */

/**
 * Parse an HTTP request
 * @ingroup globus_i_xio_http_server
 *
 * Parses the HTTP request line and then uses globus_i_xio_http_header_parse()
 * to parse the header bock .If the entire request header section is reqad, the
 * boolean pointed to by @a done will be modified to be GLOBUS_TRUE
 *
 * @param http_handle
 * @param done
 *
 * @return
 *     This function returns GLOBUS_SUCCESS, GLOBUS_XIO_HTTP_ERROR_PARSE,  or
 *     GLOBUS_XIO_ERROR_MEMORY. Other errors may be generated from
 *     globus_i_xio_http_header_parse()
 *
 * @retval GLOBUS_SUCCESS
 *     No parsing errors occurred while parsing the status line or headers.
 *     Parsing may still be incomplete, depending on the final value of @a
 *     done.
 * @retval GLOBUS_XIO_HTTP_ERROR_PARSE
 *     Parse error reading the HTTP request line
 * @retval GLOBUS_XIO_ERROR_MEMORY
 *     Parsing failed because of memory constraints.
 */
static
globus_result_t
globus_l_xio_http_server_parse_request(
    globus_i_xio_http_handle_t *        http_handle,
    globus_bool_t *                     done)
{
    globus_result_t                     result;
    char *                              eol;
    char *                              current_offset;
    int                                 parsed;
    int                                 rc;
    int                                 http_major;
    int                                 http_minor;
    GlobusXIOName(globus_l_xio_http_server_parse_request);

    if (http_handle->request_info.http_version == GLOBUS_XIO_HTTP_VERSION_UNSET)
    {
        /* Parse the request line:
         *
         * Method SP Request-URI SP HTTP-Version CRLF
         */
        current_offset = ((char *) (http_handle->read_buffer.iov_base))
                + http_handle->read_buffer_offset;

        eol = globus_i_xio_http_find_eol(
                current_offset,
                http_handle->read_buffer_valid);
        if (eol == NULL)
        {
            *done = GLOBUS_FALSE;

            return GLOBUS_SUCCESS;
        }
        *eol = '\0';

        rc = sscanf(current_offset, "%*s %n", &parsed);

        if (rc < 1)
        {
            result = GlobusXIOHttpErrorParse("Method", current_offset);

            goto error_exit;
        }

        http_handle->request_info.method = globus_libc_malloc(parsed+1);
        if (http_handle->request_info.method == NULL)
        {
            result = GlobusXIOErrorMemory("method");

            goto error_exit;
        }

        rc = sscanf(current_offset, "%s ", http_handle->request_info.method);
        globus_assert(rc == 1);

        current_offset += parsed;
        
        rc = sscanf(current_offset, "%*s %n", &parsed);
        if (rc < 1)
        {
            result = GlobusXIOHttpErrorParse("Request-URI", current_offset);

            goto error_exit;
        }

        http_handle->request_info.uri = globus_libc_malloc(parsed+1);
        if (http_handle->request_info.uri == NULL)
        {
            result = GlobusXIOErrorMemory("uri");

            goto error_exit;
        }
        rc = sscanf(current_offset, "%s ", http_handle->request_info.uri);
        globus_assert(rc == 1);

        current_offset += parsed;

        rc = sscanf(current_offset, "HTTP/%d.%d", &http_major, &http_minor);

        if (rc < 2)
        {
            result = GlobusXIOHttpErrorParse("Http-Version", current_offset);

            goto error_exit;
        }

        http_handle->request_info.http_version =
            globus_i_xio_http_guess_version(http_major, http_minor);

        /* Set current offset to end of CRLF at the end of this line */
        current_offset = eol+2;

        parsed = current_offset - ((char *) http_handle->read_buffer.iov_base
                + http_handle->read_buffer_offset);
        http_handle->read_buffer_valid -= parsed;
        http_handle->read_buffer_offset += parsed;
    }
    return globus_i_xio_http_header_parse(http_handle, done);

error_exit:
    parsed = current_offset - ((char *) http_handle->read_buffer.iov_base
                + http_handle->read_buffer_offset);

    /* Chop of what we managed to parse from the buffer */
    http_handle->read_buffer_valid -= parsed;
    http_handle->read_buffer_offset += parsed;

    return result;
}
/* globus_l_xio_http_server_parse_request() */

/**
 * Call the request ready callback associated with a handle.
 * @ingroup globus_i_xio_http_server
 *
 * @param http_handle
 *     Handle which is done parsing the request.
 * @param result
 *     Result to pass to the user.
 *
 * @return void
 */
static
void
globus_l_xio_http_server_call_ready_callback(
    globus_i_xio_http_handle_t *        http_handle,
    globus_result_t                     result)
{
    if (http_handle->response_info.request_callback == NULL)
    {
        /* User is missing out */
        return;
    }
    http_handle->response_info.request_callback(
            result,
            http_handle->request_info.method,
            http_handle->request_info.uri,
            http_handle->request_info.http_version,
            http_handle->request_info.headers.headers);
}
/* globus_l_xio_http_server_call_ready_callback()*/

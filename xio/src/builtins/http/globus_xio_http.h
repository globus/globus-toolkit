#if !defined GLOBUS_XIO_DRIVER_HTTP_H
#define GLOBUS_XIO_DRIVER_HTTP_H 1

/**
 * @defgroup http_api Globus XIO/HTTP API
 */

/**
 * HTTP Header
 * @ingroup http_api
 */
typedef struct
{
    /** Header Name */
    char *                              name;
    /** Header Value */
    char *                              value;
}
globus_xio_http_header_t;

/**
 * HTTP Handle Commands
 * @ingroup http_api
 */
typedef enum
{
    /**
     * Set the value of a response HTTP header. 
     *
     * The caller must pass in a <code>globus_xio_http_string_pair_t *</code>
     * which should be initialized to contain the header name and value.
     * Certain headers will cause the HTTP driver to behave differently than
     * normal.
     *
     * - Transfer-Encoding: {identity|chunked}
     *   Override the default transfer encoding. If a server knows the
     *   exact length of the message body, or does not intend to support
     *   persistent connections, it may set this header to be
     *   "identity".<br><br>
     *   If this is set to "identity" and any of the following are true, then
     *   the connection will be closed after the end of the response is sent:
     *   <br><br>
     *   - A Content-Length header is not present
     *   - The HTTP version is set to "HTTP/1.0"
     *   - The Connection header is set to "close"
     *   Attempts to set this to "chunked" with an "HTTP/1.0" client will
     *   fail with a GLOBUS_XIO_ERROR_HTTP_INVALID_HEADER error.
     * - Content-Length: 1*Digit
     *   - Provide a content length for the response message. If the 
     *     "chunked" transfer encoding is being used, then this header
     *     will be silently ignored by the HTTP driver.
     * - Connection: close
     *   - The HTTP connection will be closed after the end of the data
     *     response is written.
     *
     * This handle control function can fail with
     * - GLOBUS_XIO_ERROR_MEMORY
     * - GLOBUS_XIO_ERROR_PARAMETER 
     * - GLOBUS_XIO_ERROR_HTTP_INVALID_HEADER
     *
     */
    GLOBUS_XIO_HTTP_HANDLE_SET_RESPONSE_HEADER,
    /**
     * Set the response status code.
     *
     * The caller must pass in a <code>int</code> value, in the range 100-599
     * which will be used as the HTTP response code, as per RFC 2616. If this
     * cntl is not called by a server, then the default value of 200 ("Ok")
     * will be used. If this is called on the client-side of an HTTP
     * connection, the handle control will fail with a
     * GLOBUS_XIO_ERROR_PARAMETER error.
     *
     * This handle control function can fail with
     * - GLOBUS_XIO_ERROR_PARAMETER 
     */
    GLOBUS_XIO_HTTP_HANDLE_SET_RESPONSE_STATUS_CODE,
    /**
     * Set the response reason phrase.
     *
     * The caller must pass in a <code>char *</code> containing the value of
     * the HTTP response string, as per RFC 2616. If this cntl is not called
     * by a server, then a default value based on the handle's response status
     * code will be generated. If this is called on the
     * client-side of an HTTP connection, the handle control will fail with
     * a GLOBUS_XIO_ERROR_PARAMETER error.
     *
     * This handle control function can fail with
     * - GLOBUS_XIO_ERROR_MEMORY
     * - GLOBUS_XIO_ERROR_PARAMETER 
     */
    GLOBUS_XIO_HTTP_HANDLE_SET_RESPONSE_REASON_PHRASE,
    /**
     * Set the response HTTP version.
     *
     * The caller must pass in a <code>globus_xio_http_version_t</code>
     * containing the HTTP version to be used in the serve response line.
     * If this cntl is not called by a server, then the default of
     * GLOBUS_XIO_HTTP_VERSION_1_1 will be used, though no HTTP/1.1 features 
     * (chunking, persistent connections, etc) will be
     * assumed if the client request was an HTTP/1.0 request. If this is called
     * on the client-side of an HTTP connection, the handle control will fail
     * with GLOBUS_XIO_ERROR_PARAMETER.
     *
     * This handle control function can fail with
     * - GLOBUS_XIO_ERROR_MEMORY
     * - GLOBUS_XIO_ERROR_PARAMETER
     */
    GLOBUS_XIO_HTTP_HANDLE_SET_RESPONSE_HTTP_VERSION,
    /**
     * Set the end-of-entity.
     *
     * HTTP clients and servers must call this command to indicate to the
     * driver that the entity-body which is being sent is completed. Subsequent
     * attempts to write data on the handle will fail.
     *
     * This handle command MUST be called on the client side of an HTTP
     * connection when the HTTP method is OPTIONS, POST, or PUT, or when
     * the open attributes indicate that an entity will be sent. This handle
     * command MUST be called on the server side of an HTTP request connection
     * when the HTTP method was OPTIONS, GET, POST, or TRACE.
     *
     * (IS THIS ADEQUATELY DEFINED?)
     */
    GLOBUS_XIO_HTTP_HANDLE_SET_END_OF_ENTITY
}
globus_xio_http_handle_cmd_t;

/**
 * HTTP Attribute Commands
 * @ingroup http_api
 */
typedef enum
{
    /**
     * Set the HTTP method to use for a client request.
     *
     * The caller must pass in a <code>char *</code> pointing to the
     * request method string ("GET", "PUT", "POST", etc) that will be
     * used in the HTTP request.
     *
     * If this is not set on the target before it is opened, it will default
     * to GET.
     *
     * This attribute is ignored when opening the server side of an HTTP
     * connection.
     *
     * Setting this attribute may fail with
     * - GLOBUS_XIO_ERROR_MEMORY
     * - GLOBUS_XIO_ERROR_PARAMETER
     */
    GLOBUS_XIO_HTTP_ATTR_SET_REQUEST_METHOD,
    /**
     * Set the HTTP version to use for a client request.
     *
     * The caller must pass in a <code>globus_xio_http_version_t</code>
     * containing the HTTP version to use for the client request. If the
     * client is using "HTTP/1.0" in a request which will send a request
     * message body (such as a POST or PUT), then the client MUST set the
     * "Content-Length" HTTP header to be the length of the message. If this
     * attribute is not present, then the default of GLOBUS_XIO_HTTP_VERSION_1_1
     * will be used.
     *
     * This attribute is ignored when opening the server side of an HTTP
     * connection.
     */
    GLOBUS_XIO_HTTP_ATTR_SET_REQUEST_HTTP_VERSION,
    /**
     * Set the value of an HTTP request header. 
     *
     * The caller must pass in a <code>globus_xio_http_string_pair_t *</code>
     * which should be initialized to contain the header name and value.
     * Certain headers will cause the HTTP driver to behave differently than
     * normal. This must be called before
     *
     * - Transfer-Encoding: {identity|chunked}
     *   Override the default transfer encoding. If a server knows the
     *   exact length of the message body, or does not intend to support
     *   persistent connections, it may set this header to be
     *   "identity".<br><br>
     *   If this is set to "identity" and any of the following are true, then
     *   the connection will be closed after the end of the message is sent:
     *   <br><br>
     *     - A Content-Length header is not present
     *     - The HTTP version is set to "HTTP/1.0"
     *     - The Connection header is set to "close"
     *   Attempts to set this to "chunked" with an "HTTP/1.0" client will
     *   fail with a GLOBUS_XIO_ERROR_HTTP_INVALID_HEADER error.
     * - Content-Length: 1*Digit
     *   - Provide a content length for the response message. If the 
     *     "chunked" transfer encoding is being used, then this header
     *     will be silently ignored by the HTTP driver.
     * - Connection: close
     *   - If present in the server response, the connection
     *     will be closed after the end of the data response is written.
     *     Otherwise, when persistent connections are enabled, the connection
     *     <em>may</em> be left open by the driver. Persistent connections
     *     are not yet implemented.
     */
    GLOBUS_XIO_HTTP_ATTR_SET_REQUEST_HEADER,
    /**
     * Set a function to be called when the HTTP request headers have
     * been read.
     *
     * The caller must pass in a
     * #globus_xio_http_request_ready_callback_t function
     * pointer. This function will be called once all of the HTTP 
     * request headers have been read by the server.
     *
     * This attribute is ignored when opening the client side of an HTTP
     * connection.
     */
    GLOBUS_XIO_HTTP_ATTR_SET_REQUEST_CALLBACK,
    /**
     * Set a function to be called when the HTTP response headers have
     * been read.
     *
     * The caller must pass in a
     * #globus_xio_http_response_ready_callback_t function
     * pointer. This function will be called once all of the HTTP 
     * response headers have been read by the client.
     *
     * This attribute is ignored when opening the server side of an HTTP
     * connection.
     */
    GLOBUS_XIO_HTTP_ATTR_SET_RESPONSE_CALLBACK
}
globus_xio_http_attr_cmd_t;

/**
 * Error types used to generate errors using the globus_error_generic module.
 * @ingroup http_api
 */
typedef enum
{
    /**
     * An attempt to set a header which is not compatible with the HTTP
     * version being used.
     * @hideinitializer
     */
    GLOBUS_XIO_HTTP_ERROR_INVALID_HEADER = 1024,
    /**
     * Error parsing HTTP protocol
     */
    GLOBUS_XIO_HTTP_ERROR_PARSE,
    /**
     * There is no entity body to read or write.
     */
    GLOBUS_XIO_HTTP_ERROR_NO_ENTITY
}
globus_xio_http_errors_t;

/**
 * @ingroup http_api
 * Valid HTTP versions, used with the
 * #GLOBUS_XIO_HTTP_ATTR_SET_REQUEST_HTTP_VERSION attribute and the
 * #GLOBUS_XIO_HTTP_HANDLE_SET_RESPONSE_HTTP_VERSION, and
 * #GLOBUS_XIO_HTTP_HANDLE_GET_REQUEST_HTTP_VERSION handle controls.
 */
typedef enum
{
    GLOBUS_XIO_HTTP_VERSION_UNSET,
    /**
     * HTTP/1.0
     */
    GLOBUS_XIO_HTTP_VERSION_1_0,
    /**
     * HTTP/1.1
     */
    GLOBUS_XIO_HTTP_VERSION_1_1
}
globus_xio_http_version_t;

/**
 * Callback type for indicating that the HTTP request is available.
 * @ingroup http_api
 *
 * @param user_arg
 *        Pointer to user data.
 * @param result
 *        The result of parsing the request line and headers. If this is
 *        not GLOBUS_SUCCESS, then the status_code and reason_phrase will
 *        be NULL, and attempts to read the response will fail.
 * @param method
 *        The HTTP method (GET, PUT, POST, etc), requested by the client
 *        for the specified URI.
 * @param uri
 *        URI path that the client is requesting the method to be acted upon.
 * @param version
 *        The HTTP version used in the response.
 * @param headers
 *        A hashtable of HTTP headers associated with this request. The
 *        keys to this hashtable will be <code>char *</code>header names, and
 *        the values in the table will be #globus_xio_http_header_t structure
 *        pointers. Applications which access values from this table must make
 *        local copies if they want them to be valid after this callback
 *        returns.
 * @see GLOBUS_XIO_HTTP_ATTR_SET_REQUEST_CALLBACK
 */
typedef void (*globus_xio_http_request_ready_callback_t) (
    void *                              user_arg,
    globus_result_t                     result,
    const char *                        method,
    const char *                        uri,
    globus_xio_http_version_t           version,
    globus_hashtable_t                  headers);

/**
 * Callback type for indicating that the HTTP response is available.
 * @ingroup http_api
 *
 * @param user_arg
 *        Pointer to user data.
 * @param result
 *        The result of parsing the response line and headers. If this is
 *        not GLOBUS_SUCCESS, then the status_code and reason_phrase will
 *        be NULL, and attempts to read the response will fail.
 * @param status_code
 *        The HTTP status code (in the range 100-599), indicating how
 *        the request was handled by the server.
 * @param reason_phrase
 *        Text string containing the reason for the response.
 * @param version
 *        The HTTP version used in the response.
 * @param headers
 *        A hashtable of HTTP headers associated with this response. The
 *        keys to this hashtable will be <code>char *</code>header names, and
 *        the values in the table will be #globus_xio_http_header_t structure
 *        pointers. Applications which access values from this table must make
 *        local copies if they want them to be valid after this callback
 *        returns.
 * @see GLOBUS_XIO_HTTP_ATTR_SET_RESPONSE_CALLBACK
 */
typedef void (*globus_xio_http_response_ready_callback_t) (
    void *                              user_arg,
    globus_result_t                     result,
    int                                 status_code,
    const char *                        reason_phrase,
    globus_xio_http_version_t           version,
    globus_hashtable_t                  headers);

#endif

#if !defined GLOBUS_XIO_DRIVER_HTTP_H
#define GLOBUS_XIO_DRIVER_HTTP_H 1

#include "globus_common.h"

typedef enum
    {
        GLOBUS_XIO_HTTP_GET_HEADERS,
        GLOBUS_XIO_HTTP_SET_HEADERS,
        GLOBUS_XIO_HTTP_GET_CONTACT,
        GLOBUS_XIO_HTTP_GET_REQUEST_TYPE,
        GLOBUS_XIO_HTTP_SET_EXIT_CODE,
        GLOBUS_XIO_HTTP_SET_EXIT_TEXT
    } globus_xio_http_handle_cmd_t;

typedef enum
    {
        GLOBUS_XIO_HTTP_SUCCESS,
        GLOBUS_XIO_HTTP_PARSE_FAILED,
        GLOBUS_XIO_HTTP_NEED_MORE
    } globus_xio_http_parse_state_t;

typedef enum
    {
        GLOBUS_XIO_HTTP_INSUFFICIENT_HEADER
    } globus_xio_http_errors_t;

typedef struct globus_xio_http_string_pair_s
{
    char *key;
    char *value;
} globus_xio_http_string_pair_t;

#endif

#include <string.h>
#include "globus_xio_driver.h"
#include "globus_xio_load.h"
#include "globus_i_xio.h"
#include "globus_common.h"
#include "globus_hashtable.h"
#include "globus_error_string.h"
#include "globus_xio_http.h"
#include "version.h"

#define _SERVER "test_server_string"
#define _TARGET "test_target_string"
#define CHUNK_SIZE 2048

static
int
globus_l_xio_http_activate(void);

static
int
globus_l_xio_http_deactivate(void);

static void
globus_l_xio_http_handle_destroy_element(void *datum);

static globus_module_descriptor_t  globus_i_xio_http_module =
{
    "globus_xio_http", //module name
    globus_l_xio_http_activate, //activate
    globus_l_xio_http_deactivate, //deactivate
    GLOBUS_NULL, //at exit
    GLOBUS_NULL, //get pointer
    &local_version //version
};

#define GlobusXIOHttpParseError()                                          \
    globus_error_put(                                                      \
        globus_error_construct_error(                                      \
            &globus_i_xio_http_module,                                     \
            GLOBUS_NULL,                                                   \
            GLOBUS_XIO_HTTP_PARSE_FAILED,                                  \
            "[%s:%d] header failed to parse ",                             \
            _xio_name, __LINE__))

typedef struct l_http_info_s
{
    globus_xio_iovec_t     iovec;

    char *                 uri;
    char *                 http_standard;
    char *                 request_type;
    globus_hashtable_t     recv_headers;
    char *                 buffer;
    char *                 remainder;
    int                    buffer_offset;

    int                    header_written;
    char *                 exit_code;
    char *                 exit_text;
    globus_hashtable_t     user_headers;
} l_http_info_t;
    
/*
 *  used as attr and handle
 */

static void
l_http_destroy_info(l_http_info_t *info ) 
{
    globus_hashtable_destroy_all(&info->recv_headers, globus_l_xio_http_handle_destroy_element);
    globus_hashtable_destroy_all(&info->user_headers, globus_l_xio_http_handle_destroy_element);
    globus_free(info->uri);
    globus_free(info->http_standard);
    globus_free(info->request_type);
    globus_free(info->buffer);
    globus_free(info->exit_code);
    globus_free(info->exit_text);
    globus_free(info->user_headers);
}

static l_http_info_t *
l_http_create_new_info()
{
    l_http_info_t *                         info;
    globus_xio_http_string_pair_t* string_pair;

    info = (l_http_info_t *) globus_malloc(sizeof(l_http_info_t));
    info->iovec.iov_base = 0;
    info->iovec.iov_len = 0;

    info->uri = 0;
    info->http_standard = 0;
    info->request_type = 0;
    info->buffer = 0;
    info->remainder = 0;
    info->buffer_offset = 0;
    info->header_written = 0;
    info->exit_code = 0;
    info->exit_text = 0;
    info->user_headers = 0;
    globus_hashtable_init(&info->recv_headers,
                          16,  /*XXX how to decide this size? */
                          globus_hashtable_string_hash,
                          globus_hashtable_string_keyeq);
    globus_hashtable_init(&info->user_headers,
                          16,  /*XXX how to decide this size? */
                          globus_hashtable_string_hash,
                          globus_hashtable_string_keyeq);

    string_pair = (globus_xio_http_string_pair_t*)malloc(sizeof(globus_xio_http_string_pair_t));
    string_pair->key = "Content";
    string_pair->value = "bob";
    globus_hashtable_insert(&info->user_headers, "Content", string_pair);

    return info;
}

static globus_result_t
globus_l_xio_http_target_destroy(
    void *                                  driver_target)
{
    return GLOBUS_SUCCESS;
}


static globus_result_t
globus_l_xio_http_attr_init(
    void **                             out_attr)
{
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_http_attr_cntl(
    void *                              driver_attr,
    int                                 cmd,
    va_list                             ap)
{
    return GLOBUS_SUCCESS;
}
 
static void
globus_l_xio_http_handle_copy_element(
    void **                             dest_key,
    void **                             dest_datum,
    void *                              src_key,
    void *                              src_datum)
{
    globus_xio_http_string_pair_t* source;
    globus_xio_http_string_pair_t** dest;
    source = (globus_xio_http_string_pair_t*)src_datum;
    dest = (globus_xio_http_string_pair_t**)dest_datum;
    *dest_key = globus_libc_strdup(src_key);
    *dest = (globus_xio_http_string_pair_t*)malloc(sizeof(globus_xio_http_string_pair_t));
    (*dest)->key = globus_libc_strdup(source->key);
    (*dest)->value = globus_libc_strdup(source->value);
}

static void
globus_l_xio_http_handle_destroy_element(
    void *                              datum)
{
    globus_free(datum);
}

static globus_result_t
globus_l_xio_http_handle_cntl(
    void *                              driver_specific_handle,
    int                                 cmd,
    va_list                             ap)
{
    globus_hashtable_t *user_table;
    char *user_str;
    l_http_info_t *info = driver_specific_handle;

    switch(cmd) {
    case GLOBUS_XIO_HTTP_GET_HEADERS:
        user_table = (globus_hashtable_t *) va_arg(ap, globus_hashtable_t *);
        globus_hashtable_copy(user_table, 
                              &((l_http_info_t *)driver_specific_handle)->recv_headers,
                              globus_l_xio_http_handle_copy_element);
        break;
    case GLOBUS_XIO_HTTP_SET_HEADERS:
        user_table = (globus_hashtable_t *) va_arg(ap, globus_hashtable_t *);
        globus_hashtable_copy(&info->user_headers,
                              user_table, 
                              globus_l_xio_http_handle_copy_element);
        break;
    case GLOBUS_XIO_HTTP_GET_CONTACT:
        user_str = (char *)va_arg(ap, char *);
        strcpy(user_str, info->uri);
        break;
    case GLOBUS_XIO_HTTP_SET_EXIT_CODE:
        user_str = (char *)va_arg(ap, char *);
        info->exit_code = globus_libc_strdup(user_str);
        break;
    case GLOBUS_XIO_HTTP_SET_EXIT_TEXT:
        user_str = (char *)va_arg(ap, char *);
        info->exit_text = globus_libc_strdup(user_str);
        break;
    }
    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_http_attr_copy(
    void **                             dst,
    void *                              src)
{
    l_http_info_t *                     src_info;
    l_http_info_t *                     dst_info;

    src_info = (l_http_info_t *) src;
    dst_info = l_http_create_new_info();
    memcpy(dst_info, src_info, sizeof(l_http_info_t));

    *dst = dst_info;

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_http_attr_destroy(
    void *                              driver_attr)
{
    globus_free(driver_attr);

    return GLOBUS_SUCCESS;
}

static int
globus_l_xio_http_parse_header( l_http_info_t * info) 
{
    char *uri_start, *uri_end, *current_location, *colon_loc,
        *key, *value, *line_end;
    globus_xio_http_string_pair_t *string_pair;
    current_location = info->buffer + info->buffer_offset;
    if(!info->uri) {
        //first word is GET or POST
        if( strstr(current_location, "GET") )
            {
                info->request_type = globus_libc_strdup("GET");
            }
        else if(strstr(current_location, "POST") )
            {
                info->request_type = globus_libc_strdup("POST");
            }
        else
            {
                return GLOBUS_XIO_HTTP_PARSE_FAILED;
            }

        //next get the path
        uri_start = strstr(current_location, " ") + 1;
        uri_end = strstr(uri_start, " ");
        info->uri = globus_libc_strndup(uri_start, uri_end - uri_start);

        //and the version of http we're speaking
        info->http_standard = globus_libc_strdup(uri_end+1);
        current_location = strstr(uri_end, "\r\n") + 2;
    }

    //process the rest of the recv_headers
    while( strstr(current_location, "\r\n") != current_location )
        {
            //check if we have an unterminated line
            if( !strstr(current_location, "\r\n" ) )
            {
                info->buffer_offset = index(current_location, '\0') - 
                    info->buffer;
                return GLOBUS_XIO_HTTP_NEED_MORE;
            }

            //we know we have a line, process it.
            line_end = strstr(current_location, "\r\n");
            colon_loc = index(current_location, ':');
            if(!colon_loc || colon_loc > line_end)
                {
                    return GLOBUS_XIO_HTTP_PARSE_FAILED;
                }
            else
                {
                    key = globus_libc_strndup(current_location, colon_loc - current_location);
                    value = globus_libc_strndup(colon_loc, line_end - colon_loc);
                    string_pair = (globus_xio_http_string_pair_t*)malloc(sizeof(globus_xio_http_string_pair_t));
                    string_pair->key = key;
                    string_pair->value = value;
                    globus_hashtable_insert(&info->recv_headers, key, string_pair);
                    current_location = line_end + 2;
                }  
        }
    if(strlen(current_location) > 0)
        {
            info->remainder = globus_libc_strdup(current_location);
        }
    return GLOBUS_SUCCESS;        
}


/*
 *  read
 */
static void
globus_l_xio_http_read_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    int parse_result;

    GlobusXIOName(globus_l_xio_http_read_cb);

    globus_xio_driver_handle_t          driver_handle;
    l_http_info_t *info = (l_http_info_t *)user_arg;
    driver_handle = GlobusXIOOperationGetDriverHandle(op);

    parse_result = globus_l_xio_http_parse_header(info);
    switch(parse_result) {
    case GLOBUS_XIO_HTTP_NEED_MORE:  //header not complete, read some more
        info->iovec.iov_len = 2048;
        info->iovec.iov_base = info->buffer + info->buffer_offset;
        result = globus_xio_driver_pass_read(op, &(info->iovec), 1, 1,
                                globus_l_xio_http_read_cb, info);
        break;
    case GLOBUS_XIO_HTTP_PARSE_FAILED:  //error parsing header
        result = GlobusXIOHttpParseError();
        globus_xio_driver_finished_open(driver_handle, info, op, result);
        break;
    default:
        result = GLOBUS_SUCCESS;
        globus_xio_driver_finished_open(driver_handle, info, op, result);
    }

}

static
globus_result_t
globus_l_xio_http_read(
    void *                              driver_specific_handle,
    const globus_xio_iovec_t *          iovec,
    int                                 iovec_count,
    globus_xio_operation_t              op)
{
    globus_result_t                     res;
    globus_size_t                       wait_for;

    wait_for = GlobusXIOOperationGetWaitFor(op);

    res = globus_xio_driver_pass_read(op, (void*)iovec, iovec_count, wait_for,
        NULL, NULL);

    return res;
}

/*
 *  open
 */


static void
globus_l_xio_http_open_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    void *                                  user_arg)
{
    globus_xio_driver_handle_t              driver_handle;
    l_http_info_t                           *handle;
    int                                     nbytes=0;
    driver_handle = GlobusXIOOperationGetDriverHandle(op);

    //Parse the recv_headers
    nbytes = 2048;
    handle = l_http_create_new_info();
    handle->buffer = (char*)globus_malloc(CHUNK_SIZE);
    
    handle->iovec.iov_len = 2048;
    handle->iovec.iov_base = handle->buffer + handle->buffer_offset;
    result = globus_xio_driver_pass_read(op, &(handle->iovec), 1, 5, 
                            globus_l_xio_http_read_cb, handle);
}

static
globus_result_t
globus_l_xio_http_open(
    void *                                  driver_target,
    void *                                  driver_attr,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res = GLOBUS_SUCCESS;
    globus_xio_driver_handle_t              driver_handle;

    res = globus_xio_driver_pass_open(
        &driver_handle, op, globus_l_xio_http_open_cb, NULL);

    return GLOBUS_SUCCESS;
}

/*
 *  close
 */
static void
globus_l_xio_http_close_cb(
    globus_xio_operation_t              op,
    globus_result_t                     result,
    void *                              user_arg)
{   
    globus_xio_driver_handle_t          driver_handle;

    driver_handle = GlobusXIOOperationGetDriverHandle(op);
    globus_xio_driver_finished_close(op, result);
    globus_xio_driver_handle_close(driver_handle);
}

/*
 *  simply pass the close on down
 */
static globus_result_t
globus_l_xio_http_close(
    void *                                  driver_specific_handle,
    void *                                  attr,
    globus_xio_driver_handle_t              driver_handle,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;
    l_http_destroy_info(driver_specific_handle);
    res = globus_xio_driver_pass_close(op, globus_l_xio_http_close_cb, NULL);

    return res;
}

/*
 *  write
 */
static void
globus_l_xio_http_write_cb(
    globus_xio_operation_t                  op,
    globus_result_t                         result,
    globus_size_t                           nbytes,
    void *                                  user_arg)
{
    globus_xio_driver_finished_write(op, result, nbytes);
}

/*
 *  writes are easy, just pass everything along
 */
static
globus_result_t
globus_l_xio_http_write(
    void *                                  driver_specific_handle,
    const globus_xio_iovec_t *              iovec,
    int                                     iovec_count,
    globus_xio_operation_t                  op)
{
    globus_result_t                         res;
    globus_size_t                           wait_for;
    l_http_info_t *                         info;
    char *                                  header_str;
    char                                    buffer_to_send[1024];
    globus_xio_http_string_pair_t           *current_pair;
    int                                     send_size;

    info = (l_http_info_t *) driver_specific_handle;

    wait_for = GlobusXIOOperationGetWaitFor(op);

    if(!info->header_written)
        { 
            //create a header to prepend to the user buffer
            //header_str = globus_libc_strdup("");
            info->header_written =1;
            if(!info->exit_code && !info->exit_text)
                {
                    globus_xio_driver_finished_write(op, 
                                                 GLOBUS_XIO_HTTP_INSUFFICIENT_HEADER, 
                                                 0);
                }
            header_str = (char*)globus_malloc( strlen("HTTP/1.1 ")+
                                              strlen(info->exit_code)+
                                              strlen(info->exit_text) + 10 );
            sprintf(buffer_to_send, 
                    "%s %s %s\r\n", 
                    "HTTP/1.1 ", 
                    info->exit_code, 
                    info->exit_text); 

            current_pair = globus_hashtable_first(&info->user_headers);
            while(current_pair) 
                {
                    //sprintf(&buffer_to_send + strlen(&buffer_to_send) - 1,
                    sprintf(&buffer_to_send[strlen(buffer_to_send)],
                            "%s: %s\r\n",
                            current_pair->key, 
                            current_pair->value);
                    current_pair = globus_hashtable_next(&info->user_headers);
                }
            strcpy(buffer_to_send, header_str);
            strcat(buffer_to_send, "\r\n");

            memcpy(buffer_to_send+strlen(buffer_to_send), 
                   iovec->iov_base, 
                   iovec->iov_len);
            info->iovec.iov_base = buffer_to_send;
            info->iovec.iov_len = send_size;
            res = globus_xio_driver_pass_write(
                op, (void*)&(info->iovec), 1, info->iovec.iov_len, 
               globus_l_xio_http_write_cb, driver_specific_handle);
        } 
    else
        {            res = globus_xio_driver_pass_write(
                op, (void*)iovec, iovec_count, wait_for,
                                     globus_l_xio_http_write_cb, driver_specific_handle);
        }

    return res;
}
 

static globus_result_t
globus_l_xio_http_target_init(
    void **                             out_target,
    void *                              driver_attr,
    globus_xio_contact_t *              contact_info)
{ 
    //We don't do client work yet.  Only server
    *out_target = (void *)globus_libc_strdup(_TARGET);

    return GLOBUS_SUCCESS;
}

static globus_result_t
globus_l_xio_http_server_init(
    void **                             out_server,
    void *                              driver_attr)
{
    *out_server = (void *)globus_libc_strdup(_SERVER);

    return GLOBUS_SUCCESS;
}


/*
 *   accepting
 *
 *   Meary pass the accept, set target state to server.  The open will
 *   take care of the protocol exchange.
 */
static void
globus_l_xio_http_accept_cb(
    globus_i_xio_op_t *                     op,
    globus_result_t                         result,
    void *                                  user_arg)
{

    globus_xio_driver_finished_accept(op, globus_libc_strdup(_TARGET), GLOBUS_SUCCESS);
    return;

}
 

static globus_result_t
globus_l_xio_http_accept(
    void *                                  driver_server,
    void *                                  driver_attr,
    globus_xio_operation_t                   accept_op)
{
    globus_result_t                         res;
    GlobusXIOName(globus_l_xio_http_accept);

    res = globus_xio_driver_pass_accept(accept_op, 
        globus_l_xio_http_accept_cb, NULL);

    return res;
}


static globus_result_t
globus_l_xio_http_load(
    globus_xio_driver_t *                   out_driver,
    va_list                                 ap)
{
    globus_xio_driver_t                     driver;
    globus_result_t                         res;

    res = globus_xio_driver_init(&driver, "http", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        globus_l_xio_http_open,
        globus_l_xio_http_close,
        globus_l_xio_http_read,
        globus_l_xio_http_write,
        globus_l_xio_http_handle_cntl,
	NULL);

    globus_xio_driver_set_attr(
        driver,
        globus_l_xio_http_attr_init,
        globus_l_xio_http_attr_copy,
        globus_l_xio_http_attr_cntl,
        globus_l_xio_http_attr_destroy);

    globus_xio_driver_set_client(
        driver,
        globus_l_xio_http_target_init,
        NULL,
        globus_l_xio_http_target_destroy);

    globus_xio_driver_set_server(
        driver,
        globus_l_xio_http_server_init,
        globus_l_xio_http_accept,
        NULL,
        NULL,
        globus_l_xio_http_target_destroy);
    *out_driver = driver;

    return GLOBUS_SUCCESS;
}



static void
globus_l_xio_http_unload(
    globus_xio_driver_t                     driver)
{
    globus_xio_driver_destroy(driver);
}


static
int
globus_l_xio_http_activate(void)
{
    int                                     rc;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);

    return rc;
}

static
int
globus_l_xio_http_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_COMMON_MODULE);
}

GlobusXIODefineDriver(
    http,
    &globus_i_xio_http_module,
    globus_l_xio_http_load,
    globus_l_xio_http_unload);

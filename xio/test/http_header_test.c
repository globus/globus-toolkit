/**
 * @file http_header_test.c HTTP Header test
 *
 * Test that clients can send arbitrary HTTP headers to servers.
 *
 * Test cases are read from a file passed on the command line.
 * File contains pseudo-xml sequences
 * <name>header-name</name>
 * <value>header-value</value>
 * so that we can test handling of whitespace in header names and values
 *
 * The test client will send the HEAD request for the /header-test URI and
 * set all of the headers in the test file in the request attributes.
 *
 * The test server will 
 * - verify the receipt of the /header-test URI
 * - compare request headers to contents of the file---additional headers
 *   such as Host will be ignored
 * - generate response headers which contain the headers in the test file
 */
#include "globus_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "globus_xio.h"
#include "globus_xio_http.h"
#include "globus_xio_tcp_driver.h"

globus_xio_driver_t                     tcp_driver;
globus_xio_driver_t                     http_driver;
globus_xio_attr_t                       server_attr;
globus_xio_handle_t                     server_handle;
globus_mutex_t                          mutex;
globus_cond_t                           cond;
globus_hashtable_t                      hashtable;
int                                     done = 0;

static
int
read_test_file(
    const char *                        filename,
    globus_hashtable_t *                hashtable);

static
void
globus_l_xio_test_server_accept_callback(
    globus_xio_server_t                 server,
    globus_xio_target_t                 target,
    globus_result_t                     result,
    void *                              user_arg);

static
void
globus_l_xio_test_server_request_callback(
    globus_result_t                     result,
    const char *                        method,
    const char *                        uri,
    globus_xio_http_version_t           http_version,
    globus_hashtable_t                  headers);

static 
void
globus_l_xio_test_client_response_callback(
    globus_result_t                     result,
    int                                 status_code,
    const char *                        reason_phrase,
    globus_xio_http_version_t           version,
    globus_hashtable_t                  headers);

static
void
globus_l_xio_test_server_open_callback(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg);

static
globus_bool_t
headers_match(
    globus_hashtable_t                  headers);

int
main(
    int                                 argc,
    char *                              argv[])
{
    int                                 rc;
    globus_result_t                     result;
    char *                              local_contact;
    globus_xio_stack_t                  stack;
    globus_xio_server_t                 server;
    globus_xio_attr_t                   attr;
    char *                              contact_string;
    globus_xio_target_t                 target;
    globus_xio_http_header_t *          current_header;
    globus_xio_handle_t                 handle;

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if (rc != 0)
    {
        rc = 1;

        fprintf(stderr, "Error activation GLOBUS_COMMON\n");

        goto error_exit;
    }

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    if (rc != 0)
    {
        fprintf(stderr, "Error activating GLOBUS_XIO\n");
        rc = 2;

        goto deactivate_exit;
    }
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s header-test-filename\n", argv[0]);

        rc = 3;
        goto deactivate_exit;
    }
    rc = globus_mutex_init(&mutex, NULL);
    if (rc != 0)
    {
        fprintf(stderr, "Error initializing mutex\n");
        rc = 27;
        goto deactivate_exit;
    }
    rc = globus_cond_init(&cond, NULL);
    if (rc != 0)
    {
        fprintf(stderr, "Error initializing cond\n");
        rc = 28;
        goto destroy_mutex_exit;
    }
    rc = read_test_file(argv[1], &hashtable);

    if (rc != 0)
    {
        goto destroy_cond_exit;
    }

    result = globus_xio_driver_load("tcp", &tcp_driver);
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error loading tcp driver: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));

        rc = 10;

        goto deactivate_exit;
    }
    result = globus_xio_driver_load("http", &http_driver);
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error loading http driver: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));

        rc = 11;

        goto unload_tcp_exit;
    }

    result = globus_xio_stack_init(&stack, NULL);
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error initializing xio stack: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));
        rc = 12;

        goto unload_http_exit;
    }
    result = globus_xio_stack_push_driver(
            stack,
            tcp_driver);
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error pushing tcp onto stack: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));
        rc = 13;

        goto destroy_stack_exit;
    }

    result = globus_xio_stack_push_driver(
            stack,
            http_driver);
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error pushing http onto stack: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));
        rc = 14;

        goto destroy_stack_exit;
    }
    result = globus_xio_attr_init(&server_attr);
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error pushing http onto stack: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));
        rc = 25;

        goto destroy_stack_exit;
    }
    result = globus_xio_attr_cntl(
            server_attr,
            http_driver,
            GLOBUS_XIO_HTTP_ATTR_SET_REQUEST_CALLBACK,
            globus_l_xio_test_server_request_callback,
            NULL);
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error setting server request callback: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));
        rc = 26;

        goto destroy_server_attr_exit;
    }

    result = globus_xio_server_create(
            &server,
            server_attr,
            stack);
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error creating http server: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));
        rc = 15;
        goto destroy_server_attr_exit;
    }

    result = globus_xio_server_cntl(
            server,
            tcp_driver,
            GLOBUS_XIO_TCP_GET_LOCAL_CONTACT,
            &local_contact);
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error getting http server contact: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));
        rc = 16;
        goto destroy_server_exit;
    }
    result = globus_xio_server_register_accept(
            server,
            NULL,
            globus_l_xio_test_server_accept_callback,
            NULL);
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error registering http server accept: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));
        rc = 17;
        goto destroy_server_exit;
    }
    contact_string = globus_libc_malloc(
            strlen("http:///%2fheader-test") + strlen(local_contact) + 1);
    if (contact_string == NULL)
    {
        fprintf(stderr,
                "Error allocating contact string: %s\n",
                strerror(errno));
        rc = 18;
        goto destroy_server_exit;
    }
    sprintf(contact_string,
            "http://%s/%%2fheader-test",
            local_contact);
    result = globus_xio_target_init(
            &target,
            NULL,
            contact_string,
            stack);
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error initializing target: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));
        rc = 19;
        goto free_contact_exit;
    }

    result = globus_xio_attr_init(&attr);
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error initializing attr: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));
        rc = 20;
        goto free_target_exit;
    }

    result = globus_xio_attr_cntl(
            attr,
            http_driver,
            GLOBUS_XIO_HTTP_ATTR_SET_REQUEST_METHOD,
            "HEAD");
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error setting http method in attr: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));
        rc = 21;
        goto free_attr_exit;
    }

    result = globus_xio_attr_cntl(
            attr,
            http_driver,
            GLOBUS_XIO_HTTP_ATTR_SET_RESPONSE_CALLBACK,
            globus_l_xio_test_client_response_callback,
            NULL);

    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error setting response callback: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));
        rc = 24;

        goto free_attr_exit;
    }
    current_header = globus_hashtable_first(&hashtable);

    while (current_header != NULL)
    {
        result = globus_xio_attr_cntl(
                attr,
                http_driver,
                GLOBUS_XIO_HTTP_ATTR_SET_REQUEST_HEADER,
                current_header->name,
                current_header->value);

        if (result != GLOBUS_SUCCESS)
        {
            fprintf(stderr,
                    "Error setting header: %s\n",
                    globus_object_printable_to_string(
                        globus_error_peek(result)));
            rc = 22;

            goto free_attr_exit;
        }

        current_header = globus_hashtable_next(&hashtable);
    }
    result = globus_xio_open(
            &handle,
            attr,
            target);
    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr,
                "Error opening HTTP stream: %s\n",
                globus_object_printable_to_string(globus_error_peek(result)));
        rc = 23;

        goto free_attr_exit;
    }

    globus_mutex_lock(&mutex);
    while (!done)
    {
        globus_cond_wait(&cond, &mutex);
    }

    if (done == 1)
    {
        fprintf(stdout, "Success\n");
        rc = 0;
    }
    else
    {
        fprintf(stdout, "Test failed\n");
        rc = 100;
    }
    globus_mutex_unlock(&mutex);

free_attr_exit:
    globus_xio_attr_destroy(attr);
free_target_exit:
    globus_xio_target_destroy(target);
free_contact_exit:
    globus_libc_free(contact_string);
destroy_server_exit:
    globus_xio_server_close(server);
destroy_server_attr_exit:
    globus_xio_attr_destroy(server_attr);
destroy_stack_exit:
    globus_xio_stack_destroy(stack);
unload_http_exit:
    globus_xio_driver_unload(http_driver);
unload_tcp_exit:
    globus_xio_driver_unload(tcp_driver);
destroy_cond_exit:
    globus_cond_destroy(&cond);
destroy_mutex_exit:
    globus_mutex_destroy(&mutex);
deactivate_exit:
    globus_module_deactivate_all();
error_exit:
    return rc;
}
/* main() */

static
int
read_test_file(
    const char *                        filename,
    globus_hashtable_t *                hashtable)
{
    int                                 rc;
    long                                file_size;
    char *                              buffer;
    char *                              token;
    char *                              token_end;
    FILE *                              file;
    globus_xio_http_header_t *          header;

    rc = globus_hashtable_init(
            hashtable,
            16,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);

    if (rc != 0)
    {
        rc = 3;
        goto error_exit;
    }
    file = fopen(filename, "r");

    if (file == NULL)
    {
        fprintf(stderr,
                "Unable to open %s for reading: %s\n",
                filename,
                strerror(errno));
        rc = 4;
        goto error_exit;
    }
    rc = fseek(file, 0, SEEK_END);

    if (rc != 0)
    {
        fprintf(stderr,
                "Unable to seek to end of file %s: %s\n",
                filename,
                strerror(errno));
        rc = 5;
        goto fclose_exit;
    }

    file_size = ftell(file);
    if (file_size == -1)
    {
        fprintf(stderr,
                "Unable to determine size of %s: %s\n",
                filename,
                strerror(errno));
        rc = 6;

        goto fclose_exit;
    }
    rewind(file);

    buffer = globus_libc_malloc((size_t) file_size+1);
    if (buffer == NULL)
    {
        fprintf(stderr,
                "Unable to allocate buffer: %s\n",
                strerror(errno));

        rc = 8;
        goto fclose_exit;
    }
    rc = fread(buffer, (size_t) file_size, 1, file);
    if (rc != 1)
    {
        rc = 9;
        fprintf(stderr,
                "Error reading %s: %s\n",
                filename,
                strerror(errno));

        goto fclose_exit;
    }
    buffer[(size_t) file_size] = '\0';

    /* This parser assumes the file has matching tags */
    while ((token = strstr(buffer, "<name>")) != NULL)
    {
        header = globus_libc_malloc(sizeof(globus_xio_http_header_t));

        token += strlen("<name>");
        token_end = strstr(token, "</name>");
        *token_end = '\0';

        header->name = token;

        token = strstr(token_end+1, "<value>");
        token += strlen("<value>");
        token_end = strstr(token, "</value>");
        *token_end = '\0';

        header->value = token;

        globus_hashtable_insert(hashtable, header->name, header);
        buffer = token_end+1;
    }
    fclose(file);

    return 0;

fclose_exit:
    fclose(file);
error_exit:
    return rc;
}
/* read_test_file() */

static
void
globus_l_xio_test_server_accept_callback(
    globus_xio_server_t                 server,
    globus_xio_target_t                 target,
    globus_result_t                     result,
    void *                              user_arg)
{
    if (result != GLOBUS_SUCCESS)
    {
        goto error_exit;
    }
    result = globus_xio_register_open(
            &server_handle,
            server_attr,
            target,
            globus_l_xio_test_server_open_callback,
            NULL);
    return;

error_exit:
    globus_xio_target_destroy(target);
}
/* globus_l_xio_test_server_accept_callback() */

static
void
globus_l_xio_test_server_open_callback(
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    /* Do nothing here */
}
/* globus_l_xio_test_server_open_callback() */

static
void
globus_l_xio_test_server_request_callback(
    globus_result_t                     result,
    const char *                        method,
    const char *                        uri,
    globus_xio_http_version_t           http_version,
    globus_hashtable_t                  headers)
{
    globus_xio_http_header_t *          current_header;

    if (method && uri)
    {
        if (strcmp(method, "HEAD") != 0)
        {
            fprintf(stderr, "Unexpected method: %s\n", method);
        }
        if (strcmp(uri, "/header-test") != 0)
        {
            fprintf(stderr, "Unexpected uri: %s\n", uri);
        }

        if (headers_match(headers))
        {
            current_header = globus_hashtable_first(&hashtable);

            while (current_header != NULL)
            {
                result = globus_xio_handle_cntl(
                        server_handle,
                        http_driver,
                        GLOBUS_XIO_HTTP_HANDLE_SET_RESPONSE_HEADER,
                        current_header->name,
                        current_header->value);

                if (result != GLOBUS_SUCCESS)
                {
                    fprintf(stderr,
                            "Error setting header: %s\n",
                            globus_object_printable_to_string(
                                globus_error_peek(result)));

                    globus_xio_handle_cntl(
                        server_handle,
                        http_driver,
                        GLOBUS_XIO_HTTP_HANDLE_SET_RESPONSE_STATUS_CODE,
                        404);
                    break;
                }

                current_header = globus_hashtable_next(&hashtable);
            }
        }
        else
        {
            globus_xio_handle_cntl(
                server_handle,
                http_driver,
                GLOBUS_XIO_HTTP_HANDLE_SET_RESPONSE_STATUS_CODE,
                404);
        }
    }
    else
    {
        fprintf(stderr, "Invalid request\n");

        globus_xio_handle_cntl(
            server_handle,
            http_driver,
            GLOBUS_XIO_HTTP_HANDLE_SET_RESPONSE_STATUS_CODE,
            404);
    }

    globus_xio_handle_cntl(
        server_handle,
        http_driver,
        GLOBUS_XIO_HTTP_HANDLE_SET_END_OF_ENTITY);

}
/* globus_l_xio_test_server_request_callback() */

static 
void
globus_l_xio_test_client_response_callback(
    globus_result_t                     result,
    int                                 status_code,
    const char *                        reason_phrase,
    globus_xio_http_version_t           version,
    globus_hashtable_t                  headers)
{
    globus_mutex_lock(&mutex);
    if (status_code == 200 && headers_match(headers))
    {
        done = 1;
    }
    else
    {
        fprintf(stderr, "Invalid response\n");

        done = -1;
    }
    globus_cond_signal(&cond);
    globus_mutex_unlock(&mutex);
}
/* globus_l_xio_test_client_response_callback() */

static
globus_bool_t
headers_match(
    globus_hashtable_t                  headers)
{
    globus_xio_http_header_t *          current_header;
    globus_xio_http_header_t *          current_header_orig;
    char *                              src_value;
    char *                              dst_value;

    current_header = globus_hashtable_first(&hashtable);

    while (current_header != NULL)
    {
        current_header_orig = globus_hashtable_lookup(
                &headers,
                current_header->name);

        if (current_header_orig == NULL)
        {
            fprintf(stderr, "Header \"%s\" not found\n", current_header->name);
            return GLOBUS_FALSE;
        }
        src_value = current_header_orig->value;
        dst_value = current_header->value;

        while (src_value != NULL && dst_value != NULL &&
                *src_value != '\0' && *dst_value != '\0')
        {
            if (isspace(*src_value))
            {
                src_value++;
            }
            else if (isspace(*dst_value))
            {
                dst_value++;
            }
            else if (*src_value != *dst_value)
            {
                fprintf(stderr,
                        "value of header \"%s\" mismatch\n",
                        current_header->name);
                return GLOBUS_FALSE;
            }
            else
            {
                src_value++;
                dst_value++;
            }
        }
        while (isspace(*dst_value))
        {
            dst_value++;
        }
        if ((*src_value) != (*dst_value))
        {
            return GLOBUS_FALSE;
        }
        current_header = globus_hashtable_next(&hashtable);
    }
    return GLOBUS_TRUE;
}

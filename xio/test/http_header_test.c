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

/**
 * @file http_header_test.c HTTP Header test
 *
 * Test that clients can send arbitrary HTTP headers to servers, and servers
 * can send arbitrary HTTP headers to clients.
 *
 * Test cases are read from a file passed on the command line.
 * File contains pseudo-xml sequences
 * <name>header-name</name>
 * <value>header-value</value>
 * so that we can test handling of whitespace in header names and values
 *
 * The test client will send a HEAD request for the /header-test URI and
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
#include "http_test_common.h"

globus_xio_http_header_t *              test_headers;
globus_size_t                           test_headers_length;
int                                     done = 0;

static
int
read_test_file(
    const char *                        filename);

static
globus_bool_t
headers_match(
    globus_hashtable_t                  headers);

static
void
globus_l_xio_test_server_request_callback(
    void *                              user_arg,
    globus_result_t                     result,
    const char *                        method,
    const char *                        uri,
    globus_xio_http_version_t           http_version,
    globus_hashtable_t                  headers);


static
int
server_main(
    const char *                        filename,
    globus_xio_driver_t                 tcp_driver,
    globus_xio_driver_t                 http_driver,
    globus_xio_stack_t                  stack)
{
    int                                 rc;
    globus_result_t                     result;
    http_test_server_t                  test_server;

    rc = read_test_file(filename);

    if (rc != 0)
    {
        goto error_exit;
    }

    result = http_test_server_init(
            &test_server,
            tcp_driver,
            http_driver,
            stack);

    if (result != GLOBUS_SUCCESS)
    {
        rc = 29;

        goto error_exit;
    }

    result = http_test_server_register_handler(
            &test_server,
            "/header-test",
            globus_l_xio_test_server_request_callback,
            &test_server);

    printf("%s\n", test_server.contact);

    fflush(stdout);

    result = http_test_server_run(&test_server);

    if (result != GLOBUS_SUCCESS)
    {
        rc = 30;

        goto error_exit;
    }
    http_test_server_destroy(&test_server);

error_exit:
    return rc;
}

static
int
client_main(
    const char *                        filename,
    const char *                        contact,
    globus_xio_driver_t                 tcp_driver,
    globus_xio_driver_t                 http_driver,
    globus_xio_stack_t                  stack)
{
    int                                 rc;
    globus_xio_handle_t                 handle;
    globus_result_t                     result;
    int                                 status_code;
    char *                              reason_phrase;
    globus_xio_data_descriptor_t        descriptor;
    globus_byte_t                       buffer[1];
    globus_hashtable_t                  headers;

    rc = read_test_file(filename);

    if (rc != 0)
    {
        goto error_exit;
    }

    result = http_test_client_request(
            &handle,
            tcp_driver,
            http_driver,
            stack,
            contact,
            "%2fheader-test",
            "HEAD",
            GLOBUS_XIO_HTTP_VERSION_UNSET,
            test_headers,
            test_headers_length);

    if (result != GLOBUS_SUCCESS)
    {
        rc = 40;
        goto error_exit;
    }

    /* READ RESPONSE */
    result = globus_xio_data_descriptor_init(&descriptor, handle);
    if (result != GLOBUS_SUCCESS)
    {
        rc = 51;

        goto close_exit;
    }

    result = globus_xio_read(
            handle,
            buffer, 
            0,
            0,
            NULL,
            descriptor);

    if (result != GLOBUS_SUCCESS)
    {
        rc = 52;

        goto close_exit;
    }

    result = globus_xio_data_descriptor_cntl(
        descriptor,
        http_driver,
        GLOBUS_XIO_HTTP_GET_RESPONSE,
        &status_code,
        &reason_phrase,
        NULL,
        &headers);

    if (result != GLOBUS_SUCCESS || status_code < 200 || status_code > 299)
    {
        fprintf(stderr, "HEAD failed with \"%03d %s\"\n",
                status_code,
                reason_phrase);
        rc = 53;

        goto close_exit;
    }

    
    if (!headers_match(headers))
    {
        rc = 54;

        goto close_exit;
    }
close_exit:
    globus_xio_close(handle, NULL);

    if (rc == 0)
    {
        fprintf(stdout, "Success\n");
    }
    else
    {
        fprintf(stdout, "Test failed\n");
        rc = 100;
    }
error_exit:
    return rc;
}
/* main() */

static
int
read_test_file(
    const char *                        filename)
{
    int                                 rc;
    long                                file_size;
    char *                              buffer;
    char *                              token;
    char *                              token_end;
    FILE *                              file;
    globus_hashtable_t                  hashtable;
    globus_xio_http_header_t *          header;
    globus_xio_http_header_t *          current_header;
    int                                 i;

    rc = globus_hashtable_init(
            &hashtable,
            512,
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

        globus_hashtable_insert(&hashtable, header->name, header);
        buffer = token_end+1;
    }

    fclose(file);

    test_headers_length = globus_hashtable_size(&hashtable);
    test_headers = globus_libc_malloc(
            test_headers_length *
            sizeof(globus_xio_http_header_t));

    current_header = globus_hashtable_first(&hashtable);
    i=0;

    while (current_header != NULL)
    {
        test_headers[i].name = current_header->name;
        test_headers[i].value = current_header->value;

        current_header = globus_hashtable_next(&hashtable);
        i++;
    }

    return 0;

fclose_exit:
    fclose(file);
error_exit:
    return rc;
}
/* read_test_file() */

static
void
globus_l_xio_test_server_request_callback(
    void *                              user_arg,
    globus_result_t                     result,
    const char *                        method,
    const char *                        uri,
    globus_xio_http_version_t           http_version,
    globus_hashtable_t                  headers)
{
    http_test_server_t *                test_server = user_arg;
    int                                 rc;

    if (result == GLOBUS_SUCCESS && headers_match(headers))
    {
        rc = 200;
    }
    else
    {
        rc = 404;
    }
    http_test_server_respond(
            test_server,
            rc,
            NULL,
            rc == 200 ? test_headers : NULL,
            rc == 200 ? test_headers_length: 0);
    http_test_server_close_handle(test_server);
    http_test_server_shutdown(test_server);

    return;
}
/* globus_l_xio_test_server_request_callback() */

static
globus_bool_t
headers_match(
    globus_hashtable_t                  headers)
{
    int                                 i;
    globus_xio_http_header_t *          current_header;
    char *                              src_value;
    char *                              dst_value;


    for (i = 0; i < test_headers_length; i++)
    {
        current_header = globus_hashtable_lookup(
                &headers,
                test_headers[i].name);

        if (current_header == NULL)
        {
            fprintf(stderr, "Header \"%s\" not found\n", test_headers[i].name);
            return GLOBUS_FALSE;
        }
        src_value = test_headers[i].value;
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
    }
    return GLOBUS_TRUE;
}

void usage(char * argv0)
{
    fprintf(stderr,
            "Usage: %s [-c|-s] -f filename\n"
            "  If -c is used, stdin should contain the contact string of the\n"
            "  server process.",
            argv0);
}

int main(int argc, char * argv[])
{
    int                                 rc;
    char *                              filename = NULL;
    globus_bool_t                       server = GLOBUS_FALSE;
    char *                              contact = NULL;
    globus_xio_driver_t                 tcp_driver;
    globus_xio_driver_t                 http_driver;
    globus_xio_stack_t                  stack;
    char                                gets_buffer[1024];

    while ((rc = getopt(argc, argv, "hf:cs")) != EOF)
    {
        switch (rc)
        {
            case 'f':
                filename = optarg;
                break;
            case 'c':
                server = GLOBUS_FALSE;
                contact = fgets(gets_buffer, sizeof(gets_buffer), stdin);
                break;
            case 's':
                server = GLOBUS_TRUE;
                contact = NULL;
                break;
            case 'h':
                usage(argv[0]);
                exit(0);
            default:
                usage(argv[0]);
                exit(1);
        }
    }

    if (((!server) && (contact == NULL)) || (filename == NULL))
    {
        usage(argv[0]);
        exit(1);
    }

    rc = http_test_initialize(&tcp_driver, &http_driver, &stack);

    if (rc != 0)
    {
        goto error_exit;
    }

    if (server)
    {
        rc = server_main(filename, tcp_driver, http_driver, stack);
    }
    else
    {
        rc = client_main(filename, contact, tcp_driver, http_driver, stack);
    }

    globus_xio_stack_destroy(stack);
    globus_xio_driver_unload(http_driver);
    globus_xio_driver_unload(tcp_driver);
    globus_module_deactivate_all();

error_exit:
    return rc;
}

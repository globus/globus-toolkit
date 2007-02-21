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

#include "globus_xio.h"
#include "globus_xio_tcp_driver.h"

#define LINE_LEN 1024

void
test_res(
    globus_result_t                         res)
{
    if(res == GLOBUS_SUCCESS)
    {
        return;
    }

    fprintf(stderr, "ERROR: %s\n", globus_object_printable_to_string(
        globus_error_get(res)));

    globus_assert(0);
}

void
help()
{
    fprintf(stdout, "globus-gridftp-register <registry contact> <contact port> <max conneciton count> [<total>] [<repo name>]\n");
}

int
main(
    int                                     argc,
    char **                                 argv)
{
    int                                     arg_i = 0;
    int                                     c_count;
    int                                     total;
    globus_xio_driver_t                     tcp_driver;
    globus_xio_driver_t                     gsi_driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    char *                                  cs;
    char *                                  repo;
    char *                                  registry_cs;
    globus_result_t                         res;
    char                                    msg[256];
    globus_size_t                           nbytes;
    int                                     len;
    char *                                  local_contact = NULL;
    char *                                  tmp_ptr;
    char *                                  cookie_str;
    char                                    cookie[16];

    if(argc < 5)
    {
        help();
        return 1;
    }

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_xio_stack_init(&stack, NULL);

    res = globus_xio_driver_load("tcp", &tcp_driver);
    test_res(res);
    res = globus_xio_stack_push_driver(stack, tcp_driver);
    test_res(res);

    arg_i = 1;
    if(strcmp(argv[arg_i], "-s") == 0)
    {
        arg_i++;
        res = globus_xio_driver_load("gsi", &gsi_driver);
        test_res(res);
        res = globus_xio_stack_push_driver(stack, gsi_driver);
        test_res(res);
    }
    if(strcmp(argv[arg_i], "-rn") == 0)
    {
        arg_i++;
        local_contact = strdup(argv[arg_i]);
        arg_i++;
    }
    registry_cs = argv[arg_i];
    arg_i++;
    cs = argv[arg_i];
    arg_i++;
    cookie_str = argv[arg_i];
    arg_i++;
    c_count = atoi(argv[arg_i]);
    arg_i++;

    if(arg_i != argc)
    {
        total = atoi(argv[arg_i]);
        arg_i++;
    }
    if(arg_i == argc)
    {
        repo = "";
    }
    else
    {
        repo = argv[arg_i];
    }

    memset(cookie, '\0', 16);
    strncpy(cookie, cookie_str, 16);

    res = globus_xio_handle_create(&xio_handle, stack);
    test_res(res);

printf("##### %s\n", registry_cs);
    res = globus_xio_open(xio_handle, registry_cs, NULL);
    test_res(res);

    if(local_contact == NULL)
    {
        res = globus_xio_handle_cntl(
            xio_handle,
            tcp_driver,
            GLOBUS_XIO_TCP_GET_LOCAL_NUMERIC_CONTACT,
            &local_contact);
        test_res(res);
    }

    tmp_ptr = strchr(local_contact, ':');
    assert(tmp_ptr != NULL);
    *tmp_ptr = '\0';
    printf("%s\n", local_contact); /* write out the actual IP we will use */

    memset(msg, '\0', 256);
    len = strlen(repo);
    msg[0] = (char)c_count;
    msg[1] = (char)total;
    strncpy(&msg[2], cookie, 16);
    
    memcpy(&msg[16+2], repo, len);
    msg[len+16+2] = '\0';
    sprintf(&msg[len+16+3], "%s:%s", local_contact, cs);
    printf("registering\n  repo=[%s]\n  server contact=[%s]\n  max=[%d]\n"
                        "  total=[%d]\n  cookie=[%s]\n",
        repo, &msg[len+16+3], c_count, total, &msg[len+2]);
    res = globus_xio_write(xio_handle, msg, 256, 256, &nbytes, NULL);
    test_res(res);
    assert(nbytes == 256);

    globus_xio_close(xio_handle, NULL);

    globus_module_activate(GLOBUS_XIO_MODULE);

    return 0;
}

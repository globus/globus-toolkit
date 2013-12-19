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
#include "globus_common.h"
#include "test_common.h"
#include "globus_xio_test_transport.h"

#define OP_COUNT 8

static void
data_close_cb(
    globus_xio_handle_t                     handle,
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           len,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
}

int
unload_main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_driver_t                     test_driver;
    globus_xio_driver_t                     debug_driver;
    globus_xio_driver_t                     bounce_driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     handle;
    globus_result_t                         res;
    globus_byte_t                           buffer[1024];
    int                                     pos;

    pos = atoi(argv[1]);

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    /* simple unload test */
    res = globus_xio_stack_init(&stack, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_driver_load("test", &test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_driver_load("bounce", &debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_driver_load("debug", &bounce_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_stack_push_driver(stack, test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_stack_push_driver(stack, bounce_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_stack_push_driver(stack, debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_handle_create(&handle, stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    if(pos == 1)
    {
        res = globus_xio_open(
            handle,
            "whatever",
            NULL);
    }
    else if(pos == 2)
    {
        res = globus_xio_register_open(
            handle,
            "whatever",
            NULL,
            NULL,
            NULL);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    }
    else if(pos == 3)
    {
        res = globus_xio_open(
            handle,
            "whatever",
            NULL);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

        res = globus_xio_register_write(
            handle,
            buffer,
            sizeof(buffer),
            sizeof(buffer),
            NULL,
            data_close_cb,
            NULL);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    }
    else if(pos == 4)
    {
        res = globus_xio_open(
            handle,
            "whatever",
            NULL);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

        res = globus_xio_register_read(
            handle,
            buffer,
            sizeof(buffer),
            sizeof(buffer),
            NULL,
            data_close_cb,
            NULL);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    }
    else
    {
        globus_assert(0);
    }
    
    globus_xio_stack_destroy(stack);
    res = globus_xio_driver_unload(debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_driver_unload(test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_driver_unload(bounce_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    fprintf(stdout, "Success.\n");

    return 0;
}

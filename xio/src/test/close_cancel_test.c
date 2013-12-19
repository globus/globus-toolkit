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

static globus_mutex_t                   globus_l_mutex;
static globus_cond_t                    globus_l_cond;

#define OP_COUNT                            16

static void
data_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    globus_byte_t *                             buffer,
    globus_size_t                               len,
    globus_size_t                               nbytes,
    globus_xio_data_descriptor_t                data_desc,
    void *                                      user_arg)
{
    globus_mutex_lock(&globus_l_mutex);
    {
        if(result == GLOBUS_SUCCESS)
        {
            printf("WARINING: data allback should have a failure code\n");
        }
    }
    globus_mutex_unlock(&globus_l_mutex);
}

static void
open_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
        if(result == GLOBUS_SUCCESS ||
            (!globus_error_match(
                globus_error_peek(result),
                GLOBUS_XIO_MODULE,
                GLOBUS_XIO_ERROR_CANCELED))) 
        {
            fprintf(stderr, "open callback should have been with a cancel.\n");
        }
}

int
close_cancel_main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    int                                     pos;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     handle;
    globus_result_t                         res;
    globus_xio_attr_t                       attr;
    globus_byte_t                           buffer[1024];

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    res = globus_xio_attr_init(&attr);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_stack_init(&stack, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    parse_parameters(argc, argv, stack, attr);
    pos = atoi(argv[argc - 1]);

    globus_mutex_init(&globus_l_mutex, NULL);
    globus_cond_init(&globus_l_cond, NULL);

    res = globus_xio_handle_create(&handle, stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    if(pos == 1)
    {
            res = globus_xio_register_open(
                    handle,
                    "whatever", 
                    attr,
                    open_cb,
                    NULL);
            test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
            res = globus_xio_close(handle, NULL);
            test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    }
    else if(pos == 2)
    {
        res = globus_xio_open(handle, "whatever", attr);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
        res = globus_xio_register_write(
                handle,
                buffer,
                sizeof(buffer),
                sizeof(buffer),
                NULL,
                data_cb,
                NULL);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
        res = globus_xio_close(handle, NULL);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    }

    res = globus_xio_attr_destroy(attr);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_stack_destroy(stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    test_common_end();

    globus_mutex_destroy(&globus_l_mutex);
    globus_cond_destroy(&globus_l_cond);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    fprintf(stdout, "Success.\n");

    return 0;
}

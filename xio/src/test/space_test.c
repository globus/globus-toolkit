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

static globus_mutex_t                       globus_l_mutex;
static globus_cond_t                        globus_l_cond;
static globus_bool_t                        globus_l_closed = GLOBUS_FALSE;
static globus_bool_t                        globus_l_close_called=GLOBUS_FALSE;

static globus_callback_space_t              globus_l_space;

static void
close_cb(
    globus_xio_handle_t                     handle,
    globus_result_t                         result,
    void *                                  user_arg)
{
    globus_mutex_lock(&globus_l_mutex);
    {
        globus_l_closed = GLOBUS_TRUE;
        globus_cond_broadcast(&globus_l_cond);
    }
    globus_mutex_unlock(&globus_l_mutex);
}

static void
data_cb(
    globus_xio_handle_t                     handle,
    globus_result_t                         result,
    globus_byte_t *                         buffer,
    globus_size_t                           len,
    globus_size_t                           nbytes,
    globus_xio_data_descriptor_t            data_desc,
    void *                                  user_arg)
{
    globus_result_t                         res;

    globus_mutex_lock(&globus_l_mutex);
    {
        res = globus_xio_register_close(
                handle,
                NULL,
                close_cb,
                user_arg);
        if(globus_l_close_called)
        {
            if(res == GLOBUS_SUCCESS)
            {
                failed_exit("close should have failed the second time.\n");
            }
        }
        else
        {
            test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
        }
        globus_l_close_called = GLOBUS_TRUE;
    }
    globus_mutex_unlock(&globus_l_mutex);
}

static void
open_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_result_t                             res;
    globus_byte_t *                             buffer;
    globus_size_t                               buffer_length;
    globus_size_t                               nbytes;
    int                                         ctr;

    buffer = globus_l_test_info.buffer;
    buffer_length = globus_l_test_info.buffer_length;

    globus_mutex_lock(&globus_l_mutex);
    {
        for(ctr = 0; ctr < OP_COUNT; ctr++)
        {
            res = globus_xio_register_write(
                    handle,
                    buffer,
                    buffer_length,
                    buffer_length,
                    NULL,
                    data_cb,
                    user_arg);
            test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
            res = globus_xio_register_read(
                    handle,
                    buffer,
                    buffer_length,
                    buffer_length,
                    NULL,
                    data_cb,
                    user_arg);
            test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

            res = globus_xio_write(
                    handle,
                    buffer,
                    buffer_length,
                    buffer_length,
                    &nbytes,
                    NULL);
            res = globus_xio_read(
                    handle,
                    buffer,
                    buffer_length,
                    buffer_length,
                    &nbytes,
                    NULL);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);
}

int
space_main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     handle;
    globus_result_t                         res;
    globus_xio_attr_t                       attr;
    globus_condattr_t                       condattr;

    globus_l_closed = GLOBUS_FALSE;
    globus_l_close_called = GLOBUS_FALSE;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    res = globus_xio_attr_init(&attr);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_stack_init(&stack, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    parse_parameters(argc, argv, stack, attr);

    globus_callback_space_init(&globus_l_space, NULL);
    globus_condattr_init(&condattr);
    globus_condattr_setspace(&condattr, globus_l_space);

    globus_mutex_init(&globus_l_mutex, NULL);
    globus_cond_init(&globus_l_cond, &condattr);

    res = globus_xio_handle_create(&handle, stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_attr_cntl(attr, NULL, GLOBUS_XIO_ATTR_SET_SPACE, globus_l_space);

    res = globus_xio_register_open(
            handle,
            "whatever", 
            attr,
            open_cb,
            argv[argc-1]);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    globus_mutex_lock(&globus_l_mutex);
    {
        while(!globus_l_closed)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);

    globus_xio_attr_destroy(attr);
    globus_xio_stack_destroy(stack);
 
    test_common_end();

    globus_callback_space_destroy(globus_l_space);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    fprintf(stdout, "Success.\n");

    return 0;
}

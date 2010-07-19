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

/*
 *  read barrier test
 *  -----------------
 *
 *  verifies that all successful callback are devilvered before
 *  any eof callbacks.
 *
 *  working options
 *  -i          call finish inline
 *  -r <int>    number of outstanding reads that can be out at oncea
 *  -R <int>    total number of bytes to "read"
 *  -c <int>    chuck size to finish at once
 *  -b <int>    buffer size to post
 *
 *  test suite
 *  ----------
 *  - should be called w/ and w/o -i    :  * 2
 *  - called with -r (1,2,4,8)          :  * 2
 *  - called with -c < -b and with      :  * 3  ( / 2; / 2.3; / 1)
 *    numbers that do not end in nice   
 *    math
 *  - different drivers                 :  * 6
 *    1) transport
 *    2) transport simple
 *    3) transport bounce
 *    4) transport simple bounce
 *    5) transport simple bounce simple
 *    6) transport bounce simple bounce
 *                                         72
 */

#include "globus_xio.h"
#include "globus_common.h"
#include "test_common.h"
#include "globus_xio_test_transport.h"

#define SLEEP_TIME 10000

static globus_mutex_t                   globus_l_mutex;
static globus_cond_t                    globus_l_cond;
static globus_bool_t                    globus_l_close_called = GLOBUS_FALSE;
static globus_bool_t                    globus_l_closed = GLOBUS_FALSE;
static globus_bool_t                    globus_l_eof_hit = GLOBUS_FALSE;
static globus_size_t                    globus_l_nbytes= 0;
static globus_size_t                    globus_l_total_read_post;

static void
close_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_mutex_lock(&globus_l_mutex);
    {
        globus_l_closed = GLOBUS_TRUE;
        globus_cond_signal(&globus_l_cond);
    }
    globus_mutex_unlock(&globus_l_mutex);
}

static void
read_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    globus_byte_t *                             buffer,
    globus_size_t                               len,
    globus_size_t                               nbytes,
    globus_xio_data_descriptor_t                data_desc,
    void *                                      user_arg)
{
    globus_result_t                             res;

    globus_mutex_lock(&globus_l_mutex);
    {
        globus_l_nbytes += len;
        if(globus_l_nbytes < globus_l_total_read_post)
        {
            res = globus_xio_register_read(
                    handle,
                    buffer,
                    len,
                    len,
                    NULL,
                    read_cb,
                    user_arg);
            if(!globus_l_eof_hit)
            {
                test_res(GLOBUS_XIO_TEST_FAIL_NONE, result, __LINE__, __FILE__);
            }
            else if(globus_l_eof_hit && result == GLOBUS_SUCCESS)
            {
                failed_exit("allowed a read_register() after eof was "
                    "delivered.");
            }
        }
        else if(!globus_l_close_called)
        {
            globus_l_close_called = GLOBUS_TRUE;
            res = globus_xio_register_close(
                    handle,
                    NULL,
                    close_cb,
                    user_arg);
            test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
        }

        if(result != GLOBUS_SUCCESS &&
            globus_xio_error_is_eof(result))
        {
            globus_l_eof_hit = GLOBUS_TRUE;
        }
        else
        {
            if(globus_l_eof_hit)
            {
                failed_exit("non eof callback after an EOF callback");
            }
        }

    }
    globus_mutex_unlock(&globus_l_mutex);

    globus_mutex_lock(&globus_l_mutex);
    {
        if(globus_l_closed)
        {
            failed_exit("the close callback occurred prior to all data"
                        "callbacks returning");
        }
    }
    globus_mutex_unlock(&globus_l_mutex);

    globus_thread_blocking_will_block();
    globus_libc_usleep(SLEEP_TIME);
}

static void
open_cb(
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_result_t                             res;
    int                                         ctr;
    globus_byte_t *                             buffer;
    globus_size_t                               buffer_length;

    buffer = globus_l_test_info.buffer;
    buffer_length = globus_l_test_info.buffer_length;
    globus_l_total_read_post = globus_l_test_info.total_read_bytes +
                                (buffer_length * globus_l_test_info.read_count);

    globus_mutex_lock(&globus_l_mutex);
    {
        for(ctr = 0; ctr < globus_l_test_info.read_count; ctr++)
        {
            res = globus_xio_register_read(
                    handle,
                    buffer,
                    buffer_length,
                    buffer_length,
                    NULL,
                    read_cb,
                    user_arg);
            test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);
}

int
read_barrier_main(
    int                                     argc,
    char **                                 argv)
{
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     handle;
    globus_result_t                         res;
    globus_abstime_t                        end_time;
    globus_xio_attr_t                       attr;
    int                                     rc;

    globus_l_close_called = GLOBUS_FALSE;
    globus_l_closed = GLOBUS_FALSE;
    globus_l_eof_hit = GLOBUS_FALSE;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    res = globus_xio_attr_init(&attr);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    
    res = globus_xio_stack_init(&stack, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    parse_parameters(argc, argv, stack, attr);

    globus_mutex_init(&globus_l_mutex, NULL);
    globus_cond_init(&globus_l_cond, NULL);

    res = globus_xio_handle_create(&handle, stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_register_open(
            handle,
            "whatever", 
            attr,
            open_cb,
            NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    globus_mutex_lock(&globus_l_mutex);
    {
        while(!globus_l_closed)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
        GlobusTimeAbstimeSet(end_time, 0, SLEEP_TIME);
        globus_cond_timedwait(&globus_l_cond, &globus_l_mutex, &end_time);
    }
    globus_mutex_unlock(&globus_l_mutex);

    res = globus_xio_attr_destroy(attr);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_stack_destroy(stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
   
    test_common_end();
 
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    fprintf(stdout, "Success.\n");

    return 0;
}

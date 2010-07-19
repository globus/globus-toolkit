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

static globus_mutex_t                       globus_l_mutex;
static globus_cond_t                        globus_l_cond;
static globus_bool_t                        globus_l_closed = GLOBUS_FALSE;
static int                                  globus_l_accepted = 0;
static int                                  globus_l_cb_cnt = 0;

static void
close_cb(
    globus_xio_server_t                     server,
    void *                                  user_arg)
{
    globus_mutex_lock(&globus_l_mutex);
    {
        globus_l_closed = GLOBUS_TRUE;
        globus_l_cb_cnt++;
        globus_cond_broadcast(&globus_l_cond);
    }
    globus_mutex_unlock(&globus_l_mutex);
}

static void
accept_close_cb(
    globus_xio_server_t                         server,
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    globus_result_t                             res;
    
    if(result == GLOBUS_SUCCESS)
    {
        globus_xio_close(handle, NULL);
    }
    
    globus_mutex_lock(&globus_l_mutex);
    {
        globus_l_cb_cnt++;
        globus_l_closed = GLOBUS_FALSE;
        res = globus_xio_server_register_close(
                server,
                close_cb,
                NULL);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

        while(!globus_l_closed)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
        globus_cond_signal(&globus_l_cond);
    }
    globus_mutex_unlock(&globus_l_mutex);

}

static void
accept_cb(
    globus_xio_server_t                         server,
    globus_xio_handle_t                         handle,
    globus_result_t                             result,
    void *                                      user_arg)
{
    if(globus_l_closed)
    {
        failed_exit("the accept callback came after the server_close callback");
    }
    
    if(result == GLOBUS_SUCCESS)
    {
        globus_xio_close(handle, NULL);
    }

    globus_mutex_lock(&globus_l_mutex);
    {
        globus_l_cb_cnt++;
        globus_l_accepted++;
        globus_cond_signal(&globus_l_cond);
    }
    globus_mutex_unlock(&globus_l_mutex);
}

int
server2_main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_stack_t                      stack;
    globus_result_t                         res;
    globus_xio_server_t                     server;
    globus_xio_attr_t                       attr;
    globus_xio_handle_t                     handle;
    int                                     accept_count = 0;

    globus_l_cb_cnt = 0;
    globus_l_closed = GLOBUS_FALSE;
    globus_l_accepted = 0;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    globus_mutex_init(&globus_l_mutex, NULL);    
    globus_cond_init(&globus_l_cond, NULL);    

    res = globus_xio_stack_init(&stack, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_attr_init(&attr);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    parse_parameters(argc, argv, stack, attr);

    /*
     *  create the server
     */
    res = globus_xio_server_create(&server, attr, stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    /* blocking */
    res = globus_xio_server_accept(&handle, server);
    if(res == GLOBUS_SUCCESS)
    {
        globus_xio_close(handle, NULL);
    }
    
    globus_mutex_lock(&globus_l_mutex);
    {
        /* non blocking */
        res = globus_xio_server_register_accept(
                server,
                accept_cb,
                &handle);
        test_res(GLOBUS_XIO_TEST_FAIL_PASS_ACCEPT, res, __LINE__, __FILE__);
        accept_count++;
        /* should fail */
        res = globus_xio_server_register_accept(
                server,
                accept_cb,
                &handle);
        if(res == GLOBUS_SUCCESS)
        {
#           if defined(BUILD_LITE)
            {
                failed_exit("2nd register accept should have failed");
            }
#           else
            {
                accept_count++;
                fprintf(stderr, 
                    "MINOR WARNING: 2nd register accept didn't fail.\n"); 
            }
#           endif
        }

        while(globus_l_accepted < accept_count)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }

        globus_l_accepted = 0;

        /* non with close */
        globus_l_cb_cnt = 0;
        res = globus_xio_server_register_accept(
                server,
                accept_cb,
                &handle);
        test_res(GLOBUS_XIO_TEST_FAIL_PASS_ACCEPT, res, __LINE__, __FILE__);
        res = globus_xio_server_register_close(
                server,
                close_cb,
                NULL);

        while(globus_l_cb_cnt < 2)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }

        /* close called from within the accept_cb */
        res = globus_xio_server_create(&server, attr, stack);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
        globus_l_cb_cnt = 0;
        res = globus_xio_server_register_accept(
                server,
                accept_close_cb,
                &handle);
        test_res(GLOBUS_XIO_TEST_FAIL_PASS_ACCEPT, res, __LINE__, __FILE__);
        while(globus_l_cb_cnt < 2)
        {
            globus_cond_wait(&globus_l_cond, &globus_l_mutex);
        }
    }
    globus_mutex_unlock(&globus_l_mutex);

    globus_xio_attr_destroy(attr);
    globus_xio_stack_destroy(stack);

    if(globus_l_test_info.server)
    {
        res = globus_xio_server_close(server);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    }

    test_common_end();

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    fprintf(stdout, "Success.\n");

    return 0;
}

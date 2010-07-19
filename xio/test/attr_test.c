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


int
attr_main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    globus_xio_stack_t                      stack;
    globus_result_t                         res;
    globus_xio_attr_t                       attr;
    globus_xio_attr_t                       cp_attr;
    globus_xio_driver_t                     test_driver;
    globus_xio_driver_t                     debug_driver;
    globus_xio_handle_t                     handle;
    globus_byte_t *                         buffer;
    globus_size_t                           len = 1024;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    buffer = globus_malloc(len);

    /*
     *  init a bunch of structures
     */
    res = globus_xio_driver_load("test", &test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_driver_load("debug", &debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_attr_init(NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }
    res = globus_xio_stack_init(NULL, NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }
    res = globus_xio_handle_create(NULL, NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter create() should have failed.\n");
    }
    res = globus_xio_handle_create(&handle, NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter create() should have failed.\n");
    }
    
    res = globus_xio_attr_init(&attr);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_stack_init(&stack, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_handle_create(&handle, stack);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("handle_create() should have failed. empty stack\n");
    }

    res = globus_xio_stack_push_driver(stack, debug_driver);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("stack_push() should have failed. transform\n");
    }

    res = globus_xio_stack_push_driver(stack, test_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_stack_push_driver(stack, test_driver);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("stack_push() should have failed. transport twice\n");
    }

    res = globus_xio_stack_push_driver(stack, debug_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_handle_create(&handle, stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_close(handle, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_handle_create(&handle, stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_register_close(handle, NULL, NULL, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    /*
     *  do some operations
     */
    res = globus_xio_attr_copy(&cp_attr, attr);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    /*
     *  destroy the structures
     */
    res = globus_xio_attr_cntl(NULL, NULL, 0);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }

    res = globus_xio_attr_copy(&cp_attr, NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }

    res = globus_xio_attr_copy(NULL, attr);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }

    res = globus_xio_attr_copy(NULL, NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }

    res = globus_xio_attr_destroy(NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }

    res = globus_xio_stack_destroy(NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }

    /*
     *  use things before they are destroyed 
     */
    res = globus_xio_open(NULL, NULL, NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }
    
    res = globus_xio_handle_create(&handle, stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    
    res = globus_xio_open(handle, "whatever", NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    /* reads */
    res = globus_xio_read(NULL, NULL, -1, 0, NULL, NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }
    res = globus_xio_read(NULL, globus_l_test_info.buffer, -1, 0, NULL, NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }
    res = globus_xio_read(NULL, buffer, 1, 0, NULL, NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }
    res = globus_xio_read(handle, buffer, 
            len, 0, NULL, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    /* writes */
    res = globus_xio_write(NULL, NULL, -1, 0, NULL, NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }
    res = globus_xio_write(NULL, buffer, -1, 0, NULL, NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }
    res = globus_xio_write(NULL, buffer, 1, 0, NULL, NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }
    res = globus_xio_write(handle, buffer,
            len, 0, NULL, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_close(NULL, NULL);
    if(res == GLOBUS_SUCCESS)
    {
        failed_exit("bad parameter init() should have failed.\n");
    }

    res = globus_xio_close(handle, NULL);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    globus_free(buffer);

    res = globus_xio_attr_destroy(attr);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_stack_destroy(stack);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_driver_unload(debug_driver); 
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_driver_unload(test_driver); 
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == 0);

    fprintf(stdout, "Success.\n");

    return 0;
}

/*
 * Copyright 1999-2014 University of Chicago
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

#include "globus_common.h"
#include "globus_xio.h"
#include "globus_xio_driver.h"

/*
 * This test program creates a driver that has server pre-init and init
 * functions. It has two tests:
 *
 * pre_init_no_fail_test:
 *     Pre init function doesn't fail, server is created, and both
 *     pre-init and init functions are called.
 * pre_init_fail_test:
 *     Pre init function fails, server is not created, and 
 *     init function is not called.
 */
enum
{
    PRE_INIT_FAIL
};

globus_bool_t pre_init_func_called;
globus_bool_t init_func_called;

static
globus_result_t
pre_init_attr_init(
    void                              **out_attr_driver)
{
    *out_attr_driver = calloc(1, sizeof(int));

    return (*out_attr_driver) ? GLOBUS_SUCCESS : GLOBUS_FAILURE;
}

static
globus_result_t
pre_init_attr_copy(
    void                              **dst,
    void                               *src)
{
    pre_init_attr_init(dst);
    if (*dst)
    {
        **(int **)dst = *(int*)src;
        return GLOBUS_SUCCESS;
    }
    else
    {
        return GLOBUS_FAILURE;
    }
}

static
globus_result_t
pre_init_attr_cntl(
    void                               *attr,
    int                                 cmd,
    va_list                             ap)
{
    if (cmd == PRE_INIT_FAIL)
    {
        *(int *)attr = 1;
    }
    return GLOBUS_SUCCESS;
}

static
globus_result_t
pre_init_attr_destroy(
    void                               *driver_attr)
{
    free(driver_attr);
    return GLOBUS_SUCCESS;
}

static
globus_result_t
pre_init_func(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{
    pre_init_func_called = GLOBUS_TRUE;
    if (driver_attr && *(int*)driver_attr)
    {
        return GLOBUS_FAILURE;
    }
    return GLOBUS_SUCCESS;
}
/* pre_init_func() */

static
globus_result_t
init_func(
    void *                              driver_attr,
    const globus_xio_contact_t *        contact_info,
    globus_xio_operation_t              op)
{
    init_func_called = GLOBUS_TRUE;
    return (driver_attr != NULL);
}
/* pre_init_func() */

GlobusXIODeclareModule(pre_init_test);

GlobusXIODefineModule(pre_init_test) =
{
    "pre_init_test"
};

globus_result_t
pre_init_test_init(
    globus_xio_driver_t *               out_driver)
{
    globus_xio_driver_t                 driver;
    globus_result_t                     res;

    res = globus_xio_driver_init(&driver, "null", NULL);
    if(res != GLOBUS_SUCCESS)
    {
        return res;
    }

    globus_xio_driver_set_transform(
        driver,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    globus_xio_driver_set_attr(
        driver,
        pre_init_attr_init,
        pre_init_attr_copy,
        pre_init_attr_cntl,
        pre_init_attr_destroy);

    globus_xio_driver_set_server(
        driver,
        init_func,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    globus_xio_driver_set_server_pre_init(
        driver,
        pre_init_func);

    *out_driver = driver;

    return GLOBUS_SUCCESS;
}

void
pre_init_test_destroy(
    globus_xio_driver_t                 driver)
{
    globus_xio_driver_destroy(driver);
}
    
GlobusXIODefineDriver(
    pre_init_test,
    pre_init_test_init,
    pre_init_test_destroy);

globus_xio_driver_t tcp_driver, pre_init_test_driver;
globus_xio_stack_t stack;

int
pre_init_no_fail_test(void)
{
    globus_xio_attr_t attr;
    globus_xio_server_t server;
    globus_result_t result;

    globus_xio_attr_init(&attr);
    result = globus_xio_server_create(&server, attr, stack);

    globus_xio_server_close(server);
    globus_xio_attr_destroy(attr);

    return result;
}

int
pre_init_fail_test(void)
{
    globus_xio_attr_t attr;
    globus_xio_server_t server;
    globus_result_t result;

    globus_xio_attr_init(&attr);
    globus_xio_attr_cntl(attr, pre_init_test_driver, PRE_INIT_FAIL);
    result = globus_xio_server_create(&server, attr, stack);

    globus_xio_server_close(server);
    globus_xio_attr_destroy(attr);

    return result;
}

int main()
{
    int rc = 0, xc = 0;
    const char *testname;
    const char *res;

    printf("1..2\n");

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_extension_register_builtin(
        GlobusXIOExtensionName(pre_init_test),
        GlobusXIOMyModule(pre_init_test));
    GlobusXIORegisterDriver(pre_init_test);

    globus_xio_driver_load("pre_init_test", &pre_init_test_driver);
    globus_xio_driver_load("tcp", &tcp_driver);
    globus_xio_stack_init(&stack, NULL);
    globus_xio_stack_push_driver(stack, tcp_driver);
    globus_xio_stack_push_driver(stack, pre_init_test_driver);

    testname = "pre_init_no_fail_test";
    pre_init_func_called = init_func_called = GLOBUS_FALSE;
    xc = rc = pre_init_no_fail_test();
    if (rc == GLOBUS_SUCCESS && pre_init_func_called && init_func_called)
    {
        res = "ok";
    }
    else
    {
        res = "not ok";
    }
    printf("%s 1 - %s\n", res, testname);

    testname = "pre_init_fail_test";
    pre_init_func_called = init_func_called = GLOBUS_FALSE;
    rc = pre_init_fail_test();
    if (rc == GLOBUS_FAILURE && pre_init_func_called && !init_func_called)
    {
        res = "ok";
    }
    else
    {
        res = "not ok";
        xc++;
    }
    printf("%s 2 - %s\n", res, testname);

    return xc;
}

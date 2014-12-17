#include "globus_xio.h"
#include "globus_xio_net_manager_driver.h"
#include "globus_net_manager_attr.h"
#include "globus_test_tap.h"

static globus_xio_driver_t              nm_driver;

/*
 * Test case: set_task_id cntl with null task id; should succeed and not crash
 */
static
int
set_task_id_test_null(void)
{
    globus_xio_attr_t                   attr;
    globus_result_t                     result;

    globus_xio_attr_init(&attr);
    result = globus_xio_attr_cntl(
            attr,
            nm_driver,
            GLOBUS_XIO_NET_MANAGER_SET_TASK_ID, NULL);
    globus_xio_attr_destroy(attr);

    TEST_ASSERT(result == GLOBUS_SUCCESS);
    return 0;
}

/*
 * Test case: get_task_id cntl with null task id; should not succeed but not
 * crash
 */
static
int
get_task_id_test_null(void)
{
    globus_xio_attr_t                   attr;
    globus_result_t                     result;

    globus_xio_attr_init(&attr);
    result = globus_xio_attr_cntl(
            attr, 
            nm_driver,
            GLOBUS_XIO_NET_MANAGER_GET_TASK_ID, NULL);
    globus_xio_attr_destroy(attr);
    TEST_ASSERT(result != GLOBUS_SUCCESS);
    return 0;
}

/*
 * Test case: set_task_id cntl with non-null task id; get_task_id to retrieve
 * value, compare they are the same.
 */
static
int 
set_get_task_id_test(void)
{
    globus_xio_attr_t                   attr;
    globus_result_t                     result;
    const char                         *expected_task_id="1";
    char                               *taskid;

    globus_xio_attr_init(&attr);
    result = globus_xio_attr_cntl(
            attr,
            nm_driver,
            GLOBUS_XIO_NET_MANAGER_SET_TASK_ID, expected_task_id);
    TEST_ASSERT(result == GLOBUS_SUCCESS);

    result = globus_xio_attr_cntl(
            attr, nm_driver, GLOBUS_XIO_NET_MANAGER_GET_TASK_ID, &taskid);
    TEST_ASSERT(result == GLOBUS_SUCCESS);

    TEST_ASSERT(strcmp(taskid, expected_task_id)==0);
    free(taskid);

    globus_xio_attr_destroy(attr);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    return 0;
}

/*
 * Test case: set_string_opts cntl with null string; should not fail or crash
 */
static
int
set_string_opts_null(void)
{
    globus_xio_attr_t                   attr;
    globus_result_t                     result;

    globus_xio_attr_init(&attr);
    result = globus_xio_attr_cntl(
            attr,
            nm_driver,
            GLOBUS_XIO_SET_STRING_OPTIONS, NULL);
    globus_xio_attr_destroy(attr);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    return 0;
}

/*
 * Test case: get_string_opts cntl with null string; should fail but not crash
 */
static
int
get_string_opts_null(void)
{
    globus_xio_attr_t                   attr;
    globus_result_t                     result;

    globus_xio_attr_init(&attr);
    result = globus_xio_attr_cntl(
            attr,
            nm_driver,
            GLOBUS_XIO_GET_STRING_OPTIONS, NULL);

    globus_xio_attr_destroy(attr);
    TEST_ASSERT(result != GLOBUS_SUCCESS);
    return 0;
}

/*
 * Test case: set_string_opts cntl with non-null string; get_string_opts cntl
 * to verify that the opts are set
 */
static
int
set_get_string_opts(void)
{
    globus_xio_attr_t                   attr;
    globus_result_t                     result;
    const char                         *expected_opts = "task-id=42;manager=null;";
    char                               *opts;

    globus_xio_attr_init(&attr);
    result = globus_xio_attr_cntl(
            attr,
            nm_driver,
            GLOBUS_XIO_SET_STRING_OPTIONS, expected_opts);
    TEST_ASSERT_RESULT_SUCCESS(result);
    result = globus_xio_attr_cntl(
            attr,
            nm_driver,
            GLOBUS_XIO_GET_STRING_OPTIONS, &opts);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(strcmp(expected_opts, opts) == 0);
    free(opts);
    globus_xio_attr_destroy(attr);
    return 0;
}

static
int
get_driver_name(void)
{
    globus_xio_attr_t                   attr;
    globus_result_t                     result;
    const char                         *name;

    globus_xio_attr_init(&attr);
    result = globus_xio_attr_cntl(
            attr,
            nm_driver,
            GLOBUS_XIO_GET_DRIVER_NAME, &name);
    globus_xio_attr_destroy(attr);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    TEST_ASSERT(strcmp(name, "net_manager") == 0);
    return 0;
}

struct tests
{
    char * test_name;
    int (*test_func)(void);
};

#define TEST_INITIALIZER(name) { #name, name }

int
main(int argc, char *argv[])
{
    struct tests tests[] = {
        TEST_INITIALIZER(set_task_id_test_null),
        TEST_INITIALIZER(get_task_id_test_null),
        TEST_INITIALIZER(set_get_task_id_test),
        TEST_INITIALIZER(set_string_opts_null),
        TEST_INITIALIZER(get_string_opts_null),
        TEST_INITIALIZER(set_get_string_opts),
        TEST_INITIALIZER(get_driver_name),
        {NULL, NULL}
    };
    int i;
    globus_xio_driver_t tcp_driver;
    globus_result_t result;

    globus_module_activate(GLOBUS_XIO_MODULE);

    result = globus_xio_driver_load("tcp", &tcp_driver);
    result = globus_xio_driver_load("net_manager", &nm_driver);

    printf("1..%d\n", (int) (sizeof(tests)/sizeof(tests[0]))-1);
    for (i = 0; tests[i].test_name; i++)
    {
        ok(tests[i].test_func() == 0, tests[i].test_name);
    }
    return TEST_EXIT_CODE;
}

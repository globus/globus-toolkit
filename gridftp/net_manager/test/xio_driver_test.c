#include "globus_xio.h"
#include "globus_xio_net_manager_driver.h"
#include "globus_net_manager_attr.h"
#include "globus_net_manager.h"
#include "globus_test_tap.h"

#ifdef ENABLE_PYTHON
#define SKIP_PYTHON_TEST(x) 0
#else
#define SKIP_PYTHON_TEST(x) (strcmp(x.test_name, "port_plus_one") == 0 || strcmp(x.test_name, "port_plus_one_minus_one") == 0)
#endif

globus_xio_driver_t                     net_manager_driver;
globus_xio_driver_t                     tcp_driver;
globus_xio_stack_t                      stack;

typedef struct
{
    globus_mutex_t                      lock;
    globus_cond_t                       cond;
    globus_bool_t                       open;
    globus_result_t                     result;
    globus_xio_handle_t                 handle;
}
test_monitor_t;

static
void
accept_cb(
    globus_xio_server_t                 server,
    globus_xio_handle_t                 handle,
    globus_result_t                     result,
    void *                              user_arg)
{
    test_monitor_t                     *passive = user_arg;

    globus_mutex_lock(&passive->lock);
    passive->result = result;
    if (result == GLOBUS_SUCCESS)
    {
        passive->handle = handle;
        result = globus_xio_open(handle, NULL, NULL);
        if (result)
        {
            passive->result = result;
        }
        passive->open = GLOBUS_TRUE;
    }
    globus_cond_signal(&passive->cond);
    globus_mutex_unlock(&passive->lock);
}

/*
 * Test case: Create a handle using a stack that includes the network
 * manager configure with no managers
 */
static
int
stack_with_no_managers(void)
{
    globus_xio_attr_t                   attr = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;;
    globus_xio_server_t                 server;
    char                               *contact;
    test_monitor_t                      passive = {0};
    globus_xio_handle_t                 active = NULL;

    globus_mutex_init(&passive.lock, NULL);
    globus_cond_init(&passive.cond, NULL);

    result = globus_xio_attr_init(&attr);
    TEST_ASSERT(result == GLOBUS_SUCCESS);

    result = globus_xio_server_create(&server, attr, stack);
    TEST_ASSERT_RESULT_SUCCESS(result);
    result = globus_xio_server_cntl(server,
            tcp_driver,
            GLOBUS_XIO_GET_LOCAL_NUMERIC_CONTACT,
            &contact);
    TEST_ASSERT_RESULT_SUCCESS(result);
    result = globus_xio_server_register_accept(server, accept_cb, &passive);
    TEST_ASSERT_RESULT_SUCCESS(result);
    result = globus_xio_handle_create(&active, stack);
    TEST_ASSERT_RESULT_SUCCESS(result);
    result = globus_xio_open(active, contact, attr);
    TEST_ASSERT_RESULT_SUCCESS(result);
    globus_mutex_lock(&passive.lock);
    while ((!passive.open) && (passive.result == GLOBUS_SUCCESS))
    {
        globus_cond_wait(&passive.cond, &passive.lock);
    }

    globus_mutex_unlock(&passive.lock);
    TEST_ASSERT_RESULT_SUCCESS(passive.result);

    result = globus_xio_close(passive.handle, NULL);
    TEST_ASSERT_RESULT_SUCCESS(result);

    result = globus_xio_close(active, NULL);
    TEST_ASSERT_RESULT_SUCCESS(result);

    globus_cond_destroy(&passive.cond);
    globus_mutex_destroy(&passive.lock);
    globus_xio_server_close(server);

    free(contact);

    return 0;
}

/*
 * Test case: Try to configure a listener with a non-existant network manager
 */
static
int
listener_bad_manager(void)
{
    globus_xio_attr_t                   attr = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;

    result = globus_xio_attr_init(&attr);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    result = globus_xio_attr_cntl(
            attr,
            net_manager_driver,
            GLOBUS_XIO_SET_STRING_OPTIONS,
            "manager=bad_manager;");
    TEST_ASSERT(result != GLOBUS_SUCCESS);
    globus_xio_attr_destroy(attr);

    return 0;
}

/*
 * Test case: stack that includes the network manager configure with the
 * port plus one manager
 */
static
int
port_plus_one(void)
{
    globus_xio_attr_t                   attr = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_xio_server_t                 server;
    char                               *contact;
    globus_bool_t                       port_plus_one_ok = GLOBUS_FALSE;

    result = globus_xio_attr_init(&attr);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    result = globus_xio_attr_cntl(
            attr,
            tcp_driver,
            GLOBUS_XIO_SET_STRING_OPTIONS,
            "port=50505");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    result = globus_xio_attr_cntl(
            attr,
            net_manager_driver,
            GLOBUS_XIO_SET_STRING_OPTIONS,
            "manager=python;pymod=port_plus_one;");
    TEST_ASSERT(result == GLOBUS_SUCCESS);

    result = globus_xio_server_create(&server, attr, stack);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    result = globus_xio_server_cntl(server,
            tcp_driver,
            GLOBUS_XIO_GET_LOCAL_NUMERIC_CONTACT,
            &contact);
    if (strcmp(strrchr(contact, ':'), ":50506") == 0)
    {
        port_plus_one_ok = GLOBUS_TRUE;
    }
    free(contact);
    globus_xio_attr_destroy(attr);
    globus_xio_server_close(server);
    TEST_ASSERT(port_plus_one_ok);

    return 0;
}

int
port_plus_one_minus_one(void)
{
    globus_xio_attr_t                   attr = NULL;
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_xio_server_t                 server;
    char                               *contact;
    globus_bool_t                       port_plus_one_ok = GLOBUS_FALSE;

    result = globus_xio_attr_init(&attr);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    result = globus_xio_attr_cntl(
            attr,
            tcp_driver,
            GLOBUS_XIO_SET_STRING_OPTIONS,
            "port=50505");
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    result = globus_xio_attr_cntl(
            attr,
            net_manager_driver,
            GLOBUS_XIO_SET_STRING_OPTIONS,
            "manager=python;pymod=port_plus_one;manager=python;pymod=port_minus_one");
    TEST_ASSERT(result == GLOBUS_SUCCESS);

    result = globus_xio_server_create(&server, attr, stack);
    TEST_ASSERT(result == GLOBUS_SUCCESS);
    result = globus_xio_server_cntl(server,
            tcp_driver,
            GLOBUS_XIO_GET_LOCAL_NUMERIC_CONTACT,
            &contact);
    if (strcmp(strrchr(contact, ':'), ":50505") == 0)
    {
        port_plus_one_ok = GLOBUS_TRUE;
    }
    free(contact);
    globus_xio_attr_destroy(attr);
    globus_xio_server_close(server);
    TEST_ASSERT(port_plus_one_ok);

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
        TEST_INITIALIZER(stack_with_no_managers),
        TEST_INITIALIZER(listener_bad_manager),
        TEST_INITIALIZER(port_plus_one),
        TEST_INITIALIZER(port_plus_one_minus_one),
        {NULL, NULL}
    };
    int i;
    globus_result_t result;

    globus_module_activate(GLOBUS_XIO_MODULE);
    globus_module_activate(GLOBUS_NET_MANAGER_MODULE);

    result = globus_xio_driver_load("tcp", &tcp_driver);
    if (result)
    {
        fprintf(stderr, "Error initializing before tests could run (tcp): %s\n",
            globus_error_print_friendly(globus_error_peek(result)));
        exit(EXIT_FAILURE);
    }
    result = globus_xio_driver_load("net_manager", &net_manager_driver);
    if (result)
    {
        fprintf(stderr, "Error initializing before tests could run (net_manager): %s\n",
            globus_error_print_friendly(globus_error_peek(result)));
        exit(EXIT_FAILURE);
    }
    result = globus_xio_stack_init(&stack, NULL);
    if (result)
    {
        fprintf(stderr, "Error initialzing before tests could run (stack init): %s\n",
            globus_error_print_friendly(globus_error_peek(result)));
        exit(EXIT_FAILURE);
    }

    result = globus_xio_stack_push_driver(stack, tcp_driver);
    if (result)
    {
        fprintf(stderr, "Error initialzing before tests could run (push tcp): %s\n",
            globus_error_print_friendly(globus_error_peek(result)));
        exit(EXIT_FAILURE);
    }
    result = globus_xio_stack_push_driver(stack, net_manager_driver);
    if (result)
    {
        fprintf(stderr, "Error initialzing before tests could run (push net manager): %s\n",
            globus_error_print_friendly(globus_error_peek(result)));
        exit(EXIT_FAILURE);
    }

    printf("1..%d\n", (int) (sizeof(tests)/sizeof(tests[0]))-1);
    for (i = 0; tests[i].test_name; i++)
    {
        skip(SKIP_PYTHON_TEST(tests[i]),
            ok(tests[i].test_func() == 0, "%s", tests[i].test_name));
    }
    globus_xio_stack_destroy(stack);
    globus_xio_driver_unload(net_manager_driver);
    globus_xio_driver_unload(tcp_driver);
    globus_module_deactivate_all();

    return TEST_EXIT_CODE;
}

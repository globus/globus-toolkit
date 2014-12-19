#include "globus_net_manager.h"
#include "globus_test_tap.h"

int
activate_deactivate(void)
{
    int rc = 0;
    rc = globus_module_activate(GLOBUS_NET_MANAGER_MODULE);
    TEST_ASSERT(rc == 0);
    rc = globus_module_deactivate(GLOBUS_NET_MANAGER_MODULE);
    TEST_ASSERT(rc == 0);

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
        TEST_INITIALIZER(activate_deactivate),
        {NULL, NULL}
    };
    int i;

    printf("1..%d\n", (int) (sizeof(tests)/sizeof(tests[0]))-1);
    for (i = 0; tests[i].test_name; i++)
    {
        ok(tests[i].test_func() == 0, tests[i].test_name);
    }
    return TEST_EXIT_CODE;
}

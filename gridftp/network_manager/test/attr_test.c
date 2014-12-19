#include "globus_net_manager_attr.h"
#include "globus_net_manager.h"
#include "globus_test_tap.h"

int
attr_init_null(void)
{
    globus_result_t result;
    globus_net_manager_attr_t attr;
    const char *scope = "scope";
    const char *name = "name";
    const char *value = "value";

    result = globus_net_manager_attr_init(NULL, scope, name, value);
    TEST_ASSERT (result != GLOBUS_SUCCESS);

    result = globus_net_manager_attr_init(&attr, NULL, name, value);
    TEST_ASSERT (result != GLOBUS_SUCCESS);

    result = globus_net_manager_attr_init(&attr, scope, NULL, value);
    TEST_ASSERT (result != GLOBUS_SUCCESS);

    result = globus_net_manager_attr_init(&attr, scope, name, NULL);
    TEST_ASSERT (result != GLOBUS_SUCCESS);

    return 0;
}

int attr_init_destroy(void)
{
    globus_result_t result;
    globus_net_manager_attr_t attr;
    const char *scope = "scope";
    const char *name = "name";
    const char *value = "value";

    result = globus_net_manager_attr_init(&attr, scope, name, value);
    TEST_ASSERT (result == GLOBUS_SUCCESS);

    TEST_ASSERT (strcmp(attr.scope, scope) == 0);
    TEST_ASSERT (strcmp(attr.name, name) == 0);
    TEST_ASSERT (strcmp(attr.value, value) == 0);

    globus_net_manager_attr_destroy(&attr);

    return 0;
}

int
attr_destroy_null(void)
{
    globus_net_manager_attr_destroy(NULL);

    return 0;
}

int
attr_create_from_string_null(void)
{
    globus_result_t result;
    globus_net_manager_attr_t *attr;
    const char *scope = "scope";
    const char *attr_string = "manager=foo";

    result = globus_net_manager_attr_array_from_string(
            NULL, scope, attr_string);
    TEST_ASSERT (result != GLOBUS_SUCCESS);
    result = globus_net_manager_attr_array_from_string(
            &attr, NULL, attr_string);
    TEST_ASSERT (result != GLOBUS_SUCCESS);
    result = globus_net_manager_attr_array_from_string(
            &attr, scope, NULL);
    TEST_ASSERT (result != GLOBUS_SUCCESS);

    return 0;
}

int
attr_create_from_string_bad(void)
{
    globus_result_t result;
    globus_net_manager_attr_t *attr;
    const char *scope = "Scope";
    const char *bad_strings[] = {
        "manager",
        "manager=",
        "manager=foo;manager",
        "manager=foo;manager=",
        NULL
    };

    for (int i = 0; bad_strings[i] != NULL; i++)
    {
        result = globus_net_manager_attr_array_from_string(
                &attr, scope, bad_strings[i]);
        TEST_ASSERT (result != GLOBUS_SUCCESS);
    }

    return 0;
}

int
attr_array_delete_null(void)
{
    globus_net_manager_attr_array_delete(NULL);
    return 0;
}

int
attr_create_from_string_destroy(void)
{
    globus_result_t result;
    globus_net_manager_attr_t *attr;
    const char scope[] = "scope";
    const char attr_string[] = "manager=foo;arg=bar;arg=baz";
    int i;
    int num=3;

    result = globus_net_manager_attr_array_from_string(
            &attr, scope, attr_string);
    TEST_ASSERT (result == GLOBUS_SUCCESS);
    TEST_ASSERT ((attr != NULL));

    for (i = 0; attr[i].scope != NULL; i++)
    {
        TEST_ASSERT (strcmp(attr[i].scope, scope) == 0);
    }
    TEST_ASSERT (i == 3);

    TEST_ASSERT (strcmp(attr[0].name, "manager") == 0);
    TEST_ASSERT (strcmp(attr[0].value, "foo") == 0);

    TEST_ASSERT (strcmp(attr[1].name, "arg") == 0);
    TEST_ASSERT (strcmp(attr[1].value, "bar") == 0);

    TEST_ASSERT (strcmp(attr[2].name, "arg") == 0);
    TEST_ASSERT (strcmp(attr[2].value, "baz") == 0);

    globus_net_manager_attr_array_delete(attr);

    return 0;
}

int
attr_array_copy_null(void)
{
    globus_result_t result;
    globus_net_manager_attr_t *attr = NULL;

    result = globus_net_manager_attr_array_copy(
            NULL, attr);
    TEST_ASSERT (result != GLOBUS_SUCCESS);
    result = globus_net_manager_attr_array_copy(
            &attr, NULL);
    TEST_ASSERT (result != GLOBUS_SUCCESS);

    return 0;
}

int
attr_array_copy_delete(void)
{
    globus_result_t result;
    globus_net_manager_attr_t src[] = {
        { "scope", "name", "value" },
        { "scope2", "name2", "value2" },
        GLOBUS_NET_MANAGER_NULL_ATTR
    };
    globus_net_manager_attr_t *attr = NULL;

    result = globus_net_manager_attr_array_copy(
            &attr, src);
    TEST_ASSERT (result == GLOBUS_SUCCESS);

    for (int i = 0; src[i].scope != NULL; i++)
    {
        TEST_ASSERT(strcmp(attr[i].scope, src[i].scope) == 0);
        TEST_ASSERT(strcmp(attr[i].name, src[i].name) == 0);
        TEST_ASSERT(strcmp(attr[i].value, src[i].value) == 0);
    }
    globus_net_manager_attr_array_delete(attr);

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
    globus_module_activate(GLOBUS_NET_MANAGER_MODULE);
    
    struct tests tests[] = {
        TEST_INITIALIZER(attr_init_null),
        TEST_INITIALIZER(attr_init_destroy),
        TEST_INITIALIZER(attr_destroy_null),
        TEST_INITIALIZER(attr_create_from_string_null),
        TEST_INITIALIZER(attr_create_from_string_bad),
        TEST_INITIALIZER(attr_array_delete_null),
        TEST_INITIALIZER(attr_create_from_string_destroy),
        TEST_INITIALIZER(attr_array_copy_null),
        TEST_INITIALIZER(attr_array_copy_delete),
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

#include "globus_gram_protocol.h"
#include "globus_preload.h"

#define test_assert(assertion, message) \
    if (!(assertion)) \
    { \
        printf("# %s:%d ", __FILE__, __LINE__); \
        printf message; \
        return 1; \
    }

#define TEST_CASE(x) { #x, x }

#define ARRAY_LEN(x) ((int) (sizeof(x)/sizeof(x[0])))

typedef struct
{
    char * name;
    int (*test_function)(void);
}
test_case;

char *                                  job_id = "http://example.org:43343/1/2";

/*
 * Test case: 
 *
 * PURPOSE:
 *     Check that
 *     globus_gram_protocol_create_extensions correctly creates extension
 *     hashtable entries.
 *
 * STEPS:
 *     - Creates an extension
 *     - Parses message to hash.
 *     - Verifies that all attributes we expect in the message are present int
 *       the parsed values.
 *     - Verifies that the number of attributes in the message match the count
 *       of ones we expect.
 */
int test_create_extension(void)
{
    globus_gram_protocol_extension_t *  extension;

    extension = globus_gram_protocol_create_extension(
            "test",
            "%d",
            1);
    test_assert(extension != NULL,
            ("Unable to create extension \"test: 1\"\n"));
    test_assert(strcmp(extension->attribute, "test") == 0,
            ("extension attribute mismatch\n"));
    test_assert(strcmp(extension->value, "1") == 0,
            ("extension value mismatch\n"));
    free(extension->attribute);
    free(extension->value);
    free(extension);

    extension = globus_gram_protocol_create_extension(
            "test",
            "%s",
            "hello, world");
    test_assert(extension != NULL,
            ("Unable to create extension \"test: 1\"\n"));
    test_assert(strcmp(extension->attribute, "test") == 0,
            ("extension attribute mismatch\n"));
    test_assert(strcmp(extension->value, "hello, world") == 0,
            ("extension value mismatch\n"));


    return 0;
}


/* Test case:
 * PURPOSE:
 *     Make sure globus_gram_protocol_create_extension()
 *     handles NULL attribute or format.
 */
int test_null_param(void)
{
    globus_gram_protocol_extension_t *  extension;

    extension = globus_gram_protocol_create_extension(
            NULL,
            "%d",
            1);
    test_assert(
            extension == NULL,
            ("Unexpected success with null attribute\n"));

    extension = globus_gram_protocol_create_extension(
            "test",
            NULL);

    test_assert(
            extension == NULL,
            ("Unexpected success with null value\n"));

    return 0;
}

int main(int argc, char * argv[])
{
    test_case                           tests[] =
    {
        TEST_CASE(test_create_extension),
        TEST_CASE(test_null_param)
    };
    int                                 i;
    int                                 rc;
    int                                 not_ok = 0;

    LTDL_SET_PRELOADED_SYMBOLS();
    printf("1..%d\n", ARRAY_LEN(tests));

    globus_module_activate(GLOBUS_GRAM_PROTOCOL_MODULE);
    for (i = 0; i < ARRAY_LEN(tests); i++)
    {
        rc = tests[i].test_function();

        if (rc != 0)
        {
            not_ok++;
            printf("not ok - %s\n", tests[i].name);
        }
        else
        {
            printf("ok - %s\n", tests[i].name);
        }
    }
    globus_module_deactivate(GLOBUS_GRAM_PROTOCOL_MODULE);

    return not_ok;
}

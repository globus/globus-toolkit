#include <stdio.h>
#include <stdbool.h>

#include "globus_i_gridftp_server_config.h"
#include "globus_i_gfs_ipc.h"

typedef struct
{
    char *name;
    int (*test)(void);
}
test_case;

#define TEST_CASE(x) { .name = #x, .test = (x) }
#define TEST_ASSERT(x) \
if (!(x)) \
    { \
        fprintf(stderr, "    [%s:%d] %s\n", __func__, __LINE__, (#x)); \
        testres = 1; \
        goto cleanup; \
    }

int
test_uint32(void)
{
    char *start = NULL;
    char *buf = NULL;
    size_t len = 0;
    uint32_t test_uints[] = { 0, UINT32_C(1)<< 25, UINT32_C(1)<<30, UINT32_MAX };
    uint32_t test_uints_out[4];
    void *test_uintps_out[4];
    int testres = 0;

    start = buf = malloc(len = 8);

    TEST_ASSERT(start != NULL);
    TEST_ASSERT(buf != NULL);

    for (int i = 0; i < sizeof(test_uints) / sizeof(*test_uints); i++)
    {
        GFSEncodeUInt32(start, len, buf, test_uints[i]);
    }

    buf = start;
    for (int i = 0; i < sizeof(test_uints_out) / sizeof(*test_uints_out); i++)
    {
        GFSDecodeUInt32(buf, len, test_uints_out[i]);
    }
    buf = start;
    for (int i = 0; i < sizeof(test_uintps_out) / sizeof(*test_uintps_out); i++)
    {
        GFSDecodeUInt32P(buf, len, test_uintps_out[i]);
    }

    for (int i = 0; i < sizeof(test_uints) / sizeof(*test_uints); i++)
    {
        TEST_ASSERT(test_uints[i] == test_uints_out[i]);
        TEST_ASSERT((intptr_t) test_uints[i] == (intptr_t) test_uintps_out[i]);
    }
cleanup:
    return testres;
decode_err:
    TEST_ASSERT(false);
}

int
test_uint64(void)
{
    char *start = NULL;
    char *buf = NULL;
    size_t len = 0;
    uint64_t test_uints[] = { 0, 1<<25, UINT64_C(1)<<30, UINT64_C(1)<<34, UINT64_C(1)<<60, UINT64_MAX };
    uint64_t test_uints_out[6];
    int testres = 0;

    start = buf = malloc(len = 8);

    TEST_ASSERT(start != NULL);
    TEST_ASSERT(buf != NULL);

    for (int i = 0; i < sizeof(test_uints) / sizeof(*test_uints); i++)
    {
        GFSEncodeUInt64(start, len, buf, test_uints[i]);
    }

    buf = start;
    for (int i = 0; i < sizeof(test_uints_out) / sizeof(*test_uints_out); i++)
    {
        GFSDecodeUInt64(buf, len, test_uints_out[i]);
    }

    for (int i = 0; i < sizeof(test_uints) / sizeof(*test_uints); i++)
    {
        TEST_ASSERT(test_uints[i] == test_uints_out[i]);
    }
cleanup:
    return testres;
decode_err:
    TEST_ASSERT(false);
}

int
test_char(void)
{
    char *start = NULL;
    char *buf = NULL;
    size_t len = 0;
    char test_chars[] = { 0, 1, 2, 3, 124, 127 };
    char test_chars_out[6];
    int testres = 0;

    start = buf = malloc(len = 8);

    TEST_ASSERT(start != NULL);
    TEST_ASSERT(buf != NULL);

    for (int i = 0; i < sizeof(test_chars) / sizeof(*test_chars); i++)
    {
        GFSEncodeChar(start, len, buf, test_chars[i]);
    }

    buf = start;
    for (int i = 0; i < sizeof(test_chars_out) / sizeof(*test_chars_out); i++)
    {
        GFSDecodeChar(buf, len, test_chars_out[i]);
    }

    for (int i = 0; i < sizeof(test_chars) / sizeof(*test_chars); i++)
    {
        TEST_ASSERT(test_chars[i] == test_chars_out[i]);
    }
cleanup:
    return testres;
decode_err:
    TEST_ASSERT(false);
}

int
test_string(void)
{
    char *start = NULL;
    char *buf = NULL;
    size_t len = 0;
    char* test_strings[] = { "hello", "", "\n" };
    char *test_strings_out[3];
    int testres = 0;

    start = buf = malloc(len = 8);

    TEST_ASSERT(start != NULL);
    TEST_ASSERT(buf != NULL);

    for (int i = 0; i < sizeof(test_strings) / sizeof(*test_strings); i++)
    {
        GFSEncodeString(start, len, buf, test_strings[i]);
    }

    buf = start;
    for (int i = 0; i < sizeof(test_strings_out) / sizeof(*test_strings_out); i++)
    {
        GFSDecodeString(buf, len, test_strings_out[i]);
    }

    for (int i = 0; i < sizeof(test_strings) / sizeof(*test_strings); i++)
    {
        TEST_ASSERT(strcmp(test_strings[i], test_strings_out[i]) == 0);
    }
cleanup:
    return testres;
decode_err:
    TEST_ASSERT(false);
}
int main()
{
    test_case tests[] =
    {
        TEST_CASE(test_uint32),
        TEST_CASE(test_uint64),
        TEST_CASE(test_char),
        TEST_CASE(test_string)
    };
    int failed = 0;
    int rc = 0;

#ifdef WORDS_BIGENDIAN
    printf("# big endian test\n");
#else
    printf("# little endian test\n");
#endif
    printf("1..%d\n", (int) (sizeof(tests) / sizeof(*tests)));

    for (int i = 0; i < sizeof(tests) / sizeof(*tests); i++)
    {
        rc = tests[i].test();

        if (rc == 0)
        {
            printf("ok %d - %s\n", i+1, tests[i].name);
        }
        else
        {
            printf("not ok %d - %s\n", i+1, tests[i].name);
            failed++;
        }
    }
    return failed;
}

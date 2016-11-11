#include "globus_gridftp_server.h"
#include "globus_i_gridftp_server.h"
#include <stdbool.h>

#define _gfs_name __func__
#
bool
test_default_response_code(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    int                                 code = 0;
    bool                                ok = false;

    result = GlobusGFSErrorParameter("foo");

    code = globus_gfs_error_get_ftp_response_code(globus_error_peek(result));

    ok = (code == 500);

    return ok;
}

bool
test_default_message(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    char                               *message = NULL;
    bool                                ok = false;

    result = GlobusGFSErrorParameter("foo");

    message = globus_gfs_error_get_ftp_response_message(
            globus_error_peek(result));

    fprintf(stderr, "# %s\n", message);

    ok = (message != NULL);

    free(message);

    return ok;
}

bool
test_explicit_response_code(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    int                                 code = 0;
    bool                                ok = false;

    result = GlobusGFSErrorFtpResponse(550, "File not found");

    code = globus_gfs_error_get_ftp_response_code(
            globus_error_peek(result));

    ok = (code == 550);

    return ok;
}

bool
test_explicit_message(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    const char                         *expect = "Not found";
    char                               *message = NULL;
    bool                                ok = false;

    result = GlobusGFSErrorFtpResponse(550, "%s", expect);

    message = globus_gfs_error_get_ftp_response_message(
            globus_error_peek(result));

    fprintf(stderr, "# %s\n", message);

    ok = (strcmp(message, expect) == 0);
    free(message);

    return ok;
}

typedef struct
{
    bool                              (*test_case)(void);
    const char                         *name;
}
test_case_t;

#define TEST(x) { x, #x }

int main()
{
    test_case_t                         tests[] =
    {
        TEST(test_default_response_code),
        TEST(test_default_message),
        TEST(test_explicit_response_code),
        TEST(test_explicit_message),
    };
    size_t                              num_tests
                                      = sizeof(tests)/sizeof(tests[0]);
    int                                 failed = 0;

    globus_module_activate(GLOBUS_GRIDFTP_SERVER_MODULE);

    printf("1..%zu\n", num_tests);
    for (size_t i = 0; i < num_tests; i++)
    {
        bool                            ok = false;

        ok = tests[i].test_case();

        if (ok)
        {
            printf("ok %zu - %s\n", i+1, tests[i].name);
        }
        else
        {
            printf("not ok %zu - %s\n", i+1, tests[i].name);
            failed++;
        }
    }
    globus_module_deactivate_all();
    return failed;
}

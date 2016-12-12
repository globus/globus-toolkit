#include "globus_gridftp_server.h"
#include "globus_i_gridftp_server.h"
#include <stdbool.h>

#define _gfs_name __func__

bool
test_default_message(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    char                               *message = NULL;
    bool                                ok = false;

    result = GlobusGFSErrorMemory("foo");

    message = globus_gfs_error_get_ftp_response_message(
            globus_error_peek(result));

    fprintf(stderr, "# %s %s\n", __func__, message);

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

    fprintf(stderr, "# %s \"%s\"\n", __func__, message);

    ok = (strncmp(message, expect, strlen(expect)) == 0);
    free(message);

    return ok;
}

bool
test_error_system(void)
{
    globus_object_t                    *err = NULL;
    int                                 code = 0;
    bool                                ok = false;

    errno = ENOENT;
    err = globus_i_gfs_error_system(0);

    code = globus_gfs_error_get_ftp_response_code(err);

    fprintf(stderr, "# %s %d\n", __func__, code);

    ok = (code == 550);
    globus_object_free(err);

    return ok;
}

bool
test_error_multiline(void)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    globus_object_t                    *err = NULL;
    char                               *msg = NULL;
    char                               *ftp_str = NULL;
    bool                                ok = false;
    char                               *dupes = NULL;
    char                               *p = NULL;
    int                                 count=0;

    dupes = globus_common_create_string(
            "Path: %s\nObjects: \"%s\", \"%s\"",
            "/Some/Dupe/Path",
            "18VORejiUuU0tJDGFK3itg3a_XG2-6-MSCGW3A8yFskk",
            "1NoyxMEDtDPa2ZfWStCky6ZSgpF1rQjKQe7d2TCo0Ulg");
            
    result = GlobusGFSErrorAmbiguousPath();
    err = globus_error_peek(result);

    globus_error_set_cause(err, GlobusGFSErrorObjGeneric(dupes));

    msg = globus_error_print_friendly(err);
    ftp_str = globus_gsc_string_to_959(globus_gfs_error_get_ftp_response_code(err), msg, NULL);

    p = ftp_str;

    while (*p != 0)
    {
        char *q = strstr(p, "\r\n");

        if (q)
        {
            *q = 0;
            fprintf(stderr, "# %s: %s\n", __func__, p);
            count++;
            p = q+2;
        }
        else
        {
            fprintf(stderr, "# %s: %s\n", __func__, p);
            count++;
            p += strlen(p);
        }
    }
    ok = (count == 4);
    
    free(msg);
    free(dupes);

    globus_object_free(err);

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
        TEST(test_default_message),
        TEST(test_explicit_response_code),
        TEST(test_explicit_message),
        TEST(test_error_system),
        TEST(test_error_multiline),
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

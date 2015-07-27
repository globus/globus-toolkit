#include "globus_gsi_cert_utils.h"

struct test_case
{
    const char *name;
    globus_bool_t expected_success;
};

int main()
{
    globus_result_t result = GLOBUS_SUCCESS;
    int failed = 0;
    int i;

    struct test_case test_case[] = {
        { "/CN=foo", GLOBUS_TRUE },
        { "CN=foo", GLOBUS_FALSE },
        { "/CN=foo/CN=bar", GLOBUS_TRUE },
        { "/CN=foo=bar", GLOBUS_TRUE },
        { 0 }
    };

    result = globus_module_activate(GLOBUS_GSI_CERT_UTILS_MODULE);
    if (result != GLOBUS_SUCCESS)
    {
        exit(99);
    }

    printf("1..%d\n", (int) (sizeof(test_case)/sizeof(test_case[0])-1));

    for (i = 0; test_case[i].name; i++)
    {
        X509_NAME                      *name = X509_NAME_new();
        globus_bool_t                   success = GLOBUS_FALSE;

        if (name == NULL)
        {
            failed++;
            continue;
        }
        result = globus_gsi_cert_utils_get_x509_name(
                test_case[i].name, strlen(test_case[i].name), name);

        if (test_case[i].expected_success)
        {
            if (result == GLOBUS_SUCCESS)
            {
                char *oneline;
                oneline = X509_NAME_oneline(name, NULL, 0);
                success = strcmp(oneline, test_case[i].name) == 0;
                OPENSSL_free(oneline);
            }
            else
            {
                success = GLOBUS_FALSE;
            }
        }
        else
        {
            success = (result != GLOBUS_SUCCESS);
        }
        printf("%s - %s\n", success ? "ok" : "not ok", test_case[i].name);
        if (!success)
        {
            failed++;
        }
        X509_NAME_free(name);

    }

    globus_module_deactivate(GLOBUS_GSI_CERT_UTILS_MODULE);
    return failed;
}

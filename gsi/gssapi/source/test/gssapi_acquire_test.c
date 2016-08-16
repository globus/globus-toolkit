/*
 * Copyright 1999-2008 University of Chicago
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

#include "gssapi.h"
#include "globus_common.h"
#include "gssapi_test_utils.h"
#include <stdbool.h>

struct acquire_test_case
{
    const char                         *x509_user_cert;
    const char                         *x509_user_key;
    int                                 expect_success;
};

int main()
{
    int                                 failed = 0;
    struct acquire_test_case            test_cases[] =
    {
        {
            .x509_user_cert = getenv("X509_USER_CERT"),
            .x509_user_key = getenv("X509_USER_KEY"),
            .expect_success = 1
        },
        {
            .x509_user_cert = getenv("X509_USER_CERT2"),
            .x509_user_key = getenv("X509_USER_KEY2"),
            .expect_success = 1
        },
        {
            .x509_user_cert = getenv("X509_USER_CERT"),
            .x509_user_key = getenv("X509_USER_KEY2"),
            .expect_success = 0
        },
        {
            .x509_user_cert = getenv("X509_USER_CERT2"),
            .x509_user_key = getenv("X509_USER_KEY"),
            .expect_success = 0
        }
    };
    size_t                              test_count = sizeof(test_cases)/sizeof(test_cases[0]);

    printf("1..%zd\n", test_count);

    globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    
    for (size_t i = 0; i < test_count; i++)
    {
        bool success = true;
        OM_uint32 major_status, minor_status;
        gss_cred_id_t cred;

        if (test_cases[i].x509_user_cert == NULL)
        {
            printf("ok %zd # SKIP undefined cert\n", i+1);
            continue;
        }
        if (test_cases[i].x509_user_key == NULL)
        {
            printf("ok %zd # SKIP undefined key\n", i+1);
            continue;
        }
        globus_libc_setenv("X509_USER_CERT", test_cases[i].x509_user_cert, 1);
        globus_libc_setenv("X509_USER_KEY", test_cases[i].x509_user_key, 1);

        major_status = gss_acquire_cred(
            &minor_status,
            NULL,
            GSS_C_INDEFINITE,
            GSS_C_NO_OID_SET,
            GSS_C_BOTH,
            &cred,
            NULL,
            NULL);
    
        if (test_cases[i].expect_success)
        {
            success = (major_status == GSS_S_COMPLETE);
            if (GSS_ERROR(major_status))
            {
                globus_gsi_gssapi_test_print_error(stderr, major_status, minor_status);
            }
        }
        else
        {
            success = (major_status != GSS_S_COMPLETE);
        }


        printf("%s %zd - %s %s\n",
               success?"ok":"not ok",
               i+1,
               test_cases[i].x509_user_cert,
               test_cases[i].x509_user_key);
        failed += (!success);
        
        (void) gss_release_cred(
            &minor_status,
            &cred);
    }
    
    globus_module_deactivate_all();
    
    return failed;
}

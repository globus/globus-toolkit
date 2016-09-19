/*
 * Copyright 1999-2015 University of Chicago
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

#include "gssapi_test_utils.h"
#include <stdbool.h>

gss_ctx_id_t                            init_ctx = GSS_C_NO_CONTEXT;
gss_ctx_id_t                            accept_ctx = GSS_C_NO_CONTEXT;
static gss_buffer_desc                  hello_buffer =
{
    .value = "hello",
    .length = 5
};

bool
mic_test(void)
{
    OM_uint32                           get_mic_major_status = GSS_S_COMPLETE;
    OM_uint32                           get_mic_minor_status = 0;
    OM_uint32                           verify_mic_major_status = GSS_S_COMPLETE;
    OM_uint32                           verify_mic_minor_status = 0;
    OM_uint32                           release_minor_status = 0;
    gss_buffer_desc                     mic_hello_buffer = { .value = NULL };
    bool                                ok = true;

    get_mic_major_status = gss_get_mic(
            &get_mic_minor_status,
            init_ctx,
            GSS_C_QOP_DEFAULT,
            &hello_buffer,
            &mic_hello_buffer);
    if (get_mic_major_status != GSS_S_COMPLETE)
    {
        ok = false;

        globus_gsi_gssapi_test_print_error(
                stderr,
                get_mic_major_status,
                get_mic_minor_status);
        
        goto end_test;
    }
    
    verify_mic_major_status = gss_verify_mic(
            &verify_mic_minor_status,
            accept_ctx,
            &hello_buffer,
            &mic_hello_buffer,
            NULL);
    if (verify_mic_major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(
                stderr,
                verify_mic_major_status,
                verify_mic_minor_status);
        ok = false;
    }
    gss_release_buffer(&release_minor_status, &mic_hello_buffer);
end_test:
    return ok;
}

bool
altered_message_test(void)
{
    OM_uint32                           get_mic_major_status = GSS_S_COMPLETE;
    OM_uint32                           get_mic_minor_status = 0;
    OM_uint32                           verify_mic_major_status = GSS_S_COMPLETE;
    OM_uint32                           verify_mic_minor_status = 0;
    OM_uint32                           release_minor_status = 0;
    gss_buffer_desc                     bad_hello_buffer = { .value = "HELLO", .length = 5 };
    gss_buffer_desc                     mic_hello_buffer = { .value = NULL };
    bool                                ok = true;

    get_mic_major_status = gss_get_mic(
            &get_mic_minor_status,
            init_ctx,
            GSS_C_QOP_DEFAULT,
            &hello_buffer,
            &mic_hello_buffer);
    if (get_mic_major_status != GSS_S_COMPLETE)
    {
        ok = false;
        goto end_test;
    }

    verify_mic_major_status = gss_verify_mic(
            &verify_mic_minor_status,
            accept_ctx,
            &bad_hello_buffer,
            &mic_hello_buffer,
            NULL);
    if (!GSS_ERROR(verify_mic_major_status))
    {
        globus_gsi_gssapi_test_print_error(
                stderr,
                verify_mic_major_status,
                verify_mic_minor_status);
        ok = false;
    }

    gss_release_buffer(&release_minor_status, &mic_hello_buffer);
end_test:
    return ok;
}

bool
altered_mic_test(void)
{
    OM_uint32                           get_mic_major_status = GSS_S_COMPLETE;
    OM_uint32                           get_mic_minor_status = 0;
    OM_uint32                           verify_mic_major_status = GSS_S_COMPLETE;
    OM_uint32                           verify_mic_minor_status = 0;
    OM_uint32                           release_minor_status = 0;
    gss_buffer_desc                     mic_hello_buffer = { .value = NULL };
    gss_buffer_desc                     bad_mic_hello_buffer = { .value = (unsigned char[16]){"HELLO"}, .length = 16 };
    bool                                ok = true;

    get_mic_major_status = gss_get_mic(
            &get_mic_minor_status,
            init_ctx,
            GSS_C_QOP_DEFAULT,
            &hello_buffer,
            &mic_hello_buffer);
    if (get_mic_major_status != GSS_S_COMPLETE)
    {
        ok = false;
        goto end_test;
    }

    /* Try to verify with a bad mic */
    verify_mic_major_status = gss_verify_mic(
            &verify_mic_minor_status,
            accept_ctx,
            &hello_buffer,
            &bad_mic_hello_buffer,
            NULL);
    if (!GSS_ERROR(verify_mic_major_status))
    {
        globus_gsi_gssapi_test_print_error(
                stderr,
                verify_mic_major_status,
                verify_mic_minor_status);
        ok = false;
    }

    /* Verify the correct mic to get back in sequence */
    verify_mic_major_status = gss_verify_mic(
            &verify_mic_minor_status,
            accept_ctx,
            &hello_buffer,
            &mic_hello_buffer,
            NULL);
    if (GSS_ERROR(verify_mic_major_status))
    {
        globus_gsi_gssapi_test_print_error(
                stderr,
                verify_mic_major_status,
                verify_mic_minor_status);
        ok = false;
    }

    gss_release_buffer(&release_minor_status, &mic_hello_buffer);
end_test:
    return ok;
}

bool
replay_mic_test(void)
{
    OM_uint32                           get_mic_major_status = GSS_S_COMPLETE;
    OM_uint32                           get_mic_minor_status = 0;
    OM_uint32                           verify_mic_major_status = GSS_S_COMPLETE;
    OM_uint32                           verify_mic_minor_status = 0;
    OM_uint32                           release_minor_status = 0;
    gss_buffer_desc                     mic_hello_buffer = { .value = NULL };
    bool                                ok = true;

    get_mic_major_status = gss_get_mic(
            &get_mic_minor_status,
            init_ctx,
            GSS_C_QOP_DEFAULT,
            &hello_buffer,
            &mic_hello_buffer);
    if (get_mic_major_status != GSS_S_COMPLETE)
    {
        ok = false;
        goto end_test;
    }
    
    /* Verify MIC */
    verify_mic_major_status = gss_verify_mic(
            &verify_mic_minor_status,
            accept_ctx,
            &hello_buffer,
            &mic_hello_buffer,
            NULL);
    if (verify_mic_major_status != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(
                stderr,
                verify_mic_major_status,
                verify_mic_minor_status);
        ok = false;
        goto end_test_release;
    }

    /* Verify MIC again (old token) */
    verify_mic_major_status = gss_verify_mic(
            &verify_mic_minor_status,
            accept_ctx,
            &hello_buffer,
            &mic_hello_buffer,
            NULL);
    if (verify_mic_major_status != GSS_S_OLD_TOKEN)
    {
        globus_gsi_gssapi_test_print_error(
                stderr,
                verify_mic_major_status,
                verify_mic_minor_status);
        ok = false;
        goto end_test_release;
    }
end_test_release:
    gss_release_buffer(&release_minor_status, &mic_hello_buffer);
end_test:
    return ok;
}

bool
out_of_order_mic_test(void)
{
    OM_uint32                           get_mic_major_status = GSS_S_COMPLETE;
    OM_uint32                           get_mic_minor_status = 0;
    OM_uint32                           verify_mic_major_status = GSS_S_COMPLETE;
    OM_uint32                           verify_mic_minor_status = 0;
    OM_uint32                           release_minor_status = 0;
    gss_buffer_desc                     mic_hello_buffer = { .value = NULL };
    gss_buffer_desc                     mic_hello_buffer2 = { .value = NULL };
    bool                                ok = true;

    /* Compute MIC */
    get_mic_major_status = gss_get_mic(
            &get_mic_minor_status,
            init_ctx,
            GSS_C_QOP_DEFAULT,
            &hello_buffer,
            &mic_hello_buffer);
    if (get_mic_major_status != GSS_S_COMPLETE)
    {
        ok = false;
        goto end_test;
    }

    /* Compute 2nd MIC */
    get_mic_major_status = gss_get_mic(
            &get_mic_minor_status,
            init_ctx,
            GSS_C_QOP_DEFAULT,
            &hello_buffer,
            &mic_hello_buffer2);
    if (get_mic_minor_status != GSS_S_COMPLETE)
    {
        ok = false;
        goto end_test;
    }
    
    /* Verify 2nd MIC (GAP) */
    verify_mic_major_status = gss_verify_mic(
            &verify_mic_minor_status,
            accept_ctx,
            &hello_buffer,
            &mic_hello_buffer2,
            NULL);
    if (verify_mic_major_status != GSS_S_GAP_TOKEN)
    {
        globus_gsi_gssapi_test_print_error(
                stderr,
                verify_mic_major_status,
                verify_mic_minor_status);
        ok = false;
        goto end_test;
    }

    /* Verify 1st MIC (OLD TOKEN) */
    verify_mic_major_status = gss_verify_mic(
            &verify_mic_minor_status,
            accept_ctx,
            &hello_buffer,
            &mic_hello_buffer,
            NULL);
    if (verify_mic_major_status != GSS_S_OLD_TOKEN)
    {
        globus_gsi_gssapi_test_print_error(
                stderr,
                verify_mic_major_status,
                verify_mic_minor_status);
        ok = false;
        goto end_test;
    }
    gss_release_buffer(&release_minor_status, &mic_hello_buffer);
    gss_release_buffer(&release_minor_status, &mic_hello_buffer2);
end_test:
    return ok;
}

bool
double_mic_test(void)
{
    OM_uint32                           get_mic_major_status = GSS_S_COMPLETE;
    OM_uint32                           get_mic_minor_status = 0;
    OM_uint32                           verify_mic_major_status = GSS_S_COMPLETE;
    OM_uint32                           verify_mic_minor_status = 0;
    OM_uint32                           release_minor_status = 0;
    gss_buffer_desc                     mic_hello_buffer = { .value = NULL };
    bool                                ok = true;

    for (size_t i = 0; ok && i < 2; i++)
    {
        get_mic_major_status = gss_get_mic(
                &get_mic_minor_status,
                init_ctx,
                GSS_C_QOP_DEFAULT,
                &hello_buffer,
                &mic_hello_buffer);
        if (get_mic_major_status != GSS_S_COMPLETE)
        {
            ok = false;
            goto end_test;
        }
        
        verify_mic_major_status = gss_verify_mic(
                &verify_mic_minor_status,
                accept_ctx,
                &hello_buffer,
                &mic_hello_buffer,
                NULL);
        if (verify_mic_major_status != GSS_S_COMPLETE)
        {
            globus_gsi_gssapi_test_print_error(
                    stderr,
                    verify_mic_major_status,
                    verify_mic_minor_status);
            ok = false;
        }
        gss_release_buffer(&release_minor_status, &mic_hello_buffer);
    }
end_test:
    return ok;
}


struct test_case
{
    bool                              (*func)(void);
    const char *                        name;
};

#define TEST_CASE_INITIALIZER(x) {x,#x}
int
main(int argc, char *argv[])
{
    OM_uint32                           context_major_status;
    OM_uint32                           context_minor_status;
    OM_uint32                           release_minor_status;
    int                                 failed = 0;
    struct test_case                    test_cases[] =
    {
        TEST_CASE_INITIALIZER(mic_test),
        TEST_CASE_INITIALIZER(altered_message_test),
        TEST_CASE_INITIALIZER(altered_mic_test),
        TEST_CASE_INITIALIZER(replay_mic_test),
        TEST_CASE_INITIALIZER(out_of_order_mic_test),
        TEST_CASE_INITIALIZER(double_mic_test),
    };
    OM_uint32                           flags[] =
    {
        0,
        GSS_C_CONF_FLAG,
    };
    size_t                              num_test_cases;
    size_t                              num_flags;
    size_t                              testnum = 1;
    
    num_flags = sizeof(flags)/sizeof(flags[0]);
    num_test_cases = sizeof(test_cases)/sizeof(test_cases[0]);

    printf("1..%zu\n", num_flags * num_test_cases);

    for (size_t f = 0; f < num_flags; f++)
    {
        failed = test_establish_contexts(
            &init_ctx,
            &accept_ctx,
            flags[f],
            &context_major_status,
            &context_minor_status);

        if (failed != 0)
        {
            printf("Bail out! couldn't establish security context\n");
            globus_gsi_gssapi_test_print_error(
                    stderr, context_major_status, context_minor_status);
            failed = 99;
            goto establish_failed;
        }
        
        for (size_t i = 0; i < num_test_cases; i++, testnum++)
        {
            int ok = test_cases[i].func();

            if (!ok)
            {
                printf("not ");
                failed++;
            }
            printf("ok %zu - %s (flags=%d)\n",
                    testnum,
                    test_cases[i].name,
                    flags[f]);
        }

    establish_failed:
        if (init_ctx != GSS_C_NO_CONTEXT)
        {
            gss_delete_sec_context(&release_minor_status, &init_ctx, NULL);
        }
        if (accept_ctx != GSS_C_NO_CONTEXT)
        {
            gss_delete_sec_context(&release_minor_status, &accept_ctx, NULL);
        }
    }

    exit(failed);
}

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
#include "gssapi_openssl.h"
#include "gssapi_test_utils.h"

void internal_release_buffer(
    gss_buffer_desc *                   buffer);

void globus_print_error(
    globus_result_t                     error_result);

int main()
{
    OM_uint32                           init_maj_stat;
    OM_uint32                           accept_maj_stat;
    OM_uint32                           maj_stat;
    OM_uint32                           min_stat;
    OM_uint32                           ret_flags;
    OM_uint32                           req_flags = 0;
    OM_uint32                           time_rec;
    gss_buffer_desc                     send_tok;
    gss_buffer_desc                     recv_tok;
    gss_buffer_desc *                   token_ptr;
    gss_OID                             mech_type;
    gss_name_t                          target_name;
    gss_ctx_id_t                        init_context;
    gss_ctx_id_t                        accept_context;
    gss_ctx_id_t                        del_init_context;
    gss_ctx_id_t                        del_accept_context;
    gss_cred_id_t                       delegated_cred;
    gss_cred_id_t                       imported_cred;
    gss_cred_id_t                       cred_handle;
    int                                 rc = EXIT_SUCCESS;

    printf("1..1\n");
    /* Initialize variables */
    
    token_ptr = GSS_C_NO_BUFFER;
    init_context = GSS_C_NO_CONTEXT;
    accept_context = GSS_C_NO_CONTEXT;
    del_init_context = GSS_C_NO_CONTEXT;
    del_accept_context = GSS_C_NO_CONTEXT;
    delegated_cred = GSS_C_NO_CREDENTIAL;
    accept_maj_stat = GSS_S_CONTINUE_NEEDED;
    ret_flags = 0;
    req_flags |= GSS_C_GLOBUS_SSL_COMPATIBLE;

    /* Activate Modules */
    globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);

    maj_stat = gss_acquire_cred(&min_stat,
                                NULL,
                                GSS_C_INDEFINITE,
                                GSS_C_NO_OID_SET,
                                GSS_C_BOTH,
                                &cred_handle,
                                NULL,
                                NULL);

    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, maj_stat, min_stat);
        globus_print_error((globus_result_t) min_stat);
        rc = EXIT_FAILURE;
        goto fail;
    }

    
    /* get the subject name */
    
    maj_stat = gss_inquire_cred(&min_stat, 
                                cred_handle,
                                &target_name,
                                NULL,
                                NULL,
                                NULL);

    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, maj_stat, min_stat);
        globus_print_error((globus_result_t) min_stat);
        rc = EXIT_FAILURE;
        goto fail;
    }


    /* set up the first security context */
    
    init_maj_stat = gss_init_sec_context(&min_stat,
                                         cred_handle,
                                         &init_context,
                                         target_name,
                                         GSS_C_NULL_OID,
                                         0,
                                         0,
                                         GSS_C_NO_CHANNEL_BINDINGS,
                                         token_ptr,
                                         NULL,
                                         &send_tok,
                                         NULL,
                                         NULL);


    if(init_maj_stat != GSS_S_CONTINUE_NEEDED)
    {
        globus_gsi_gssapi_test_print_error(stderr, init_maj_stat, min_stat);
        globus_print_error((globus_result_t) min_stat);
        rc = EXIT_FAILURE;
        goto fail;
    }

    while(1)
    {
        
        accept_maj_stat=gss_accept_sec_context(&min_stat,
                                               &accept_context,
                                               GSS_C_NO_CREDENTIAL,
                                               &send_tok, 
                                               GSS_C_NO_CHANNEL_BINDINGS,
                                               NULL,
                                               &mech_type,
                                               &recv_tok,
                                               &ret_flags,
                                               /* ignore time_rec */
                                               NULL, 
                                               NULL);

        if(accept_maj_stat != GSS_S_COMPLETE &&
           accept_maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            globus_gsi_gssapi_test_print_error(stderr, accept_maj_stat, min_stat);
            globus_print_error((globus_result_t) min_stat);
            rc = EXIT_FAILURE;
            goto fail;
        }
        else if(accept_maj_stat == GSS_S_COMPLETE)
        {
            break;
        }

        init_maj_stat = gss_init_sec_context(&min_stat,
                                             GSS_C_NO_CREDENTIAL,
                                             &init_context,
                                             target_name,
                                             GSS_C_NULL_OID,
                                             0,
                                             0,
                                             GSS_C_NO_CHANNEL_BINDINGS,
                                             &recv_tok,
                                             NULL,
                                             &send_tok,
                                             NULL,
                                             NULL);
        
        
        if(init_maj_stat != GSS_S_COMPLETE &&
           init_maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            globus_gsi_gssapi_test_print_error(stderr, init_maj_stat, min_stat);
            globus_print_error((globus_result_t) min_stat);
            rc = EXIT_FAILURE;
            goto fail;
        }
    }

    printf("# %s:%d: Successfully established initial security context\n",
           __FILE__,
           __LINE__);


    init_maj_stat = gss_init_delegation(&min_stat,
                                        init_context,
                                        cred_handle,
                                        GSS_C_NO_OID,
                                        GSS_C_NO_OID_SET,
                                        GSS_C_NO_BUFFER_SET,
                                        token_ptr,
                                        req_flags,
                                        0,
                                        &send_tok);
    

    if(init_maj_stat != GSS_S_COMPLETE &&
       init_maj_stat != GSS_S_CONTINUE_NEEDED)
    {
        globus_gsi_gssapi_test_print_error(stderr, init_maj_stat, min_stat);
        globus_print_error((globus_result_t) min_stat);
        rc = EXIT_FAILURE;
        goto fail;
    }

    internal_release_buffer(&recv_tok);
    maj_stat = gss_wrap(&min_stat,
                        init_context,
                        0,
                        GSS_C_QOP_DEFAULT,
                        &send_tok,
                        NULL,
                        &recv_tok);

    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, maj_stat, min_stat);
        globus_print_error((globus_result_t) min_stat);
        rc = EXIT_FAILURE;
        goto fail;
    }
    
    while(1)
    {

        internal_release_buffer(&send_tok);
        maj_stat = gss_unwrap(&min_stat,
                              accept_context,
                              &recv_tok,
                              &send_tok,
                              NULL,
                              NULL);
            
        if(maj_stat != GSS_S_COMPLETE)
        {
            globus_gsi_gssapi_test_print_error(stderr, maj_stat, min_stat);
            globus_print_error((globus_result_t) min_stat);
            rc = EXIT_FAILURE;
            goto fail;
        }

        internal_release_buffer(&recv_tok);
        accept_maj_stat=gss_accept_delegation(&min_stat,
                                              accept_context,
                                              GSS_C_NO_OID_SET,
                                              GSS_C_NO_BUFFER_SET,
                                              &send_tok,
                                              req_flags,
                                              0,
                                              &time_rec,
                                              &delegated_cred,
                                              &mech_type,
                                              &recv_tok);
        
        if(accept_maj_stat != GSS_S_COMPLETE &&
           accept_maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            globus_gsi_gssapi_test_print_error(stderr, init_maj_stat, min_stat);
            globus_print_error((globus_result_t) min_stat);

            rc = EXIT_FAILURE;
            goto fail;
        }
        else if(accept_maj_stat == GSS_S_COMPLETE)
        {
            break;
        }

        internal_release_buffer(&send_tok);
        maj_stat = gss_wrap(&min_stat,
                            accept_context,
                            0,
                            GSS_C_QOP_DEFAULT,
                            &recv_tok,
                            NULL,
                            &send_tok);
                        
    
        if(maj_stat != GSS_S_COMPLETE)
        {
            globus_gsi_gssapi_test_print_error(stderr, maj_stat, min_stat);
            globus_print_error((globus_result_t) min_stat);
            rc = EXIT_FAILURE;
            goto fail;
        }

        internal_release_buffer(&recv_tok);
        maj_stat = gss_unwrap(&min_stat,
                              init_context,
                              &send_tok,
                              &recv_tok,
                              NULL,
                              NULL);
        
    
        if(maj_stat != GSS_S_COMPLETE)
        {
            globus_gsi_gssapi_test_print_error(stderr, maj_stat, min_stat);
            globus_print_error((globus_result_t) min_stat);
            rc = EXIT_FAILURE;
            goto fail;
        }

        internal_release_buffer(&send_tok);
        init_maj_stat = gss_init_delegation(&min_stat,
                                            init_context,
                                            cred_handle,
                                            GSS_C_NO_OID,
                                            GSS_C_NO_OID_SET,
                                            GSS_C_NO_BUFFER_SET,
                                            &recv_tok,
                                            req_flags,
                                            0,
                                            &send_tok);


        if(init_maj_stat != GSS_S_COMPLETE &&
           init_maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            globus_gsi_gssapi_test_print_error(stderr, init_maj_stat, min_stat);
            globus_print_error((globus_result_t) min_stat);
            rc = EXIT_FAILURE;
            goto fail;
        }

        internal_release_buffer(&recv_tok);
        maj_stat = gss_wrap(&min_stat,
                            init_context,
                            0,
                            GSS_C_QOP_DEFAULT,
                            &send_tok,
                            NULL,
                            &recv_tok);
        
        
        if(maj_stat != GSS_S_COMPLETE)
        {
            globus_gsi_gssapi_test_print_error(stderr, maj_stat, min_stat);
            globus_print_error((globus_result_t) min_stat);
            rc = EXIT_FAILURE;
            goto fail;
        }
    }
    
    printf("# %s:%d: Successfully delegated credential\n",
           __FILE__,
           __LINE__);

    /* export and import the delegated credential */
    /* this can be done both to a buffer and to a file */
    /* New in GT 2.0 */

    internal_release_buffer(&send_tok);
    maj_stat = gss_export_cred(&min_stat,
                               delegated_cred,
                               GSS_C_NO_OID,
                               0,
                               &send_tok);

    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, init_maj_stat, min_stat);
        globus_print_error((globus_result_t) min_stat);
        rc = EXIT_FAILURE;
        goto fail;
    }

    maj_stat = gss_import_cred(&min_stat,
                               &imported_cred,
                               GSS_C_NO_OID,
                               0,
                               &send_tok,
                               0,
                               &time_rec);


    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, init_maj_stat, min_stat);
        globus_print_error((globus_result_t) min_stat);
        rc = EXIT_FAILURE;
        goto fail;
    }

    internal_release_buffer(&send_tok);

    printf("# %s:%d: Successfully exported/imported the delegated credential\n",
           __FILE__,
           __LINE__);

    /* set up another security context using the delegated credential */
    
    init_maj_stat = gss_init_sec_context(&min_stat,
                                         imported_cred,
                                         &del_init_context,
                                         target_name,
                                         GSS_C_NULL_OID,
                                         0,
                                         0,
                                         GSS_C_NO_CHANNEL_BINDINGS,
                                         token_ptr,
                                         NULL,
                                         &send_tok,
                                         NULL,
                                         NULL);


    if(init_maj_stat != GSS_S_COMPLETE &&
       init_maj_stat != GSS_S_CONTINUE_NEEDED)
    {
        globus_gsi_gssapi_test_print_error(stderr, init_maj_stat, min_stat);
        globus_print_error((globus_result_t) min_stat);
        rc = EXIT_FAILURE;
        goto fail;
    }
    
    while(1)
    {
        internal_release_buffer(&recv_tok);

        accept_maj_stat=gss_accept_sec_context(&min_stat,
                                               &del_accept_context,
                                               imported_cred,
                                               &send_tok, 
                                               GSS_C_NO_CHANNEL_BINDINGS,
                                               &target_name,
                                               &mech_type,
                                               &recv_tok,
                                               &ret_flags,
                                               /* ignore time_rec */
                                               NULL, 
                                               NULL);

        if(accept_maj_stat != GSS_S_COMPLETE &&
           accept_maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            globus_gsi_gssapi_test_print_error(stderr, init_maj_stat, min_stat);
            globus_print_error((globus_result_t) min_stat);
            rc = EXIT_FAILURE;
            goto fail;
        }
        else if(accept_maj_stat == GSS_S_COMPLETE)
        {
            break;
        }

        init_maj_stat = gss_init_sec_context(&min_stat,
                                             imported_cred,
                                             &del_init_context,
                                             target_name,
                                             GSS_C_NULL_OID,
                                             0,
                                             0,
                                             GSS_C_NO_CHANNEL_BINDINGS,
                                             &recv_tok,
                                             NULL,
                                             &send_tok,
                                             NULL,
                                             NULL);
        
        
        if(init_maj_stat != GSS_S_COMPLETE &&
           init_maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            globus_gsi_gssapi_test_print_error(stderr, init_maj_stat, min_stat);
            globus_print_error((globus_result_t) min_stat);
            rc = EXIT_FAILURE;
            goto fail;
        }
    }

    /* got sec context based on delegated cred now */

    printf("# %s:%d: Successfully established security context with delegated credential\n",
           __FILE__,
           __LINE__);

fail:
    printf("%s gssapi_delegation_compat_test\n", 
            (rc == EXIT_SUCCESS) ? "ok" : "not ok");
    globus_module_deactivate_all();

    exit(rc);
}

void globus_print_error(
    globus_result_t                     error_result)
{
    globus_object_t *                   error_obj = NULL;
    char *                              error_string = NULL;
    
    error_obj = globus_error_get(error_result);
    error_string = globus_error_print_chain(error_obj);
    globus_libc_fprintf(stderr, "%s\n", error_string);
    globus_libc_free(error_string);
    globus_object_free(error_obj);
}

void internal_release_buffer(
    gss_buffer_desc *                   buffer)
{
    OM_uint32                           maj_stat, min_stat;

    maj_stat = gss_release_buffer(&min_stat, (gss_buffer_t) buffer);
    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gsi_gssapi_test_print_error(stderr, maj_stat, min_stat);
        globus_print_error((globus_result_t) min_stat);
        exit(1);
    }
}

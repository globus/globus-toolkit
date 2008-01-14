/*
 * Copyright 1999-2006 University of Chicago
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

#define EXT_SIZE 16
#include "gssapi.h"
#include "gssapi_openssl.h"
#include "globus_gss_assist.h"

void internal_release_buffer(
    gss_buffer_desc *                   buffer);

int verify_cred(
    gss_cred_id_t                       credential);

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
    gss_buffer_desc                     oid_buffer;
    gss_buffer_set_desc                 oid_buffers;
    gss_buffer_set_t                    inquire_buffers;
    gss_OID                             mech_type;
    gss_OID_set_desc                    oid_set;
    gss_name_t                          target_name;
    gss_ctx_id_t                        init_context;
    gss_ctx_id_t                        accept_context;
    gss_ctx_id_desc *                   init_context_handle;
    gss_ctx_id_t                        del_init_context;
    gss_ctx_id_t                        del_accept_context;
    gss_cred_id_t                       delegated_cred;
    gss_cred_id_t                       imported_cred;
    gss_cred_id_t                       cred_handle;
    char *                              error_str;
    char *                              buf; 

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
    globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);

/*      oid_buffer.value = malloc(EXT_SIZE); */
/*      oid_buffer.length = EXT_SIZE; */

/*      buf = (char *) oid_buffer.value; */
    
/*      memset(buf,'A',EXT_SIZE); */
/*      buf[EXT_SIZE-1]='\0'; */
    
/*      oid_buffers.count = 1; */
/*      oid_buffers.elements = &oid_buffer; */
/*      oid_set.count = 1; */
/*      oid_set.elements = gss_restrictions_extension; */
    
    /* acquire the credential */

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
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        globus_print_error((globus_result_t) min_stat);
        exit(1);
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
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        globus_print_error((globus_result_t) min_stat);
        exit(1);
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
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             init_maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        globus_print_error((globus_result_t) min_stat);
        exit(1);
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
                                               GSS_C_NO_CREDENTIAL);

        if(accept_maj_stat != GSS_S_COMPLETE &&
           accept_maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 init_maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            globus_print_error((globus_result_t) min_stat);
            exit(1);
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
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 init_maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            globus_print_error((globus_result_t) min_stat);
            exit(1);
        }
    }

    printf("%s:%d: Successfully established initial security context\n",
           __FILE__,
           __LINE__);


    /* delegate our credential over the initial security context and
     * insert a restriction extension into the delegated credential.
     * This is a post GT 2.0 feature.
     */


    init_maj_stat = gss_init_delegation(&min_stat,
                                        init_context,
                                        cred_handle,
                                        GSS_C_NO_OID,
                                        GSS_C_NO_OID_SET,
                                        GSS_C_NO_BUFFER_SET,
/*                                          &oid_set, */
/*                                          &oid_buffers, */
                                        token_ptr,
                                        req_flags,
                                        0,
                                        &send_tok);
    

    if(init_maj_stat != GSS_S_COMPLETE &&
       init_maj_stat != GSS_S_CONTINUE_NEEDED)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             init_maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        globus_print_error((globus_result_t) min_stat);
        exit(1);
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
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        globus_print_error((globus_result_t) min_stat);
        exit(1);
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
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            globus_print_error((globus_result_t) min_stat);
            exit(1);
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
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 init_maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            globus_print_error((globus_result_t) min_stat);

            exit(1);
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
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            globus_print_error((globus_result_t) min_stat);
            exit(1);
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
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            globus_print_error((globus_result_t) min_stat);
            exit(1);
        }

        internal_release_buffer(&send_tok);
        init_maj_stat = gss_init_delegation(&min_stat,
                                            init_context,
                                            cred_handle,
                                            GSS_C_NO_OID,
                                            GSS_C_NO_OID_SET,
                                            GSS_C_NO_BUFFER_SET,
/*                                              &oid_set, */
/*                                              &oid_buffers, */
                                            &recv_tok,
                                            req_flags,
                                            0,
                                            &send_tok);


        if(init_maj_stat != GSS_S_COMPLETE &&
           init_maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 init_maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            globus_print_error((globus_result_t) min_stat);
            exit(1);
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
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            globus_print_error((globus_result_t) min_stat);
            exit(1);
        }
    }
    
    printf("%s:%d: Successfully delegated credential\n",
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
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             init_maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        globus_print_error((globus_result_t) min_stat);
        exit(1);
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
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             init_maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            globus_print_error((globus_result_t) min_stat);
        exit(1);
    }

    internal_release_buffer(&send_tok);

    printf("%s:%d: Successfully exported/imported the delegated credential\n",
           __FILE__,
           __LINE__);

/*      free(oid_buffer.value); */
    
/*      oid_buffer.value = (void *) &oid_set; */
/*      oid_buffer.length = 1; */


    /* Tell the GSS that we will handle restriction extensions */
    /* This is a post GT 2.0 feature */
    
/*      maj_stat = gss_set_sec_context_option( */
/*          &min_stat, */
/*          &del_init_context, */
/*          (gss_OID) GSS_APPLICATION_WILL_HANDLE_EXTENSIONS, */
/*          &oid_buffer); */
    

/*      if(maj_stat != GSS_S_COMPLETE) */
/*      { */
/*          globus_gss_assist_display_status_str(&error_str, */
/*                                               NULL, */
/*                                               maj_stat, */
/*                                               min_stat, */
/*                                               0); */
/*          printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str); */
/*          globus_print_error((globus_result_t) min_stat); */
/*          exit(1); */
/*      } */
    

/*      maj_stat = gss_set_sec_context_option( */
/*          &min_stat, */
/*          &del_accept_context, */
/*          (gss_OID) GSS_APPLICATION_WILL_HANDLE_EXTENSIONS, */
/*          &oid_buffer); */
    

/*      if(maj_stat != GSS_S_COMPLETE) */
/*      { */
/*          globus_gss_assist_display_status_str(&error_str, */
/*                                               NULL, */
/*                                               maj_stat, */
/*                                               min_stat, */
/*                                               0); */
/*          printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str); */
/*          globus_print_error((globus_result_t) min_stat); */
/*          exit(1); */
/*      } */


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
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             init_maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        globus_print_error((globus_result_t) min_stat);
        exit(1);
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
                                               GSS_C_NO_CREDENTIAL);

        if(accept_maj_stat != GSS_S_COMPLETE &&
           accept_maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 init_maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            globus_print_error((globus_result_t) min_stat);
            exit(1);
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
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 init_maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            globus_print_error((globus_result_t) min_stat);
            exit(1);
        }
    }

    /* got sec context based on delegated cred now */

    printf("%s:%d: Successfully established security context with delegated credential\n",
           __FILE__,
           __LINE__);

/*      /* Extract and print the restrictions extension from the security */
/*       * context. */
/*       * This is a post GT 2.0 feature. */
/*       * */
    
/*      maj_stat = gss_inquire_sec_context_by_oid(&min_stat, */
/*                                                del_accept_context, */
/*                                                gss_restrictions_extension, */
/*                                                &inquire_buffers); */

    
/*      if(maj_stat != GSS_S_COMPLETE) */
/*      { */
/*          globus_gss_assist_display_status_str(&error_str, */
/*                                               NULL, */
/*                                               init_maj_stat, */
/*                                               min_stat, */
/*                                               0); */
/*          printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str); */
/*          exit(1); */
/*      } */
    
/*      printf("%s:%d: Security context contains restriction extension %s\n", */
/*             __FILE__, */
/*             __LINE__, */
/*             (char *) inquire_buffers->elements[0].value); */

    globus_module_deactivate_all();

    exit(0);
}

int verify_cred(
    gss_cred_id_t                       credential)
{
    gss_cred_id_desc *                  cred_handle;
    X509 *                              cert;
    X509 *                              previous_cert;
    STACK_OF(X509) *                    cert_chain;
    int                                 cert_count;
    char *                              error_str;
    globus_object_t *                   error_obj;
    globus_result_t                     result;

    cert_count = 1;
    cred_handle = (gss_cred_id_desc *) credential;

    result = globus_gsi_cred_get_cert_chain(
        cred_handle->cred_handle,
        &cert_chain);
    if(result != GLOBUS_SUCCESS)
    {
        error_obj = globus_error_get(result);
        error_str = globus_error_print_chain(error_obj);
        fprintf(stderr, error_str);
        globus_libc_free(error_str);
        globus_object_free(error_obj);
        exit(1);
    }        
    
    if(cert_chain)
    {
        cert_count += sk_X509_num(cert_chain);
    }

    result = globus_gsi_cred_get_cert(cred_handle->cred_handle,
                                      &cert);
    if(result != GLOBUS_SUCCESS)
    {
        error_obj = globus_error_get(result);
        error_str = globus_error_print_chain(error_obj);
        fprintf(stderr, error_str);
        globus_libc_free(error_str);
        globus_object_free(error_obj);
        exit(1);
    }

    previous_cert=NULL;
    cert_count--;

    do
    {
        if(previous_cert != NULL)
        {
            if(!X509_verify(previous_cert, X509_get_pubkey(cert)))
            {
                return 0;
            }
        }

        previous_cert = cert;

    } while(cert_count-- &&
            (cert = sk_X509_value(cert_chain, cert_count)));

    return 1;
}

void globus_print_error(
    globus_result_t                     error_result)
{
    globus_object_t *                   error_obj = NULL;
    globus_object_t *                   base_error_obj = NULL;
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
    char *                              error_str = NULL;
    OM_uint32                           maj_stat, min_stat;

    maj_stat = gss_release_buffer(&min_stat, (gss_buffer_t) buffer);
    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        globus_print_error((globus_result_t) min_stat);
        exit(1);
    }
}

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



/*
gcc -g -I$GLOBUS_LOCATION/include -I$GLOBUS_LOCATION/include/gcc32dbg -L$GLOBUS_LOCATION/lib delegation_test.c -lglobus_gssapi_gsi_gcc32dbg -lglobus_gss_assist_gcc32dbg -lglobus_ssl_utils_gcc32dbg -lssl_gcc32dbg -lcrypto_gcc32dbg

*/


#define EXT_SIZE 16
#include "gssapi.h"
#include "../source/library/gssapi_ssleay.h"


int verify_cred(
    gss_cred_id_t                       credential);


int main()
{
    OM_uint32                           init_maj_stat;
    OM_uint32                           accept_maj_stat;
    OM_uint32                           maj_stat;
    OM_uint32                           min_stat;
    OM_uint32                           ret_flags;
    OM_uint32                           time_rec;
    gss_buffer_desc                     send_tok;
    gss_buffer_desc                     recv_tok;
    gss_buffer_desc *                   token_ptr;
    gss_buffer_desc                     oid_buffer;
    gss_buffer_set_desc                 oid_buffers;
    gss_buffer_set_t                    inquire_buffers;
    gss_OID				name_type;
    gss_OID                             mech_type;
    gss_OID_set_desc                    oid_set;
    gss_name_t                          target_name;
    gss_ctx_id_t  			init_context;
    gss_ctx_id_t  			accept_context;
    gss_ctx_id_desc *                   init_context_handle;
    gss_ctx_id_t  			del_init_context;
    gss_ctx_id_t  			del_accept_context;
    gss_cred_id_t                       delegated_cred;
    gss_cred_id_t                       imported_cred;
    gss_cred_id_t                       cred_handle;
    char *                              subject =
        "/O=Grid/O=Globus/OU=mcs.anl.gov/CN=Samuel Meder";
    char *                              error_str;
    char *                              buf; 

    /* Initialize variables */
    
    token_ptr = GSS_C_NO_BUFFER;
    init_context = GSS_C_NO_CONTEXT;
    accept_context = GSS_C_NO_CONTEXT;
    del_init_context = GSS_C_NO_CONTEXT;
    del_accept_context = GSS_C_NO_CONTEXT;
    name_type = GSS_C_NT_USER_NAME;
    delegated_cred = GSS_C_NO_CREDENTIAL;
    accept_maj_stat = GSS_S_CONTINUE_NEEDED;
    ret_flags = 0;


    oid_buffer.value = malloc(EXT_SIZE);
    oid_buffer.length = EXT_SIZE;

    buf = (char *) oid_buffer.value;
    
    memset(buf,'A',EXT_SIZE);
    buf[EXT_SIZE-1]='\0';
    
    oid_buffers.count = 1;
    oid_buffers.elements = &oid_buffer;
    oid_set.count = 1;
    oid_set.elements = gss_restrictions_extension;
    
    send_tok.value = subject;
    send_tok.length = strlen(subject) + 1;

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
        exit(1);
    }

    
    /* import the subject name */
    
    maj_stat = gss_import_name(&min_stat, 
                               &send_tok, 
                               name_type, 
                               &target_name);

    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
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
                                        &oid_set,
                                        &oid_buffers,
                                        token_ptr,
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
        exit(1);
    }

    while(1)
    {
        accept_maj_stat=gss_accept_delegation(&min_stat,
                                              accept_context,
                                              GSS_C_NO_OID_SET,
                                              GSS_C_NO_BUFFER_SET,
                                              &send_tok,
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
            exit(1);
        }
        else if(accept_maj_stat == GSS_S_COMPLETE)
        {
            break;
        }

        init_maj_stat = gss_init_delegation(&min_stat,
                                            init_context,
                                            cred_handle,
                                            GSS_C_NO_OID,
                                            &oid_set,
                                            &oid_buffers,
                                            &recv_tok,
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
            exit(1);
        }
    }
    
    printf("%s:%d: Successfully delegated credential\n",
           __FILE__,
           __LINE__);

    /* export and import the delegated credential */
    /* this can be done both to a buffer and to a file */
    /* New in GT 2.0 */

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
        exit(1);
    }

    printf("%s:%d: Successfully exported/imported the delegated credential\n",
           __FILE__,
           __LINE__);

    free(oid_buffer.value);
    
    oid_buffer.value = (void *) &oid_set;
    oid_buffer.length = 1;


    /* Tell the GSS that we will handle restriction extensions */
    /* This is a post GT 2.0 feature */
    
    maj_stat = gss_set_sec_context_option(
        &min_stat,
        &del_init_context,
        (gss_OID) GSS_APPLICATION_WILL_HANDLE_EXTENSIONS,
        &oid_buffer);
    

    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }
    

    maj_stat = gss_set_sec_context_option(
        &min_stat,
        &del_accept_context,
        (gss_OID) GSS_APPLICATION_WILL_HANDLE_EXTENSIONS,
        &oid_buffer);
    

    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }


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
        exit(1);
    }


    
    while(1)
    {
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
            exit(1);
        }
    }

    /* got sec context based on delegated cred now */

    printf("%s:%d: Successfully established security context with delegated credential\n",
           __FILE__,
           __LINE__);

    /* Extract and print the restrictions extension from the security
     * context.
     * This is a post GT 2.0 feature.
     */
    
    maj_stat = gss_inquire_sec_context_by_oid(&min_stat,
                                              del_accept_context,
                                              gss_restrictions_extension,
                                              &inquire_buffers);

    
    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             init_maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }
    
    printf("%s:%d: Security context contains restriction extension %s\n",
           __FILE__,
           __LINE__,
           (char *) inquire_buffers->elements[0].value);

    
}



int verify_cred(
    gss_cred_id_t                       credential)
{
    gss_cred_id_desc *                  cred_handle;
    X509 *                              cert;
    X509 *                              previous_cert;
    int                                 cert_count;

    cert_count = 1;
    cred_handle = (gss_cred_id_desc *) credential;
    
    if(cred_handle->pcd->cert_chain)
    {
        cert_count += sk_X509_num(cred_handle->pcd->cert_chain);
    }

    cert = cred_handle->pcd->ucert;
    previous_cert=NULL;
    cert_count--;

    do
    {
        if(previous_cert != NULL)
        {
            if(!X509_verify(previous_cert,X509_get_pubkey(cert)))
            {
                return 0;
            }
        }
        previous_cert = cert;
    } while(cert_count-- &&
            (cert = sk_X509_value(cred_handle->pcd->cert_chain,cert_count)));

    return 1;
}


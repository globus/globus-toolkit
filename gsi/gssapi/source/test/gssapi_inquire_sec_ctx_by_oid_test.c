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

/**
 * @file gssapi_inquire_sec_ctx_by_oid_test.c
 * @brief Test cases for gss_inquire_sec_context_by_oid()
 * @test
 * The gssapi-inquire-sec-ctx-by-oid-test does a GSSAPI handshake and
 * then verifies that gss_inquire_sec_context_by_oid() can extract the
 * peer certificate chain from both the initiating and accepting sides.
 */
#include "gssapi_test_utils.h"

#include <openssl/x509.h>
#include <stdio.h>


int
main(int argc, char *argv[])
{
    OM_uint32                           context_major_status;
    OM_uint32                           context_minor_status;
    OM_uint32                           init_major_status;
    OM_uint32                           init_minor_status;
    OM_uint32                           accept_major_status;
    OM_uint32                           accept_minor_status;
    OM_uint32                           release_minor_status;
    gss_ctx_id_t                        init_ctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t                        accept_ctx = GSS_C_NO_CONTEXT;
    int                                 rc;
    int                                 failed = 0;
    gss_OID_desc                        cert_chain_oid =
        {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x08"}; 
    gss_buffer_set_t                    cert_chain_buffers; 

    printf("1..2\n");

    rc = test_establish_contexts(
        &init_ctx,
        &accept_ctx,
        &context_major_status,
        &context_minor_status);

    if (rc != 0)
    {
        globus_gsi_gssapi_test_print_error(
                stderr, context_major_status, context_minor_status);
        failed = 1;
        goto establish_failed;
    }
    
    init_major_status = gss_inquire_sec_context_by_oid(
        &init_minor_status,
        init_ctx,
        &cert_chain_oid,
        &cert_chain_buffers);
    
    if (GSS_ERROR(init_major_status))
    {
        globus_gsi_gssapi_test_print_error(
                stderr, init_major_status, init_minor_status);
        printf("not ok 1 - gss_inquire_sec_context_by_oid(init)\n");
        failed++;

        goto skip_init_cert_chain_checks;
    }

    for (int i = 0; i < cert_chain_buffers->count; i++)
    {
        const unsigned char * tmp_ptr;
        X509 *cert;

        tmp_ptr = cert_chain_buffers->elements[i].value;
        cert = d2i_X509(NULL, &tmp_ptr,
                        cert_chain_buffers->elements[i].length);
        if(cert == NULL)
        {
            printf("not ok 1 - gss_inquire_sec_context_by_oid(init)\n");
            fprintf(stderr,
                    "\tCouldn't deserialize initializer's peer's cert chain\n");
            goto skip_init_cert_chain_checks;
        }
        X509_free(cert);
    }
    printf("ok 1 - gss_inquire_sec_context_by_oid(init)\n");
skip_init_cert_chain_checks:
    if (cert_chain_buffers != NULL)
    {
        gss_release_buffer_set(&release_minor_status,
                               &cert_chain_buffers);
        cert_chain_buffers = NULL;
    }

    accept_major_status = gss_inquire_sec_context_by_oid(
        &accept_minor_status,
        accept_ctx,
        &cert_chain_oid,
        &cert_chain_buffers);
    
    if (GSS_ERROR(accept_major_status))
    {
        printf("not ok 2 - gss_inquire_sec_context_by_oid(accept)\n");
        failed++;
        goto skip_accept_cert_chain_checks;
    }

    for (int i = 0; i < cert_chain_buffers->count; i++)
    {
        const unsigned char * tmp_ptr;
        X509 *cert;

        tmp_ptr = cert_chain_buffers->elements[i].value;
        cert = d2i_X509(NULL, &tmp_ptr,
                        cert_chain_buffers->elements[i].length);
        if(cert == NULL)
        {
            printf("not ok 2 - gss_inquire_sec_context_by_oid(accept)\n");
            fprintf(stderr,
                    "\tCouldn't deserialize accepter's peer cert chain\n");
            goto skip_accept_cert_chain_checks;
        }
        X509_free(cert);
    }
    printf("ok 2 - gss_inquire_sec_context_by_oid(accept)\n");
    if (cert_chain_buffers != NULL)
    {
        gss_release_buffer_set(&release_minor_status,
                               &cert_chain_buffers);
        cert_chain_buffers = NULL;
    }

skip_accept_cert_chain_checks:
establish_failed:
    if (init_ctx != GSS_C_NO_CONTEXT)
    {
        gss_delete_sec_context(&release_minor_status, &init_ctx, NULL);
    }
    if (accept_ctx != GSS_C_NO_CONTEXT)
    {
        gss_delete_sec_context(&release_minor_status, &accept_ctx, NULL);
    }
    return failed;
}

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

#include "globus_common.h"
#include "globus_gsi_system_config.h"
#include "gssapi.h"
#include "globus_gss_assist.h"
#include "globus_gsi_credential.h"
#include "globus_gridmap_callout_error.h"

#include <stdlib.h>
#include <openssl/ssl.h>


/* 1.2.3.4.4.3.2.1.7.8 */
static const gss_OID_desc               ggvm_cert_chain_oid =
    {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x01\x08"}; 

#if OPENSSL_VERSION_NUMBER < 0x0090801fL
#define GT_D2I_ARG_CAST (unsigned char **)
#else
#define GT_D2I_ARG_CAST
#endif

static
globus_result_t
ggvm_load_cert_from_file(
    char *                              certfile,
    X509 **                             out_cert)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    FILE *                              certfp = NULL;
    X509 *                              cert;
   
    certfp = fopen(certfile, "r");
    if(!certfp)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("error opening file."));
        goto err;
    }
    
    cert = PEM_read_X509(certfp, 0, 0, 0);
    if(!cert)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("file does not contain a valid PEM certificate."));
        goto err;
    }
    
    *out_cert = cert;
    
err:
    if(certfp)
    {
        fclose(certfp);
    }
    
    return result;
}

static
globus_result_t
ggvm_extract_cert_from_chain(
    gss_ctx_id_t                        context,
    int                                 cert_index,
    X509 **                             out_cert)
{
    globus_result_t                     result = GLOBUS_SUCCESS;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    gss_buffer_set_t                    cert_chain_buffers = 0;
    X509 *                              cert;
    const unsigned char *               ptr;
    
    major_status = gss_inquire_sec_context_by_oid(
        &minor_status,
        context,
        (gss_OID) &ggvm_cert_chain_oid,
        &cert_chain_buffers);

    if(GSS_ERROR(major_status))
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("can't extract cert chain"));
        goto err;
    }
    
    if(cert_chain_buffers->count <= cert_index)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("too few certs in chain"));
        goto err;
    }

    ptr = cert_chain_buffers->elements[cert_index].value;
    cert = d2i_X509(
        NULL, 
        GT_D2I_ARG_CAST &ptr, 
        cert_chain_buffers->elements[cert_index].length);
    if(cert == NULL)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("can't extract cert from chain"));
        goto err;
    }
    
    *out_cert = cert;

err:
    if(cert_chain_buffers)
    {
        gss_release_buffer_set(&minor_status, &cert_chain_buffers);
    }
    
    return result;
}


static
globus_result_t 
ggvm_verify_cert(
    X509 *                              cert,
    X509 *                              ca_cert)
{
    X509_STORE *                        ca_store = NULL;
    X509_STORE_CTX *                    cert_ctx = NULL;
    int                                 rc;
    globus_result_t                     result = GLOBUS_FAILURE;
    
    ca_store = X509_STORE_new();
    if(ca_store == NULL)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("store allocation failed."));
        goto err;
    }

    rc = X509_STORE_add_cert(ca_store, ca_cert);
    if(rc != 1)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("ca cert add failed."));
        goto err;
    }    

    cert_ctx = X509_STORE_CTX_new();
    if(cert_ctx == NULL)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("conxtext allocation failed."));
        goto err;
    }
        
    rc = X509_STORE_CTX_init(cert_ctx, ca_store, cert, NULL);
    if(rc != 1)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("context initialization failed."));
        goto err;
    }
    
    rc = X509_verify_cert(cert_ctx);
    if(rc != 1)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("verification failed."));
        goto err;
    }
    
    X509_STORE_CTX_free(cert_ctx);
    X509_STORE_free(ca_store);
    
    return GLOBUS_SUCCESS;

err:
    if(cert_ctx)
    {
        X509_STORE_CTX_free(cert_ctx);
    }
    if(ca_store)
    {
        X509_STORE_free(ca_store);
    }
        
    return result;
}


static
globus_result_t
ggvm_get_myproxy_userid(
    gss_ctx_id_t                        context,
    char *                              shared_user_cert,
    char *                              subject,
    char **                             userid)
{
    X509 *                              user_cert = NULL;
    X509 *                              myproxy_ca_cert = NULL;
    char *                              myproxy_ca_cert_file = NULL;
    char *                              ptr;
    globus_result_t                     result = GLOBUS_SUCCESS;


    if(!shared_user_cert)
    {
        myproxy_ca_cert_file = getenv("GLOBUS_MYPROXY_CA_CERT");
        if(!myproxy_ca_cert_file)
        {
            GLOBUS_GRIDMAP_CALLOUT_ERROR(
                result,
                GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
                ("GLOBUS_MYPROXY_CA_CERT not set."));
            goto error;
        }
    
        /* extract user cert */
        result = ggvm_extract_cert_from_chain(context, 0, &user_cert);
        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GRIDMAP_CALLOUT_ERROR(
                result,
                GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
                ("Could not extract user credentials."));
            goto error;
        }    
    
        /* load ca cert for verify */   
        result = ggvm_load_cert_from_file(myproxy_ca_cert_file, &myproxy_ca_cert);
        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GRIDMAP_CALLOUT_ERROR(
                result,
                GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
                ("Unable to load myproxy CA cert."));
            goto error;
        }    
    
        /* verify cert */
        result = ggvm_verify_cert(user_cert, myproxy_ca_cert);
        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GRIDMAP_CALLOUT_ERROR(
                result,
                GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
                ("Cert was not issued by correct CA."));
            goto error;
        }    
    }
    
    /* verify succeeded or we are sharing, parse userid from subject */
    ptr = strrchr(subject, '/');
    if(ptr && 
        *ptr == '/' && 
        *(ptr+1) == 'C' && 
        *(ptr+2) == 'N' && 
        *(ptr+3) == '=' &&
        *(ptr+4) != '\0')
    {
        *userid = globus_libc_strdup(ptr+4);
    }
    else
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("Could not parse userid from DN."));
        goto error;
    }
    
error:

    if(myproxy_ca_cert)
    {
        X509_free(myproxy_ca_cert);
    }
    if(user_cert)
    {
        X509_free(user_cert);
    }
    return result;
}


globus_result_t
ggvm_get_subject(
    gss_ctx_id_t                        context,
    char **                             subject)
{
    gss_name_t                          peer;
    gss_buffer_desc                     peer_name_buffer;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    int                                 initiator;
    globus_result_t                     result = GLOBUS_SUCCESS;

    major_status = gss_inquire_context(&minor_status,
                                       context,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       &initiator,
                                       GLOBUS_NULL);

    if(GSS_ERROR(major_status))
    {
        GLOBUS_GRIDMAP_CALLOUT_GSS_ERROR(result, major_status, minor_status);
        goto error;
    }

    major_status = gss_inquire_context(&minor_status,
                                       context,
                                       initiator ? GLOBUS_NULL : &peer,
                                       initiator ? &peer : GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL);

    if(GSS_ERROR(major_status))
    {
        GLOBUS_GRIDMAP_CALLOUT_GSS_ERROR(result, major_status, minor_status);
        goto error;
    }
    
    major_status = gss_display_name(&minor_status,
                                    peer,
                                    &peer_name_buffer,
                                    GLOBUS_NULL);
    
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GRIDMAP_CALLOUT_GSS_ERROR(result, major_status, minor_status);
        gss_release_name(&minor_status, &peer);
        goto error;
    }
    

    *subject = globus_libc_strdup(peer_name_buffer.value);
    gss_release_buffer(&minor_status, &peer_name_buffer);
    gss_release_name(&minor_status, &peer);

    return GLOBUS_SUCCESS;

error:
    return result;
}

globus_result_t
globus_gridmap_verify_myproxy_callout(
    va_list                             ap)
{
    gss_ctx_id_t                        context;
    char *                              service;
    char *                              desired_identity;
    char *                              identity_buffer;
    char *                              found_identity = NULL;
    char *                              subject = NULL;
    unsigned int                        buffer_length;
    globus_result_t                     result = GLOBUS_SUCCESS;
    char *                              shared_user_cert = NULL;
    int                                 rc;

    rc = globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    rc = globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    rc = globus_module_activate(GLOBUS_GRIDMAP_CALLOUT_ERROR_MODULE);
    
    context = va_arg(ap, gss_ctx_id_t);
    service = va_arg(ap, char *);
    desired_identity = va_arg(ap, char *);
    identity_buffer = va_arg(ap, char *);
    buffer_length = va_arg(ap, unsigned int);

    if(strcmp(service, "sharing") == 0)
    {
        shared_user_cert = va_arg(ap, char *);
    
        result = globus_gsi_cred_read_cert_buffer(
            shared_user_cert, NULL, NULL, NULL, &subject);
        if(result != GLOBUS_SUCCESS)
        {
            GLOBUS_GRIDMAP_CALLOUT_ERROR(
                result,
                GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
                ("Could not extract shared user identity."));
            goto error;
        }
    }
    else
    {
        result = ggvm_get_subject(context, &subject);
    }
    
    if(result != GLOBUS_SUCCESS || subject == NULL)
    {
        GLOBUS_GRIDMAP_CALLOUT_ERROR(
            result,
            GLOBUS_GRIDMAP_CALLOUT_GSSAPI_ERROR,
            ("Could not extract user identity."));
        goto error;
    }    

    result = ggvm_get_myproxy_userid(
        context, shared_user_cert, subject, &found_identity);
    if(result == GLOBUS_SUCCESS)
    {
        if(desired_identity && strcmp(found_identity, desired_identity) != 0)
        {
            GLOBUS_GRIDMAP_CALLOUT_ERROR(
                result,
                GLOBUS_GRIDMAP_CALLOUT_LOOKUP_FAILED,
                ("Credentials specify id of %s, can not allow id of %s.\n",
                 found_identity, desired_identity));
            globus_free(found_identity);
            goto error;
        }
    }
    else
    {
        result = GLOBUS_SUCCESS;
        /* proceed with gridmap lookup */
        if(desired_identity == NULL)
        {
            rc = globus_gss_assist_gridmap(subject, &found_identity);
            if(rc != 0)
            {
                GLOBUS_GRIDMAP_CALLOUT_ERROR(
                    result,
                    GLOBUS_GRIDMAP_CALLOUT_LOOKUP_FAILED,
                    ("Could not map %s\n", subject));
                goto error;
            }
        }
        else
        {
            rc = globus_gss_assist_userok(subject, desired_identity);
            if(rc != 0)
            {
                GLOBUS_GRIDMAP_CALLOUT_ERROR(
                    result,
                    GLOBUS_GRIDMAP_CALLOUT_LOOKUP_FAILED,
                    ("Could not map %s to %s\n",
                     subject, desired_identity));
                goto error;
            }
            found_identity = globus_libc_strdup(desired_identity);
        }
    }

    if(found_identity)
    {
        if(strlen(found_identity) + 1 > buffer_length)
        {
            GLOBUS_GRIDMAP_CALLOUT_ERROR(
                result,
                GLOBUS_GRIDMAP_CALLOUT_BUFFER_TOO_SMALL,
                ("Local identity length: %d Buffer length: %d\n",
                 strlen(found_identity), buffer_length));
        }
        else
        {
            strcpy(identity_buffer, found_identity);
        }
        globus_free(found_identity);
    }

    
error:

    if(subject)
    {
        globus_free(subject);
    }
    
    globus_module_deactivate(GLOBUS_GRIDMAP_CALLOUT_ERROR_MODULE);
    globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
    globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    
    return result;
}




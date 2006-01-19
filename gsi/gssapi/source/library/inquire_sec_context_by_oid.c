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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file inquire_sec_context_by_oid.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"
#include <string.h>

/* Only build if we have the extended GSSAPI */
#ifdef _HAVE_GSI_EXTENDED_GSSAPI

static char *rcsid = "$Id$";

extern const gss_OID_desc * const gss_ext_x509_cert_chain_oid;

/**
 * @name Inquire Sec Context by OID
 */
/* @{ */
OM_uint32
GSS_CALLCONV gss_inquire_sec_context_by_oid(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_OID                       desired_object,
    gss_buffer_set_t *                  data_set)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;
    gss_ctx_id_desc *                   context;
    int                                 found_index;
    int                                 chain_index;
    int                                 cert_count;
    X509_EXTENSION *                    extension;
    X509 *                              cert = NULL;
    STACK_OF(X509) *                    cert_chain = NULL;
    ASN1_OBJECT *                       asn1_desired_obj = NULL;
    ASN1_OCTET_STRING *                 asn1_oct_string;
    gss_buffer_desc                     data_set_buffer = GSS_C_EMPTY_BUFFER;
    globus_result_t                     local_result = GLOBUS_SUCCESS;
    unsigned char *                     tmp_ptr;
    static char *                       _function_name_ =
        "gss_inquire_sec_context_by_oid";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    /* parameter checking goes here */

    if(minor_status == NULL)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid minor_status (NULL) passed to function")));
        major_status = GSS_S_FAILURE;
        goto exit;
    }
    
    if(context_handle == GSS_C_NO_CONTEXT)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid context_handle passed to function")));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    *minor_status = (OM_uint32) GLOBUS_SUCCESS;
    context = (gss_ctx_id_desc *) context_handle;

    if(desired_object == GSS_C_NO_OID)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid desired_object passed to function")));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    if(data_set == NULL)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid data_set (NULL) passed to function")));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    *data_set = NULL;

    /* lock the context mutex */
    globus_mutex_lock(&context->mutex);

    local_result = 
        globus_gsi_callback_get_cert_depth(context->callback_data,
                                           &cert_count);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CALLBACK_DATA);
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    if(cert_count == 0)
    {
        goto exit;
    }
    
    major_status = gss_create_empty_buffer_set(&local_minor_status, data_set);

    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_BUFFER);
        goto exit;
    }
    
    local_result = globus_gsi_callback_get_cert_chain(
        context->callback_data,
        &cert_chain);
    if(local_result != GLOBUS_SUCCESS)
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_result,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_CALLBACK_DATA);
        major_status = GSS_S_FAILURE;
        cert_chain = NULL;
        goto exit;
    }

    if(((gss_OID_desc *)desired_object)->length !=
       gss_ext_x509_cert_chain_oid->length ||
       memcmp(((gss_OID_desc *)desired_object)->elements,
              gss_ext_x509_cert_chain_oid->elements,
              gss_ext_x509_cert_chain_oid->length))
    {
        /* figure out what object was asked for */
        
        asn1_desired_obj = ASN1_OBJECT_new();
        if(!asn1_desired_obj)
        {
            GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
                (_GGSL("Couldn't create ASN1 object")));
            major_status = GSS_S_FAILURE;
            goto exit;
        }

        asn1_desired_obj->length = ((gss_OID_desc *)desired_object)->length;
        asn1_desired_obj->data = ((gss_OID_desc *)desired_object)->elements;

        found_index = -1;

        for(chain_index = 0; chain_index < cert_count; chain_index++)
        {
            cert = sk_X509_value(cert_chain, chain_index);

            data_set_buffer.value = NULL;
            data_set_buffer.length = 0;

            found_index = X509_get_ext_by_OBJ(cert, 
                                              asn1_desired_obj, 
                                              found_index);
        
            if(found_index >= 0)
            {
                extension = X509_get_ext(cert, found_index);
                if(!extension)
                {
                    GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                        minor_status,
                        GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
                        (_GGSL("Couldn't get extension at index %d "
                         "from cert in credential."), found_index));
                    major_status = GSS_S_FAILURE;
                    goto exit;
                }

                asn1_oct_string = X509_EXTENSION_get_data(extension);
                if(!asn1_oct_string)
                {
                    GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                        minor_status,
                        GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
                        (_GGSL("Couldn't get cert extension in the form of an "
                         "ASN1 octet string.")));
                    major_status = GSS_S_FAILURE;
                    goto exit;
                }

                asn1_oct_string = ASN1_OCTET_STRING_dup(asn1_oct_string);

                if(!asn1_oct_string)
                {
                    GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                        minor_status,
                        GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
                        (_GGSL("Failed to make copy of extension data")));
                    major_status = GSS_S_FAILURE;
                    goto exit;
                }

                data_set_buffer.value = asn1_oct_string->data;
                data_set_buffer.length = asn1_oct_string->length;

                OPENSSL_free(asn1_oct_string);
            
                major_status = gss_add_buffer_set_member(
                    &local_minor_status,
                    &data_set_buffer,
                    data_set);
                if(GSS_ERROR(major_status))
                {
                    GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                        minor_status, local_minor_status,
                        GLOBUS_GSI_GSSAPI_ERROR_WITH_BUFFER);
                    goto exit;
                }
            }
        } 
    }
    else
    {
        for(chain_index = 0; chain_index < cert_count; chain_index++)
        {
            cert = sk_X509_value(cert_chain, chain_index);

            data_set_buffer.length = i2d_X509(cert, NULL);

            if(data_set_buffer.length < 0)
            {
                GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                    minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
                    (_GGSL("Failed to serialize certificate")));
                major_status = GSS_S_FAILURE;
                goto exit;                
            }
            
            tmp_ptr = realloc(data_set_buffer.value,
                              data_set_buffer.length);

            if(tmp_ptr == NULL)
            {
                GLOBUS_GSI_GSSAPI_MALLOC_ERROR(minor_status);
                major_status = GSS_S_FAILURE;
                goto exit;                
            }

            data_set_buffer.value = tmp_ptr;
            
            if(i2d_X509(cert,&tmp_ptr) < 0)
            {
                free(data_set_buffer.value);
                GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                    minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
                    (_GGSL("Failed to serialize certificate")));
                major_status = GSS_S_FAILURE;
                goto exit;                
            }

            major_status = gss_add_buffer_set_member(
                &local_minor_status,
                &data_set_buffer,
                data_set);
            if(GSS_ERROR(major_status))
            {
                GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                    minor_status, local_minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_WITH_BUFFER);
                goto exit;
            }
        }
        
        if(data_set_buffer.value != NULL)
        {
            free(data_set_buffer.value);
        }
    }
 exit:

    /* unlock the context mutex */
    globus_mutex_unlock(&context->mutex);

    if(cert_chain != NULL)
    {
        sk_X509_pop_free(cert_chain, X509_free);
    }
    
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

#endif /* _HAVE_GSI_EXTENDED_GSSAPI */

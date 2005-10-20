/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file init_delegation.c
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
#include "proxycertinfo.h"

/* Only build if we have the extended GSSAPI */
#ifdef _HAVE_GSI_EXTENDED_GSSAPI

static char *rcsid = "$Id$";

/**
 * @name Init Delegation
 */
/*@{*/
/**
 * Initiate the delegation of a credential.
 *
 * This functions drives the initiating side of the credential
 * delegation process. It is expected to be called in tandem with the
 * gss_accept_delegation function.
 *
 * @param minor_status
 *        The minor status returned by this function. This paramter
 *        will be 0 upon success.
 * @param context_handle
 *        The security context over which the credential is
 *        delegated. 
 * @param cred_handle
 *        The credential to be delegated. May be GSS_C_NO_CREDENTIAL
 *        in which case the credential associated with the security
 *        context is used.
 * @param desired_mech
 *        The desired security mechanism. Currently not used. May be
 *        GSS_C_NO_OID. 
 * @param extension_oids
 *        A set of extension oids corresponding to buffers in the
 *        extension_buffers paramter below. The extensions specified
 *        will be added to the delegated credential. May be
 *        GSS_C_NO_BUFFER_SET. 
 * @param extension_buffers
 *        A set of extension buffers corresponding to oids in the
 *        extension_oids paramter above. May be
 *        GSS_C_NO_BUFFER_SET.
 * @param input_token
 *        The token that was produced by a prior call to
 *        gss_accept_delegation. This parameter will be ignored the
 *        first time this function is called.
 * @param req_flags
 *        Flags that modify the behavior of the function. Currently
 *        only GSS_C_GLOBUS_SSL_COMPATIBLE and
 *        GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG are checked for. The
 *        GSS_C_GLOBUS_SSL_COMPATIBLE  flag results in tokens that
 *        aren't wrapped and GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG
 *        causes the delegated proxy to be limited (requires that no
 *        extensions are specified.
 *        
 * @param time_req
 *        The requested period of validity (seconds) of the delegated
 *        credential. Passing a time_req of 0 cause the delegated credential to
 *        have the same lifetime as the credential that issued it. 
 * @param output_token
 *        A token that should be passed to gss_accept_delegation if the
 *        return value is GSS_S_CONTINUE_NEEDED.
 * @return
 *        GSS_S_COMPLETE upon successful completion
 *        GSS_S_CONTINUE_NEEDED if the function needs to be called
 *                              again.
 *        GSS_S_FAILURE upon failure
 */
OM_uint32
GSS_CALLCONV gss_init_delegation(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_cred_id_t                 cred_handle,
    const gss_OID                       desired_mech,
    const gss_OID_set                   extension_oids,
    const gss_buffer_set_t              extension_buffers,
    const gss_buffer_t                  input_token,
    OM_uint32                           req_flags,
    OM_uint32                           time_req,
    gss_buffer_t                        output_token)
{
    BIO *                               bio = NULL;
    BIO *                               read_bio = NULL;
    BIO *                               write_bio = NULL;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;
    gss_ctx_id_desc *                   context;
    gss_cred_id_desc *                  cred;
    X509 *                              cert = NULL;
    STACK_OF(X509) *                    cert_chain = NULL;
    PROXYCERTINFO *                     pci;
    globus_gsi_cert_utils_cert_type_t   cert_type;
    int                                 index;
    globus_result_t                     local_result = GLOBUS_SUCCESS;
    static char *                       _function_name_ =
        "init_delegation";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    if(minor_status == NULL)
    {
        major_status = GSS_S_FAILURE;
        goto exit;
    }
    
    *minor_status = (OM_uint32) GLOBUS_SUCCESS;

    if(context_handle == GSS_C_NO_CONTEXT)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid context_handle passed to function")));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    context = (gss_ctx_id_desc *) context_handle;

    cred = (gss_cred_id_desc *) cred_handle;

    if (cred_handle == GSS_C_NO_CREDENTIAL)
    {
        cred = (gss_cred_id_desc *) context->cred_handle;
    }

    if(cred == GSS_C_NO_CREDENTIAL)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Couldn't initialize delegation credential handle")));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    if(desired_mech != GSS_C_NO_OID &&
       desired_mech != (gss_OID) gss_mech_globus_gssapi_openssl)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid desired_mech passed to function")));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    if(extension_oids != GSS_C_NO_OID_SET &&
       (extension_buffers == GSS_C_NO_BUFFER_SET ||
        extension_oids->count != extension_buffers->count))
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid extension parameters passed to function")));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    if(output_token == GSS_C_NO_BUFFER)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            (_GGSL("Invalid output_token passed to function")));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    output_token->length = 0;

    if(req_flags & GSS_C_GLOBUS_SSL_COMPATIBLE)
    {
        bio = BIO_new(BIO_s_mem());
        read_bio = bio;
        write_bio = bio;
    }
    else
    {
        bio = context->gss_sslbio;
    }

    /* lock the context mutex */
    globus_mutex_lock(&context->mutex);
    
    /* pass the input to the BIO */
    if(context->delegation_state != GSS_DELEGATION_START)
    {
        /*
         * first time there is no input token, but after that
         * there will always be one
         */
        if(input_token == GSS_C_NO_BUFFER)
        {
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
                (_GGSL("Invalid input_token passed to function: "
                 "delegation is not at initial state")));
            major_status = GSS_S_FAILURE;
            goto mutex_unlock;
        }

        major_status = 
            globus_i_gsi_gss_put_token(&local_minor_status,
                                       context, 
                                       read_bio, 
                                       input_token);

        if (GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL);
            goto mutex_unlock;
        }
    }

    
    /* delegation state machine */
    
    switch (context->delegation_state)
    {

    case GSS_DELEGATION_START:

        /* start delegation by sending a "D" */
        BIO_write(bio, "D", 1); 
        context->delegation_state = GSS_DELEGATION_SIGN_CERT;
        break;

    case GSS_DELEGATION_SIGN_CERT:

        /* get the returned cert from the ssl BIO, make sure it is
         * correct and then sign it and place it in the output_token
         */
        local_result = globus_gsi_proxy_inquire_req(context->proxy_handle,
                                                    bio);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_PROXY);
            major_status = GSS_S_FAILURE;
            goto mutex_unlock;
        }

        local_result = globus_gsi_cred_get_cert_type(
            context->cred_handle->cred_handle,
            &cert_type);

        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            context->delegation_state = GSS_DELEGATION_DONE;
            goto mutex_unlock;
        }

        if(cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_CA)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            context->delegation_state = GSS_DELEGATION_DONE;
            goto mutex_unlock;            
        }
        else if(req_flags & GSS_C_GLOBUS_DELEGATE_LIMITED_PROXY_FLAG)
        {
            if(GLOBUS_GSI_CERT_UTILS_IS_GSI_2_PROXY(cert_type))
            { 
                cert_type = GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_LIMITED_PROXY;
            }
            else if(GLOBUS_GSI_CERT_UTILS_IS_RFC_PROXY(cert_type))
            {
                cert_type = GLOBUS_GSI_CERT_UTILS_TYPE_RFC_LIMITED_PROXY;
            }
            else
            {
                cert_type = GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_LIMITED_PROXY;
            }
        }
        else if(cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_EEC)
        {
            cert_type = GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_IMPERSONATION_PROXY;
        }
        else if(GLOBUS_GSI_CERT_UTILS_IS_GSI_2_PROXY(cert_type))
        {
            cert_type = GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_PROXY;
        }
        else if(GLOBUS_GSI_CERT_UTILS_IS_RFC_PROXY(cert_type))
        {
            cert_type = GLOBUS_GSI_CERT_UTILS_TYPE_RFC_IMPERSONATION_PROXY;
        }
        
        local_result =
            globus_gsi_proxy_handle_set_type(
                context->proxy_handle,
                cert_type);
        
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_PROXY);
            major_status = GSS_S_FAILURE;
            context->delegation_state = GSS_DELEGATION_DONE;
            goto mutex_unlock;            
        }    

        /* set the requested time */

        if(time_req != 0)
        {
            if(time_req%60)
            {
                /* round up */
                time_req += 60;
            }
            
            local_result = globus_gsi_proxy_handle_set_time_valid(
                context->proxy_handle,
                time_req/60);

            if(local_result != GLOBUS_SUCCESS)
            {
                GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                    minor_status, local_result,
                    GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_PROXY);
                major_status = GSS_S_FAILURE;
                context->delegation_state = GSS_DELEGATION_DONE;
                goto mutex_unlock;            
            }
        }
        
        /* clear the proxycertinfo */
        
        local_result =
            globus_gsi_proxy_handle_clear_cert_info(context->proxy_handle);
        
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_PROXY);
            major_status = GSS_S_FAILURE;
            context->delegation_state = GSS_DELEGATION_DONE;
            goto mutex_unlock;            
        }
        
        /* set the proxycertinfo here */
        if(extension_oids != GSS_C_NO_OID_SET)
        {
            if(!GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY(cert_type))
            {
                GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                    minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
                    (_GGSL("A restricted globus proxy may not be created "
                     "from a legacy globus proxy")));
                context->delegation_state = GSS_DELEGATION_DONE;
                major_status = GSS_S_FAILURE;
                goto mutex_unlock;
            }
            
            for(index = 0; index < extension_oids->count; index++)
            {
                if(g_OID_equal((gss_OID) &extension_oids->elements[index],
                               gss_proxycertinfo_extension))
                {
                    local_result =
                        globus_gsi_proxy_handle_set_proxy_cert_info(
                            context->proxy_handle,
                            pci);
                    if(local_result != GLOBUS_SUCCESS)
                    {
                        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                            minor_status, local_result,
                            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_PROXY);
                        major_status = GSS_S_FAILURE;
                        context->delegation_state = GSS_DELEGATION_DONE;
                        goto mutex_unlock;
                    }
                }
            }
        }

        local_result = globus_gsi_proxy_sign_req(
            context->proxy_handle,
            cred->cred_handle,
            bio);
        
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_PROXY);
            major_status = GSS_S_FAILURE;
            context->delegation_state = GSS_DELEGATION_DONE;
            goto mutex_unlock;
        }

        local_result = globus_gsi_cred_get_cert(cred->cred_handle, &cert);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            context->delegation_state = GSS_DELEGATION_DONE;
            goto mutex_unlock;
        }
                
        /* push the cert used to sign the proxy */
        i2d_X509_bio(bio, cert);
        X509_free(cert);
        
        /* push the number of certs in the cert chain */
        local_result = globus_gsi_cred_get_cert_chain(cred->cred_handle,
                                                      &cert_chain);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            major_status = GSS_S_FAILURE;
            context->delegation_state = GSS_DELEGATION_DONE;
            goto mutex_unlock;
        }

        for(index = 0; index < sk_X509_num(cert_chain); index++)
        {
            cert = sk_X509_value(cert_chain, index);
            if(!cert)
            {
                GLOBUS_GSI_GSSAPI_OPENSSL_ERROR_RESULT(
                    minor_status,
                    GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL,
                    (_GGSL("Couldn't get cert from cert chain")));
                major_status = GSS_S_FAILURE;
                context->delegation_state = GSS_DELEGATION_DONE;
                goto mutex_unlock;
            }
            
            i2d_X509_bio(bio, cert);
        }
        sk_X509_pop_free(cert_chain, X509_free);

        /* reset state machine */
        context->delegation_state = GSS_DELEGATION_START; 
        break;

    case GSS_DELEGATION_COMPLETE_CRED:
    case GSS_DELEGATION_DONE:
        break;
    }
    
    major_status = globus_i_gsi_gss_get_token(&local_minor_status,
                                              context, 
                                              write_bio, 
                                              output_token);
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL);
        goto mutex_unlock;
    }

    if (context->delegation_state != GSS_DELEGATION_START)
    {
        major_status |= GSS_S_CONTINUE_NEEDED;
    }

 mutex_unlock:
    globus_mutex_unlock(&context->mutex);

 exit:

    if(req_flags & GSS_C_GLOBUS_SSL_COMPATIBLE)
    {
        BIO_free(bio);
    }
        
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

#endif /* _HAVE_GSI_EXTENDED_GSSAPI */

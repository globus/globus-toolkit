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

static char *rcsid = "$Id$";

/* Only build if we have the extended GSSAPI */
#ifdef _HAVE_GSI_EXTENDED_GSSAPI

#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"

/**
 * Accept a delegated credential.
 *
 * This functions drives the accepting side of the credential
 * delegation process. It is expected to be called in tandem with the
 * gss_init_delegation function.
 *
 * @param minor_status
 *        The minor status returned by this function. This paramter
 *        will be 0 upon success.
 * @param context_handle
 *        The security context over which the credential is
 *        delegated. 
 * @param extension_oids
 *        A set of extension oids corresponding to buffers in the
 *        extension_buffers paramter below. May be
 *        GSS_C_NO_BUFFER_SET. Currently not used.
 * @param extension_buffers
 *        A set of extension buffers corresponding to oids in the
 *        extension_oids paramter above. May be
 *        GSS_C_NO_BUFFER_SET. Currently not used. 
 * @param input_token
 *        The token that was produced by a prior call to
 *        gss_init_delegation. 
 * @param req_flags
 *        Flags that modify the behavior of the function. Currently
 *        only GSS_C_GLOBUS_SSL_COMPATIBLE is checked for. This flag
 *        results in tokens that aren't wrapped.
 * @param time_req
 *        The requested period of validity (seconds) of the delegated
 *        credential. May be NULL.
 * @param time_rec
 *        This parameter will contain the received period of validity
 *        of the delegated credential upon success. May be NULL.
 * @param delegated_cred_handle
 *        This parameter will contain the delegated credential upon
 *        success. 
 * @param mech_type
 *        Returns the security mechanism upon success. Currently not
 *        implemented. May be NULL.
 * @param output_token
 *        A token that should be passed to gss_init_delegation if the
 *        return value is GSS_S_CONTINUE_NEEDED.
 * @return
 *        GSS_S_COMPLETE upon successful completion
 *        GSS_S_CONTINUE_NEEDED if the function needs to be called
 *                              again.
 *        GSS_S_FAILURE upon failure
 */
OM_uint32
GSS_CALLCONV gss_accept_delegation(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_OID_set                   extension_oids,
    const gss_buffer_set_t              extension_buffers,
    const gss_buffer_t                  input_token,
    OM_uint32                           req_flags,
    OM_uint32                           time_req,
    OM_uint32 *                         time_rec,
    gss_cred_id_t *                     delegated_cred_handle,
    gss_OID *                           mech_type, 
    gss_buffer_t                        output_token)
{
    BIO *                               bio = NULL;
    BIO *                               read_bio = NULL;
    BIO *                               write_bio = NULL;
    OM_uint32                           major_status = GSS_S_COMPLETE;
    gss_ctx_id_desc *                   context;
    X509_REQ *                          reqp = NULL;
    X509 *                              dcert = NULL;
    STACK_OF(X509) *                    cert_chain;
    int                                 cert_chain_length = 0;
    int                                 i;
    char                                dbuf[1];

    static char *                       _function_name_ =
        "gss_accept_delegation";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;
    
    /* parameter checking goes here */
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
            ("Invalid context_handle passed to function"));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    context = (gss_ctx_id_desc *) context_handle;

    if(delegated_cred_handle == NULL)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            ("Invalid delegated_cred_handle passed to function"));
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
            ("Invalid extension parameters passed to function"));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    if(output_token == GSS_C_NO_BUFFER)
    {
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            ("Invalid output token passed to function"));
        major_status = GSS_S_FAILURE;
        goto exit;
    }

    output_token->length = 0;

    if(input_token == GSS_C_NO_BUFFER)
    {
        major_status |= GSS_S_CONTINUE_NEEDED;
        goto exit;
    }

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

    major_status = globus_i_gsi_gss_put_token(&local_minor_status,
                                              context, 
                                              read_bio, 
                                              input_token);

    if (GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_TOKEN);
        goto mutex_unlock;
    }

    switch(context->delegation_state)
    {

    case GSS_DELEGATION_START:

        /* generate the proxy */
        BIO_read(bio, dbuf, 1);

        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            2, (globus_i_gsi_gssapi_debug_fstream,
                "delegation flag: %.1s\n", dbuf));

        if (dbuf[0] == 'D')
        {
            if(context->proxy_handle)
            {
                globus_gsi_proxy_handle_destroy(context->proxy_handle);
            }

            local_result = 
                globus_gsi_proxy_handle_init(&context->proxy_handle, NULL);
            if(local_result != GLOBUS_SUCCESS)
            {
                GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                    minor_status, local_result,
                    GLOBUS_GSI_GSSAPI_ERROR_WITH_DELEGATION);
                major_status = GSS_S_FAILURE;
                goto mutex_unlock;
            }

            local_result = 
                globus_gsi_proxy_create_req(context->proxy_handle, bio);
            if(local_result != GLOBUS_SUCCESS)
            {
                GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                    minor_status, local_result,
                    GLOBUS_GSI_GSSAPI_ERROR_WITH_DELEGATION);
                major_status = GSS_S_FAILURE;
                goto mutex_unlock;
            }

            context->delegation_state = GS_DELEGATION_COMPLETE_CRED;
        }
        else
        {
            GLOBUS_GSI_GSSAPI_ERROR_RESULT(
                minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_IN_DELEGATION,
                ("Invalid initial hello message, expecting: 'D', "
                 "received: '%c'", dbuf[0]));
            major_status = GSS_S_FAILURE;
            goto mutex_unlock;
        }
        
        break;

    case GSS_DELEGATION_COMPLETE_CRED:

        /* get the signed cert and the key chain and insert them into
         * the cred structure
         */

        local_result = globus_gsi_proxy_assemble_cred(
            context->proxy_handle,
            delegated_cred,
            bio);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_PROXY_CRED);
            major_status = GSS_S_FAILURE;
            goto mutex_unlock;
        }

        major_status = globus_i_gsi_gss_create_cred(&local_minor_status,
                                                    GSS_C_BOTH,
                                                    delegated_cred_handle,
                                                    delegetad_cred);
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED);
            goto mutex_unlock;
        }

        cert_chain = sk_X509_new_null();

        while(BIO_pending(bio))
        {
            sk_X509_insert(cert_chain,
                           d2i_X509_bio(bio, NULL),
                           cert_chain_length);
            cert_chain_length++;
        }

        local_result = globus_gsi_cred_handle_set_cert_chain(
            delegated_cred_handle->cred_handle,
            cert_chain);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED);
            major_status = GSS_S_FAILURE;
            goto mutex_unlock;
        }

        sk_X509_pop_free(cert_chain, X509_free);

        /* reset state machine */
        context->delegation_state = GSS_DELEGATION_START;

        if (time_rec != NULL)
        {
            local_result = globus_gsi_cred_get_lifetime(
                delegated_cred_handle->cred_handle,
                &time_rec);
            if(local_result != GLOBUS_SUCCESS)
            {
                GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                    minor_status, local_result,
                    GLOBUS_GSI_GSSAPI_ERROR_WITH_CRED);
                major_status = GSS_S_FAILURE;
                goto mutex_unlock;
            }
        }
    }

    /* returns empty token when there is no output */
    
    major_status = globus_i_gsi_gss_get_token(&local_minor_status,
                                              context, 
                                              write_bio, 
                                              output_token);
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_TOKEN);
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

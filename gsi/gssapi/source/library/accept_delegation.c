static char *rcsid = "$Header$";

#include "gssapi_ssleay.h"
#include "gssutils.h"

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
    OM_uint32                           major_status = 0;
    gss_ctx_id_desc *                   context;
    X509_REQ *                          reqp = NULL;
    X509 *                              dcert = NULL;
    STACK_OF(X509) *                    cert_chain;
    int                                 cert_chain_length = 0;
    int                                 i;
    char                                dbuf[1];
    
#ifdef DEBUG
    fprintf(stderr, "accept_delegation:\n") ;
#endif /* DEBUG */
    
    /* parameter checking goes here */

    if(minor_status == NULL)
    {
        GSSerr(GSSERR_F_ACCEPT_DELEGATION, GSSERR_R_BAD_ARGUMENT);
        /*
         * Can't actually set minor_status here, but if we did, it
         * would look like:
         * *minor_status = GSSERR_R_BAD_ARGUMENT;
         */
        major_status = GSS_S_FAILURE;
        goto err;
    }


    if(context_handle == GSS_C_NO_CONTEXT)
    {
        GSSerr(GSSERR_F_ACCEPT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(delegated_cred_handle == NULL)
    {
        GSSerr(GSSERR_F_ACCEPT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(extension_oids != GSS_C_NO_OID_SET &&
       (extension_buffers == GSS_C_NO_BUFFER_SET ||
        extension_oids->count != extension_buffers->count))
    {
        GSSerr(GSSERR_F_ACCEPT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(output_token == GSS_C_NO_BUFFER)
    {
        GSSerr(GSSERR_F_ACCEPT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(input_token == GSS_C_NO_BUFFER)
    {
        major_status |= GSS_S_CONTINUE_NEEDED;
        goto err;
    }

    *minor_status = 0;
    output_token->length = 0;
    context = (gss_ctx_id_desc *) context_handle;

    if(req_flags & GSS_C_GLOBUS_SSL_COMPATIBLE)
    {
        bio = BIO_new(BIO_s_mem());
        read_bio = bio;
        write_bio = bio;
    }
    else
    {
        bio = context->gs_sslbio;
    }
    
    /* lock the context mutex */
    
    globus_mutex_lock(&context->mutex);

    major_status = gs_put_token(context, read_bio, input_token);

    if (major_status != GSS_S_COMPLETE)
    {
        *minor_status = gsi_generate_minor_status();
        goto err_unlock;
    }

    switch(context->delegation_state)
    {

    case GS_DELEGATION_START:

        /* generate the proxy */

        BIO_read(bio,dbuf,1);
#ifdef DEBUG
        fprintf(stderr,"delegation flag:%.1s\n",dbuf);
#endif
        if (dbuf[0] == 'D')
        {
            if(proxy_genreq(
                   context->gs_ssl->session->peer,
                   &reqp,
                   &(context->dpkey),
                   0,
                   NULL,
                   context->cred_handle->pcd))
            {
                /* can we get more error stuff here? */
                major_status = GSS_S_FAILURE;
                goto err_unlock;
            }

            
#ifdef DEBUG
            X509_REQ_print_fp(stderr,reqp);
#endif
            i2d_X509_REQ_bio(bio,reqp);
            X509_REQ_free(reqp);
            context->delegation_state = GS_DELEGATION_COMPLETE_CRED;
        }
        else
        {
            major_status = GSS_S_FAILURE;
            goto err_unlock;
        }
        
        break;
    case GS_DELEGATION_COMPLETE_CRED:

        /* get the signed cert and the key chain and insert them into
         * the cred structure
         */

        dcert = d2i_X509_bio(bio, NULL);

        if(dcert == NULL)
        {
            major_status = GSS_S_FAILURE;
            goto err_unlock;
        }
        
#ifdef DEBUG
        X509_print_fp(stderr,dcert);
#endif

        cert_chain = sk_X509_new_null();

        while(BIO_pending(bio))
        {
            sk_X509_insert(cert_chain,
                           d2i_X509_bio(bio, NULL),
                           cert_chain_length);
            cert_chain_length++;
        }

        major_status = gss_create_and_fill_cred(delegated_cred_handle,
                                                GSS_C_BOTH,
                                                dcert,
                                                context->dpkey,
                                                cert_chain,
                                                NULL);
        sk_X509_pop_free(cert_chain, X509_free);

        context->dpkey = NULL;
        
        /* reset state machine */
        
        context->delegation_state = GS_DELEGATION_START;

        if(major_status != GSS_S_COMPLETE)
        {
            goto err_unlock;
        }



        if (time_rec != NULL)
        {
            time_t                time_after;
            time_t                time_now;
            ASN1_UTCTIME *        asn1_time = NULL;
            
            asn1_time = ASN1_UTCTIME_new();
            X509_gmtime_adj(asn1_time,0);
            time_now = ASN1_UTCTIME_mktime(asn1_time);
            time_after = ASN1_UTCTIME_mktime(
                X509_get_notAfter(dcert));
            *time_rec = (OM_uint32) time_after - time_now;
            ASN1_UTCTIME_free(asn1_time);
        }
    }

    /* returns empty token when there is no output */
    
    gs_get_token(context, write_bio, output_token);

    if (context->delegation_state != GS_DELEGATION_START)
    {
        major_status |= GSS_S_CONTINUE_NEEDED;
    }

    if(req_flags & GSS_C_GLOBUS_SSL_COMPATIBLE)
    {
        BIO_free(bio);
    }
    
    globus_mutex_unlock(&context->mutex);
    
    return major_status;

err_unlock:
    globus_mutex_unlock(&context->mutex);
err:

    if(req_flags & GSS_C_GLOBUS_SSL_COMPATIBLE)
    {
        BIO_free(bio);
    }

    if(minor_status)
    {
        *minor_status = gsi_generate_minor_status();
    }

    return major_status;
}








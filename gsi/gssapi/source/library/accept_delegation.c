/**********************************************************************

accept_delegation.c:

Description:
    GSSAPI routine to accept the delegation of a credential

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$

**********************************************************************/


static char *rcsid = "$Header$";

#include "gssapi_ssleay.h"
#include "gssutils.h"

OM_uint32
GSS_CALLCONV gss_accept_delegation(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    gss_cred_id_t *                     delegated_cred_handle,
    gss_OID *                           mech_type, 
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    const gss_buffer_t                  input_token,
    gss_buffer_t                        output_token)
{
    OM_uint32 		                major_status = 0;
    gss_ctx_id_desc *                   context;
    X509_REQ *                          reqp = NULL;
    X509 *                              dcert = NULL;
    STACK_OF(X509) *                    cert_chain;
    int                                 cert_chain_length;
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
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(delegated_cred_handle == NULL)
    {
        GSSerr(GSSERR_F_ACCEPT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(mech_type == NULL)
    {
        GSSerr(GSSERR_F_ACCEPT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(restriction_oids != GSS_C_NO_OID_SET &&
       (restriction_buffers == GSS_C_NO_BUFFER_SET ||
        restriction_oids->count != restriction_buffers->count))
    {
        GSSerr(GSSERR_F_ACCEPT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(output_token == GSS_C_NO_BUFFER)
    {
        GSSerr(GSSERR_F_ACCEPT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(input_token == GSS_C_NO_BUFFER)
    {
        GSSerr(GSSERR_F_ACCEPT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    *minor_status = 0;
    output_token->length = 0;
    context = (gss_ctx_id_desc *) context_handle;
    
    major_status = gs_put_token(context, input_token);

    if (major_status != GSS_S_COMPLETE)
    {
        *minor_status = gsi_generate_minor_status();
        return major_status;
    }

    switch(context->delegation_state)
    {

    case GS_DELEGATION_START:

        /* generate the proxy */

        BIO_read(context->gs_sslbio,dbuf,1);
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
                *minor_status = gsi_generate_minor_status();
                goto err;
            }

            
#ifdef DEBUG
            X509_REQ_print_fp(stderr,reqp);
#endif
            i2d_X509_REQ_bio(context->gs_sslbio,reqp);
            X509_REQ_free(reqp);
            context->delegation_state = GS_DELEGATION_COMPLETE_CRED;
        }
        else
        {
            major_status = GSS_S_FAILURE;
            *minor_status = gsi_generate_minor_status();
            goto err;
        }
        
        break;
    case GS_DELEGATION_COMPLETE_CRED:

        /* get the signed cert and the key chain and insert them into
         * the cred structure
         */

        dcert = d2i_X509_bio(context->gs_sslbio, NULL);
#ifdef DEBUG
        X509_print_fp(stderr,dcert);
#endif
        d2i_integer_bio(context->gs_sslbio, (long *) &cert_chain_length);

        cert_chain = sk_X509_new_null();

        /* probably messing up the cert chain */
        
        for(i=0;i<cert_chain_length;i++)
        {
            sk_X509_insert(cert_chain,
                           d2i_X509_bio(context->gs_sslbio, NULL),
                           sk_X509_num(cert_chain));
        }

        major_status = gss_create_and_fill_cred(delegated_cred_handle,
                                                GSS_C_BOTH,
                                                dcert,
                                                context->dpkey,
                                                cert_chain,
                                                NULL);
        sk_X509_pop_free(cert_chain, X509_free);

        /* reset state machine */
        
        context->delegation_state = GS_DELEGATION_START;

        if(major_status != GSS_S_COMPLETE)
        {
            X509_free(dcert);
            EVP_PKEY_free(context->dpkey);
            goto err;
        }
    }

    /* returns empty token when there is no output */
    
    gs_get_token(context, output_token);

    if (context->delegation_state != GS_DELEGATION_START)
    {
        major_status |= GSS_S_CONTINUE_NEEDED;
    }

    return major_status;
    
err:
    
    *minor_status = gsi_generate_minor_status();

    return major_status;

}

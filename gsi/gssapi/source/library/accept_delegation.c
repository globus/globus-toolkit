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
    EVP_PKEY *                          dpkey;
    STACK_OF(X509) *                    cert_chain;
    int                                 cert_chain_length;
    int                                 i;
    char                                dbuf[1];
    
#ifdef DEBUG
    fprintf(stderr, "accept_delegation:\n") ;
#endif /* DEBUG */

    *minor_status = 0;
    output_token->length = 0;
    context = (gss_ctx_id_desc *) context_handle;

    major_status = gs_put_token(minor_status,context,input_token);

    if (major_status != GSS_S_COMPLETE)
    {
        return major_status;
    }

    /* need to check for errors and mem leaks */
    
    switch(context->delegation_state)
    {

    case GS_DELEGATION_START:

        /* generate the proxy */
        
        BIO_read(context->gs_sslbio,dbuf,1);
#ifdef DEBUG
        fprintf(stderr,"delegation flag:%.1s\n",&dbuf);
#endif
        if (*dbuf == 'D')
        {
            if(proxy_genreq(
                   context->gs_ssl->session->peer,
                   &reqp,
                   &(context->dpkey),
                   0,
                   NULL,
                   context->cred_handle->pcd))
            {
                major_status = GSS_S_FAILURE;
                break;
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
            break;
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
        d2i_integer_bio(context->gs_sslbio, &cert_chain_length);

        cert_chain = sk_X509_new_null();

        /* probably messing up the cert chain */
        
        for(i=0;i<cert_chain_length;i++)
        {
            sk_X509_insert(cert_chain,
                           d2i_X509_bio(context->gs_sslbio, NULL),
                           sk_X509_num(cert_chain));
        }

        major_status = gss_create_and_fill_cred(minor_status,
                                                delegated_cred_handle,
                                                GSS_C_BOTH,
                                                dcert,
                                                dpkey,
                                                cert_chain,
                                                NULL);
        sk_X509_pop_free(cert_chain, X509_free);
        
        context->delegation_state = GS_DELEGATION_START;
    }

    /* returns empty token when there is no output */
    
    gs_get_token(minor_status,context,output_token);

    if (context->delegation_state != GS_DELEGATION_START)
    {
        major_status |= GSS_S_CONTINUE_NEEDED;
    }

    return major_status;

}




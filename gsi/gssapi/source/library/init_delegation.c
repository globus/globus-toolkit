/**********************************************************************

init_delegation.c:

Description:
    GSSAPI routine to initiate the delegation of a credential

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
GSS_CALLCONV gss_init_delegation(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_cred_id_t                 cred_handle,
    const gss_OID                       desired_mech,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    const gss_buffer_t                  input_token,
    gss_buffer_t                        output_token)
{
    OM_uint32 		                major_status = 0;
    OM_uint32                           time_req; /* probably a
                                                     parameter */
    gss_ctx_id_desc *                   context;
    gss_cred_id_desc *                  cred;
    X509_REQ *                          reqp = NULL;
    X509 *                              ncert = NULL;
    X509 *                              cert = NULL;
    X509_EXTENSION *                    ex = NULL;
    STACK_OF(X509_EXTENSION) *          extensions = NULL;
    int                                 i;
    
#ifdef DEBUG
    fprintf(stderr, "init_delegation:\n") ;
#endif /* DEBUG */

    *minor_status = 0;
    output_token->length = 0;
    time_req = GSS_C_INDEFINITE;
    context = (gss_ctx_id_desc *) context_handle;
    cred = (gss_cred_id_desc *) cred_handle;

    /* input parameter checking needs to go here */

    /* pass the input to the read BIO in the context */
    
    if(input_token != GSS_C_NO_BUFFER)
    {
        /*
         * first time there is no input token, but after that
         * there will always be one
         */

    	major_status = gs_put_token(minor_status,context,input_token);

    	if (major_status != GSS_S_COMPLETE)
        {
            return major_status;
    	}
    }
    
    /* delegation state machine */
    
    switch (context->delegation_state)
    {
    case GS_DELEGATION_START:
        /* start delegation by sending a "D" */
        BIO_write(context->gs_sslbio,"D",1); 
        context->delegation_state=GS_DELEGATION_SIGN_CERT;
        break;
    case GS_DELEGATION_SIGN_CERT:
        /* get the returned cert from the ssl BIO, make sure it is
         * correct and then sign it and place it in the output_token
         */

        reqp = d2i_X509_REQ_bio(context->gs_sslbio,NULL);

        if (reqp == NULL)
        {
            GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_PROXY_NOT_RECEIVED);
            major_status=GSS_S_FAILURE;
            return major_status;
        }
        
#ifdef DEBUG
        X509_REQ_print_fp(stderr,reqp);
#endif

        if ((extensions = sk_X509_EXTENSION_new_null()) == NULL)
        {
            GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_ADD_EXT);
            major_status = GSS_S_FAILURE;
            return major_status;
        }

        /* TODO add the restrictions here */
/*
        if ()
        {
            if ((ex = proxy_extension_restriction_create()) 
                == NULL)
            {
                GSSerr(GSSERR_F_INIT_SEC,GSSERR_R_ADD_EXT);
                major_status = GSS_S_FAILURE;
                return major_status;
            }
            
            
            if (!sk_X509_EXTENSION_push(extensions, ex))
            {
                GSSerr(GSSERR_F_INIT_SEC,GSSERR_R_ADD_EXT);
                major_status = GSS_S_FAILURE;
                return major_status;
            }
        }
*/        
        proxy_sign_ext(0,
                       cred->pcd->ucert,
                       cred->pcd->upkey,
                       EVP_md5(),
                       reqp,
                       &ncert,
                       time_req,
                       0, /* don't want limited proxy */
                       0,
                       "proxy",
                       extensions);
		
        if (extensions)
        {
            sk_X509_EXTENSION_pop_free(extensions, 
                                       X509_EXTENSION_free);
        }
#ifdef DEBUG
        X509_print_fp(stderr,ncert);
#endif

        /* push the proxy cert */
        
        i2d_X509_bio(context->gs_sslbio,ncert);

        /* push the number of certs in the cert chain */
        
        i2d_integer_bio(context->gs_sslbio,
                        sk_X509_num(cred->pcd->cert_chain) + 1);
        for(i=sk_X509_num(cred->pcd->cert_chain)-1;i>=0;i--)
        {
            cert = sk_X509_value(cred->pcd->cert_chain,i);
            
            /*
             * add additional certs, but not our cert, or the 
             * proxy cert, or any self signed certs or write all
             * certs? 
             */

#ifdef DEBUG
            {
                char * s;
                s = X509_NAME_oneline(X509_get_subject_name(cert),
                                      NULL,
                                      0);
                fprintf(stderr,"  cert:%s\n",s);
                free(s);
            }
#endif
            i2d_X509_bio(context->gs_sslbio,cert);
        }

        /* push the cert used to sign the proxy */
        
        i2d_X509_bio(context->gs_sslbio,cred->pcd->ucert);
        
        context->gs_state = GS_DELEGATION_START; /* reset state
                                                    machine */
        X509_free(ncert);
        ncert = NULL;
        break;
    }
    
    gs_get_token(minor_status,context,output_token);

    if (context->delegation_state != GS_DELEGATION_START)
    {
        major_status |=GSS_S_CONTINUE_NEEDED;
    }

    return major_status;
}



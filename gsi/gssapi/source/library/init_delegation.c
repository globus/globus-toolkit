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
#include <string.h>

static X509_EXTENSION *
proxy_extension_create(
    const gss_OID                       extension_oid,
    const gss_buffer_t                  extension_data);

OM_uint32
GSS_CALLCONV gss_init_delegation(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    const gss_cred_id_t                 cred_handle,
    const gss_OID                       desired_mech,
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    OM_uint32                           time_req,
    const gss_buffer_t                  input_token,
    gss_buffer_t                        output_token)
{
    OM_uint32 		                major_status = GSS_S_COMPLETE;
    gss_ctx_id_desc *                   context;
    gss_cred_id_desc *                  cred;
    X509_REQ *                          reqp = NULL;
    X509 *                              ncert = NULL;
    X509 *                              cert = NULL;
    X509_EXTENSION *                    ex = NULL;
    STACK_OF(X509_EXTENSION) *          extensions = NULL;
    int                                 i;
    int                                 cert_chain_length = 0;
    
#ifdef DEBUG
    fprintf(stderr, "init_delegation:\n") ;
#endif /* DEBUG */

    *minor_status = 0;
    output_token->length = 0;
    context = (gss_ctx_id_desc *) context_handle;

    cred = (gss_cred_id_desc *) cred_handle; 
        
    /* parameter checking goes here */

    /* take the cred from the context if no cred is given us
     * explicitly
     */
    
    if (cred_handle == GSS_C_NO_CREDENTIAL)
    {
	cred = (gss_cred_id_desc *) context->cred_handle;
    }
    
    if(minor_status == NULL)
    {
        GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_IMPEXP_BAD_PARMS);
        *minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
        major_status = GSS_S_FAILURE;
        goto err;
    }
    
    if(context_handle == GSS_C_NO_CONTEXT)
    {
        GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_IMPEXP_BAD_PARMS);
        *minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(cred_handle == GSS_C_NO_CREDENTIAL)
    {
        GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_IMPEXP_BAD_PARMS);
        *minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(desired_mech != GSS_C_NO_OID &&
       desired_mech != (gss_OID) gss_mech_globus_gssapi_ssleay)
    {
        GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_IMPEXP_BAD_PARMS);
        *minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(restriction_oids != GSS_C_NO_OID_SET &&
       (restriction_buffers == GSS_C_NO_BUFFER_SET ||
        restriction_oids->count != restriction_buffers->count))
    {
        GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_IMPEXP_BAD_PARMS);
        *minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(output_token == GSS_C_NO_BUFFER)
    {
        GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_IMPEXP_BAD_PARMS);
        *minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
        major_status = GSS_S_FAILURE;
        goto err;
    }
    
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
    else if(context->delegation_state != GS_DELEGATION_START)
    {
        GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_IMPEXP_BAD_PARMS);
        *minor_status = GSSERR_R_IMPEXP_BAD_PARMS;
        major_status = GSS_S_FAILURE;
        goto err;
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
            goto err;
        }

        /* add the restrictions here */

        if(restriction_oids != GSS_C_NO_OID_SET)
        {
            for(i = 0;i < restriction_oids->count;i++)
            {
                if ((ex = proxy_extension_create(
                         (gss_OID) &restriction_oids->elements[i],
                         (gss_buffer_t) &restriction_buffers->elements[i]))
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
                    goto err;
                }
            }
        }

        if(proxy_sign(cred->pcd->ucert,
                      cred->pcd->upkey,
                      reqp,
                      &ncert,
                      time_req,
                      extensions,
                      0))
        {
            /* should probably return a error related to not being
               able to sign the cert */
            GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_ADD_EXT);
            major_status = GSS_S_FAILURE;
            goto err;
        }
		
#ifdef DEBUG
        X509_print_fp(stderr,ncert);
#endif

        /* push the proxy cert */
        
        i2d_X509_bio(context->gs_sslbio,ncert);

        /* push the number of certs in the cert chain */

        if(cred->pcd->cert_chain != NULL)
        {
            cert_chain_length = sk_X509_num(cred->pcd->cert_chain);
        }
        
        /* Add one for the issuer's certificate */
        
        i2d_integer_bio(context->gs_sslbio, cert_chain_length + 1);

        for(i=cert_chain_length-1;i>=0;i--)
        {
            cert = sk_X509_value(cred->pcd->cert_chain,i);
            
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
        /* reset state machine */
        context->delegation_state = GS_DELEGATION_START; 
        X509_free(ncert);
        ncert = NULL;
        break;
    }
    
    gs_get_token(minor_status,context,output_token);

    if (context->delegation_state != GS_DELEGATION_START)
    {
        major_status |=GSS_S_CONTINUE_NEEDED;
    }

err:

    if (extensions)
    {
        sk_X509_EXTENSION_pop_free(extensions, 
                                   X509_EXTENSION_free);
    }
    
    return major_status;
}


/**********************************************************************
Function: proxy_extension_create()

Description:
            create a X509_EXTENSION based on an OID and a buffer
        
Parameters:
                A buffer and length. The date is added as
                ANS1_OCTET_STRING to an extension with the 
                class_add  OID.

Returns:

**********************************************************************/

static X509_EXTENSION *
proxy_extension_create(
    const gss_OID                       extension_oid,
    const gss_buffer_t                  extension_data)

{
    X509_EXTENSION *                    ex = NULL;
    ASN1_OBJECT *                       asn1_obj = NULL;
    ASN1_OCTET_STRING *                 asn1_oct_string = NULL;
    int                                 crit = 0;

    if(g_OID_equal(extension_oid, gss_restrictions_extension))
    {
        asn1_obj = OBJ_txt2obj("RESTRICTEDRIGHTS",0);   
    }
    else
    {
        return ex;
    }
    
    if(!(asn1_oct_string = ASN1_OCTET_STRING_new()))
    {
        /* set some sort of error */
        goto err;
    }

    asn1_oct_string->data = extension_data->value;
    asn1_oct_string->length = extension_data->length;

    if (!(ex = X509_EXTENSION_create_by_OBJ(NULL, asn1_obj, 
                                            crit, asn1_oct_string)))
    {
        /* set some sort of error */
        goto err;
    }
    asn1_oct_string = NULL;

    X509_EXTENSION_set_critical(ex,1);
    
    return ex;

err:
    if (asn1_oct_string)
    {
        ASN1_OCTET_STRING_free(asn1_oct_string);
    }
    
    if (asn1_obj)
    {
        ASN1_OBJECT_free(asn1_obj);
    }
    
    return NULL;
}

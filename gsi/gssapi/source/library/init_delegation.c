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
 *        credential. May be NULL.
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
    gss_ctx_id_desc *                   context;
    gss_cred_id_desc *                  cred;
    X509_REQ *                          reqp = NULL;
    X509 *                              ncert = NULL;
    X509 *                              cert = NULL;
    X509_EXTENSION *                    ex = NULL;
    STACK_OF(X509_EXTENSION) *          extensions = NULL;
    globus_proxy_type_t                 proxy_type = GLOBUS_FULL_PROXY;
    int                                 i;
    int                                 cert_chain_length = 0;
    int                                 found_group_extension = 0;
    
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
        GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        /* *minor_status = gsi_generate_minor_status(); */
        major_status = GSS_S_FAILURE;
        goto err;
    }
    
    if(context_handle == GSS_C_NO_CONTEXT)
    {
        GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(cred == GSS_C_NO_CREDENTIAL)
    {
        GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(desired_mech != GSS_C_NO_OID &&
       desired_mech != (gss_OID) gss_mech_globus_gssapi_ssleay)
    {
        GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(extension_oids != GSS_C_NO_OID_SET &&
       (extension_buffers == GSS_C_NO_BUFFER_SET ||
        extension_oids->count != extension_buffers->count))
    {
        GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(output_token == GSS_C_NO_BUFFER)
    {
        GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    if(req_flags & GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG)
    {
        if(extension_oids != GSS_C_NO_OID_SET ||
           proxy_check_proxy_name(cred->pcd->ucert)
           == GLOBUS_RESTRICTED_PROXY)
        {
            GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
            *minor_status = gsi_generate_minor_status();
            major_status = GSS_S_FAILURE;
            goto err;
        }
        else
        {
            proxy_type = GLOBUS_LIMITED_PROXY;        
        }
    }
    
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
    
    /* pass the input to the BIO */
    
    if(context->delegation_state != GS_DELEGATION_START)
    {
        /*
         * first time there is no input token, but after that
         * there will always be one
         */

        if(input_token == GSS_C_NO_BUFFER)
        {
            GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_BAD_ARGUMENT);
            *minor_status = gsi_generate_minor_status();
            major_status = GSS_S_FAILURE;
            goto err_unlock;
        }

        major_status = gs_put_token(context, read_bio, input_token);

        if (major_status != GSS_S_COMPLETE)
        {
            *minor_status = gsi_generate_minor_status();
            goto err_unlock;
        }
    }

    
    /* delegation state machine */
    
    switch (context->delegation_state)
    {
    case GS_DELEGATION_START:
        /* start delegation by sending a "D" */
        BIO_write(bio,"D",1); 
        context->delegation_state=GS_DELEGATION_SIGN_CERT;
        break;
    case GS_DELEGATION_SIGN_CERT:
        /* get the returned cert from the ssl BIO, make sure it is
         * correct and then sign it and place it in the output_token
         */

        reqp = d2i_X509_REQ_bio(bio,NULL);

        if (reqp == NULL)
        {
            GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_PROXY_NOT_RECEIVED);
            major_status=GSS_S_FAILURE;
            goto err_unlock;
        }
        
#ifdef DEBUG
        X509_REQ_print_fp(stderr,reqp);
#endif

        if ((extensions = sk_X509_EXTENSION_new_null()) == NULL)
        {
            GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_ADD_EXT);
            major_status = GSS_S_FAILURE;
            goto err_unlock;
        }

        /* add the extensions here */

        if(extension_oids != GSS_C_NO_OID_SET)
        {
            for(i = 0;i < extension_oids->count;i++)
            {
                if(g_OID_equal((gss_OID) &extension_oids->elements[i],
                               gss_trusted_group) ||
                   g_OID_equal((gss_OID) &extension_oids->elements[i],
                               gss_untrusted_group))
                {
                    if(found_group_extension)
                    {
                        /* only one group extension allowed */
                        GSSerr(GSSERR_F_INIT_SEC,GSSERR_R_ADD_EXT);
                        major_status = GSS_S_FAILURE;
                        *minor_status = gsi_generate_minor_status();
                        goto err_unlock;
                    }
                    else
                    {
                        found_group_extension = 1;
                    }
                }
                   
                if ((ex = proxy_extension_create(
                         (gss_OID) &extension_oids->elements[i],
                         (gss_buffer_t) &extension_buffers->elements[i]))
                    == NULL)
                {
                    GSSerr(GSSERR_F_INIT_SEC,GSSERR_R_ADD_EXT);
                    major_status = GSS_S_FAILURE;
                    *minor_status = gsi_generate_minor_status();
                    goto err_unlock;
                }
            
                
                if (!sk_X509_EXTENSION_push(extensions, ex))
                {
                    GSSerr(GSSERR_F_INIT_SEC,GSSERR_R_ADD_EXT);
                    major_status = GSS_S_FAILURE;
                    *minor_status = gsi_generate_minor_status();
                    goto err_unlock;
                }
            }
        }

        /* For now make any delegated cert with extensions into a
         * restricted proxy. This may need to be changed later on.
         */ 
        
        if(sk_num(extensions) ||
           proxy_check_proxy_name(cred->pcd->ucert)
           == GLOBUS_RESTRICTED_PROXY)
        {
            proxy_type = GLOBUS_RESTRICTED_PROXY;
        }

        if(proxy_sign(cred->pcd->ucert,
                      cred->pcd->upkey,
                      reqp,
                      &ncert,
                      time_req,
                      extensions,
                      proxy_type))
        {
            /* should probably return a error related to not being
               able to sign the cert */
            GSSerr(GSSERR_F_INIT_DELEGATION,GSSERR_R_ADD_EXT);
            *minor_status = gsi_generate_minor_status();
            major_status = GSS_S_FAILURE;
            goto err_unlock;
        }
        
#ifdef DEBUG
        X509_print_fp(stderr,ncert);
#endif

        /* push the proxy cert */
        
        i2d_X509_bio(bio,ncert);

        /* push the number of certs in the cert chain */

        if(cred->pcd->cert_chain != NULL)
        {
            cert_chain_length = sk_X509_num(cred->pcd->cert_chain);
        }
        
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
            i2d_X509_bio(bio,cert);
        }

        /* push the cert used to sign the proxy */
        
        i2d_X509_bio(bio,cred->pcd->ucert);

        /* reset state machine */
        context->delegation_state = GS_DELEGATION_START; 
        X509_free(ncert);
        ncert = NULL;
        break;
    }
    
    gs_get_token(context, write_bio, output_token);

    if (context->delegation_state != GS_DELEGATION_START)
    {
        major_status |=GSS_S_CONTINUE_NEEDED;
    }

err_unlock:
    globus_mutex_unlock(&context->mutex);
err:

    if(req_flags & GSS_C_GLOBUS_SSL_COMPATIBLE)
    {
        BIO_free(bio);
    }
        
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
    int                                 crit = 1;

    if(g_OID_equal(extension_oid, gss_restrictions_extension))
    {
        asn1_obj = OBJ_txt2obj("RESTRICTEDRIGHTS",0);   
    }
    else if(g_OID_equal(extension_oid, gss_trusted_group))
    {
        asn1_obj = OBJ_txt2obj("TRUSTEDGROUP",0);   
    }
    else if(g_OID_equal(extension_oid, gss_untrusted_group))
    {
        asn1_obj = OBJ_txt2obj("UNTRUSTEDGROUP",0);   
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

/**********************************************************************

accept_sec_context.c:

Description:
        GSSAPI routine to accept the security context
        See: <draft-ietf-cat-gssv2-cbind-04.txt>

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$

**********************************************************************/

static char *rcsid = "$Header$";

/**********************************************************************
                             Include header files
**********************************************************************/

#include "gssapi_ssleay.h"
#include "gssutils.h"
#include <string.h>

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/

/**********************************************************************
Function:   gss_accept_sec_context()   

Description:
    Calls the gs_handshake routin to use SSL to process and make 
    gssapi tokens. 

Parameters:
        
Returns:
**********************************************************************/


OM_uint32
GSS_CALLCONV gss_accept_sec_context(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t *                      context_handle_P,
    const gss_cred_id_t                 acceptor_cred_handle,
    const gss_buffer_t                  input_token,
    const gss_channel_bindings_t        input_chan_bindings,
    gss_name_t *                        src_name_P,
    gss_OID *                           mech_type,
    gss_buffer_t                        output_token,
    OM_uint32 *                         ret_flags,
    OM_uint32 *                         time_rec,
    gss_cred_id_t *                     delegated_cred_handle_P) 
{
    gss_ctx_id_desc *                   context = NULL;
    OM_uint32                           major_status = 0;
    OM_uint32                           nreq_flags = 0;
    X509_REQ *                          reqp;
    int                                 rc;
    char                                dbuf[1];
    X509 *                              current_cert = NULL;
    time_t                              goodtill = 0;
    int                                 cert_count = 0;
    
#ifdef DEBUG
    fprintf(stderr,"accept_sec_context:\n");
#endif /* DEBUG */

    *minor_status = 0;
    output_token->length = 0;

    context = *context_handle_P;

    /* module activation if not already done by calling
     * globus_module_activate
     */
    
    globus_thread_once(
        &once_control,
        (void (*)(void))globus_i_gsi_gssapi_module.activation_func);
    
    if (context == (gss_ctx_id_t) GSS_C_NO_CONTEXT ||
        !(context->ctx_flags & GSS_I_CTX_INITIALIZED))
    {
#if defined(DEBUG) || defined(DEBUGX)
        fprintf(stderr, 
                "\n**********\naccept_sec_context: uid=%d pid=%d\n**********\n",
                getuid(), getpid()) ;
#endif /* DEBUG */

        /* accept does not have req_flags, so we will use ret_flags */
        if (ret_flags)
        {
            nreq_flags = *ret_flags;
        }

#ifdef DEBUG
        if (getenv("DEE_DEBUG_ENC_A"))
        {
            nreq_flags |= GSS_C_CONF_FLAG;
            fprintf(stderr,"DEE_FORCING GSS_C_CONF_FLAG\n");
        }
#endif

        major_status = gss_create_and_fill_context(&context,
                                                   acceptor_cred_handle,
                                                   GSS_C_ACCEPT,
                                                   nreq_flags);
        if (GSS_ERROR(major_status))
        {
            *minor_status = gsi_generate_minor_status();
            return major_status;                        
        }

        *context_handle_P = context;

        if (mech_type != NULL)
        {
            *mech_type = (gss_OID) gss_mech_globus_gssapi_ssleay;
        }

        if (ret_flags != NULL)
        {
            /* accept does not have req_flags, we need one */
            *ret_flags = 0 ;
        }

        if (time_rec != NULL)
        {
            *time_rec = GSS_C_INDEFINITE ;
        }

        if (delegated_cred_handle_P != NULL)
        {
            *delegated_cred_handle_P = GSS_C_NO_CREDENTIAL ;
        }
    } /* end of first time */

    /*
     * put token data onto the SSL bio so it can be read
     */

    major_status = gs_put_token(context, NULL, input_token);
    if (major_status != GSS_S_COMPLETE)
    {
        *minor_status = gsi_generate_minor_status();
        return major_status;
    }

    switch (context->gs_state)
    {
    case(GS_CON_ST_HANDSHAKE):
            
        major_status = gs_handshake(context);
            
        if (major_status == GSS_S_CONTINUE_NEEDED)
        {
            break;
        }   
            
        /* if failed, may have SSL alert message too */
            
        if (major_status != GSS_S_COMPLETE)
        {
            context->gs_state = GS_CON_ST_DONE;
            break; 
        }
                        
        major_status = gs_retrieve_peer(context,
                                        GSS_C_ACCEPT);
        if (major_status != GSS_S_COMPLETE)
        {
            context->gs_state = GS_CON_ST_DONE;
            break;
        }

        if(g_OID_equal(context->source_name->name_oid,
                       GSS_C_NT_ANONYMOUS))
        {
            context->ret_flags |= GSS_C_ANON_FLAG;
        }

        if (src_name_P != NULL)
        {
            major_status = gss_copy_name_to_name(
                (gss_name_desc **)src_name_P, 
                context->source_name);
        }
                        
        if (context->pvd.limited_proxy)
        {
            context->ret_flags |= GSS_C_GLOBUS_LIMITED_PROXY_FLAG;
            /*
             * Are we willing to accept authentication 
             * from a limited proxy? 
             * Globus gatekeepers will say no
             */

            if (context->req_flags & 
                GSS_C_GLOBUS_LIMITED_PROXY_FLAG)
            {
                GSSerr(GSSERR_F_ACCEPT_SEC,GSSERR_R_PROXY_VIOLATION);
                context->gs_state = GS_CON_ST_DONE;
                major_status = GSS_S_DEFECTIVE_CREDENTIAL;
                break;
            }
                                
        }

        context->ret_flags |= GSS_C_MUTUAL_FLAG;
        context->ret_flags |= GSS_C_PROT_READY_FLAG;
        context->ret_flags |= GSS_C_INTEG_FLAG  
            | GSS_C_TRANS_FLAG
            | GSS_C_REPLAY_FLAG
            | GSS_C_SEQUENCE_FLAG;

        /* 
         * IF we are talking to a real SSL client,
         * we dont want to do delegation, so we are done
         */

        if (context->req_flags & GSS_C_GLOBUS_SSL_COMPATIBLE)
        {
            context->gs_state = GS_CON_ST_DONE;
            break;
        }
        
        /* 
         * To keep the gss exchange going, if we received
         * the last token but dont have a token to send
         * we need to send a null So peek at what we might send
         */

        if (BIO_pending(context->gs_wbio) == 0)
        {
            BIO_write(context->gs_sslbio,"\0",1);
        }
        context->gs_state = GS_CON_ST_FLAGS;
        break;

    case(GS_CON_ST_FLAGS):
        BIO_read(context->gs_sslbio,dbuf,1);
#ifdef DEBUG
        fprintf(stderr,"delegation flag:%.1s\n",dbuf);
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
                context->gs_state = GS_CON_ST_DONE;
                major_status = GSS_S_FAILURE;
                break;
            }
#ifdef DEBUG
            X509_REQ_print_fp(stderr,reqp);
#endif
            i2d_X509_REQ_bio(context->gs_sslbio,reqp);
            X509_REQ_free(reqp);
            context->gs_state = GS_CON_ST_CERT;
        }
        else
        {
            context->gs_state = GS_CON_ST_DONE;
        }
        break;
    case(GS_CON_ST_REQ): ;
    case(GS_CON_ST_CERT):
        context->dcert = d2i_X509_bio(context->gs_sslbio, NULL);
#ifdef DEBUG
        X509_print_fp(stderr,context->dcert);
#endif

        /* DEE? until the gss_export_cred is written,
         * If the user did not ask for the delegated cred handle
         * we will write out the delegated proxy here
         * on the server, the s3_srvr.c does not save the 
         * peer cert chain. So our proxy_verify_callback 
         * will. If this is fixed, then 
         * we could use SSL_get_peer_cert_chain(context->gs_ssl) 
         * Also need to set the ret_flag for 
         * GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG
         * The delegated cert, key and chain will be transfered 
         * to the delegated cred. 
         */

        if (context->pvd.cert_chain == NULL)
        {
            context->pvd.cert_chain = sk_X509_new_null();
        }

        if (delegated_cred_handle_P != NULL)
        {
            major_status = gss_create_and_fill_cred(delegated_cred_handle_P,
                                                    GSS_C_BOTH,
                                                    context->dcert,
                                                    context->dpkey,
                                                    context->pvd.cert_chain, NULL);
            context->dcert = NULL;
            context->dpkey = NULL;
        }
        else
        {
            rc = proxy_marshal_tmp(context->dcert,
                                   context->dpkey,
                                   NULL,
                                   context->pvd.cert_chain,
                                   NULL);
            if (rc)
            {
                major_status |= GSS_S_FAILURE;
            }
        }

        if (!GSS_ERROR(major_status))
        {
            context->ret_flags |= GSS_C_DELEG_FLAG;
        }
                        
        context->gs_state = GS_CON_ST_DONE;

    case(GS_CON_ST_DONE): ;

    } /* end of switch for gs_con_st */

    /*
     * Couple of notes about this gs_get_token() call:
     *
     * First don't mess with minor_status here as it may contain real info.
     *
     * Second, we want to go ahead and get an ouput token even if we previously
     * encountered an error since the output token may contain information
     * about the error (i.e. an SSL alert message) we want to send to the other
     * side.
     */
    gs_get_token(context, NULL, output_token);

    if (context->gs_state != GS_CON_ST_DONE)
    {
        major_status |= GSS_S_CONTINUE_NEEDED;
    }
    else if(major_status == GSS_S_COMPLETE)
    {
        current_cert = context->cred_handle->pcd->ucert;

        if(context->cred_handle->pcd->cert_chain)
        {
            cert_count = sk_X509_num(context->cred_handle->pcd->cert_chain);
        }
        
        while(current_cert)
        {
            goodtill = ASN1_UTCTIME_mktime(
                X509_get_notAfter(current_cert));

            if (context->goodtill == 0 || goodtill < context->goodtill)
            {
                context->goodtill = goodtill;
            }
            
            if(context->cred_handle->pcd->cert_chain && cert_count)
            {
                cert_count--;
                current_cert = sk_X509_value(
                    context->cred_handle->pcd->cert_chain,
                    cert_count);
            }
            else
            {
                current_cert = NULL;
            }
        }

        if(context->goodtill > context->pvxd.goodtill)
        {
            context->goodtill = context->pvxd.goodtill;
        }
    }


    if (ret_flags != NULL)
    {
        *ret_flags = context->ret_flags;
    }

    if (GSS_ERROR(major_status))
    {
        *minor_status = gsi_generate_minor_status();
    }
        
#if defined(DEBUG) || defined(DEBUGX)
    fprintf(stderr,
            "accept_sec_context:major_status:%08x:gs_state:%d:ret_flags=%08x\n",
            major_status,context->gs_state,context->ret_flags);
    if (GSS_ERROR(major_status))
    {
        ERR_print_errors_fp(stderr);
    }
#endif
    return major_status;
}










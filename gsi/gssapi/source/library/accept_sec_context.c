
static char * rcsid = "$Id$";

#include "gssapi_ssleay.h"
#include "gssutils.h"
#include <string.h>

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
    OM_uint32                           local_minor_status = 0;
    OM_uint32                           nreq_flags = 0;
    int                                 rc;
    char                                dbuf[1];
    X509 *                              current_cert = NULL;
    time_t                              goodtill = 0;
    int                                 cert_count = 0;
    
    static char *                       _function_name_ =
        "gss_accept_sec_context";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = 0;
    output_token->length = 0;

    context = *context_handle_P;

    if(delegated_cred_handle_P == NULL && 
       !((*ret_flags) & GSS_C_GLOBUS_SSL_COMPATIBLE))
    {
#error return error here
    } 

    /* module activation if not already done by calling
     * globus_module_activate
     */
    
    globus_thread_once(
        &once_control,
        (void (*)(void))globus_i_gsi_gssapi_module.activation_func);
    
    if (context == (gss_ctx_id_t) GSS_C_NO_CONTEXT ||
        !(context->ctx_flags & GSS_I_CTX_INITIALIZED))
    {
        /* accept does not have req_flags, so we will use ret_flags */
        if (ret_flags)
        {
            nreq_flags = *ret_flags;
        }

        major_status = globus_i_gsi_gss_create_and_fill_context(
            & local_minor_status,
            & context,
            acceptor_cred_handle,
            GSS_C_ACCEPT,
            nreq_flags);

        if (GSS_ERROR(major_status))
        {
#error add error here
            return major_status;                        
        }

        *context_handle_P = context;

        if (mech_type != NULL)
        {
            *mech_type = (gss_OID) gss_mech_globus_gssapi_openssl;
        }

        if (ret_flags != NULL)
        {
            /* accept does not have req_flags, we need one */
            *ret_flags = 0 ;
        }

        if (time_rec != NULL)
        {
            *time_rec = GSS_C_INDEFINITE;
        }

        if (delegated_cred_handle_P != NULL)
        {
            *delegated_cred_handle_P = GSS_C_NO_CREDENTIAL;
        }
    } /* end of first time */

    /*
     * put token data onto the SSL bio so it can be read
     */

    major_status = globus_i_gsi_gss_put_token(& local_minor_status,
                                              context, NULL, input_token);
    if (major_status != GSS_S_COMPLETE)
    {
#error need error here
        return major_status;
    }

    switch (context->gss_state)
    {
        case(GSS_CON_ST_HANDSHAKE):
            
            major_status = globus_i_gsi_gss_handshake(& local_minor_status, 
                                                      context);
            
            if (major_status == GSS_S_CONTINUE_NEEDED)
            {
                break;
            }   
            
            /* if failed, may have SSL alert message too */
            
            if (major_status != GSS_S_COMPLETE)
            {
#error add minor status for error
                context->gss_state = GSS_CON_ST_DONE;
                break; 
            }
                        
            major_status = globus_i_gsi_gss_retrieve_peer(& local_minor_status,
                                                          context,
                                                          GSS_C_ACCEPT);
            if (major_status != GSS_S_COMPLETE)
            {
#error add minor status
                context->gss_state = GSS_CON_ST_DONE;
                break;
            }

            if(g_OID_equal(context->source_name->name_oid,
                           GSS_C_NT_ANONYMOUS))
            {
                context->ret_flags |= GSS_C_ANON_FLAG;
            }
            
            if (src_name_P != NULL)
            {
                major_status = globus_i_gsi_gss_copy_name_to_name(
                    & local_minor_status,
                    (gss_name_desc **)src_name_P, 
                    context->source_name);

                if(major_status != GSS_S_COMPLETE)
                {
#error add minor status
                    context->gss_state = GSS_CON_ST_DONE;
                    break;
                }
            }
                        
            if (context->callback_data.limited_proxy)
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
#error add minor status to error
                    GSSerr(GSSERR_F_ACCEPT_SEC,GSSERR_R_PROXY_VIOLATION);
                    context->gss_state = GSS_CON_ST_DONE;
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
                context->gss_state = GSS_CON_ST_DONE;
                break;
            }
        
            /* 
             * To keep the gss exchange going, if we received
             * the last token but dont have a token to send
             * we need to send a null So peek at what we might send
             */

            if (BIO_pending(context->gss_wbio) == 0)
            {
                BIO_write(context->gss_sslbio,"\0",1);
            }
            context->gss_state = GSS_CON_ST_FLAGS;
            break;

        case(GSS_CON_ST_FLAGS):
        
            BIO_read(context->gss_sslbio,dbuf,1);

            if (*dbuf == 'D')
            {
                if(result = globus_gsi_proxy_create_req(context->proxy_handle,
                                                        context->gss_sslbio) 
                   != GLOBUS_SUCCESS)
                {
#error  add error here
                    context->gss_stat = GSS_CON_ST_DONE;
                    major_status = GSS_S_FAILURE;
                    break;
                }                    
                context->gss_state = GSS_CON_ST_CERT;
            }
            else
            {
                context->gss_state = GSS_CON_ST_DONE;
            }

            break;

        case(GSS_CON_ST_CERT):

            *delegated_cred_handle_P = 
                (gss_cred_id_t) globus_malloc(sizeof(gss_cred_id_desc));
            
            if(result = globus_gsi_proxy_assemble_cred(
                context->proxy_handle,
                (*delegated_cred_handle_P)->cred_handle,
                context->gss_sslbio) != GLOBUS_SUCCESS)
            {
#error add error
                context->gss_stat = GSS_CON_ST_DONE;
                major_status = GSS_S_FAILURE;
                break;
            }
            
            if(result = globus_gsi_cred_set_cert_chain(
                (*delegated_cred_handle_P)->cred_handle,
                context->callback_data.cert_chain) != GLOBUS_SUCCESS)
            {
#error add error
                context->gss_stat = GSS_CON_ST_DONE;
                major_status = GSS_S_FAILURE;
                break;
            }

            /* DEE? until the gss_export_cred is written,
             * If the user did not ask for the delegated cred handle
             * we will write out the delegated proxy here
             * on the server, the s3_srvr.c does not save the 
             * peer cert chain. So our proxy_verify_callback 
             * will. If this is fixed, then 
             * we could use SSL_get_peer_cert_chain(context->gss_ssl) 
             * Also need to set the ret_flag for 
             * GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG
             * The delegated cert, key and chain will be transfered 
             * to the delegated cred. 
             */            

            context->gss_state = GSS_CON_ST_DONE;

        default:
            break;

    } /* end of switch for gss_con_st */

    /*
     * Couple of notes about this gss_get_token() call:
     *
     * First don't mess with minor_status here as it may contain real info.
     *
     * Second, we want to go ahead and get an ouput token even if we previously
     * encountered an error since the output token may contain information
     * about the error (i.e. an SSL alert message) we want to send to the other
     * side.
     */
    tmp_major_status = globus_i_gsi_gss_get_token(& local_minor_status, 
                                                  context, NULL, output_token);

    if(tmp_major_status != GSS_S_COMPLETE)
    {
#error error here
    }

    if (context->gss_state != GSS_CON_ST_DONE)
    {
        major_status |= GSS_S_CONTINUE_NEEDED;
    }
    else if(major_status == GSS_S_COMPLETE)
    {
        if(result = globus_gsi_cred_goodtill(
                        context->cred_handle->cred_handle,
                        & context->goodtill) != GLOBUS_SUCCESS)
        {
#error error here
        }

        if(context->goodtill > context->callback_data.goodtill)
        {
            context->goodtill = context->callback_data.goodtill;
        }
    }

    if (ret_flags != NULL)
    {
        *ret_flags = context->ret_flags;
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
        2, 
        (stderr, 
         "accept_sec_context:major_status:%08x:gss_state:%d:ret_flags=%08x\n",
         major_status, context->gss_state, context->ret_flags));

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;

    return major_status;
}

/**********************************************************************

init_sec_context.c:

Description:
    GSSAPI routine to initiate the sending of a security context
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
#include "openssl/evp.h"

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
Function: gss_init_sec_context

Description:
    Called by the client in a loop, it will return a token
    to be sent to the accept_sec_context running in the server. 
Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_init_sec_context(
    OM_uint32 *                         minor_status,
    const gss_cred_id_t                 initiator_cred_handle,
    gss_ctx_id_t *                      context_handle_P,
    const gss_name_t                    target_name,
    const gss_OID                       mech_type,
    OM_uint32                           req_flags,
    OM_uint32                           time_req,
    const gss_channel_bindings_t        input_chan_bindings,
    const gss_buffer_t                  input_token,
    gss_OID *                           actual_mech_type,
    gss_buffer_t                        output_token,
    OM_uint32 *                         ret_flags,
    OM_uint32 *                         time_rec) 
{

    gss_ctx_id_desc *                   context = NULL;
    OM_uint32                           major_status = 0;
    OM_uint32                           local_minor_status = 0;
    OM_uint32                           local_major_status = 0;
    X509_REQ *                          reqp = NULL;
    X509 *                              ncert = NULL;
    X509 *                              current_cert = NULL;
    int                                 rc;
    char                                cbuf[1];
    time_t                              goodtill = 0;
    int                                 cert_count = 0;
    globus_proxy_type_t                 proxy_type = GLOBUS_FULL_PROXY;

    static char *                       _function_name_ = 
        "gss_init_sec_context";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    *minor_status = 0;
    output_token->length = 0;

    context = *context_handle_P;

    /* module activation if not already done by calling
     * globus_module_activate
     */
    
    globus_thread_once(
        &once_control,
        (void (*)(void))globus_i_gsi_gssapi_module.activation_func);

    if(req_flags & GSS_C_ANON_FLAG & GSS_C_DELEG_FLAG)
    {
#error here
        GSSerr(GSSERR_F_INIT_SEC,GSSERR_R_BAD_ARGUMENT);
        major_status = GSS_S_FAILURE;
    }
    
    if ((context == (gss_ctx_id_t) GSS_C_NO_CONTEXT) ||
        !(context->ctx_flags & GSS_I_CTX_INITIALIZED))
    {
        GLOBUS_I_GSI_GSSAPI_DEBUG_FPRINTF(
            2, (stderr, "Creating context w/%s.\n",
                (initiator_cred_handle == GSS_C_NO_CREDENTIAL) ?
                "GSS_C_NO_CREDENTIAL" :
                "Credentials provided"));

        major_status = gss_create_and_fill_context(&local_minor_status,
                                                   &context,
                                                   initiator_cred_handle,
                                                   GSS_C_INITIATE,
                                                   req_flags);
        if (GSS_ERROR(major_status))
        {
#error here
        }

        *context_handle_P = context;

        if (actual_mech_type != NULL)
        {
            *actual_mech_type = (gss_OID) gss_mech_globus_gssapi_openssl;
        }

        if (ret_flags != NULL)
        {
            *ret_flags = 0 ;
        }

        if (time_rec != NULL)
        {
            *time_rec = GSS_C_INDEFINITE;
        }
    }
    else
    {
        /*
         * first time there is no input token, but after that
         * there will always be one
         */

    	major_status = globus_i_gsi_gss_put_token(&local_minor_status,
                                                  context, 
                                                  NULL, 
                                                  input_token);
    	if (major_status != GSS_S_COMPLETE)
        {
#error here
        }
    }


    switch (context->gss_state)
    {
    case(GSS_CON_ST_HANDSHAKE):
        
        /* do the handshake work */
        
        major_status = globus_i_gsi_gss_handshake(&local_minor_status,
                                                  context);
        
        if (major_status == GSS_S_CONTINUE_NEEDED)
        {
            break;
        }
        /* if failed, may have SSL alert message too */
        if (major_status != GSS_S_COMPLETE)
        {
            context->gss_state = GSS_CON_ST_DONE;
            break;
        } 
        /* make sure we are talking to the correct server */
        major_status = globus_i_gsi_gss_retrieve_peer(&local_minor_status,
                                                      context,
                                                      GSS_C_INITIATE);
        if (major_status != GSS_S_COMPLETE)
        {
            context->gss_state = GSS_CON_ST_DONE;
            break;
        }

        /* 
         * Need to check if the server is using a limited proxy. 
         * And if that is acceptable here. 
         * Caller tells us if it is not acceptable to 
         * use a limited proxy. 
         */
        if ((context->req_flags & GSS_C_GLOBUS_LIMITED_PROXY_FLAG)
            && context->callback_data.limited_proxy)
        {
            GSSerr(GSSERR_F_INIT_SEC,GSSERR_R_PROXY_VIOLATION);
            major_status = GSS_S_UNAUTHORIZED;
            context->gss_state = GSS_CON_ST_DONE;
            break;
        }

        /* this is the mutual authentication test */
        if (target_name != NULL)
        {
            local_major_status = gss_compare_name(&local_minor_status,
                                                  context->target_name,
                                                  target_name,
                                                  &rc);
            if (local_major_status != GSS_S_COMPLETE)
            {
                *minor_status = local_minor_status;
                major_status  = local_major_status;
                context->gss_state = GSS_CON_ST_DONE;
                break;
            }
            else if( rc == 0)
            {
#error here
                major_status = GSS_S_UNAUTHORIZED;
                context->gss_state = GSS_CON_ST_DONE;
                break;
            }
        }
    
        context->ret_flags |= GSS_C_MUTUAL_FLAG;
        context->ret_flags |= GSS_C_PROT_READY_FLAG; 
        context->ret_flags |= GSS_C_INTEG_FLAG
            | GSS_C_REPLAY_FLAG
            | GSS_C_SEQUENCE_FLAG;
        if (context->pvd.limited_proxy)
        {
            context->ret_flags |= GSS_C_GLOBUS_LIMITED_PROXY_FLAG;
        }

        /* 
         * IF we are talking to a real SSL server,
         * we dont want to do delegation, so we are done
         */

        if (context->req_flags & GSS_C_GLOBUS_SSL_COMPATIBLE)
        {
            context->gss_state = GSS_CON_ST_DONE;
            break;
        }
            
        /*
         * If we have completed the handshake, but dont
         * have any more data to send, we can send the flag
         * now. i.e. fall through without break,
         * Otherwise, we will wait for the null byte
         * to get back in sync which we will ignore
         */

        if (output_token->length != 0)
        {
            context->gss_state=GSS_CON_ST_FLAGS;
            break;
        }

    case(GSS_CON_ST_FLAGS):
        if (input_token->length > 0)
        {   
            BIO_read(context->gss_sslbio,cbuf,1);
        }

        /* send D if we want delegation, 0 otherwise */
        
        if (context->req_flags & GSS_C_DELEG_FLAG)
        {
            BIO_write(context->gss_sslbio,"D",1); 
            context->gss_state=GSS_CON_ST_REQ;
        }
        else
        {
            BIO_write(context->gss_sslbio,"0",1);
            context->gss_state=GSS_CON_ST_DONE;
        } 
        break;
            
    case(GSS_CON_ST_REQ):

        if((result = globus_gsi_proxy_inquire_req(
            context->proxy_handle,
            context->gss_sslbio)) != GLOBUS_SUCCESS)
        {
#error here
        }

        if(proxy_type != GLOBUS_RESTRICTED_PROXY &&
           context->req_flags & GSS_C_GLOBUS_LIMITED_DELEG_PROXY_FLAG)
        {
            context->proxy_handle->is_limited = GLOBUS_TRUE;
        }

        if((result = globus_gsi_proxy_sign_req(
            context->proxy_handle,
            context->cred_handle->cred_handle,
            context->gss_sslbio)) != GLOBUS_SUCCESS)
        {
#error here
        }

        context->gss_state = GSS_CON_ST_DONE;
        break;
            
    case(GSS_CON_ST_CERT): ;
    case(GSS_CON_ST_DONE): ;
    } /* end of switch for gss_con_st */

    local_major_status = globus_i_gsi_gss_get_token(&local_minor_status,
                                              context, 
                                              NULL, 
                                              output_token);

    if(local_major_status != GSS_S_COMPLETE)
    {
#error here
    }

    if (context->gss_state != GSS_CON_ST_DONE)
    {
        major_status |=GSS_S_CONTINUE_NEEDED;
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
        2, (stderr,
            "init_sec_context:major_status:%08x"
            ":gss_state:%d req_flags=%08x:ret_flags=%08x\n",
            major_status, context->gss_state,req_flags, context->ret_flags));

    return major_status;
}






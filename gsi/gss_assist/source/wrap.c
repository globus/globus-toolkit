#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file wrap.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_gss_assist.h"
#include <gssapi.h>

/**
 * @name Wrap
 * @ingroup globus_gsi_gss_assist
 */
/* @{ */
/**
 * @see gss_wrap
 *
 * @param minor_status
 *        GSSAPI return code.  If the call was successful, the minor 
 *        status is equal to GLOBUS_SUCCESS.  Otherwise, it is an
 *        error object ID for which  
 *        @ref globus_error_get and @ref globus_object free
 *        can be used to get and destroy it.
 * @param context_handle
 *        the context. 
 * @param conf_req_flag
 * @param qop_req
 * @param input_message_buffer
 *
 * @param token_status
 *        assist routine get/send token status 
 * @param gss_assist_send_token
 *        a send_token routine 
 * @param gss_assist_send_context
 *        first arg for the send_token
 * @param fperr
 *
 * @return
 *        GSS_S_COMPLETE on sucess
 *        Other gss errors on failure.  
 */
OM_uint32
globus_gss_assist_wrap_send(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    char *			        data,
    size_t			        length,
    int *			        token_status,
    int (*gss_assist_send_token)(void *, void *, size_t),
    void *                              gss_assist_send_context,
    FILE *                              fperr)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           minor_status1 = 0;
    gss_buffer_desc                     input_token_desc  = GSS_C_EMPTY_BUFFER;
    gss_buffer_t                        input_token       = &input_token_desc;
    gss_buffer_desc                     output_token_desc = GSS_C_EMPTY_BUFFER;
    gss_buffer_t                        output_token      = &output_token_desc;
    static char *                       _function_name_ =
        "globus_gss_assist_wrap_send";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    *token_status = 0;
    input_token->value = data;
    input_token->length = length;

    major_status = gss_wrap(minor_status,
                            context_handle,
                            0,
                            GSS_C_QOP_DEFAULT,
                            input_token,
                            NULL,
                            output_token);
  
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_FPRINTF(
        3, (globus_i_gsi_gss_assist_debug_fstream,
            "Wrap_send:maj:%8.8x min:%8.8x inlen:%d outlen:%d\n",
            (unsigned int) major_status, 
            (unsigned int) *minor_status, 
            input_token->length = length,
            output_token->length));

    if (major_status == GSS_S_COMPLETE)
    {
	*token_status = (*gss_assist_send_token)(gss_assist_send_context,
                                                 output_token->value,
                                                 output_token->length);
    }

    gss_release_buffer(&minor_status1,
                       output_token);
  
    if (fperr && (major_status != GSS_S_COMPLETE || *token_status != 0)) 
    {
        globus_gss_assist_display_status(
            stderr,
            "gss_assist_wrap_send failure:",
            major_status,
            *minor_status,
            *token_status);
    }

    if (*token_status) {

        GLOBUS_I_GSI_GSS_ASSIST_DEBUG_FPRINTF(
            3, (globus_i_gsi_gss_assist_debug_fstream,
                "TOKEN STATUS: %d\n", *token_status));
      
        major_status = GSS_S_FAILURE;
    }

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return major_status;
}
/* @} */

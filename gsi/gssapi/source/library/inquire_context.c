#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file delete_sec_context.c
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

static char *rcsid = "$Id$";

#include "gssapi.h"
#include "gssapi_openssl.h"
#include "globus_i_gsi_gss_utils.h"

/**
 * @name Inquire Context
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * 
 * @param minor_status
 * @param context_handle_P
 * @param src_name_P
 * @param targ_name_P
 * @param lifetime_rec
 * @param mech_type
 * @param ctx_flags
 * @param locally_initiated
 * @param open
 *
 * @return
 */
OM_uint32 
GSS_CALLCONV gss_inquire_context(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle_P,
    gss_name_t *                        src_name_P,
    gss_name_t *                        targ_name_P,
    OM_uint32 *                         lifetime_rec,
    gss_OID *                           mech_type,
    OM_uint32 *                         ctx_flags,
    int *                               locally_initiated,
    int *                               open) 
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;
    globus_result_t                     local_result;
    gss_ctx_id_desc *                   context = 
        (gss_ctx_id_desc *)context_handle_P;
    static char *                       _function_name_ =
        "gss_inquire_context";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    if (context == GSS_C_NO_CONTEXT)
    {
        major_status = GSS_S_NO_CONTEXT;
        GLOBUS_GSI_GSSAPI_ERROR_RESULT(
            minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT,
            ("Invalid context parameter passed to function"));
        goto exit;
    }

    /* lock the context mutex */
    globus_mutex_lock(&context->mutex);
    
    if (src_name_P)
    {
        major_status = globus_i_gsi_gss_copy_name_to_name(
            &local_minor_status,
            (gss_name_desc **)src_name_P,
            context->cred_handle->globusid);
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_BAD_NAME);
            goto exit;
        }
        else
        {
            *src_name_P = NULL;
        }
    }
        
    if (targ_name_P)
    {
        
        major_status = globus_i_gsi_gss_copy_name_to_name(
                &local_minor_status,
                (gss_name_desc **)targ_name_P,
                context->cred_handle->globusid);
        if (GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_BAD_NAME);
            goto exit;
        }
        else
        {
            *targ_name_P = NULL;
        }
    }
        
    if (lifetime_rec)
    {
        local_result = globus_gsi_cred_get_lifetime(
            context->cred_handle->cred_handle,
            (time_t *) &lifetime_rec);
        if(local_result != GLOBUS_SUCCESS)
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_result,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL);
            goto exit;
        }
    }

    if (mech_type)
    {
        *mech_type = (gss_OID) gss_mech_globus_gssapi_openssl;
    }

    if (ctx_flags)
    {
        if (context->gss_state == GSS_CON_ST_DONE)
        {
            *ctx_flags = context->ret_flags;
        }
        else
        {
            *ctx_flags = context->req_flags;
        }
    }

    if (locally_initiated)
    {
        *locally_initiated = context->locally_initiated;
    }
                
    if (open)
    {
        if (context->gss_state == GSS_CON_ST_DONE)
        {
            *open = GSS_CTX_FULLY_ESTABLISHED;
        }
        else
        {
            *open = GSS_CTX_TOKEN_EXPECTED_FROM_PEER;
        }
    }

 exit:

    globus_mutex_unlock(&context->mutex);    
    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

/**
 * @name Context Time
 * @ingroup globus_gsi_gssapi
 */
/* @{ */
/**
 * 
 * @param minor_status
 * @param context_handle
 * @param time_rec
 *
 * @return
 */
OM_uint32 
GSS_CALLCONV gss_context_time(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    OM_uint32 *                         time_rec)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    OM_uint32                           local_minor_status;
    static char *                       _function_name_ =
        "gss_context_time";
    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    major_status = gss_inquire_context(&local_minor_status,
                                       context_handle,
                                       NULL,
                                       NULL,
                                       time_rec,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL);
    if(GSS_ERROR(major_status))
    {
        GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
            minor_status, local_minor_status,
            GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CONTEXT);
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;
    return major_status;
}
/* @} */

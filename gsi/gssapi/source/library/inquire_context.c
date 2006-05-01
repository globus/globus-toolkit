/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
    gss_name_t *			local_name;
    gss_name_t *			peer_name;
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

    local_name = context->locally_initiated ? src_name_P : targ_name_P;
    peer_name  = context->locally_initiated ? targ_name_P : src_name_P;

    if(local_name)
    {
	if(context->cred_handle && 
	   context->cred_handle->globusid)
	{
	    major_status = globus_i_gsi_gss_copy_name_to_name(
		&local_minor_status,
		(gss_name_desc **) local_name,
		context->cred_handle->globusid);
	    if(GSS_ERROR(major_status))
	    {
		GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
		    minor_status, local_minor_status,
		    GLOBUS_GSI_GSSAPI_ERROR_BAD_NAME);
		goto exit;
	    }
	}
	else
	{
	    *local_name = NULL;
	}
    }

    if(peer_name)
    {
	if(context->peer_cred_handle && 
	   context->peer_cred_handle->globusid)
	{
	    major_status = globus_i_gsi_gss_copy_name_to_name(
		&local_minor_status,
		(gss_name_desc **) peer_name,
		context->peer_cred_handle->globusid);
	    if(GSS_ERROR(major_status))
	    {
		GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
		    minor_status, local_minor_status,
		    GLOBUS_GSI_GSSAPI_ERROR_BAD_NAME);
		goto exit;
	    }
	}
	else
	{
	    *peer_name = NULL;
        }
    }

    if (lifetime_rec)
    {
        time_t                          lifetime;
        time_t                          current_time;
        
        major_status = globus_i_gsi_gss_get_context_goodtill(
            &local_minor_status,
            context,
            &lifetime);
        if(GSS_ERROR(major_status))
        {
            GLOBUS_GSI_GSSAPI_ERROR_CHAIN_RESULT(
                minor_status, local_minor_status,
                GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CONTEXT);
            goto exit;
        }

        current_time = time(NULL);

        if(current_time > lifetime)
        {
            *lifetime_rec = 0;
        }
        else
        {
            *lifetime_rec = (OM_uint32) (lifetime - current_time);
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

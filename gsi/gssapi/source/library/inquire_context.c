
/**********************************************************************

inquire_context.c:

Description:
        GSSAPI routine to inquire about the local context
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

#include "gssapi.h"
#include "gssapi_ssleay.h"
#include "gssutils.h"

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
Function:   gss_inquire_context()

Description:
        Get information about the current context

Returns:
**********************************************************************/

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
    OM_uint32                           major_status = 0;
    gss_ctx_id_desc *                   context = 
        (gss_ctx_id_desc *)context_handle_P;
    time_t                              time_now;
    ASN1_UTCTIME *                      asn1_time = NULL;

#ifdef DEBUG
    fprintf(stderr,"inquire_context:\n");
#endif /* DEBUG */

    if (context == GSS_C_NO_CONTEXT)
    {
        major_status = GSS_S_NO_CONTEXT;
        goto err;
    }

    /* lock the context mutex */
    
    globus_mutex_lock(&context->mutex);

    
    if (src_name_P)
    {
        if (context->source_name)
        {
            major_status = gss_copy_name_to_name((gss_name_desc **)src_name_P,
                                                 context->source_name);
            if (major_status != GSS_S_COMPLETE)
            {
                *minor_status = gsi_generate_minor_status();
                goto err;
            }
        }
        else
        {
            *src_name_P = NULL;
        }
    }
        
    if (targ_name_P)
    {
        if (context->target_name)
        {
            major_status =
                gss_copy_name_to_name((gss_name_desc **)targ_name_P,
                                      context->target_name);
            if (major_status != GSS_S_COMPLETE)
            {
                *minor_status = gsi_generate_minor_status();
                goto err;
            }
        }
        else
        {
            *targ_name_P = NULL;
        }
    }
        
    if (lifetime_rec)
    {
        asn1_time = ASN1_UTCTIME_new();
        if (!asn1_time)
        {
            major_status = GSS_S_FAILURE;
            *minor_status = gsi_generate_minor_status();
            goto err;
        }
        X509_gmtime_adj(asn1_time,0);
        time_now = ASN1_UTCTIME_mktime(asn1_time);
        *lifetime_rec = context->pvxd.goodtill - time_now;
        if ( context->pvxd.goodtill == 0)
        {
            *lifetime_rec = GSS_C_INDEFINITE;
        }
        else
        {
            *lifetime_rec = context->pvxd.goodtill - time_now;
        }
        ASN1_UTCTIME_free(asn1_time);
    }

    if (mech_type)
    {
        *mech_type = (gss_OID) gss_mech_globus_gssapi_ssleay;
    }

    if (ctx_flags)
    {
        if (context->gs_state == GS_CON_ST_DONE)
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
        if (context->gs_state == GS_CON_ST_DONE)
        {
            *open = 1;
        }
        else
        {
            *open = 0;
        }
    }

err:

    globus_mutex_unlock(&context->mutex);
    
    return major_status;
}

/**********************************************************************
Function:   gss_context_time()

Description:
        Get information about the current context

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_context_time(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    OM_uint32 *                         time_rec
    )
{
    return gss_inquire_context(minor_status,
                               context_handle,
                               NULL,
                               NULL,
                               time_rec,
                               NULL,
                               NULL,
                               NULL,
                               NULL);
}


#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file display.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_gss_assist.h"
#include <gssapi.h>
#include <stdlib.h>

extern
const gss_OID_desc * const gss_proxycertinfo_extension;

/**
 * @name Will Handle Restrictions
 * @ingroup globus_gsi_gss_assist
 */
/* @{ */
/**
 * Sets the context to handle restrictions
 *
 * @param minor_status
 *        the resulting minor status from setting the context handle
 * @param context_handle
 *        the context handle to set the minor status of
 * 
 * @return
 *        the major status from setting the context
 */
OM_uint32
globus_gss_assist_will_handle_restrictions(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t *                      context_handle)
{
    OM_uint32                           maj_stat;
    gss_buffer_desc                     oid_buffer;
    gss_OID_set_desc                    oid_set;
    static char *                       _function_name_ =
        "globus_gss_assist_will_handle_restrictions";
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    oid_set.count = 1;
    oid_set.elements = (gss_OID) gss_proxycertinfo_extension;

    oid_buffer.value = (void *) &oid_set;
    oid_buffer.length = 1;
    
    maj_stat = gss_set_sec_context_option(
        minor_status,
        context_handle,
        (gss_OID) GSS_APPLICATION_WILL_HANDLE_EXTENSIONS,
        &oid_buffer);

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return maj_stat;
}
/* @} */

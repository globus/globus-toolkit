/**********************************************************************

accept_delegation.c:

Description:
    GSSAPI routine to accept the delegation of a credential

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$

**********************************************************************/


static char *rcsid = "$Header$";

#include "gssapi_ssleay.h"
#include "gssutils.h"

OM_uint32
GSS_CALLCONV gss_accept_delegation(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    gss_cred_id_t *                     delegated_cred_handle,
    gss_OID *                           mech_type, 
    const gss_OID_set                   restriction_oids,
    const gss_buffer_set_t              restriction_buffers,
    const gss_buffer_t                  input_token,
    gss_buffer_t                        output_token)
{
}



/**********************************************************************

inquire_sec_context_by_oid.c:

Description:
    GSSAPI routine to extract extensions from a credential.

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
GSS_CALLCONV gss_inquire_sec_context_by_oid(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    gss_OID                             desired_object,
    gss_buffer_set_t                    data_set)
{
}



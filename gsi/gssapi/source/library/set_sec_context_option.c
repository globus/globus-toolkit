/**********************************************************************

set_sec_context_option.c:

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


#include "gssapi_ssleay.h"
#include "gssutils.h"
#include <string.h>
#include "openssl/evp.h"

static const gss_OID_desc GSS_DISALLOW_ENCRYPTION_OID =
   {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x03\x01"}; 
const gss_OID_desc * const GSS_DISALLOW_ENCRYPTION =
   &GSS_DISALLOW_ENCRYPTION_OID;

static const gss_OID_desc GSS_PROTECTION_FAIL_ON_CONTEXT_EXPIRATION_OID =
   {11, "\x2b\x06\x01\x04\x01\x9b\x50\x01\x01\x03\x02"}; 
const gss_OID_desc * const GSS_PROTECTION_FAIL_ON_CONTEXT_EXPIRATION =
   &GSS_PROTECTION_FAIL_ON_CONTEXT_EXPIRATION_OID;



OM_uint32
gss_set_sec_context_option(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t *                      context_handle,
    const gss_OID                       option,
    const gss_buffer_t                  value)
{
    gss_ctx_id_desc *                   context = NULL;
    OM_uint32                           major_status = GSS_S_COMPLETE;

#ifdef DEBUG
    fprintf(stderr, "set_sec_context_option:\n") ;
#endif /* DEBUG */
    
    *minor_status = 0;
    context = *context_handle;
    
    if ((context == (gss_ctx_id_t) GSS_C_NO_CONTEXT))
    {
        /* for now just malloc and zero the context */
        
        context = (gss_ctx_id_desc*) malloc(sizeof(gss_ctx_id_desc)) ;

        if (context == NULL)
        {
            GSSerr(GSSERR_F_CREATE_FILL, GSSERR_R_OUT_OF_MEMORY);
            return GSS_S_FAILURE;
        }

        *context_handle = context;

        memset(context,0,sizeof(gss_ctx_id_desc));
    }

    if(g_OID_equal(option, GSS_DISALLOW_ENCRYPTION))
    {
        context->ctx_flags |= GSS_I_DISALLOW_ENCRYPTION;
    }
    else if(g_OID_equal(option, GSS_PROTECTION_FAIL_ON_CONTEXT_EXPIRATION))
    {
        context->ctx_flags |= GSS_I_PROTECTION_FAIL_ON_CONTEXT_EXPIRATION;
    }
    else
    {
        /* unknown option */
    }

    return major_status;
}

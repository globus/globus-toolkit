/**********************************************************************

release_cred.c:

Description:
    GSSAPI routine to release the credential obtained by 
	acquire_cred.
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
Function: gss_release_cred

Description:
	Release the credential

Parameters:
   
Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_release_cred(
    OM_uint32 *                         minor_status,
    gss_cred_id_t *                     cred_handle_P)
{
    gss_cred_id_desc**                  cred_handle =
        (gss_cred_id_desc**) cred_handle_P;
    OM_uint32                           inv_minor_status = 0;
    OM_uint32                           inv_major_status = 0;

    *minor_status = 0;
#ifdef DEBUG
    fprintf(stderr,"release_cred:\n");
#endif

    if (*cred_handle == NULL || *cred_handle == GSS_C_NO_CREDENTIAL )
    {
        return GSS_S_COMPLETE ;
    }

    if ((*cred_handle)->globusid != NULL)
    {
        inv_major_status = gss_release_name(
            &inv_minor_status,
            (void*) &((*cred_handle)->globusid)) ;
    }

    proxy_cred_desc_free((*cred_handle)->pcd);

    if ((*cred_handle)->gs_bio_err)
    {
        BIO_free((*cred_handle)->gs_bio_err);
    }

    free(*cred_handle) ;
    *cred_handle = GSS_C_NO_CREDENTIAL;

    return GSS_S_COMPLETE ;

} /* gss_release_cred */






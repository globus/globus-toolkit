/**********************************************************************

delete_sec_context.c:

Description:
    GSSAPI routine to delete a security context
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
Function:   gss_delete_sec_context()

Description:
        delete the security context

Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_delete_sec_context(
    OM_uint32 *                         minor_status,
    gss_ctx_id_t *                      context_handle_P, 
    gss_buffer_t                        output_token)
{
    gss_ctx_id_desc **                  context_handle = 
        (gss_ctx_id_desc**) context_handle_P ;
    OM_uint32                           inv_minor_status = 0;
    OM_uint32                           inv_major_status = 0;

    *minor_status = 0;
#ifdef DEBUG
    fprintf(stderr,"delete_sec_context:\n");
#endif

    if (output_token != GSS_C_NO_BUFFER)
    {
        output_token->length = 0;
        output_token->value = NULL;
    }

    if (*context_handle == NULL ||
        *context_handle == GSS_C_NO_CONTEXT)
    {
        return GSS_S_COMPLETE ;
    }

    /* lock the context mutex */
    
    globus_mutex_lock(&(*context_handle)->mutex);

    /*
     * we might want to send a ssl shutdown 
     * Usefull if talking to a Java SSL application which 
     * is using real SSL
     * DEE - may need to fix unwrap to look for these.
     */

    if ((*context_handle)->gs_state == GS_CON_ST_DONE
        && (*context_handle)->gs_ssl 
        && output_token != GSS_C_NO_BUFFER)
    {
        SSL_shutdown((*context_handle)->gs_ssl);
        
        gs_get_token(*context_handle,
                     NULL,
                     output_token);

#ifdef DEBUG
        fprintf(stderr,"delete_sec_context:output_token->length=%d\n",
                output_token->length);
#endif
    }

    /* ignore errors to allow for incomplete context handles */

    if ((*context_handle)->source_name != NULL)
    {
        inv_major_status = gss_release_name(
            &inv_minor_status,
            (gss_name_t*) &((*context_handle)->source_name)) ;
    }

#ifndef __CYGWIN__
    if ((*context_handle)->target_name != NULL)
    {
        inv_major_status = gss_release_name(
            &inv_minor_status,
            (gss_name_t*) &((*context_handle)->target_name)) ;
    }
#endif
        
    if ((*context_handle)->dpkey)
    {
        EVP_PKEY_free((*context_handle)->dpkey);
    }

    if ((*context_handle)->dcert)
    {
        X509_free((*context_handle)->dcert);
    }

    proxy_verify_release(&((*context_handle)->pvd));
    proxy_verify_ctx_release(&((*context_handle)->pvxd));

    if((*context_handle)->pvd.extension_oids != NULL)
    {
        free(((gss_OID_set_desc *) (*context_handle)->pvd.extension_oids)->elements);
        free((*context_handle)->pvd.extension_oids);
    }
        
    if ((*context_handle)->gs_ssl)
    {
        SSL_clear((*context_handle)->gs_ssl);
    }
        
    if ((*context_handle)->gs_sslbio)
    {
        BIO_free_all((*context_handle)->gs_sslbio);
    }

    if ((*context_handle)->gs_rbio)
    {
        BIO_free_all((*context_handle)->gs_rbio);
        (*context_handle)->gs_rbio = NULL;
    }

    if ((*context_handle)->gs_wbio)
    {
        BIO_free_all((*context_handle)->gs_wbio);
        (*context_handle)->gs_wbio = NULL;
    }

    if ((*context_handle)->gs_ssl)
    {
        (*context_handle)->gs_ssl->rbio = NULL;
        (*context_handle)->gs_ssl->wbio = NULL;
        SSL_free((*context_handle)->gs_ssl);
    } 

    if ((*context_handle)->cred_obtained)
    {
        inv_major_status = gss_release_cred(
            &inv_minor_status,
            (gss_ctx_id_t*) &((*context_handle)-> cred_handle)) ;
    }

    globus_mutex_unlock(&(*context_handle)->mutex);

    globus_mutex_destroy(&(*context_handle)->mutex);
    
    free(*context_handle) ;
    *context_handle = GSS_C_NO_CONTEXT;

#ifdef DEBUG
    fprintf(stderr,"delete_sec_context: done\n");
#endif
    
    return GSS_S_COMPLETE ;

} /* gss_delete_sec_context */


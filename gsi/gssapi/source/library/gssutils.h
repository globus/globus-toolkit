/**********************************************************************

gssutils.h

Description:
        This header file used internally  to define the gssutils

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$

**********************************************************************/

#ifndef _GSSUTILS_H
#define _GSSUTILS_H

/**********************************************************************
                             Include header files
**********************************************************************/

#include "gssapi.h"
#include "gssapi_ssleay.h"

/**********************************************************************
                               Define constants
**********************************************************************/

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                               Global variables
**********************************************************************/

/**********************************************************************
                               Function prototypes
**********************************************************************/


OM_uint32
gss_copy_name_to_name(
    gss_name_desc **                    output,
    const gss_name_desc *               input);


OM_uint32
gss_create_and_fill_context(
    gss_ctx_id_desc **                  context_handle,
    gss_cred_id_desc *                  cred_handle,
    const gss_cred_usage_t              cred_usage,
    OM_uint32                           req_flags);

OM_uint32
gss_create_anonymous_cred(
    gss_cred_id_t *                     output_cred_handle,
    const gss_cred_usage_t              cred_usage);

OM_uint32
gss_create_and_fill_cred(
    gss_cred_id_t *                     output_cred_handle_P,
    const gss_cred_usage_t              cred_usage,
    X509   *                            ucert,
    EVP_PKEY *                          upkey,
    STACK_OF(X509)  *                   cert_chain,
    BIO *                               bp);

int gss_verify_extensions_callback(
    proxy_verify_desc *                 pvd,
    X509_EXTENSION *                    extension);

/* following added for ssleay */

OM_uint32
gs_handshake(
    gss_ctx_id_desc*                    context_handle);

OM_uint32
gs_get_token(
    const gss_ctx_id_desc *             context_handle,
    BIO *                               bio,
    const gss_buffer_t                  output_token);

OM_uint32
gs_put_token(
    const gss_ctx_id_desc *             context_handle,
    BIO *                               bio,
    const gss_buffer_t                  input_token);

OM_uint32
gs_retrieve_peer(
    gss_ctx_id_desc *                   context_handle,
    const gss_cred_usage_t              cred_usage);
#endif /* _GSSUTILS_H */

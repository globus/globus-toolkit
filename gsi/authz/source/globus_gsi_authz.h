/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "gssapi.h"

#define GLOBUS_GSI_AUTHZ_MODULE         (&globus_i_gsi_authz_module)

extern
globus_module_descriptor_t    globus_i_gsi_authz_module;


/* callout handle initialization would happen in module activation  */
/* authz handle init initializes the authz state for the connection */

typedef struct globus_i_gsi_authz_handle_s *
    globus_gsi_authz_handle_t;

typedef void (* globus_gsi_authz_cb_t)(
    void *                              callback_arg,
    globus_gsi_authz_handle_t           handle,
    globus_result_t                     result); 

globus_result_t
globus_gsi_authz_handle_init(
    globus_gsi_authz_handle_t *         handle,
    const char *                        service_name,
    const gss_ctx_id_t                  context,
    globus_gsi_authz_cb_t               callback,
    void *                              callback_arg);

globus_result_t
globus_gsi_authorize(
    globus_gsi_authz_handle_t           handle,
    const void *                        action,
    const void *                        object,
    globus_gsi_authz_cb_t               callback,
    void *                              callback_arg);

globus_result_t
globus_gsi_cancel_authz(
    globus_gsi_authz_handle_t           handle);


globus_result_t
globus_gsi_authz_handle_destroy(
    globus_gsi_authz_handle_t           handle,
    globus_gsi_authz_cb_t               callback,
    void *                              callback_arg);

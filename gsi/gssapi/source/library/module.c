#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * @file module.c
 * GSSAPI module activation code
 *
 * $RCSfile$
 * $Revision$
 * $Date $
 */


#include "gssapi.h"
#include "version.h"
#include "globus_openssl_module.h"

static int globus_l_gsi_gssapi_activate(void);
static int globus_l_gsi_gssapi_deactivate(void);

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t		globus_i_gsi_gssapi_module =
{
    "globus_gsi_gssapi",
    globus_l_gsi_gssapi_activate,
    globus_l_gsi_gssapi_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Module activation
 */
static
int
globus_l_gsi_gssapi_activate(void)
{
    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_OPENSSL_MODULE);
    ERR_load_gsserr_strings(0);
    return GLOBUS_SUCCESS;
}
/* globus_l_gsi_gssapi_activate() */

/**
 * Module deactivation
 *
 */
static
int
globus_l_gsi_gssapi_deactivate(void)
{
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    globus_module_deactivate(GLOBUS_OPENSSL_MODULE);
    return GLOBUS_SUCCESS;
}
/* globus_l_gsi_gssapi_deactivate() */
#endif


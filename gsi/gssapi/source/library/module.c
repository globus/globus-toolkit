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
#include "globus_openssl.h"

static int globus_l_gsi_gssapi_activate(void);
static int globus_l_gsi_gssapi_deactivate(void);

/**
 * Debugging level
 *
 * Currently this isn't terribly well defined. The idea is that 0 is no
 * debugging output, and 9 is a whole lot.
 */
int globus_i_gssapi_debug_level = 0;

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
 * State variables needed for dealing with the case when globus module
 * activation isn't used.
 *
 */

globus_thread_once_t                once_control;

static int                          active = 0;

/**
 * Module activation
 */
static
int
globus_l_gsi_gssapi_activate(void)
{
    char *                              tmp_string;
    static char *                       _function_name_ =
        "globus_l_gsi_gssapi_activate";

    if(!active)
    {
        tmp_string = globus_module_getenv("GLOBUS_GSSAPI_DEBUG_LEVEL");
        if(tmp_string != GLOBUS_NULL)
        {
            globus_i_gssapi_debug_level = atoi(tmp_string);
        
            if(globus_i_gssapi_debug_level < 0)
            {
                globus_i_gssapi_debug_level = 0;
            }
        }

        GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

        globus_module_activate(GLOBUS_COMMON_MODULE);
        globus_module_activate(GLOBUS_OPENSSL_MODULE);

        GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;

        active = 1;
    }
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
    static char *                       _function_name_ =
        "globus_l_gsi_gssapi_deactivate";

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    globus_module_deactivate(GLOBUS_OPENSSL_MODULE);
    active = 0;

    GLOBUS_I_GSI_GSSAPI_DEBUG_EXIT;

    return GLOBUS_SUCCESS;
}
/* globus_l_gsi_gssapi_deactivate() */
#endif


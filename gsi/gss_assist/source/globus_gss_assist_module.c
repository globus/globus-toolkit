#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_assist.c
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_i_gss_assist.h"
#include "globus_gsi_system_config.h"
#include "globus_callout.h"
#include "version.h"
#include <stdlib.h>

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

static int globus_l_gsi_gss_assist_activate(void);
static int globus_l_gsi_gss_assist_deactivate(void);

int                               globus_i_gsi_gss_assist_debug_level = 0;
FILE *                            globus_i_gsi_gss_assist_debug_fstream = NULL;

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t globus_i_gsi_gss_assist_module =
{
    "globus_gss_assist",
    globus_l_gsi_gss_assist_activate,
    globus_l_gsi_gss_assist_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Module activation
 */
static
int
globus_l_gsi_gss_assist_activate(void)
{
    int                                 result;
    char *                              tmp_string;
    static char *                       _function_name_ =
        "globus_l_gsi_gss_assist_activate";

    tmp_string = getenv("GLOBUS_GSI_GSS_ASSIST_DEBUG_LEVEL");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_gss_assist_debug_level = atoi(tmp_string);
        if(globus_i_gsi_gss_assist_debug_level < 0)
        {
            globus_i_gsi_gss_assist_debug_level = 0;
        }
    }

    tmp_string = getenv("GLOBUS_GSI_GSS_ASSIST_DEBUG_FILE");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_gss_assist_debug_fstream = fopen(tmp_string, "w");
        if(globus_i_gsi_gss_assist_debug_fstream == NULL)
        {
            result = GLOBUS_NULL;
            goto exit;
        }
    }
    else
    {
        globus_i_gsi_gss_assist_debug_fstream = stderr;
    }

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;

    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_CALLOUT_MODULE);
    globus_module_activate(GLOBUS_GSI_SYSCONFIG_MODULE);
    globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);

 exit:
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;    
    return GLOBUS_SUCCESS;
}

/**
 * Module deactivation
 */
static
int
globus_l_gsi_gss_assist_deactivate(void)
{
    static char *                       _function_name_ =
        "globus_l_gsi_gssapi_deactivate";
    
    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_ENTER;
    
    globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
    globus_module_deactivate(GLOBUS_GSI_SYSCONFIG_MODULE);
    globus_module_deactivate(GLOBUS_CALLOUT_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    GLOBUS_I_GSI_GSS_ASSIST_DEBUG_EXIT;
    return GLOBUS_SUCCESS;
}
/* globus_l_gsi_gss_assist_deactivate() */

#endif


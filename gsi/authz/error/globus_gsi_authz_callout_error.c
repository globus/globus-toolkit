#include "globus_gsi_authz_callout_error.h"
#include "version.h"

char * 
globus_gsi_authz_callout_error_strings[GLOBUS_GSI_AUTHZ_CALLOUT_ERROR_LAST] =
{
    /* 0 */   "Authz callout error",
    /* 1 */   "Authorization denied by callout",
    /* 2 */   "Configuration Error",
    /* 3 */   "System Error",
    /* 4 */   "Credentials Error",
    /* 5 */   "A invalid paramater was detected"
};

static int
globus_l_gsi_authz_callout_error_activate()
{
    return((int)GLOBUS_SUCCESS);
}

static int
globus_l_gsi_authz_callout_error_deactivate()
{
    return((int)GLOBUS_SUCCESS);
}

globus_module_descriptor_t globus_gsi_authz_callout_error_module =
{
    "globus_gsi_authz_callout_error_module",
    globus_l_gsi_authz_callout_error_activate,
    globus_l_gsi_authz_callout_error_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};


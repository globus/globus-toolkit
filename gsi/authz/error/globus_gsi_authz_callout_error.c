/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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


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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * @file module.c
 * ssl_utils module activation code
 *
 * $RCSfile$
 * $Revision$
 * $Date $
 */


#include "sslutils.h"
#include "version.h"
#include "globus_openssl.h"

static int globus_l_gsi_ssl_utils_activate(void);
static int globus_l_gsi_ssl_utils_deactivate(void);

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t		globus_i_gsi_ssl_utils_module =
{
    "globus_gsi_ssl_utils",
    globus_l_gsi_ssl_utils_activate,
    globus_l_gsi_ssl_utils_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Global mutex
 */

globus_mutex_t                          globus_l_gsi_ssl_utils_mutex;

/**
 * Module activation
 */
static
int
globus_l_gsi_ssl_utils_activate(void)
{
    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_OPENSSL_MODULE);

    globus_mutex_init(&globus_l_gsi_ssl_utils_mutex, NULL);
    
    return GLOBUS_SUCCESS;
}
/* globus_l_gsi_ssl_utils_activate() */

/**
 * Module deactivation
 *
 */
static
int
globus_l_gsi_ssl_utils_deactivate(void)
{
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    globus_module_deactivate(GLOBUS_OPENSSL_MODULE);

    globus_mutex_destroy(&globus_l_gsi_ssl_utils_mutex);
    
    return GLOBUS_SUCCESS;
}
/* globus_l_gsi_ssl_utils_deactivate() */
#endif


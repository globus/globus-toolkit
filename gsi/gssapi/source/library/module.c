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
 * GSSAPI module activation code
 *
 * $RCSfile$
 * $Revision$
 * $Date $
 */

#include "gssapi.h"
#include "version.h"
#include "globus_openssl.h"
#include "globus_i_gsi_gss_utils.h"

static int globus_l_gsi_gssapi_activate(void);
static int globus_l_gsi_gssapi_deactivate(void);

/**
 * Debugging level
 *
 * Currently this isn't terribly well defined. The idea is that 0 is no
 * debugging output, and 9 is a whole lot.
 */
int                                     globus_i_gsi_gssapi_debug_level;

/**
 * Debugging Log File
 *
 * Debugging output gets written to this file
 */
FILE *                                  globus_i_gsi_gssapi_debug_fstream;

/**
 * Optionally force use of TLSv1 if GLOBUS_GSSAPI_FORCE_TLS is defined
 * in the environment.
 */
int                                     globus_i_gsi_gssapi_force_tls;


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

globus_thread_once_t                once_control = GLOBUS_THREAD_ONCE_INIT;
globus_mutex_t                      globus_i_gssapi_activate_mutex;
globus_bool_t                       globus_i_gssapi_active = GLOBUS_FALSE;

/**
 * Module activation
 */
static
int
globus_l_gsi_gssapi_activate(void)
{
    int                                 result = (int) GLOBUS_SUCCESS;
    char *                              tmp_string;
    static char *                       _function_name_ =
        "globus_l_gsi_gssapi_activate";

    tmp_string = globus_module_getenv("GLOBUS_GSSAPI_DEBUG_LEVEL");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_gssapi_debug_level = atoi(tmp_string);
    
        if(globus_i_gsi_gssapi_debug_level < 0)
        {
            globus_i_gsi_gssapi_debug_level = 0;
        }
    }

    tmp_string = globus_module_getenv("GLOBUS_GSSAPI_DEBUG_FILE");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_gssapi_debug_fstream = fopen(tmp_string, "a");
        if(!globus_i_gsi_gssapi_debug_fstream)
        {
            result = (int) GLOBUS_FAILURE;
            goto exit;
        }
    }
    else
    {
        globus_i_gsi_gssapi_debug_fstream = stderr;
        if(!globus_i_gsi_gssapi_debug_fstream)
        {
            result = (int) GLOBUS_FAILURE;
            goto exit;
        }
    }

    tmp_string = globus_module_getenv("GLOBUS_GSSAPI_FORCE_TLS");
    if(tmp_string != GLOBUS_NULL)
    {
        globus_i_gsi_gssapi_force_tls = 1;
    }
    else
    {
        globus_i_gsi_gssapi_force_tls = 0;
    }

    GLOBUS_I_GSI_GSSAPI_DEBUG_ENTER;

    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_OPENSSL_MODULE);
    globus_module_activate(GLOBUS_GSI_PROXY_MODULE);
    globus_module_activate(GLOBUS_GSI_CALLBACK_MODULE);

    GLOBUS_I_GSI_GSSAPI_INTERNAL_DEBUG_EXIT;

    globus_i_gssapi_active = GLOBUS_TRUE;

 exit:
    return result;
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

    globus_module_deactivate(GLOBUS_GSI_CALLBACK_MODULE);
    globus_module_deactivate(GLOBUS_GSI_PROXY_MODULE);
    globus_module_deactivate(GLOBUS_OPENSSL_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    globus_i_gssapi_active = GLOBUS_FALSE;
    GLOBUS_I_GSI_GSSAPI_INTERNAL_DEBUG_EXIT;

    return GLOBUS_SUCCESS;
}
/* globus_l_gsi_gssapi_deactivate() */

void
globus_l_gsi_gssapi_activate_once(void)
{
    globus_mutex_init(&globus_i_gssapi_activate_mutex, NULL);
}

#endif

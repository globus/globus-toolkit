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

/******************************************************************************
globus_common.h

Description:

  Routines common to all of Globus

CVS Information:

  $Source$
  $Date$
  $Revision$
  $State$
  $Author$
******************************************************************************/

/******************************************************************************
			     Include header files
******************************************************************************/
#include "globus_common.h"
#include "globus_common_include.h"
#include "globus_module.h"
#include "globus_error.h"
#include "globus_callback.h"
#include GLOBUS_THREAD_INCLUDE
#include "globus_extension.h"
#include "version.h"

/******************************************************************************
			  Module activation structure
******************************************************************************/



static int
globus_l_common_activate(void);

static int
globus_l_common_deactivate(void);

globus_module_descriptor_t		globus_i_common_module =
{
    "globus_common",
    globus_l_common_activate,
    globus_l_common_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

typedef
char *
(*get_l_string_by_key_t)(
    const char *                        locale,
    const char *                        resource_name,
    const char *                        key);
                       
globus_extension_registry_t             i18n_registry;
static get_l_string_by_key_t            globus_l_common_i18n_get_string_by_key;
static globus_extension_handle_t        i18n_handle;

/******************************************************************************
		   globus_common module activation functions
******************************************************************************/

static int
globus_l_common_activate(void)
{
	char * 		env;
#ifdef TARGET_ARCH_WIN32
	int rc;
	WORD wVersionRequested;
	WSADATA wsaData;

	/* initialize Winsock for the database functions in globus_libc.c */
	wVersionRequested = MAKEWORD( 2, 0 ); /* version 2.0 */	 
	rc= WSAStartup( wVersionRequested, &wsaData );
	if ( rc != 0 ) /* error- Winsock not available */
		return GLOBUS_FAILURE;
#endif
    
    if(globus_module_activate(GLOBUS_ERROR_MODULE) != GLOBUS_SUCCESS)
    {
        goto error_error;
    }

    if(globus_module_activate(GLOBUS_CALLBACK_MODULE) != GLOBUS_SUCCESS)
    {
	goto error_callback;
    }

    if(globus_module_activate(GLOBUS_THREAD_MODULE) != GLOBUS_SUCCESS)
    {
	goto error_thread;
    }
    
    if(globus_module_activate(GLOBUS_EXTENSION_MODULE) != GLOBUS_SUCCESS)
    {
	goto error_extension;
    }
    
    globus_l_common_i18n_get_string_by_key = NULL;
    i18n_handle = NULL;
    /*Check for GLOBUS_I18N==NO to see if we should load i18n lib*/
    env = globus_libc_getenv("GLOBUS_I18N");
    if(env != GLOBUS_NULL && strncmp(env, "NO", 2) != 0)
    {
        if(globus_extension_activate("globus_i18n") != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "globus_i18n library did not load. "
                "Set the GLOBUS_EXTENSION_DEBUG env for more info\n");
        }
        else
        {
            globus_l_common_i18n_get_string_by_key =
                globus_extension_lookup(
                    &i18n_handle, &i18n_registry, "get_string_by_key");
            if(!globus_l_common_i18n_get_string_by_key)
            {
                fprintf(stderr, "globus_i18n library does not have "
                    "get_string_by_key\n");
            }
        }
    }

    return GLOBUS_SUCCESS;

error_extension:
    globus_module_deactivate(GLOBUS_THREAD_MODULE);
error_thread:
    globus_module_deactivate(GLOBUS_CALLBACK_MODULE);
error_callback:
    globus_module_deactivate(GLOBUS_ERROR_MODULE);
error_error:
    return GLOBUS_FAILURE;
}


static int
globus_l_common_deactivate(void)
{
    if(i18n_handle)
    {
        globus_extension_release(i18n_handle);
    }
    globus_module_deactivate(GLOBUS_EXTENSION_MODULE);
    globus_module_deactivate(GLOBUS_THREAD_MODULE);
    globus_module_deactivate(GLOBUS_CALLBACK_MODULE);
    globus_module_deactivate(GLOBUS_ERROR_MODULE);
    
#ifdef TARGET_ARCH_WIN32
	/* shutdown Winsock */
	WSACleanup();
#endif

    return GLOBUS_SUCCESS;
}

char *
globus_common_i18n_get_string(
    globus_module_descriptor_t *        module,
    const char *                        key)
{
    if(globus_l_common_i18n_get_string_by_key != NULL &&
        module != NULL)
    {
	return globus_l_common_i18n_get_string_by_key(
            NULL, module->module_name, key);
    }
    else
    {
        return (char *) key;
    }
}

char *
globus_common_i18n_get_string_by_key(
    const char *                        locale,
    const char *                        resource_name,
    const char *                        key)
{
    if(globus_l_common_i18n_get_string_by_key)
    {
        return globus_l_common_i18n_get_string_by_key(
            locale, resource_name, key);
    }
    else
    {
        return (char *) key;
    }
}

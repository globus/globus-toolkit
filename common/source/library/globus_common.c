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

static char *
globus_l_common_i18n_echo_string(
	       	char * locale, 
		char * resource_name, 
		char * key);

static char *
globus_l_common_i18n_get_string_by_module(
		char * locale,
		globus_module_descriptor_t * module,
		char * key);


globus_module_descriptor_t		globus_i_common_module =
{
    "globus_common",
    globus_l_common_activate,
    globus_l_common_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};


globus_extension_registry_t      i18n_registry;
get_string_by_key_t              globus_common_i18n_get_string_by_key;

/******************************************************************************
		   globus_common module activation functions
******************************************************************************/

static int
globus_l_common_activate(void)
{
	globus_extension_handle_t           handle;
#ifdef TARGET_ARCH_WIN32
	int rc;
	WORD wVersionRequested;
	WSADATA wsaData;

	// initialize Winsock for the database functions in globus_libc.c
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

    if(globus_extension_activate("globus_i18n") != GLOBUS_SUCCESS)
    {
	globus_common_i18n_get_string_by_key = globus_l_common_i18n_echo_string;
    }
    else
    {
        globus_common_i18n_get_string_by_key = globus_extension_lookup(
		    		&handle, &i18n_registry, "get_string_by_key");
        if(!globus_common_i18n_get_string_by_key)
        {
            /* too lazy to check the rc from globus_extension_activate */
            printf("globus_i18n library did not load. "
            "Set the GLOBUS_EXTENSION_DEBUG env for more info\n");
            return 0;
	}
        globus_extension_release(handle);
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
    globus_module_deactivate(GLOBUS_EXTENSION_MODULE);
    globus_module_deactivate(GLOBUS_THREAD_MODULE);
    globus_module_deactivate(GLOBUS_CALLBACK_MODULE);
    globus_module_deactivate(GLOBUS_ERROR_MODULE);
    
#ifdef TARGET_ARCH_WIN32
	// shutdown Winsock
	WSACleanup();
#endif

    return GLOBUS_SUCCESS;
}

static char *
globus_l_common_i18n_echo_string(
	       		char * locale,
		       	char * resource_name,
		       	char * key) 
{
    return key;
}

static char *
globus_l_common_i18n_get_string_by_module(
		char * locale,
		globus_module_descriptor_t * module,
		char * key)
{
    if (module != GLOBUS_NULL && 
        globus_common_i18n_get_string_by_key != GLOBUS_NULL)
    {
	return globus_common_i18n_get_string_by_key(
	    locale, module->module_name, key);
    }
    else
    {
        return key;
    }
}

char *
globus_common_i18n_get_string(
		globus_module_descriptor_t * module,
		char * key)
{
    return globus_l_common_i18n_get_string_by_module(NULL, module, key);
}




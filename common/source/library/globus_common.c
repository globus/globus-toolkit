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


/******************************************************************************
		   globus_common module activation functions
******************************************************************************/

static int
globus_l_common_activate(void)
{
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




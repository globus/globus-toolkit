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
#include "globus_module.h"
#include "globus_error.h"
#include "globus_callback.h"
#include "globus_thread_none.h"
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

  if ( globus_module_activate(GLOBUS_ERROR_MODULE) != GLOBUS_SUCCESS )
    {
      return GLOBUS_FAILURE;
    }

    if (globus_module_activate(GLOBUS_CALLBACK_MODULE) != GLOBUS_SUCCESS)
    {
      globus_module_deactivate (GLOBUS_ERROR_MODULE);

	return GLOBUS_FAILURE;
    }

    if (globus_module_activate(GLOBUS_THREAD_MODULE) != GLOBUS_SUCCESS)
    {
        globus_module_deactivate (GLOBUS_ERROR_MODULE);
	globus_module_deactivate(GLOBUS_CALLBACK_MODULE);
	
	return GLOBUS_FAILURE;
    }

    return GLOBUS_SUCCESS;
}


static int
globus_l_common_deactivate(void)
{
    int					rc;

    rc = GLOBUS_SUCCESS;
    
    if (globus_module_deactivate(GLOBUS_THREAD_MODULE) != GLOBUS_SUCCESS)
    {
	rc = GLOBUS_FAILURE;
    }

    if (globus_module_deactivate(GLOBUS_CALLBACK_MODULE) != GLOBUS_SUCCESS)
    {
	rc = GLOBUS_FAILURE;
    }

    if ( globus_module_deactivate(GLOBUS_ERROR_MODULE) != GLOBUS_SUCCESS)
    {
	rc = GLOBUS_FAILURE;
    }

#ifdef TARGET_ARCH_WIN32
	// shutdown Winsock
	WSACleanup();
#endif

    return rc;
    
}




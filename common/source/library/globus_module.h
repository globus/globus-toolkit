/******************************************************************************
globus_module.h

Description:

  XXX - fill this in

CVS Information:

  $Source$
  $Date$
  $Revision$
  $State$
  $Author$
******************************************************************************/

#if !defined(GLOBUS_INCLUDE_GLOBUS_MODULE)
#define GLOBUS_INCLUDE_GLOBUS_MODULE 1

/******************************************************************************
			     Include header files
******************************************************************************/
#include "globus_common_include.h"
  
EXTERN_C_BEGIN

/******************************************************************************
			       Type definitions
******************************************************************************/
typedef int (*globus_module_activation_func_t)(void);
typedef int (*globus_module_deactivation_func_t)(void);
typedef void (*globus_module_atexit_func_t)(void);
typedef void * (*globus_module_get_pointer_func_t)(void);

/*
 * this remains publicly exposed.  Used throughpout globus
 */
typedef struct
{
    char *				                    module_name;
    globus_module_activation_func_t	        activation_func;
    globus_module_deactivation_func_t	    deactivation_func;
    globus_module_atexit_func_t		        atexit_func;
    globus_module_get_pointer_func_t 	    get_pointer_func;
} globus_module_descriptor_t;

/******************************************************************************
			      Function prototypes
******************************************************************************/

/*
 * NOTE: all functions return either GLOBUS_SUCCESS or an error code
 */

/**
 *  Activate a module
 */
int
globus_module_activate(
    globus_module_descriptor_t *	        module_descriptor);

/**
 *  Deactivate a module
 */
int
globus_module_deactivate(
    globus_module_descriptor_t *	        module_descriptor);

/**
 *  deactivate all active modules
 */
int
globus_module_deactivate_all(void);

/**
 *  set an environment variable
 */
void
globus_module_setenv(
    char *                                  name,
    char *                                  value);

/**
 *  Get the value of an environment variable
 */
char *
globus_module_getenv(
    char *                                  name);

/**
 *  Get a module pointer
 */
void *
globus_module_get_module_pointer(
    globus_module_descriptor_t *            mod);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_MODULE */



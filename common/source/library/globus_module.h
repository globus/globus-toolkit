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
#ifndef SWIG
#define GLOBUS_INCLUDE_GLOBUS_MODULE 1

/******************************************************************************
			     Include header files
******************************************************************************/
#include "globus_common.h"

 
#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif
  
EXTERN_C_BEGIN

/* endif SWIG */
#endif

/******************************************************************************
			       Type definitions
******************************************************************************/
typedef int (*globus_module_activation_func_t)(void);
typedef int (*globus_module_deactivation_func_t)(void);
typedef void (*globus_module_atexit_func_t)(void);
typedef void * (*globus_module_get_pointer_func_t)(void);

typedef struct
{
    char *				module_name;
    globus_module_activation_func_t	activation_func;
    globus_module_deactivation_func_t	deactivation_func;
    globus_module_atexit_func_t		atexit_func;
    globus_module_get_pointer_func_t 	get_pointer_func;
} globus_module_descriptor_t;


/******************************************************************************
			      Function prototypes
******************************************************************************/

/*
 * NOTE: all functions return either GLOBUS_SUCCESS or an error code
 */

int
globus_module_activate(
    globus_module_descriptor_t *	module_descriptor);

int
globus_module_deactivate(
    globus_module_descriptor_t *	module_descriptor);

int
globus_module_deactivate_all(void);

void
globus_module_setenv(
    char * name,
    char * value);

char *
globus_module_getenv(
    char * name);

void *
globus_module_get_module_pointer(
    globus_module_descriptor_t *);


#ifndef SWIG
EXTERN_C_END

/* endif SWIG */
#endif

#endif /* GLOBUS_INCLUDE_GLOBUS_MODULE */

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
/* Because of the nested structure of the #includes, the following
 * #include of "globus_common.h" breaks the build, so it is commented
 * out.
 *
 * Michael Lebman
 * 5-28-02
 */
/* #include "globus_common.h" */
#include <stdio.h>
 
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

/******************************************************************************
			       Type definitions
******************************************************************************/
typedef int (*globus_module_activation_func_t)(void);
typedef int (*globus_module_deactivation_func_t)(void);
typedef void (*globus_module_atexit_func_t)(void);
typedef void * (*globus_module_get_pointer_func_t)(void);

typedef struct
{
    int                                 major;
    int                                 minor;
    /* these two members are reserved for internal Globus components */    
    unsigned long                       timestamp;
    int                                 branch_id;
} globus_version_t;

/*
 * this remains publicly exposed.  Used throughpout globus
 */
typedef struct
{
    char *				module_name;
    globus_module_activation_func_t	activation_func;
    globus_module_deactivation_func_t	deactivation_func;
    globus_module_atexit_func_t		atexit_func;
    globus_module_get_pointer_func_t 	get_pointer_func;
    globus_version_t *                  version;
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
    globus_module_descriptor_t *);

int
globus_module_get_version(
    globus_module_descriptor_t *	module_descriptor,
    globus_version_t *                  version);
    
void
globus_module_print_version(
    globus_module_descriptor_t *	module_descriptor,
    FILE *                              stream,
    globus_bool_t                       verbose);
    
void
globus_module_print_activated_versions(
    FILE *                              stream,
    globus_bool_t                       verbose);

void
globus_version_print(
    const char *                        name,
    const globus_version_t *            version,
    FILE *                              stream,
    globus_bool_t                       verbose);

/* The following #ifndef makes no sense and prevents proper compiling,
 * so I commented it out.
 *
 * Michael Lebman
 * 5-24-02
 */
/* #ifndef SWIG */

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_MODULE */



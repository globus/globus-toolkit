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
struct globus_module_descriptor_s;
typedef struct globus_module_descriptor_s globus_module_descriptor_t;

#include "globus_common_include.h"
#include "globus_error_generic.h"
#include <stdio.h>
  
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
    int                                 major;
    int                                 minor;
    /* these two members are reserved for internal Globus components */    
    unsigned long                       timestamp;
    int                                 branch_id;
} globus_version_t;

/*
 * this remains publicly exposed.  Used throughpout globus
 */
struct globus_module_descriptor_s
{
    char *				module_name;
    globus_module_activation_func_t	activation_func;
    globus_module_deactivation_func_t	deactivation_func;
    globus_module_atexit_func_t		atexit_func;
    globus_module_get_pointer_func_t 	get_pointer_func;
    globus_version_t *                  version;
    globus_error_print_friendly_t       friendly_error_func;
};

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
    globus_module_descriptor_t *        module_descriptor);

/**
 *  Deactivate a module
 */
int
globus_module_deactivate(
    globus_module_descriptor_t *        module_descriptor);

/**
 *  deactivate all active modules
 */
int
globus_module_deactivate_all(void);

/**
 * module must be deactivated in this call with
 * module_descriptor->deactivation_func();
 * (be sure module_descriptor->deactivation_func is !NULL)
 */
typedef
int
(*globus_module_deactivate_proxy_cb_t)(
    globus_module_descriptor_t *        module_descriptor,
    void *                              user_arg);

/**
 * this call registers a callback to be called to handle deactivation when
 * globus_module_deactivate() or globus_module_deactivate_all() is called
 * 
 * The callback is only respected for the first call to activate this module.
 * The purpose of these proxy calls is to allow 'private' module descriptors
 * that are activated by some other user function, but may still be affected
 * by deactivate_all().
 */
int
globus_module_activate_proxy(
    globus_module_descriptor_t *        module_descriptor,
    globus_module_deactivate_proxy_cb_t deactivate_cb,
    void *                              user_arg);

/**
 *  set an environment variable
 */
void
globus_module_setenv(
    const char *                        name,
    const char *                        value);

/**
 *  Get the value of an environment variable
 */
char *
globus_module_getenv(
    const char *                        name);

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


void
globus_module_set_args(
    int *                               argc,
    char ***                            argv);

void
globus_module_get_args(
    int **                              argc,
    char ****                           argv);

#ifndef SWIG
EXTERN_C_END
#endif

#endif /* GLOBUS_INCLUDE_GLOBUS_MODULE */



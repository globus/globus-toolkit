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

#ifndef GLOBUS_XIO_LOAD_INCLUDE
#define GLOBUS_XIO_LOAD_INCLUDE

#include "globus_xio_types.h"
#include "globus_common.h"

EXTERN_C_BEGIN

extern globus_extension_registry_t      globus_i_xio_driver_registry;
#define GLOBUS_XIO_DRIVER_REGISTRY &globus_i_xio_driver_registry

typedef
globus_result_t
(*globus_xio_driver_init_t)(
    globus_xio_driver_t *               out_driver);

typedef
void
(*globus_xio_driver_destroy_t)(
    globus_xio_driver_t                 driver);

typedef struct
{
    const char *                        name;
    globus_xio_driver_init_t            init;
    globus_xio_driver_destroy_t         destroy;
} globus_xio_driver_hook_t;

globus_result_t
globus_xio_driver_load(
    const char *                        driver_name,
    globus_xio_driver_t *               out_driver);

globus_result_t
globus_xio_driver_unload(
    globus_xio_driver_t                 driver);

/**
 * GlobusXIODefineDriver(
 *      label                           driver_name,
 *      globus_xio_driver_init_t        init_func,
 *      globus_xio_driver_destroy_t     destroy_func)
 * 
 *  NOTE: driver_name is not a string.  Just put the unquoted name there.
 *  This needs to precede use of GlobusXIO{Un}RegisterDriver()
 */
#define GlobusXIODefineDriver(driver_name, init_func, destroy_func)         \
globus_xio_driver_hook_t globus_i_xio_##driver_name##_hook =                \
{                                                                           \
    #driver_name,                                                           \
    init_func,                                                              \
    destroy_func,                                                           \
}
#define GlobusXIODeclareDriver(driver_name)                                 \
    extern globus_xio_driver_hook_t globus_i_xio_##driver_name##_hook
#define GlobusXIOMyDriver(driver_name)                                      \
    &globus_i_xio_##driver_name##_hook

/**
 * The following are just utility macros for extensions that contain only one
 * driver.  If your extension contains multiple drivers, you'll need to
 * define your own extension module and register all the drivers in that
 * module's activate function manually
 */
#define GlobusXIORegisterDriver(driver_name)                                \
    globus_extension_registry_add(                                          \
        GLOBUS_XIO_DRIVER_REGISTRY,                                         \
        (void *)#driver_name,                                               \
        GlobusXIOMyModule(driver_name),                                     \
        GlobusXIOMyDriver(driver_name))
#define GlobusXIOUnRegisterDriver(driver_name)                              \
    globus_extension_registry_remove(                                       \
        GLOBUS_XIO_DRIVER_REGISTRY,                                         \
        (void*)#driver_name)

#define GlobusXIODefineModule(driver_name)                                  \
    GlobusExtensionDefineModule(globus_xio_##driver_name##_driver)
#define GlobusXIODeclareModule(driver_name)                                 \
    GlobusExtensionDeclareModule(globus_xio_##driver_name##_driver)
#define GlobusXIOMyModule(driver_name)                                      \
    GlobusExtensionMyModule(globus_xio_##driver_name##_driver)
#define GlobusXIOExtensionName(driver_name)                                 \
    "globus_xio_" #driver_name "_driver"

#define GLOBUS_XIO_EXTENSION_FORMAT "globus_xio_%s_driver"

/* internal activate funcs */
int
globus_i_xio_load_init(void);

int
globus_i_xio_load_destroy(void);
    
EXTERN_C_END

#endif

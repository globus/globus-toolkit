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

#ifndef _GLOBUS_EXTENSION_
#define _GLOBUS_EXTENSION_

#include "globus_common_include.h"
#include "globus_module.h"
#include "globus_hashtable.h"

EXTERN_C_BEGIN

extern globus_module_descriptor_t       globus_i_extension_module;
#define GLOBUS_EXTENSION_MODULE (&globus_i_extension_module)

enum
{
    GLOBUS_EXTENSION_ERROR_OPEN_FAILED,
    GLOBUS_EXTENSION_ERROR_LOOKUP_FAILED
};

/**
 * Declare your module with the following.
 * 
 * Ex:
 * GlobusExtensionDefineModule(my_module) =
 * {
 *     "my_module",
 *     globus_l_my_module_activate,
 *     globus_l_my_module_deactivate,
 *     NULL,
 *     NULL,
 *     &local_version
 * };
 */
#ifndef GLOBUS_BUILTIN
#define GlobusExtensionDefineModule(name)                                   \
    globus_module_descriptor_t globus_extension_module
#define GlobusExtensionDeclareModule(name)                                  \
    extern globus_module_descriptor_t globus_extension_module
#define GlobusExtensionMyModule(name) &globus_extension_module
#else
#define GlobusExtensionDefineModule(name)                                   \
    globus_module_descriptor_t name##_module
#define GlobusExtensionDeclareModule(name)                                  \
    extern globus_module_descriptor_t name##_module
#define GlobusExtensionMyModule(name) &name##_module
#endif

/**
 * loads the shared library 'lib<extension_name>_<flavor>.so' from
 * $GLOBUS_LOCATION/lib (or other location in LD_LIBRARY_PATH
 * and activates the module defined within.
 * 
 * In the future, a configuration file will be supported allowing arbitrary
 * extension names to be mapped to a specific library name.
 * 
 * Also, when builtin (compiled in) extensions are supported, this will
 * activate those directly without needing to load the library.
 * 
 * Search order:
 *  - <extension_name> in mappings hash  XXX not implemented
 *      - mapped name in builtin hash    XXX not implemented
 *      - mapped name in dll hash        XXX not implemented
 *      - load mapped name               XXX not implemented
 *  - <extension_name> in builtin hash
 *  - <extension_name> in dll hash
 *  - load library
 *      if(strchr(<extension_name, '/'))
 *        - concatenate / + dirname(<entension_name>) +
 *              /lib + basename(<entension_name>) + _<flavor>.so
 *          to $GLOBUS_LOCATION/lib and
 *              each search path in mappings file XXX not implemented
 *          (eg, for <extension_name> == wsrf/services/CounterService, load
 *            $GLOBUS_LOCATION/lib/wsrf/services/libCounterService_gcc32dbg.so)
 *        - lib + basename(<entension_name>) + _<flavor>.so
 *          subject to LD_LIBRARY_PATH
 *      else
 *        - load lib<extension_name>_<build_flavor>
 *          subject to LD_LIBRARY_PATH
 */
int
globus_extension_activate(
    const char *                        extension_name);

int
globus_extension_deactivate(
    const char *                        extension_name);

typedef struct globus_l_extension_handle_s * globus_extension_handle_t;

typedef struct
{
    globus_hashtable_t                  table;
    globus_bool_t                       initialized;
    globus_bool_t                       user_hashing;
} globus_extension_registry_t;

/* these two calls are only to be called from within an extensions activate
 * and deactivate functions
 * 
 * the module in the add can either be GlobusExtensionMyModule(name),
 * some other module, or NULL.  It's purpose is to specify the module that
 * is associated with the error objects that might come from use of this
 * addition to the registry.
 * 
 * symbol is a char * by default.  the key can be changed by calling
 * globus_extension_registry_set_hashing() before it is accessed.
 * 
 * regardless, the memory pointed to by symbol must exist as long as the entry
 * is in the registry
 */
int
globus_extension_registry_add(
    globus_extension_registry_t *       registry,
    void *                              symbol,
    globus_module_descriptor_t *        module,
    void *                              data);

void *
globus_extension_registry_remove(
    globus_extension_registry_t *       registry,
    void *                              symbol);

int
globus_extension_registry_set_hashing(
    globus_extension_registry_t *       registry,
    globus_hashtable_hash_func_t        hash_func,
    globus_hashtable_keyeq_func_t       keyeq_func);
    

/**
 * Get the datum associated with symbol in this registry.
 * 
 * You MUST call globus_extension_release() when you are done using
 * the data.  the lookup() and release() calls handle the reference counting
 * that prevents an extension from being unloaded while things it provides are
 * being used.  Do NOT call release() until you are done accessing the data from * the lookup() call.
 * 
 * release() could potentially block as a result of module deactivation and
 * unloading.  ensuring that globus_extension_deactivate() is not called with
 * outstanding references will prevent that.
 * 
 * symbol is a char * by default.  the key can be changed by calling
 * globus_extension_registry_set_hashing() before it is accessed.
 */
void *
globus_extension_lookup(
    globus_extension_handle_t *         handle,
    globus_extension_registry_t *       registry,
    void *                              symbol);

void *
globus_extension_reference(
    globus_extension_handle_t           handle);

void
globus_extension_release(
    globus_extension_handle_t           handle);

globus_bool_t
globus_extension_error_match(
    globus_extension_handle_t           handle,
    globus_object_t *                   error,
    int                                 type);

typedef
globus_bool_t
(*globus_extension_error_match_cb_t)(
    globus_object_t *                   error,
    globus_module_descriptor_t *        module,
    void *                              type);

globus_bool_t
globus_extension_error_match_with_cb(
    globus_extension_handle_t           handle,
    globus_object_t *                   error,
    globus_extension_error_match_cb_t   callback,
    void *                              type);

/**
 * hopefully in the future, these functions will only be needed by generated
 * code
 */
int
globus_extension_register_builtin(
    const char *                        extension_name,
    globus_module_descriptor_t *        module_descriptor);

void
globus_extension_unregister_builtin(
    const char *                        extension_name);

typedef struct
{
    char *                              extension_name;
    globus_module_descriptor_t *        module_descriptor;
} globus_extension_builtin_t;

/* array of builtins, with null entry at end */
int
globus_extension_register_builtins(
    globus_extension_builtin_t *        builtins);

void
globus_extension_unregister_builtins(
    globus_extension_builtin_t *        builtins);

EXTERN_C_END

#endif

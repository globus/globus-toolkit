#ifndef _GLOBUS_EXTENSION_
#define _GLOBUS_EXTENSION_

#include "globus_common_include.h"
#include "globus_module.h"
#include "globus_hashtable.h"

EXTERN_C_BEGIN

extern globus_module_descriptor_t       globus_i_extension_module;
#define GLOBUS_EXTENSION_MODULE (&globus_i_extension_module)

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
#define GlobusExtensionDefineModule(name)                                   \
    globus_module_descriptor_t globus_extension_module

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
 *  - <extension_name> in builtin hash   XXX not implemented
 *  - <extension_name> in mappings hash  XXX not implemented
 *      - mapped name in builtin hash    XXX not implemented
 *      - mapped name in dll hash        XXX not implemented
 *      - load mapped name               XXX not implemented
 *  - lib<extension_name>_<build_flavor> in dll hash
 *  - load lib<extension_name>_<build_flavor>
 */
int
globus_extension_activate(
    const char *                        extension_name);

int
globus_extension_deactivate(
    const char *                        extension_name);

typedef struct
{
    globus_hashtable_t                  table;
    globus_bool_t                       initialized;
} globus_extension_registry_t;

/* these two calls are only to be called from within an extensions activate
 * and deactivate functions
 */
int
globus_extension_registry_add(
    globus_extension_registry_t *       registry,
    const char *                        symbol,
    void *                              data);

void *
globus_extension_registry_remove(
    globus_extension_registry_t *       registry,
    const char *                        symbol);

/**
 * Get the datum associated with symbol in this registry.
 * 
 * You MUST call globus_extension_registry_put() when you are done using
 * the data.  the get() and put() calls handle the reference counting that
 * prevents an extension from being unloaded while things it provides are
 * being used.
 */
void *
globus_extension_registry_get(
    globus_extension_registry_t *       registry,
    const char *                        symbol);

void
globus_extension_registry_put(
    globus_extension_registry_t *       registry,
    const char *                        symbol);

EXTERN_C_END

#endif

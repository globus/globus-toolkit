#include "globus_extension.h"
#include "globus_debug.h"
#include GLOBUS_THREAD_INCLUDE
#include "globus_thread_rmutex.h"
#include "globus_libc.h"
#include "ltdl.h"

/* provides local_version and build_flavor */
#include "version.h"

#ifdef WIN32
#define MY_LIB_EXT ".dll"
#else
#define MY_LIB_EXT ".so"
#endif

GlobusDebugDefine(GLOBUS_EXTENSION);

#define GlobusExtensionDebugPrintf(level, message)                          \
    GlobusDebugPrintf(GLOBUS_EXTENSION, level, message)

#define GlobusExtensionDebugEnter()                                         \
    GlobusExtensionDebugPrintf(                                             \
        GLOBUS_L_EXTENSION_DEBUG_TRACE,                                     \
        ("[%s] Entering\n", _globus_func_name))

#define GlobusExtensionDebugExit()                                          \
    GlobusExtensionDebugPrintf(                                             \
        GLOBUS_L_EXTENSION_DEBUG_TRACE,                                     \
        ("[%s] Exiting\n", _globus_func_name))

#define GlobusExtensionDebugExitWithError()                                 \
    GlobusExtensionDebugPrintf(                                             \
        GLOBUS_L_EXTENSION_DEBUG_TRACE,                                     \
        ("[%s] Exiting with error\n", _globus_func_name))

enum globus_l_extension_debug_levels
{
    GLOBUS_L_EXTENSION_DEBUG_TRACE      = 1,
    GLOBUS_L_EXTENSION_DEBUG_DLL        = 2
};

typedef struct
{
    /* contains library name only with no XXextensionXX or path */
    char *                              library_name;
    long                                ref;
    long                                module_ref;
    globus_module_descriptor_t *        module;
    lt_dlhandle                         dlhandle;
} globus_l_extension_module_t;

typedef struct globus_l_extension_handle_s
{
    globus_l_extension_module_t *       owner;
    globus_hashtable_t *                table;
    char *                              symbol;
    void *                              datum;
    long                                ref;
} globus_l_extension_handle_t;

static globus_thread_key_t              globus_l_extension_owner_key;
static globus_thread_key_t              globus_l_libtool_key;
static globus_rmutex_t                  globus_l_libtool_mutex;
static globus_rmutex_t                  globus_l_extension_mutex;
static globus_hashtable_t               globus_l_extension_dlls;
/*
static globus_hashtable_t               globus_l_extension_mappings;
static globus_hashtable_t               globus_l_extension_builtins;
*/

static
void
globus_l_libtool_mutex_lock(void)
{
    globus_rmutex_lock(&globus_l_libtool_mutex);
}

static
void
globus_l_libtool_mutex_unlock(void)
{
    globus_rmutex_unlock(&globus_l_libtool_mutex);
}

static
void
globus_l_libtool_set_error(
    const char *                        error)
{
    globus_thread_setspecific(globus_l_libtool_key, (void *) error);
}

static
const char *
globus_l_libtool_get_error(void)
{
    return (char *) globus_thread_getspecific(globus_l_libtool_key);
}

/**
 * load config file.  substitute $BUILD_FLAVOR for build_flavor,
 * Store full library pathname and library name only in mappings table.
 * 
 * builtins table will be loaded by external api (need lock)
 */
static
int
globus_l_extension_activate(void)
{
    static globus_bool_t                initialized = GLOBUS_FALSE;
    GlobusFuncName(globus_l_extension_activate);
    
    if(!initialized)
    {
        GlobusDebugInit(GLOBUS_EXTENSION, TRACE DLL);
        GlobusExtensionDebugEnter();
    
        globus_rmutex_init(&globus_l_libtool_mutex, NULL);
        globus_thread_key_create(&globus_l_libtool_key, NULL);
        
        if(lt_dlinit() != 0)
        {
            goto error_dlinit;
        }
        if(lt_dlmutex_register(
            globus_l_libtool_mutex_lock,
            globus_l_libtool_mutex_unlock,
            globus_l_libtool_set_error,
            globus_l_libtool_get_error) != 0)
        {
            goto error_dlmutex;
        }
        
        globus_hashtable_init(
            &globus_l_extension_dlls,
            32,
            globus_hashtable_string_hash,
            globus_hashtable_string_keyeq);
        globus_rmutex_init(&globus_l_extension_mutex, NULL);
        globus_thread_key_create(&globus_l_extension_owner_key, NULL);
        
        initialized = GLOBUS_TRUE;
        GlobusExtensionDebugExit();
    }
    
    return GLOBUS_SUCCESS;

error_dlmutex:
    lt_dlexit();
error_dlinit:
    GlobusExtensionDebugExitWithError();
    return GLOBUS_FAILURE;
}

/**
 * called locked 
 * 
 * dont call until ref goes to 0 or proxy deavtivate is called
 * (circumventing my deactivate procedure)
 */
static
void
globus_l_extension_shutdown_extension(
    globus_l_extension_module_t *       handle,
    globus_bool_t                       in_proxy)
{
    globus_module_descriptor_t *        module;
    GlobusFuncName(globus_l_extension_shutdown_extension);
    
    GlobusExtensionDebugEnter();
    
    if(!in_proxy)
    {
        if(handle->module)
        {
            /* this will cause this function to be re-entered to do the 
             * bottom half
             */
            globus_module_deactivate(handle->module);
            return;
        }
    }
    else if(handle->module)
    {
        module = handle->module;
        handle->module = NULL;
        globus_hashtable_remove(
            &globus_l_extension_dlls, handle->library_name);
        if(module->deactivation_func)
        {
            module->deactivation_func();
        }
    }
    
    /** if this is not zero, then we must have been called by the deactivate
     * proxy (on behalf of globus_module_deactivate_all() or someone getting
     * a hold of our module descriptor and deactivating it themself
     * 
     * this will be non-zero if users still have outstanding
     * references on our registries when that circumvented deactivate occurred.
     */
    if(handle->ref == 0)
    {
        lt_dlclose(handle->dlhandle);
        globus_free(handle->library_name);
        globus_free(handle);
    }
    
    GlobusExtensionDebugExit();
}

static
int
globus_l_extension_deactivate_proxy(
    globus_module_descriptor_t *        module,
    void *                              user_arg)
{
    globus_l_extension_module_t *       handle;
    GlobusFuncName(globus_l_extension_deactivate_proxy);
    
    GlobusExtensionDebugEnter();
    handle = (globus_l_extension_module_t *) user_arg;
    
    globus_rmutex_lock(&globus_l_extension_mutex);
    {
        handle->ref -= handle->module_ref;
        globus_l_extension_shutdown_extension(handle, GLOBUS_TRUE);
    }
    globus_rmutex_unlock(&globus_l_extension_mutex);
    
    GlobusExtensionDebugExit();
    return GLOBUS_SUCCESS;
}

int
globus_extension_activate(
    const char *                        extension_name)
{
    globus_l_extension_module_t *       handle;
    globus_l_extension_module_t *       last_handle;
    char                                library[1024];
    const char *                        dlerror;
    int                                 rc;
    GlobusFuncName(globus_extension_activate);
    
    GlobusExtensionDebugEnter();
    
    if(!extension_name)
    {
        goto error_param;
    }
    
    snprintf(
        library, 1024, "lib%s_%s" MY_LIB_EXT, extension_name, build_flavor);
    library[1023] = 0;
    
    globus_rmutex_lock(&globus_l_extension_mutex);
    {
        handle = (globus_l_extension_module_t *)
            globus_hashtable_lookup(&globus_l_extension_dlls, library);
        if(!handle)
        {
            handle = (globus_l_extension_module_t *)
                globus_malloc(sizeof(globus_l_extension_module_t));
            if(!handle)
            {
                goto error_alloc;
            }
            
            handle->module_ref = 1;
            handle->ref = 1;
            handle->library_name = globus_libc_strdup(library);
            if(!handle->library_name)
            {
                goto error_strdup;
            }
            
            handle->dlhandle = lt_dlopenext(handle->library_name);
            if(!handle->dlhandle)
            {
                GlobusExtensionDebugPrintf(
                    GLOBUS_L_EXTENSION_DEBUG_DLL,
                    ("Couldn't dlopen %s: %s\n",
                     handle->library_name,
                     (dlerror = lt_dlerror()) ? dlerror : "(null)"));
                goto error_dll;
            }
            
            handle->module = lt_dlsym(
                handle->dlhandle, "globus_extension_module");
            if(!handle->module)
            {
                GlobusExtensionDebugPrintf(
                    GLOBUS_L_EXTENSION_DEBUG_DLL,
                    ("Couldn't find module descriptor named "
                        "'globus_extension_module' in %s: %s\n",
                    handle->library_name,
                    (dlerror = lt_dlerror()) ? dlerror : "(null)"));
                goto error_module;
            }
            
            globus_hashtable_insert(
                &globus_l_extension_dlls, handle->library_name, handle);
                
            last_handle = (globus_l_extension_module_t *)
                globus_thread_getspecific(globus_l_extension_owner_key);
            globus_thread_setspecific(globus_l_extension_owner_key, handle);
            
            rc = globus_module_activate_proxy(
                handle->module, globus_l_extension_deactivate_proxy, handle);
            
            globus_thread_setspecific(
                globus_l_extension_owner_key, last_handle);
            if(rc != GLOBUS_SUCCESS)
            {
                goto error_activate;
            }
        }
        else
        {
            handle->module_ref++;
            handle->ref++;
        }
    }
    globus_rmutex_unlock(&globus_l_extension_mutex);
    
    GlobusExtensionDebugExit();
    return GLOBUS_SUCCESS;

error_activate:
    globus_hashtable_remove(
        &globus_l_extension_dlls, handle->library_name);
error_module:
    lt_dlclose(handle->dlhandle);
error_dll:
    globus_free(handle->library_name);
error_strdup:
    globus_free(handle);
error_alloc:
    globus_rmutex_unlock(&globus_l_extension_mutex);
error_param:
    GlobusExtensionDebugExitWithError();
    return GLOBUS_FAILURE;
}

int
globus_extension_deactivate(
    const char *                        extension_name)
{
    globus_l_extension_module_t *       handle;
    char                                library[1024];
    GlobusFuncName(globus_extension_deactivate);
    
    GlobusExtensionDebugEnter();
    
    if(!extension_name)
    {
        goto error_param;
    }
    
    snprintf(
        library, 1024, "lib%s_%s" MY_LIB_EXT, extension_name, build_flavor);
    library[1023] = 0;
    
    globus_rmutex_lock(&globus_l_extension_mutex);
    {
        handle = (globus_l_extension_module_t *)
            globus_hashtable_lookup(&globus_l_extension_dlls, library);
        if(!handle)
        {
            goto error_lookup;
        }
        
        handle->module_ref--;
        if(--handle->ref == 0)
        {
            globus_l_extension_shutdown_extension(handle, GLOBUS_FALSE);
        }
    }
    globus_rmutex_unlock(&globus_l_extension_mutex);
    
    GlobusExtensionDebugExit();
    return GLOBUS_SUCCESS;

error_lookup:
    globus_rmutex_unlock(&globus_l_extension_mutex);
error_param:
    GlobusExtensionDebugExitWithError();
    return GLOBUS_FAILURE;
}

int
globus_extension_registry_add(
    globus_extension_registry_t *       registry,
    const char *                        symbol,
    void *                              data)
{
    globus_l_extension_module_t *       owner;
    globus_l_extension_handle_t *       entry;
    GlobusFuncName(globus_extension_registry_add);
    
    GlobusExtensionDebugEnter();
    
    owner = (globus_l_extension_module_t *)
        globus_thread_getspecific(globus_l_extension_owner_key);
    if(!owner || !data || !symbol || !registry)
    {
        goto error_not_extension;
    }
    
    entry = (globus_l_extension_handle_t *)
        globus_malloc(sizeof(globus_l_extension_handle_t));
    if(!entry)
    {
        goto error_malloc;
    }
    
    entry->owner = owner;
    entry->table = &registry->table;
    entry->datum = data;
    entry->ref = 1;
    entry->symbol = globus_libc_strdup(symbol);
    if(!entry->symbol)
    {
        goto error_dup;
    }
    
    globus_rmutex_lock(&globus_l_extension_mutex);
    {
        if(!registry->initialized)
        {
            if(globus_hashtable_init(
                &registry->table,
                20,
                globus_hashtable_string_hash,
                globus_hashtable_string_keyeq) != GLOBUS_SUCCESS)
            {
                goto error_init;
            }
            
            registry->initialized = GLOBUS_TRUE;
        }
        
        if(globus_hashtable_insert(
            &registry->table, entry->symbol, entry) != GLOBUS_SUCCESS)
        {
            goto error_insert;
        }
    }
    globus_rmutex_unlock(&globus_l_extension_mutex);
    
    GlobusExtensionDebugExit();
    return GLOBUS_SUCCESS;

error_insert:
error_init:
    globus_rmutex_unlock(&globus_l_extension_mutex);
    globus_free(entry->symbol);
error_dup:
    globus_free(entry);
error_malloc:
error_not_extension:
    GlobusExtensionDebugExitWithError();
    return GLOBUS_FAILURE;
}

void *
globus_extension_registry_remove(
    globus_extension_registry_t *       registry,
    const char *                        symbol)
{
    globus_l_extension_handle_t *       entry;
    void *                              datum = NULL;
    GlobusFuncName(globus_extension_registry_remove);
    
    GlobusExtensionDebugEnter();
    
    globus_rmutex_lock(&globus_l_extension_mutex);
    {
        if(registry->initialized)
        {
            entry = (globus_l_extension_handle_t *)
                globus_hashtable_lookup(&registry->table, (void *) symbol);
            if(entry && entry->datum)
            {
                datum = entry->datum;
                entry->datum = NULL;
                if(--entry->ref == 0)
                {
                    globus_hashtable_remove(&registry->table, (void *) symbol);
                    globus_free(entry->symbol);
                    globus_free(entry);
                }
            }
        }
    }
    globus_rmutex_unlock(&globus_l_extension_mutex);
    
    GlobusExtensionDebugExit();
    return datum;
}

void *
globus_extension_lookup(
    globus_extension_handle_t *         handle,
    globus_extension_registry_t *       registry,
    const char *                        symbol)
{
    globus_l_extension_handle_t *       entry;
    void *                              datum = NULL;
    GlobusFuncName(globus_extension_registry_get);
    
    GlobusExtensionDebugEnter();
    
    if(!handle)
    {
        goto error_param;
    }
    
    *handle = NULL;
    if(!registry || !symbol)
    {
        goto error_param;
    }
    
    globus_rmutex_lock(&globus_l_extension_mutex);
    {
        if(registry->initialized)
        {
            entry = (globus_l_extension_handle_t *)
                globus_hashtable_lookup(&registry->table, (void *) symbol);
            if(entry && entry->datum)
            {
                datum = entry->datum;
                entry->ref++;
                entry->owner->ref++;
                
                *handle = entry;
            }
        }
    }
    globus_rmutex_unlock(&globus_l_extension_mutex);
    
    GlobusExtensionDebugExit();
    return datum;

error_param:
    GlobusExtensionDebugExitWithError();
    return NULL;
}

void
globus_extension_release(
    globus_extension_handle_t           handle)
{
    globus_l_extension_handle_t *       entry;
    globus_l_extension_module_t *       owner = NULL;
    GlobusFuncName(globus_extension_registry_put);
    
    GlobusExtensionDebugEnter();
    
    entry = handle;
    
    globus_rmutex_lock(&globus_l_extension_mutex);
    {
        if(entry)
        {
            if(--entry->owner->ref == 0)
            {
                owner = entry->owner;
            }
            
            if(--entry->ref == 0)
            {
                globus_hashtable_remove(entry->table, entry->symbol);
                globus_free(entry->symbol);
                globus_free(entry);
            }
            
            if(owner)
            {
                globus_l_extension_shutdown_extension(owner, GLOBUS_FALSE);
            }
        }
    }
    globus_rmutex_unlock(&globus_l_extension_mutex);
    
    GlobusExtensionDebugExit();
}

globus_module_descriptor_t              globus_i_extension_module =
{
    "globus_extension_module",
    globus_l_extension_activate,
    NULL,
    NULL,
    NULL,
    &local_version
};

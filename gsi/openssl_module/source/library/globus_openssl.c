#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_openssl.c
 * @author Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#include "globus_openssl.h"
#include "version.h"
#include "openssl/crypto.h"

static int
globus_l_openssl_activate(void);

static int
globus_l_openssl_deactivate(void);

static unsigned long
globus_l_openssl_thread_id(void);
    
static void
globus_l_openssl_locking_cb(
    int                                 mode,
    int                                 type,
    const char *                        file,
    int                                 line);

static globus_mutex_t *                 mutex_pool;

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t              globus_i_openssl_module =
{
    "globus_openssl",
    globus_l_openssl_activate,
    globus_l_openssl_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Module activation
 */
static
int
globus_l_openssl_activate(void)
{
    int                                 i;
    
    globus_module_activate(GLOBUS_COMMON_MODULE);

    mutex_pool = malloc(CRYPTO_num_locks() * sizeof(globus_mutex_t));

    for(i=0;i<CRYPTO_num_locks();i++)
    {
        globus_mutex_init(&(mutex_pool[i]),NULL);
    }

    CRYPTO_set_locking_callback(globus_l_openssl_locking_cb);
    CRYPTO_set_id_callback(globus_l_openssl_thread_id);

    OBJ_create("0.9.2342.19200300.100.1.1","USERID","userId");
    
    return GLOBUS_SUCCESS;
}
/* globus_l_openssl_activate() */

/**
 * Module deactivation
 *
 */
static
int
globus_l_openssl_deactivate(void)
{
    int                                 i;

    OBJ_cleanup();

    ERR_clear_error();
    
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);

    for (i=0; i<CRYPTO_num_locks(); i++)
    {
        globus_mutex_destroy(&(mutex_pool[i]));
    }

    free(mutex_pool);

    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return GLOBUS_SUCCESS;
}
/* globus_l_openssl_deactivate() */


/**
 * OpenSSL locking callback
 *
 */
static void
globus_l_openssl_locking_cb(
    int                                 mode,
    int                                 type,
    const char *                        file,
    int                                 line)
{
    if (mode & CRYPTO_LOCK)
    {
        globus_mutex_lock(&(mutex_pool[type]));
    }
    else
    {
        globus_mutex_unlock(&(mutex_pool[type]));
    }
}
/* globus_l_openssl_locking_cb() */

/**
 * OpenSSL thread id callback
 *
 */
static unsigned long
globus_l_openssl_thread_id(void)
{
    return (unsigned long) globus_thread_self();
}
/* globus_l_openssl_thread_id() */

#endif






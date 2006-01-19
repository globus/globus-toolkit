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
#include "globus_error_openssl.h"
#include "proxycertinfo.h"
#include "version.h"
#include "openssl/crypto.h"
#include "openssl/err.h"

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
    int                                 pci_NID;
    int                                 pci_old_NID;
    X509V3_EXT_METHOD *                 pci_x509v3_ext_meth = NULL;
    X509V3_EXT_METHOD *                 pci_old_x509v3_ext_meth = NULL;
    
    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);
    mutex_pool = malloc(CRYPTO_num_locks() * sizeof(globus_mutex_t));

    for(i=0;i<CRYPTO_num_locks();i++)
    {
        globus_mutex_init(&(mutex_pool[i]),NULL);
    }

    CRYPTO_set_locking_callback(globus_l_openssl_locking_cb);
    CRYPTO_set_id_callback(globus_l_openssl_thread_id);

    OBJ_create(ANY_LANGUAGE_OID,
               ANY_LANGUAGE_SN,
               ANY_LANGUAGE_LN);

    OBJ_create(IMPERSONATION_PROXY_OID,
               IMPERSONATION_PROXY_SN,
               IMPERSONATION_PROXY_LN);

    OBJ_create(INDEPENDENT_PROXY_OID,
               INDEPENDENT_PROXY_SN,
               INDEPENDENT_PROXY_LN);

    OBJ_create(LIMITED_PROXY_OID,
               LIMITED_PROXY_SN,
               LIMITED_PROXY_LN);
    
    pci_NID = OBJ_create(PROXYCERTINFO_OID,PROXYCERTINFO_SN,PROXYCERTINFO_LN);

    pci_old_NID = OBJ_create(PROXYCERTINFO_OLD_OID,
                             PROXYCERTINFO_OLD_SN,
                             PROXYCERTINFO_OLD_LN);

    pci_x509v3_ext_meth = PROXYCERTINFO_x509v3_ext_meth();
    pci_old_x509v3_ext_meth = PROXYCERTINFO_OLD_x509v3_ext_meth();

    /* this sets the pci NID in the static X509V3_EXT_METHOD struct */
    pci_x509v3_ext_meth->ext_nid = pci_NID;
    pci_old_x509v3_ext_meth->ext_nid = pci_old_NID;
    
    X509V3_EXT_add(pci_x509v3_ext_meth);
    X509V3_EXT_add(pci_old_x509v3_ext_meth);
    
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

    X509V3_EXT_cleanup();
    
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);

    for (i=0; i<CRYPTO_num_locks(); i++)
    {
        globus_mutex_destroy(&(mutex_pool[i]));
    }

    free(mutex_pool);

    globus_module_deactivate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);
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
#ifndef TARGET_ARCH_WIN32
    return (unsigned long) globus_thread_self();
#else
    return (unsigned long) globus_thread_get_threadID_as_long();
#endif
}
/* globus_l_openssl_thread_id() */

#endif






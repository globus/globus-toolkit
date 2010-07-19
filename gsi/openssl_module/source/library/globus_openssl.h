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

#ifndef GLOBUS_INCLUDE_GLOBUS_OPENSSL_H
#define GLOBUS_INCLUDE_GLOBUS_OPENSSL_H

#include "globus_common.h"

/**
 * @anchor globus_openssl
 * @mainpage Globus OpenSSL activation/deactivation
 *
 * The globus_openssl library is motivated by the desire to
 * make OpenSSL thread safe. This is done by allocating a mutex pool
 * and setting relevant callback functions in the module activation
 * functions. 
 *
 * Any program that uses OpenSSL functions must include
 * "globus_openssl.h". 
 *
 * @htmlonly
 * <a href="main.html" target="_top">View documentation without frames</a><br>
 * <a href="index.html" target="_top">View documentation with frames</a><br>
 * @endhtmlonly
 */


#ifndef EXTERN_C_BEGIN
#    ifdef __cplusplus
#        define EXTERN_C_BEGIN extern "C" {
#        define EXTERN_C_END }
#    else
#        define EXTERN_C_BEGIN
#        define EXTERN_C_END
#    endif
#endif

EXTERN_C_BEGIN


/**
 * @defgroup globus_openssl_activation Activation
 *
 * Globus OpenSSL uses standard Globus module activation and
 * deactivation. Before any OpenSSL functions are called, the
 * following function must be called:
 *
 * @code
 *      globus_module_activate(GLOBUS_OPENSSL_MODULE)
 * @endcode
 *
 *
 * This function returns GLOBUS_SUCCESS if OpenSSL was
 * successfully initialized, and you are therefore allowed to
 * subsequently call OpenSSL functions.  Otherwise, an error
 * code is returned, and OpenSSL functions should not
 * subsequently be called. This function may be called multiple times.
 *
 * To deactivate the OpenSSL module , the following function must be
 * called: 
 *
 * @code
 *    globus_module_deactivate(GLOBUS_OPENSSL_MODULE)
 * @endcode
 *
 * This function should be called once for each time OpenSSL
 * was activated. 
 *
 */

/** Module descriptor
 * @ingroup globus_openssl_activation
 * @hideinitializer
 */
#define GLOBUS_OPENSSL_MODULE (&globus_i_openssl_module)

extern
globus_module_descriptor_t		globus_i_openssl_module;

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_OPENSSL_H */













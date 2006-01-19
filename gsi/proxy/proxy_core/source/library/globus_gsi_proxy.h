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

#ifndef GLOBUS_INCLUDE_GLOBUS_GSI_PROXY_H
#define GLOBUS_INCLUDE_GLOBUS_GSI_PROXY_H

/**
 * @anchor globus_gsi_proxy_api   
 * @mainpage Globus GSI Proxy API
 *
 * The globus_gsi_proxy library is motivated by the desire to provide
 * a abstraction layer for the proxy creation and delegation
 * process. For background on this process please refer to the proxy
 * certificate profile draft.
 *
 * Any program that uses Globus GSI Proxy functions must include
 * "globus_gsi_proxy.h". 
 *
 * We envision the API being used in the following manner:
 *
 * <TABLE>
 * <TR><TD>Delegator:</TD>                     <TD>Delegatee:</TD></TR>
 * <TR><TD></TD>                               <TD>set desired cert info extension
 *                                                 in the handle by using the handle
 *                                                 set functions.</TD></TR> 
 * <TR><TD></TD>                               <TD>globus_gsi_proxy_create_req</TD></TR>
 * <TR><TD>globus_gsi_proxy_inquire_req</TD>   <TD></TD></TR>
 * <TR><TD>modify cert info extension by using
 *         handle set/get/clear functions.</TD><TD></TD></TR>
 * <TR><TD>globus_gsi_proxy_sign_req</TD>      <TD></TD></TR>
 * <TR><TD></TD>                               <TD>globus_gsi_proxy_assemble_cred</TD></TR>
 *</TABLE>
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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
#include "globus_gsi_credential.h"
#include "globus_error_generic.h"
#include "globus_error_openssl.h"
#include "openssl/evp.h"
#include "proxycertinfo.h"
#endif

/**
 * @defgroup globus_gsi_proxy_activation Activation
 *
 * Globus GSI Proxy uses standard Globus module activation and
 * deactivation. Before any Globus GSI Proxy functions are called, the
 * following function must be called:
 *
 * @code
 *      globus_module_activate(GLOBUS_GSI_PROXY_MODULE)
 * @endcode
 *
 *
 * This function returns GLOBUS_SUCCESS if Globus GSI Proxy was
 * successfully initialized, and you are therefore allowed to
 * subsequently call Globus GSI Proxy functions.  Otherwise, an error
 * code is returned, and Globus GSI Proxy functions should not be
 * subsequently called. This function may be called multiple times.
 *
 * To deactivate Globus GSI Proxy, the following function must be called:
 *
 * @code
 *    globus_module_deactivate(GLOBUS_GSI_PROXY_MODULE)
 * @endcode
 *
 * This function should be called once for each time Globus GSI Proxy
 * was activated. 
 *
 */

/** Module descriptor
 * @ingroup globus_gsi_proxy_activation
 * @hideinitializer
 */
#define GLOBUS_GSI_PROXY_MODULE (&globus_i_gsi_proxy_module)

extern
globus_module_descriptor_t		globus_i_gsi_proxy_module;

#define _PCSL(s) globus_common_i18n_get_string(\
		  GLOBUS_GSI_PROXY_MODULE, \
		  s)

/**
 * GSI Proxy Handle.
 * @ingroup globus_gsi_proxy_handle
 *
 * An GSI Proxy handle is used to associate state with a group of
 * operations. Handles can have immutable
 * @ref globus_gsi_proxy_handle_attrs_t "attributes"
 * associated with them. All proxy @link
 * globus_gsi_proxy_operations operations @endlink take a handle pointer
 * as a parameter.
 *
 * @see globus_gsi_proxy_handle_init(),
 * globus_gsi_proxy_handle_destroy(), globus_gsi_proxy_handle_attrs_t
 */

typedef struct globus_l_gsi_proxy_handle_s * 
                                        globus_gsi_proxy_handle_t;

/**
 * Handle Attributes.
 * @ingroup globus_gsi_proxy_handle_attrs
 * 
 * A GSI Proxy handle attributes type is used to associate immutable
 * parameter values with a @ref globus_gsi_proxy_handle_t handle.
 * A handle attributes object should be created with immutable parameters
 * and then passed to the proxy handle init 
 * function @ref globus_gsi_proxy_handle_init().
 *
 * @see globus_gsi_proxy_handle_t, @ref globus_gsi_proxy_handle_attrs
 */

typedef struct 
globus_l_gsi_proxy_handle_attrs_s *     globus_gsi_proxy_handle_attrs_t;


/**
 * @defgroup globus_gsi_proxy_handle Handle Management
 *
 * Create/Destroy/Modify a GSI Proxy Handle.
 *
 * Within the Globus GSI Proxy Libary, all proxy operations require a
 * handle parameter. Currently, only one proxy operation may be in
 * progress at once per proxy handle.
 *
 * This section defines operations to create, modify and destroy GSI
 * Proxy handles.
 */

#ifndef DOXYGEN

globus_result_t
globus_gsi_proxy_handle_init(
    globus_gsi_proxy_handle_t *         handle,
    globus_gsi_proxy_handle_attrs_t     handle_attrs);

globus_result_t
globus_gsi_proxy_handle_destroy(
    globus_gsi_proxy_handle_t           handle);

globus_result_t
globus_gsi_proxy_handle_get_req(
    globus_gsi_proxy_handle_t           handle,
    X509_REQ **                         req);

globus_result_t
globus_gsi_proxy_handle_set_req(
    globus_gsi_proxy_handle_t           handle,
    X509_REQ *                          req);

globus_result_t
globus_gsi_proxy_handle_get_private_key(
    globus_gsi_proxy_handle_t           handle,
    EVP_PKEY **                         proxy_key);

globus_result_t
globus_gsi_proxy_handle_set_private_key(
    globus_gsi_proxy_handle_t           handle,
    EVP_PKEY *                          proxy_key);

globus_result_t
globus_gsi_proxy_handle_get_type(
    globus_gsi_proxy_handle_t           handle,
    globus_gsi_cert_utils_cert_type_t * type);

globus_result_t
globus_gsi_proxy_handle_set_type(
    globus_gsi_proxy_handle_t           handle,
    globus_gsi_cert_utils_cert_type_t   type);


globus_result_t
globus_gsi_proxy_handle_get_time_valid(
    globus_gsi_proxy_handle_t           handle,
    int *                               time_valid);

globus_result_t
globus_gsi_proxy_handle_set_time_valid(
    globus_gsi_proxy_handle_t           handle,
    int                                 time_valid);

globus_result_t
globus_gsi_proxy_handle_set_policy(
    globus_gsi_proxy_handle_t           handle,
    unsigned char *                     policy_data,
    int                                 policy_length,
    int                                 policy_NID);

globus_result_t
globus_gsi_proxy_handle_get_policy(
    globus_gsi_proxy_handle_t           handle,
    unsigned char **                    policy_data,
    int *                               policy_length,
    int *                               policy_NID);

globus_result_t
globus_gsi_proxy_handle_set_pathlen(
    globus_gsi_proxy_handle_t           handle,
    long                                pathlen);

globus_result_t
globus_gsi_proxy_handle_get_pathlen(
    globus_gsi_proxy_handle_t           handle,
    int *                               pathlen);

globus_result_t
globus_gsi_proxy_handle_clear_cert_info(
    globus_gsi_proxy_handle_t           handle);

globus_result_t
globus_gsi_proxy_handle_get_proxy_cert_info(
    globus_gsi_proxy_handle_t           handle,
    PROXYCERTINFO **                    pci);

globus_result_t
globus_gsi_proxy_handle_set_proxy_cert_info(
    globus_gsi_proxy_handle_t           handle,
    PROXYCERTINFO *                     pci);

globus_result_t
globus_gsi_proxy_handle_get_common_name(
    globus_gsi_proxy_handle_t           handle,
    char **                             common_name);

globus_result_t
globus_gsi_proxy_handle_set_common_name(
    globus_gsi_proxy_handle_t           handle,
    char *                              common_name);

globus_result_t
globus_gsi_proxy_is_limited(
    globus_gsi_proxy_handle_t           handle,
    globus_bool_t *                     is_limited);

globus_result_t
globus_gsi_proxy_handle_set_is_limited(
    globus_gsi_proxy_handle_t           handle,
    globus_bool_t                       is_limited);

globus_result_t
globus_gsi_proxy_handle_get_signing_algorithm(
    globus_gsi_proxy_handle_t           handle,
    EVP_MD **                           algorithm);

globus_result_t
globus_gsi_proxy_handle_get_keybits(
    globus_gsi_proxy_handle_t           handle,
    int *                               key_bits);

globus_result_t
globus_gsi_proxy_handle_get_init_prime(
    globus_gsi_proxy_handle_t           handle,
    int *                               init_prime);

globus_result_t
globus_gsi_proxy_handle_get_clock_skew_allowable(
    globus_gsi_proxy_handle_t           handle,
    int *                               skew);

globus_result_t
globus_gsi_proxy_handle_get_key_gen_callback(
    globus_gsi_proxy_handle_t           handle,
    void                                (**callback)(int, int, void *));

#endif

/**
 * @defgroup globus_gsi_proxy_handle_attrs Handle Attributes
 *
 * Handle attributes are used to control additional features of the
 * GSI Proxy handle. These features are operation independent.
 *
 * Currently there are no attributes.
 *
 * @see globus_gsi_proxy_handle_t
 */

#ifndef DOXYGEN


globus_result_t
globus_gsi_proxy_handle_attrs_init(
    globus_gsi_proxy_handle_attrs_t *   handle_attrs);

globus_result_t
globus_gsi_proxy_handle_attrs_destroy(
    globus_gsi_proxy_handle_attrs_t     handle_attrs);

globus_result_t
globus_gsi_proxy_handle_attrs_copy(
    globus_gsi_proxy_handle_attrs_t     a,
    globus_gsi_proxy_handle_attrs_t *   b);

#endif

/**
 * @defgroup globus_gsi_proxy_operations Proxy Operations
 *
 * Initiate a proxy operation.
 *
 * This module contains the API functions for a user to request proxy
 * request generation, proxy request inspection and proxy request
 * signature. 
 */


#ifndef DOXYGEN

globus_result_t
globus_gsi_proxy_create_req(
    globus_gsi_proxy_handle_t           handle,
    BIO *                               output_bio);

globus_result_t
globus_gsi_proxy_inquire_req(
    globus_gsi_proxy_handle_t           handle,
    BIO *                               input_bio);

globus_result_t
globus_gsi_proxy_sign_req(
    globus_gsi_proxy_handle_t           handle,
    globus_gsi_cred_handle_t            issuer_credential,
    BIO *                               output_bio);

globus_result_t
globus_gsi_proxy_resign_cert(
    globus_gsi_proxy_handle_t           handle,
    globus_gsi_cred_handle_t            issuer_credential,
    globus_gsi_cred_handle_t            peer_credential,
    globus_gsi_cred_handle_t *          resigned_credential);

globus_result_t
globus_gsi_proxy_assemble_cred(
    globus_gsi_proxy_handle_t           handle,
    globus_gsi_cred_handle_t *          proxy_credential,
    BIO *                               input_bio);

globus_result_t
globus_gsi_proxy_create_signed(
    globus_gsi_proxy_handle_t           handle,
    globus_gsi_cred_handle_t            issuer,
    globus_gsi_cred_handle_t *          proxy_credential);

globus_result_t
globus_gsi_proxy_handle_attrs_set_keybits(
    globus_gsi_proxy_handle_attrs_t     handle_attrs,
    int                                 bits);

globus_result_t
globus_gsi_proxy_handle_attrs_get_keybits(
    globus_gsi_proxy_handle_attrs_t     handle_attrs,
    int *                               bits);

globus_result_t
globus_gsi_proxy_handle_attrs_set_init_prime(
    globus_gsi_proxy_handle_attrs_t     handle_attrs,
    int                                 prime);

globus_result_t
globus_gsi_proxy_handle_attrs_get_init_prime(
    globus_gsi_proxy_handle_attrs_t     handle_attrs,
    int *                               prime);    

globus_result_t
globus_gsi_proxy_handle_attrs_set_signing_algorithm(
    globus_gsi_proxy_handle_attrs_t     handle_attrs,
    EVP_MD *                            algorithm);

globus_result_t
globus_gsi_proxy_handle_attrs_get_signing_algorithm(
    globus_gsi_proxy_handle_attrs_t     handle_attrs,
    EVP_MD **                           algorithm);

globus_result_t
globus_gsi_proxy_handle_attrs_set_clock_skew_allowable(
    globus_gsi_proxy_handle_attrs_t     handle,
    int                                 skew);

globus_result_t
globus_gsi_proxy_handle_attrs_get_clock_skew_allowable(
    globus_gsi_proxy_handle_attrs_t     handle,
    int *                               skew);

globus_result_t
globus_gsi_proxy_handle_attrs_get_key_gen_callback(
    globus_gsi_proxy_handle_attrs_t     handle,
    void                                (**callback)(int,  int, void *));

globus_result_t
globus_gsi_proxy_handle_attrs_set_key_gen_callback(
    globus_gsi_proxy_handle_attrs_t     handle,
    void                                (*callback)(int,  int, void *));

#endif

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_GSI_PROXY_H */

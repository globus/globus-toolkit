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
 * @file globus_gsi_cert_utils.h
 * Globus GSI Cert Utils Library
 * @author Sam Lang
 * @author Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#ifndef GLOBUS_GSI_CERT_UTILS_H
#define GLOBUS_GSI_CERT_UTILS_H

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

#include "globus_common.h"

/**
 * @mainpage Globus GSI Certificate Handling Utilities
 *
 * The Globus GSI Certificate Handling Utilities library. This library contains
 * helper functions for dealing with certificates.
 *
 * - @ref globus_gsi_cert_utils_activation
 * - @ref globus_gsi_cert_utils
 * - @ref globus_gsi_cert_utils_constants
 */

/**
 * @defgroup globus_gsi_cert_utils_activation Activation
 *
 * Globus GSI Cert Utils uses standard Globus module activation and
 * deactivation.  Before any Globus GSI Cert Utils functions are called, the
 * following function must be called:
 *
 * @code
 *      globus_module_activate(GLOBUS_GSI_CERT_UTILS_MODULE)
 * @endcode
 *
 *
 * This function returns GLOBUS_SUCCESS if Globus GSI Credential was
 * successfully initialized, and you are therefore allowed to
 * subsequently call Globus GSI Cert Utils functions.  Otherwise, an error
 * code is returned, and Globus GSI Cert Utils functions should not be
 * subsequently called. This function may be called multiple times.
 *
 * To deactivate Globus GSI Cert Utils, the following function must be called:
 *
 * @code
 *    globus_module_deactivate(GLOBUS_GSI_CERT_UTILS_MODULE)
 * @endcode
 *
 * This function should be called once for each time Globus GSI Cert Utils
 * was activated. 
 *
 */

/**
 * Module descriptor
 * @ingroup globus_gsi_cert_utils_activation
 * @hideinitializer
 */
#define GLOBUS_GSI_CERT_UTILS_MODULE    (&globus_i_gsi_cert_utils_module)

extern 
globus_module_descriptor_t              globus_i_gsi_cert_utils_module;

#define _CUSL(s) globus_common_i18n_get_string(GLOBUS_GSI_CERT_UTILS_MODULE,\
		s)
/**
 * @defgroup globus_gsi_cert_utils Cert Utils Functions
 *
 * A generic set of utility functions for manipulating 
 * OpenSSL objects, such as X509 certificates.
 */

#ifndef DOXYGEN

#include "openssl/x509.h"
#include "openssl/asn1.h"
#include "globus_error_openssl.h"
#include "globus_gsi_cert_utils_constants.h"

#define GLOBUS_GSI_CERT_UTILS_IS_PROXY(cert_type) \
        (cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_IMPERSONATION_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_INDEPENDENT_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_LIMITED_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_RESTRICTED_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_RFC_IMPERSONATION_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_RFC_INDEPENDENT_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_RFC_LIMITED_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_RFC_RESTRICTED_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_LIMITED_PROXY)

#define GLOBUS_GSI_CERT_UTILS_IS_RFC_PROXY(cert_type) \
        (cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_RFC_IMPERSONATION_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_RFC_INDEPENDENT_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_RFC_LIMITED_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_RFC_RESTRICTED_PROXY)


#define GLOBUS_GSI_CERT_UTILS_IS_GSI_3_PROXY(cert_type) \
        (cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_IMPERSONATION_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_INDEPENDENT_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_LIMITED_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_RESTRICTED_PROXY)

#define GLOBUS_GSI_CERT_UTILS_IS_GSI_2_PROXY(cert_type) \
        (cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_LIMITED_PROXY)


#define GLOBUS_GSI_CERT_UTILS_IS_INDEPENDENT_PROXY(cert_type) \
        (cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_RFC_INDEPENDENT_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_INDEPENDENT_PROXY)

#define GLOBUS_GSI_CERT_UTILS_IS_RESTRICTED_PROXY(cert_type) \
        (cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_RFC_RESTRICTED_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_RESTRICTED_PROXY)

#define GLOBUS_GSI_CERT_UTILS_IS_LIMITED_PROXY(cert_type) \
        (cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_RFC_LIMITED_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_LIMITED_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_LIMITED_PROXY)

#define GLOBUS_GSI_CERT_UTILS_IS_IMPERSONATION_PROXY(cert_type) \
        (cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_RFC_IMPERSONATION_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_RFC_LIMITED_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_IMPERSONATION_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_LIMITED_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_PROXY || \
         cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_LIMITED_PROXY)


globus_result_t
globus_gsi_cert_utils_make_time(
    ASN1_UTCTIME *                      ctm,
    time_t *                            newtime);

globus_result_t
globus_gsi_cert_utils_get_base_name(
    X509_NAME *                         subject,
    STACK_OF(X509) *                    cert_chain);

globus_result_t
globus_gsi_cert_utils_get_cert_type(
    X509 *                              cert,
    globus_gsi_cert_utils_cert_type_t * type);

globus_result_t
globus_gsi_cert_utils_get_x509_name(
    char *                              subject_string,
    int                                 length,
    X509_NAME *                         x509_name);

int
globus_i_gsi_cert_utils_dn_cmp(
    const char *                        dn1,
    const char *                        dn2);


/* For backwards compatibility */

#define globus_gsi_cert_utils_create_string \
    globus_common_create_string

#define globus_gsi_cert_utils_create_nstring \
    globus_common_create_nstring

#define globus_gsi_cert_utils_v_create_string \
    globus_common_v_create_string

#define globus_gsi_cert_utils_v_create_nstring \
    globus_common_v_create_nstring

#endif /* DOXYGEN */

EXTERN_C_END

#endif /* GLOBUS_GSI_CERT_UTILS_H */

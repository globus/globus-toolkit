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
 * @file globus_i_gsi_proxy.h
 * Globus GSI Proxy Library
 * @author Sam Meder, Sam Lang
 *
 * $RCSfile$
 * $Revision$
 * $Date $
 */

#include "globus_gsi_proxy.h"
#include "proxycertinfo.h"
#include "globus_common.h"

#ifndef GLOBUS_I_INCLUDE_GSI_PROXY_H
#define GLOBUS_I_INCLUDE_GSI_PROXY_H

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

/* DEBUG MACROS */

#ifdef BUILD_DEBUG

extern int                              globus_i_gsi_proxy_debug_level;
extern FILE *                           globus_i_gsi_proxy_debug_fstream;

#define GLOBUS_I_GSI_PROXY_DEBUG(_LEVEL_) \
    (globus_i_gsi_proxy_debug_level >= (_LEVEL_))

#define GLOBUS_I_GSI_PROXY_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_PROXY_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf _MESSAGE_; \
        } \
    }

#define GLOBUS_I_GSI_PROXY_DEBUG_FNPRINTF(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_PROXY_DEBUG(_LEVEL_)) \
        { \
           char *                          _tmp_str_ = \
               globus_common_create_nstring _MESSAGE_; \
           globus_libc_fprintf(globus_i_gsi_proxy_debug_fstream, \
                               _tmp_str_); \
           globus_libc_free(_tmp_str_); \
        } \
    }

#define GLOBUS_I_GSI_PROXY_DEBUG_PRINT(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_PROXY_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_proxy_debug_fstream, _MESSAGE_); \
        } \
    }

#define GLOBUS_I_GSI_PROXY_DEBUG_PRINT_OBJECT(_LEVEL_, _OBJ_NAME_, _OBJ_) \
    { \
        if (GLOBUS_I_GSI_PROXY_DEBUG(_LEVEL_)) \
        { \
           _OBJ_NAME_##_print_fp(globus_i_gsi_proxy_debug_fstream, _OBJ_); \
        } \
    }

#else

#define GLOBUS_I_GSI_PROXY_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_PROXY_DEBUG_FNPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_PROXY_DEBUG_PRINT(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_PROXY_DEBUG_PRINT_OBJECT(_LEVEL_, _OBJ_NAME_, _OBJ_) {}

#endif

#define GLOBUS_I_GSI_PROXY_DEBUG_ENTER \
            GLOBUS_I_GSI_PROXY_DEBUG_FPRINTF( \
                1, (globus_i_gsi_proxy_debug_fstream, \
                    "%s entering\n", _function_name_))

#define GLOBUS_I_GSI_PROXY_DEBUG_EXIT \
            GLOBUS_I_GSI_PROXY_DEBUG_FPRINTF( \
                1, (globus_i_gsi_proxy_debug_fstream, \
                    "%s exiting\n", _function_name_))

/* ERROR MACROS */

#define GLOBUS_GSI_PROXY_OPENSSL_ERROR_RESULT(_RESULT_, \
                                              _ERRORTYPE_, _ERRORSTR_) \
    char *                              _tmp_string_ = \
        globus_common_create_string _ERRORSTR_; \
    _RESULT_ = globus_i_gsi_proxy_openssl_error_result( \
        _ERRORTYPE_, \
        __FILE__, \
        _function_name_, \
        __LINE__, \
        _tmp_string_, \
        NULL); \
    globus_libc_free(_tmp_string_)

#define GLOBUS_GSI_PROXY_ERROR_RESULT(_RESULT_, \
                                      _ERRORTYPE_, _ERRORSTR_) \
    char *                              _tmp_string_ = \
        globus_common_create_string _ERRORSTR_; \
    _RESULT_ = globus_i_gsi_proxy_error_result( \
        _ERRORTYPE_, \
        __FILE__, \
        _function_name_, \
        __LINE__, \
        _tmp_string_, \
        NULL); \
    globus_libc_free(_tmp_string_)

#define GLOBUS_GSI_PROXY_ERROR_CHAIN_RESULT(_RESULT_, \
                                            _ERRORTYPE_) \
    _RESULT_ = globus_i_gsi_proxy_error_chain_result( \
        (_RESULT_), \
        (_ERRORTYPE_), \
        __FILE__, \
        _function_name_, \
        __LINE__, \
        NULL, \
        NULL)

#define GLOBUS_GSI_PROXY_OPENSSL_LONG_ERROR_RESULT(_RESULT_, \
                                                   _ERRORTYPE_, \
                                                   _ERRORSTR_, \
                                                   _LONG_DESC_) \
    char *                              _tmp_string_ = \
        globus_common_create_string _ERRORSTR_; \
    _RESULT_ = globus_i_gsi_proxy_openssl_error_result( \
        _ERRORTYPE_, \
        __FILE__, \
        _function_name_, \
        __LINE__, \
        _tmp_string_, \
        _LONG_DESC_); \
    globus_libc_free(_tmp_string_)

#define GLOBUS_GSI_PROXY_LONG_ERROR_RESULT(_RESULT_, \
                                           _ERRORTYPE_, \
                                           _ERRORSTR_, \
                                           _LONG_DESC_) \
    char *                              _tmp_string_ = \
        globus_common_create_string _ERRORSTR_; \
    _RESULT_ = globus_i_gsi_proxy_error_result( \
        _ERRORTYPE_, \
        __FILE__, \
        _function_name_, \
        __LINE__, \
        _tmp_string_, \
        NULL, \
        _LONG_DESC_); \
    globus_libc_free(_tmp_string_)

#define GLOBUS_GSI_PROXY_LONG_ERROR_CHAIN_RESULT(_RESULT_, \
                                                 _ERRORTYPE_, \
                                                 _LONG_DESC_) \
    _RESULT_ = globus_i_gsi_proxy_error_chain_result( \
        _RESULT_, \
        _ERRORTYPE_, \
        __FILE__, \
        _function_name_, \
        __LINE__, \
        NULL, \
        _LONG_DESC_)

#include "globus_gsi_proxy_constants.h"

/**
 * Handle attributes.
 * @ingroup globus_gsi_credential_handle_attrs
 */

/**
 * GSI Proxy handle attributes implementation
 * @ingroup globus_gsi_proxy_handle
 * @internal
 *
 * This structure contains the attributes
 * of a proxy handle.
 */
typedef struct globus_l_gsi_proxy_handle_attrs_s
{
    /** 
     * The size of the keys to generate for
     * the certificate request
     */
    int                                 key_bits;
    /**
     * The initial prime to use for creating
     * the key pair
     */
    int                                 init_prime;
    /**
     * The signing algorithm to use for 
     * generating the proxy certificate
     */
    EVP_MD *                            signing_algorithm;
    /**
     * The clock skew (in seconds) allowed 
     * for the proxy certificate.  The skew
     * adjusts the validity time of the proxy cert.
     */
    int                                 clock_skew;
    /**
     * The callback for the creation of the public/private key
     * pair.
     */
    void (*key_gen_callback)(int, int, void *);

} globus_i_gsi_proxy_handle_attrs_t;

/**
 * GSI Proxy handle implementation
 * @ingroup globus_gsi_proxy_handle
 * @internal
 *
 * This structure contains all of the state associated with a proxy
 * handle.
 *
 * @see globus_proxy_handle_init(), globus_proxy_handle_destroy()
 */

typedef struct globus_l_gsi_proxy_handle_s
{
    /** The proxy request */
    X509_REQ *                          req;
    /** The proxy private key */
    EVP_PKEY *                          proxy_key;
    /** Proxy handle attributes */
    globus_gsi_proxy_handle_attrs_t     attrs;
    /** The proxy cert info extension used in the operations */
    PROXYCERTINFO *                     proxy_cert_info;    
    /** The number of minutes the proxy certificate is valid for */
    int                                 time_valid;
    /** The type of the generated proxy */
    globus_gsi_cert_utils_cert_type_t   type;
    /** The common name used for draft compliant proxies. If not set a random common name will be generated. */
    char *                              common_name;
} globus_i_gsi_proxy_handle_t;


/* used for printing the status of a private key generating algorithm */
void 
globus_i_gsi_proxy_create_private_key_cb(
    int                                 num1,
    int                                 num2,
    BIO *                               output);

globus_result_t
globus_i_gsi_proxy_set_pc_times(
    X509 *                              new_pc, 
    X509 *                              issuer_cert,
    int                                 clock_skew,
    int                                 time_valid);

globus_result_t
globus_i_gsi_proxy_set_subject(
    X509 *                              new_pc, 
    X509 *                              issuer_cert,
    char *                              common_name);

globus_result_t
globus_i_gsi_proxy_openssl_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc);

globus_result_t
globus_i_gsi_proxy_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc);

globus_result_t
globus_i_gsi_proxy_error_chain_result(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc);

EXTERN_C_END

#endif /* GLOBUS_I_INCLUDE_GSI_PROXY_H */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

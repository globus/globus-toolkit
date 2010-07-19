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
 * @file globus_i_gsi_system_config.h
 * @internal
 * Globus GSI Credential System Configuration Files
 * @author Sam Meder, Sam Lang
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#ifndef GLOBUS_I_GSI_SYSTEM_CONFIG_H
#define GLOBUS_I_GSI_SYSTEM_CONFIG_H

#include "globus_common.h"
#include "globus_gsi_system_config_constants.h"
#include "globus_gsi_system_config.h"

/* DEBUG MACROS */

extern int                              globus_i_gsi_sysconfig_debug_level;
extern FILE *                           globus_i_gsi_sysconfig_debug_fstream;

#ifdef BUILD_DEBUG

#define GLOBUS_I_GSI_SYSCONFIG_DEBUG(_LEVEL_) \
    (globus_i_gsi_sysconfig_debug_level >= (_LEVEL_))

#define GLOBUS_I_GSI_SYSCONFIG_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_SYSCONFIG_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf _MESSAGE_; \
        } \
    }

#define GLOBUS_I_GSI_SYSCONFIG_DEBUG_FNPRINTF(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_SYSCONFIG_DEBUG(_LEVEL_)) \
        { \
           char *                          _tmp_str_ = \
               globus_common_create_nstring _MESSAGE_; \
           globus_libc_fprintf(globus_i_gsi_sysconfig_debug_fstream, \
                               _tmp_str_); \
           globus_libc_free(_tmp_str_); \
        } \
    }

#define GLOBUS_I_GSI_SYSCONFIG_DEBUG_PRINT(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_SYSCONFIG_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_sysconfig_debug_fstream, \
                               _MESSAGE_); \
        } \
    }

#define GLOBUS_I_GSI_SYSCONFIG_DEBUG_PRINT_OBJECT(_LEVEL_, _OBJ_NAME_, _OBJ_) \
    { \
        if (GLOBUS_I_GSI_SYSCONFIG_DEBUG(_LEVEL_)) \
        { \
           _OBJ_NAME_##_print_fp(globus_i_gsi_sysconfig_debug_fstream, \
                                 _OBJ_); \
        } \
    }

#else

#define GLOBUS_I_GSI_SYSCONFIG_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_SYSCONFIG_DEBUG_FNPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_SYSCONFIG_DEBUG_PRINT(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_SYSCONFIG_DEBUG_PRINT_OBJECT(_LEVEL_, \
                                                  _OBJ_NAME_, _OBJ_) {}

#endif

#define GLOBUS_I_GSI_SYSCONFIG_DEBUG_ENTER \
            GLOBUS_I_GSI_SYSCONFIG_DEBUG_FPRINTF( \
                1, (globus_i_gsi_sysconfig_debug_fstream, \
                    "%s entering\n", _function_name_))

#define GLOBUS_I_GSI_SYSCONFIG_DEBUG_EXIT \
            GLOBUS_I_GSI_SYSCONFIG_DEBUG_FPRINTF( \
                2, (globus_i_gsi_sysconfig_debug_fstream, \
                    "%s exiting\n", _function_name_))

/* ERROR MACROS */

#define GLOBUS_GSI_SYSCONFIG_OPENSSL_ERROR_RESULT(_RESULT_,  \
                                                  _ERRORTYPE_, \
                                                  _ERRSTR_) \
    { \
        char *                          _tmp_str_ = \
            globus_common_create_string _ERRSTR_; \
        _RESULT_ = globus_i_gsi_sysconfig_openssl_error_result(_ERRORTYPE_,  \
                                                          __FILE__, \
                                                          _function_name_, \
                                                          __LINE__, \
                                                          _tmp_str_, \
                                                          NULL); \
        globus_libc_free(_tmp_str_); \
    }

#define GLOBUS_GSI_SYSCONFIG_ERROR_RESULT(_RESULT_, _ERRORTYPE_, _ERRSTR_) \
    { \
        char *                          _tmp_str_ = \
            globus_common_create_string _ERRSTR_; \
        _RESULT_ = globus_i_gsi_sysconfig_error_result(_ERRORTYPE_, \
                                                  __FILE__, \
                                                  _function_name_, \
                                                  __LINE__, \
                                                  _tmp_str_, \
                                                  NULL); \
        globus_libc_free(_tmp_str_); \
    }

#define GLOBUS_GSI_SYSCONFIG_ERROR_CHAIN_RESULT(_TOP_RESULT_, _ERRORTYPE_) \
    _TOP_RESULT_ = globus_i_gsi_sysconfig_error_chain_result(_TOP_RESULT_, \
                                                        _ERRORTYPE_, \
                                                        __FILE__, \
                                                        _function_name_, \
                                                        __LINE__, \
                                                        NULL, \
                                                        NULL)

#define GLOBUS_GSI_SYSCONFIG_OPENSSL_LONG_ERROR_RESULT(_RESULT_, \
                                                       _ERRORTYPE_, \
                                                       _ERRSTR_, \
                                                       _LONG_DESC_) \
    { \
        char *                          _tmp_str_ = \
            globus_common_create_string _ERRSTR_; \
        _RESULT_ = globus_i_gsi_sysconfig_openssl_error_result(_ERRORTYPE_, \
                                                          __FILE__, \
                                                          _function_name_, \
                                                          __LINE__, \
                                                          _tmp_str_, \
                                                          _LONG_DESC_); \
        globus_libc_free(_tmp_str_); \
    }

#define GLOBUS_GSI_SYSCONFIG_LONG_ERROR_RESULT(_RESULT_, \
                                               _ERRORTYPE_, \
                                               _ERRSTR_, \
                                               _LONG_DESC_) \
    { \
        char *                          _tmp_str_ = \
            globus_common_create_string _ERRSTR_; \
        _RESULT_ = globus_i_gsi_sysconfig_error_result(_ERRORTYPE_, \
                                                       __FILE__, \
                                                       _function_name_, \
                                                       __LINE__, \
                                                       _tmp_str_, \
                                                       _LONG_DESC_); \
        globus_libc_free(_tmp_str_); \
    }

#define GLOBUS_GSI_SYSCONFIG_LONG_ERROR_CHAIN_RESULT(_TOP_RESULT_, \
                                                     _ERRORTYPE_, \
                                                     _LONG_DESC_) \
    _TOP_RESULT_ = globus_i_gsi_sysconfig_error_chain_result(_TOP_RESULT_, \
                                                             _ERRORTYPE_, \
                                                             __FILE__, \
                                                             _function_name_, \
                                                             __LINE__, \
                                                             NULL, \
                                                             _LONG_DESC_)

#define GLOBUS_GSI_SYSCONFIG_FILE_DOES_NOT_EXIST(_RESULT) \
    (globus_error_match(globus_error_peek(_RESULT), \
                        GLOBUS_GSI_SYSCONFIG_MODULE, \
                        GLOBUS_GSI_SYSCONFIG_ERROR_FILE_DOES_NOT_EXIST) == \
     GLOBUS_TRUE)

#define GLOBUS_GSI_SYSCONFIG_FILE_HAS_BAD_PERMISSIONS(_RESULT) \
    (globus_error_match(globus_error_peek(_RESULT), \
                        GLOBUS_GSI_SYSCONFIG_MODULE, \
                        GLOBUS_GSI_SYSCONFIG_ERROR_FILE_BAD_PERMISSIONS) == \
     GLOBUS_TRUE)

#define GLOBUS_GSI_SYSCONFIG_FILE_ZERO_LENGTH(_RESULT) \
    (globus_error_match(globus_error_peek(_RESULT), \
                        GLOBUS_GSI_SYSCONFIG_MODULE, \
                        GLOBUS_GSI_SYSCONFIG_ERROR_FILE_ZERO_LENGTH) == \
     GLOBUS_TRUE)

extern char *                       globus_l_gsi_sysconfig_error_strings[];
extern char *                       globus_l_gsi_sysconfig_status_strings[];

globus_result_t
globus_i_gsi_sysconfig_create_cert_dir_string(
    char **                             cert_dir,
    char **                             cert_dir_value,
    const char *                        format,
    ...);

globus_result_t
globus_i_gsi_sysconfig_create_cert_string(
    char **                             cert_string,
    char **                             cert_string_value,
    const char *                        format,
    ...);

globus_result_t
globus_i_gsi_sysconfig_create_key_string(
    char **                             key_string,
    char **                             key_string_value,
    const char *                        format,
    ...);

globus_result_t
globus_i_gsi_sysconfig_error_chain_result(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc);

globus_result_t
globus_i_gsi_sysconfig_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc);

globus_result_t
globus_i_gsi_sysconfig_openssl_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc);


#endif /* GLOBUS_I_GSI_SYSTEM_CONFIG_H */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_i_gsi_cert_utils.h
 * Globus GSI Cert Utils Library
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#ifndef GLOBUS_I_GSI_CERT_UTILS_H
#define GLOBUS_I_GSI_CERT_UTILS_H

#include "globus_gsi_cert_utils.h"

/* DEBUG MACROS */

#ifdef BUILD_DEBUG

extern int                              globus_i_gsi_cert_utils_debug_level;
extern FILE *                           globus_i_gsi_cert_utils_debug_fstream;

#define GLOBUS_I_GSI_CERT_UTILS_DEBUG(_LEVEL_) \
    (globus_i_gsi_cert_utils_debug_level >= (_LEVEL_))

#define GLOBUS_I_GSI_CERT_UTILS_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_CERT_UTILS_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf _MESSAGE_; \
        } \
    }

#define GLOBUS_I_GSI_CERT_UTILS_DEBUG_FNPRINTF(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_CERT_UTILS_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf _MESSAGE_; \
        } \
    }

#define GLOBUS_I_GSI_CERT_UTILS_DEBUG_PRINT(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_CERT_UTILS_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_cert_utils_debug_fstream, \
                               _MESSAGE_); \
        } \
    }

#define GLOBUS_I_GSI_CERT_UTILS_DEBUG_PRINT_OBJECT(_LEVEL_, \
                                                   _OBJ_NAME_, \
                                                   _OBJ_) \
    { \
        if (GLOBUS_I_GSI_CERT_UTILS_DEBUG(_LEVEL_)) \
        { \
           _OBJ_NAME_##_print_fp(globus_i_gsi_cert_utils_debug_fstream, \
                                 _OBJ_); \
        } \
    }

#else

#define GLOBUS_I_GSI_CERT_UTILS_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_CERT_UTILS_DEBUG_FNPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_CERT_UTILS_DEBUG_PRINT(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_CERT_UTILS_DEBUG_PRINT_OBJECT(_LEVEL_, \
                                                   _OBJ_NAME_, _OBJ_) {}

#endif
         
#define GLOBUS_I_GSI_CERT_UTILS_DEBUG_ENTER \
            GLOBUS_I_GSI_CERT_UTILS_DEBUG_FPRINTF( \
                1, (globus_i_gsi_cert_utils_debug_fstream, \
                    "%s entering\n", _function_name_))

#define GLOBUS_I_GSI_CERT_UTILS_DEBUG_EXIT \
            GLOBUS_I_GSI_CERT_UTILS_DEBUG_FPRINTF( \
                2, (globus_i_gsi_cert_utils_debug_fstream, \
                    "%s exiting\n", _function_name_))

/* ERROR MACROS */

#define GLOBUS_GSI_CERT_UTILS_OPENSSL_ERROR_RESULT(_RESULT_, \
                                                   _ERRORTYPE_, _ERRSTR_) \
    {                                                                         \
        char *                          _tmp_str_ =                           \
            globus_i_gsi_cert_utils_create_string _ERRSTR_;                   \
        _RESULT_ = globus_i_gsi_cert_utils_openssl_error_result(_ERRORTYPE_,  \
                                                          __FILE__,           \
                                                          _function_name_,    \
                                                          __LINE__,           \
                                                          _tmp_str_);         \
        globus_libc_free(_tmp_str_);                                          \
    }

#define GLOBUS_GSI_CERT_UTILS_ERROR_RESULT(_RESULT_, _ERRORTYPE_, _ERRSTR_) \
    {                                                                       \
        char *                          _tmp_str_ =                         \
            globus_i_gsi_cert_utils_create_string _ERRSTR_;                 \
        _RESULT_ = globus_i_gsi_cert_utils_error_result(_ERRORTYPE_,        \
                                                  __FILE__,                 \
                                                  _function_name_,          \
                                                  __LINE__,                 \
                                                  _tmp_str_);               \
        globus_libc_free(_tmp_str_);                                        \
    }

#define GLOBUS_GSI_CERT_UTILS_ERROR_CHAIN_RESULT(_TOP_RESULT_, _ERRORTYPE_) \
    _TOP_RESULT_ = globus_i_gsi_cert_utils_error_chain_result(_TOP_RESULT_, \
                                                        _ERRORTYPE_,        \
                                                        __FILE__,           \
                                                        _function_name_,    \
                                                        __LINE__,           \
                                                        NULL)

extern char *                    globus_l_gsi_cert_utils_error_strings[];



globus_result_t
globus_i_gsi_cert_utils_openssl_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        long_desc);

globus_result_t
globus_i_gsi_cert_utils_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        long_desc);

globus_result_t
globus_i_gsi_cert_utils_error_chain_result(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        long_desc);

char *
globus_i_gsi_cert_utils_create_string(
    const char *                        format,
    ...);

char *
globus_i_gsi_cert_utils_v_create_string(
    const char *                        format,
    va_list                             ap);

EXTERN_C_END

#endif /* GLOBUS_I_GSI_CERT_UTILS_H */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_I_ERROR_OPENSSL_H
#define GLOBUS_I_ERROR_OPENSSL_H

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_i_error_errno.c
 * Globus Generic Error
 *
 * $RCSfile$$
 * $Revision$
 * $Date$
 * 
 * @author Sam Lang
 */

#include "globus_error_openssl.h"


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

/* debug macros */

#ifdef BUILD_DEBUG

extern int globus_i_gsi_openssl_error_debug_level;

#define GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG(_LEVEL_) \
    (globus_i_gsi_openssl_error_debug_level >= (_LEVEL_))

#define GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf _MESSAGE_; \
        } \
    }


#define GLOBUS_I_GSI_GSSAPI_DEBUG_FNPRINTF(_LEVEL_, _MESSAGE_) \
{ \
        if (GLOBUS_I_GSI_GSSAPI_DEBUG(_LEVEL_)) \
        { \
           char *                       _tmp_str_ = \
               globus_common_create_nstring _MESSAGE_; \
           globus_libc_fprintf(globus_i_gsi_gssapi_debug_fstream, \
                               _tmp_str_); \
           globus_libc_free(_tmp_str_); \
        } \
}

#define GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_ENTER \
            GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_FPRINTF( \
                1, (stderr, "%s entering\n", _function_name_))

#define GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_EXIT \
            GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_FPRINTF( \
                1, (stderr, "%s exiting\n", _function_name_))

#else

#define GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_FNPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_ENTER {}
#define GLOBUS_I_GSI_OPENSSL_ERROR_DEBUG_EXIT  {}

#endif


typedef struct globus_l_openssl_error_handle_s 
{
    unsigned long                       error_code;
    const char *                        filename;
    int                                 linenumber;
    const char *                        data;
    int                                 flags;
} globus_i_openssl_error_handle_t;

globus_openssl_error_handle_t
globus_i_openssl_error_handle_init();

void
globus_i_openssl_error_handle_destroy(
    globus_openssl_error_handle_t       handle);

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

#endif /* GLOBUS_I_ERROR_OPENSSL_H */

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
 * @file globus_i_callout.h
 * Globus Callout Infrastructure
 * @author Sam Meder
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#ifndef _GLOBUS_I_CALLOUT_H_
#define _GLOBUS_I_CALLOUT_H_

#include "globus_callout.h"
#if !defined(WIN32) && !defined(BUILD_STATIC_ONLY)
#include <ltdl.h>
#endif

/* DEBUG MACROS */

#ifdef BUILD_DEBUG

extern int                              globus_i_callout_debug_level;
extern FILE *                           globus_i_callout_debug_fstream;

#define GLOBUS_I_CALLOUT_DEBUG(_LEVEL_) \
    (globus_i_callout_debug_level >= (_LEVEL_))

#define GLOBUS_I_CALLOUT_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf _MESSAGE_; \
        } \
    }

#define GLOBUS_I_CALLOUT_DEBUG_FNPRINTF(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           char *                          _tmp_str_ = \
               globus_common_create_nstring _MESSAGE_; \
           globus_libc_fprintf(globus_i_callout_debug_fstream, \
                               _tmp_str_); \
           globus_libc_free(_tmp_str_); \
        } \
    }

#define GLOBUS_I_CALLOUT_DEBUG_PRINT(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_callout_debug_fstream, \
                               _MESSAGE_); \
        } \
    }

#define GLOBUS_I_CALLOUT_DEBUG_PRINT_OBJECT(_LEVEL_, _OBJ_NAME_, _OBJ_) \
    { \
        if (GLOBUS_I_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           _OBJ_NAME_##_print_fp(globus_i_callout_debug_fstream, _OBJ_); \
        } \
    }

#else

#define GLOBUS_I_CALLOUT_DEBUG(_LEVEL_) 0
#define GLOBUS_I_CALLOUT_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_CALLOUT_DEBUG_FNPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_CALLOUT_DEBUG_PRINT(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_CALLOUT_DEBUG_PRINT_OBJECT(_LEVEL_, _OBJ_NAME_, _OBJ_) {}

#endif
         
#define GLOBUS_I_CALLOUT_DEBUG_ENTER \
            GLOBUS_I_CALLOUT_DEBUG_FPRINTF( \
                1, (globus_i_callout_debug_fstream, \
                    "%s entering\n", _function_name_))

#define GLOBUS_I_CALLOUT_DEBUG_EXIT \
            GLOBUS_I_CALLOUT_DEBUG_FPRINTF( \
                2, (globus_i_callout_debug_fstream, \
                    "%s exiting\n", _function_name_))

/* ERROR MACROS */

#define GLOBUS_CALLOUT_ERROR_RESULT(_RESULT_, _ERRORTYPE_, _ERRSTR_) \
    { \
        char *                          _tmp_str_ = \
            globus_common_create_string _ERRSTR_; \
        _RESULT_ = globus_i_callout_error_result(_ERRORTYPE_, \
                                                  __FILE__, \
                                                  _function_name_, \
                                                  __LINE__, \
                                                  _tmp_str_, \
                                                  NULL); \
        globus_libc_free(_tmp_str_); \
    }

#define GLOBUS_CALLOUT_ERROR_CHAIN_RESULT(_TOP_RESULT_, _ERRORTYPE_) \
    _TOP_RESULT_ = globus_i_callout_error_chain_result( \
                       _TOP_RESULT_, \
                       _ERRORTYPE_, \
                       __FILE__, \
                       _function_name_, \
                       __LINE__, \
                       NULL, \
                       NULL)


#define GLOBUS_CALLOUT_LONG_ERROR_RESULT(_RESULT_, \
                                              _ERRORTYPE_, \
                                              _ERRSTR_, \
                                              _LONG_DESC_) \
    { \
        char *                          _tmp_str_ = \
            globus_common_create_string _ERRSTR_; \
        _RESULT_ = globus_i_callout_error_result(_ERRORTYPE_, \
                                                  __FILE__, \
                                                  _function_name_, \
                                                  __LINE__, \
                                                  _tmp_str_, \
                                                  _LONG_DESC_); \
        globus_libc_free(_tmp_str_); \
    }

#define GLOBUS_CALLOUT_LONG_ERROR_CHAIN_RESULT(_TOP_RESULT_, \
                                                    _ERRORTYPE_, \
                                                    _LONG_DESC_) \
    _TOP_RESULT_ = globus_i_callout_error_chain_result( \
                       _TOP_RESULT_, \
                       _ERRORTYPE_, \
                       __FILE__, \
                       _function_name_, \
                       __LINE__, \
                       NULL, \
                       _LONG_DESC_)

#define GLOBUS_CALLOUT_MALLOC_ERROR(_RESULT_) \
    { \
        char *                          _tmp_str_ = \
        globus_l_callout_error_strings[ \
            GLOBUS_CALLOUT_ERROR_OUT_OF_MEMORY]; \
        _RESULT_ = globus_error_put( \
            globus_error_wrap_errno_error( \
                GLOBUS_CALLOUT_MODULE, \
                errno, \
                GLOBUS_CALLOUT_ERROR_OUT_OF_MEMORY, \
                __FILE__, \
                _function_name_, \
                __LINE__, \
                "%s", \
                _tmp_str_)); \
    }

#define GLOBUS_CALLOUT_ERRNO_ERROR_RESULT(_RESULT_, \
                                          _ERRORTYPE_, _ERRORSTR_) \
    { \
        char *                          _tmp_str_ = \
             globus_common_create_string _ERRORSTR_; \
        _RESULT_ = globus_error_put( \
            globus_error_wrap_errno_error( \
                GLOBUS_CALLOUT_MODULE, \
                errno, \
                _ERRORTYPE_, \
                __FILE__, \
                _function_name_, \
                __LINE__, \
                "%s", \
                _tmp_str_)); \
        globus_libc_free(_tmp_str_); \
    }

extern char *                    globus_l_callout_error_strings[];

globus_result_t
globus_i_callout_error_result(
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc);

globus_result_t
globus_i_callout_error_chain_result(
    globus_result_t                     chain_result,
    int                                 error_type,
    const char *                        filename,
    const char *                        function_name,
    int                                 line_number,
    const char *                        short_desc,
    const char *                        long_desc);


/**
 * Globus Callout Implementation
 * @ingroup globus_callout
 * @internal
 *
 * This structure contains the hash of define callouts
 */
typedef struct globus_i_callout_handle_s
{
    globus_hashtable_t                  symbol_htable;
    globus_hashtable_t                  library_htable;
}
globus_i_callout_handle_t;

typedef struct globus_i_callout_data_s
{
    char *                              type;
    char *                              file;
    char *                              symbol;
    struct globus_i_callout_data_s *    next;
} globus_i_callout_data_t;

#endif
#endif

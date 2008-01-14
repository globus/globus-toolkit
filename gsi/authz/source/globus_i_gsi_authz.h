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

#include "globus_common.h"
#include "globus_module.h"
#include "globus_callback.h"
#include "globus_gsi_authz_constants.h"
#include "globus_gsi_authz.h"
#include "globus_error_string.h"

/* DEBUG MACROS */

#ifdef BUILD_DEBUG

extern int                              globus_i_gsi_authz_debug_level;
extern FILE *                           globus_i_gsi_authz_debug_fstream;

#define GLOBUS_I_GSI_AUTHZ_DEBUG(_LEVEL_) \
    (globus_i_gsi_authz_debug_level >= (_LEVEL_))

#define GLOBUS_I_GSI_AUTHZ_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf _MESSAGE_; \
        } \
    }


#define GLOBUS_I_GSI_AUTHZ_DEBUG_FNPRINTF(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_DEBUG(_LEVEL_)) \
        { \
           char *                          _tmp_str_ = \
               globus_common_create_nstring _MESSAGE_; \
           globus_libc_fprintf(globus_i_gsi_authz_debug_fstream, \
                               _tmp_str_); \
           globus_libc_free(_tmp_str_); \
        } \
    }

#define GLOBUS_I_GSI_AUTHZ_DEBUG_PRINT(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_authz_debug_fstream, _MESSAGE_); \
        } \
    }

#define GLOBUS_I_GSI_AUTHZ_DEBUG_PRINT_OBJECT(_LEVEL_, _OBJ_NAME_, _OBJ_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_DEBUG(_LEVEL_)) \
        { \
pp           _OBJ_NAME_##_print_fp(globus_i_gsi_authz_debug_fstream, _OBJ_); \
        } \
    }

#else

#define GLOBUS_I_GSI_AUTHZ_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_AUTHZ_DEBUG_FNPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_AUTHZ_DEBUG_PRINT(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_AUTHZ_DEBUG_PRINT_OBJECT(_LEVEL_, _OBJ_NAME_, _OBJ_) {}

#endif

#define GLOBUS_I_GSI_AUTHZ_DEBUG_ENTER \
            GLOBUS_I_GSI_AUTHZ_DEBUG_FPRINTF( \
                2, (globus_i_gsi_authz_debug_fstream, \
                    "%s entering\n", _function_name_))

#define GLOBUS_I_GSI_AUTHZ_DEBUG_EXIT \
            GLOBUS_I_GSI_AUTHZ_DEBUG_FPRINTF( \
                2, (globus_i_gsi_authz_debug_fstream, \
                    "%s exiting\n", _function_name_))



/* ERROR MACROS */

extern char * globus_l_gsi_authz_error_strings[];

#define GLOBUS_GSI_AUTH_HANDLE_MALLOC_ERROR(_LENGTH_) \
    globus_error_put(globus_error_wrap_errno_error( \
        GLOBUS_GSI_AUTHZ_MODULE, \
        errno, \
        GLOBUS_GSI_AUTHZ_ERROR_ERRNO, \
        __FILE__, \
        _function_name_, \
        __LINE__, \
        "Could not allocate enough memory: %d bytes", \
        (_LENGTH_)))


#define GLOBUS_GSI_AUTHZ_ERROR_NULL_VALUE(_WHAT_) \
    globus_error_put(globus_error_construct_error( \
        GLOBUS_GSI_AUTHZ_MODULE, \
        NULL, \
	GLOBUS_GSI_AUTHZ_ERROR_BAD_PARAMETER, \
	__FILE__, \
        _function_name_, \
        __LINE__, \
        "%s %s is null", \
        globus_l_gsi_authz_error_strings[GLOBUS_GSI_AUTHZ_ERROR_BAD_PARAMETER]\
        , (_WHAT_)))

#define GLOBUS_GSI_AUTHZ_ERROR_WITH_CALLOUT(_RESULT_) \
    globus_error_put(globus_error_construct_error( \
        GLOBUS_GSI_AUTHZ_MODULE, \
        globus_error_get(_RESULT_), \
	GLOBUS_GSI_AUTHZ_ERROR_CALLOUT, \
	__FILE__, \
        _function_name_, \
        __LINE__, \
        "%s", \
        globus_l_gsi_authz_error_strings[GLOBUS_GSI_AUTHZ_ERROR_CALLOUT]))

typedef struct globus_l_gsi_authz_cb_arg_s
{
    globus_gsi_authz_handle_t           handle;
    void *                              arg;
    globus_gsi_authz_cb_t		callback;
} globus_l_gsi_authz_cb_arg_t;

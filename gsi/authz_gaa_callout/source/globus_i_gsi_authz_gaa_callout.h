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

#include "gaa.h"
#include "gaa_core.h"
#include "gaa_debug.h"
#include "gaa_simple.h"
#include "globus_error_string.h"

/* ERROR MACROS */

#define GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(__RESULT,__GAA_FUNC, __GAA_STATUS) \
    (__RESULT) = \
        globus_error_put(globus_error_construct_string( \
            GLOBUS_GSI_AUTHZ_MODULE, \
	    GLOBUS_NULL, \
            "%s:%d: %s returned %s (%s)", \
            __FILE__, __LINE__, __GAA_FUNC, \
            gaa_x_majstat_str(__GAA_STATUS), \
	    gaa_get_err()));

#define GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_DENIED_ACCESS(__RESULT,__GAA_FUNC, __GAA_STATUS, __GAA_ANSWER, __GAA) \
{                                                             \
    char _tmp_str_[2048];           \
        globus_error_put(globus_error_construct_string( \
            GLOBUS_GSI_AUTHZ_MODULE, \
	    GLOBUS_NULL, \
            "%s:%d: %s denied access %s (%s)", \
    __GAA_FUNC, gaa_x_majstat_str(__GAA_STATUS), \
    gaadebug_answer_string(__GAA, _tmp_str_, sizeof(_tmp_str_), __GAA_ANSWER))); \
}

/* DEBUG MACROS */

#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_ERROR 1
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_DEBUG 2
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE 3

#ifdef BUILD_DEBUG
extern int                              globus_i_gsi_authz_gaa_callout_debug_level;

#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG(_LEVEL_) \
    (globus_i_gsi_authz_gaa_callout_debug_level >= (_LEVEL_))

#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf _MESSAGE_; \
        } \
    }


#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF2(_LEVEL_, _ONE_, _TWO_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_authz_gaa_callout_debug_fstream, \
                               _ONE_, _TWO_); \
        } \
    }

#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF3(_LEVEL_, _ONE_, _TWO_, _THREE_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_authz_gaa_callout_debug_fstream, \
                               _ONE_, _TWO_, _THREE_); \
        } \
    }

#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF4(_LEVEL_, _ONE_, _TWO_, _THREE_, _FOUR_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_authz_gaa_callout_debug_fstream, \
                               _ONE_, _TWO_, _THREE_, _FOUR_); \
        } \
    }

#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF5(_LEVEL_, _ONE_, _TWO_, _THREE_, _FOUR_, _FIVE_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_authz_gaa_callout_debug_fstream, \
                               _ONE_, _TWO_, _THREE_, _FOUR_, _FIVE_); \
        } \
    }

#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_PRINT(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_authz_gaa_callout_debug_fstream, _MESSAGE_); \
        } \
    }

#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_PRINT_OBJECT(_LEVEL_, _OBJ_NAME_, _OBJ_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           _OBJ_NAME_##_print_fp(globus_i_gsi_authz_gaa_callout_debug_fstream, _OBJ_); \
        } \
    }

#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_ENTER \
            GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF( \
                GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE, \
                  (globus_i_gsi_authz_gaa_callout_debug_fstream, \
                    "%s entering\n", _function_name_))

#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_EXIT \
            GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF( \
                GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE, \
                 (globus_i_gsi_authz_gaa_callout_debug_fstream, \
                    "%s exiting\n", _function_name_))


#else
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG(_LEVEL_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF2(_LEVEL_, _ONE_, _TWO_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF3(_LEVEL_, _ONE_, _TWO_, _THREE_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF4(_LEVEL_, _ONE_, _TWO_, _THREE_, _FOUR_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF5(_LEVEL_, _ONE_, _TWO_, _THREE_, _FOUR_, _FIVE_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_PRINT(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_PRINT_OBJECT(_LEVEL_, _OBJ_NAME_, _OBJ_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_ENTER {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_EXIT {}
#endif

typedef struct globus_i_gsi_authz_handle_s
{
    gaa_ptr		                gaa;
    gaa_sc_ptr 		                sc;
    char *		                auth;	/* authority for request rights */
    int			                no_cred_extension;
} globus_i_gsi_authz_handle_t;

typedef struct globus_l_gsi_authz_gaa_cb_arg_s
{
    globus_gsi_authz_handle_t           handle;
    void *                              arg;
    globus_gsi_authz_cb_t		callback;
} globus_l_gsi_authz_gaa_cb_arg_t;

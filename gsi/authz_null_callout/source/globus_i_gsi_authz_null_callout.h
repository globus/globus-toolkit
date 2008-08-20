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

/* DEBUG MACROS */

#ifdef BUILD_DEBUG
#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_TRACE 2
extern int                              globus_i_gsi_authz_null_callout_debug_level;

#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG(_LEVEL_) \
    (globus_i_gsi_authz_null_callout_debug_level >= (_LEVEL_))

#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf _MESSAGE_; \
        } \
    }


#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF2(_LEVEL_, _ONE_, _TWO_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_authz_null_callout_debug_fstream, \
                               _ONE_, _TWO_); \
        } \
    }

#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF3(_LEVEL_, _ONE_, _TWO_, _THREE_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_authz_null_callout_debug_fstream, \
                               _ONE_, _TWO_, _THREE_); \
        } \
    }

#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF4(_LEVEL_, _ONE_, _TWO_, _THREE_, _FOUR_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_authz_null_callout_debug_fstream, \
                               _ONE_, _TWO_, _THREE_, _FOUR_); \
        } \
    }

#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF5(_LEVEL_, _ONE_, _TWO_, _THREE_, _FOUR_, _FIVE_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_authz_null_callout_debug_fstream, \
                               _ONE_, _TWO_, _THREE_, _FOUR_, _FIVE_); \
        } \
    }

#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_PRINT(_LEVEL_, _MESSAGE_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           globus_libc_fprintf(globus_i_gsi_authz_null_callout_debug_fstream, _MESSAGE_); \
        } \
    }

#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_PRINT_OBJECT(_LEVEL_, _OBJ_NAME_, _OBJ_) \
    { \
        if (GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG(_LEVEL_)) \
        { \
           _OBJ_NAME_##_print_fp(globus_i_gsi_authz_null_callout_debug_fstream, _OBJ_); \
        } \
    }

#else

#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF2(_LEVEL_, _ONE_, _TWO_) {}
#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF3(_LEVEL_, _ONE_, _TWO_, _THREE_) {}
#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF4(_LEVEL_, _ONE_, _TWO_, _THREE_, _FOUR_) {}
#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_FPRINTF5(_LEVEL_, _ONE_, _TWO_, _THREE_, _FOUR_, _FIVE_) {}
#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_PRINT(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_AUTHZ_NULL_CALLOUT_DEBUG_PRINT_OBJECT(_LEVEL_, _OBJ_NAME_, _OBJ_) {}

#endif

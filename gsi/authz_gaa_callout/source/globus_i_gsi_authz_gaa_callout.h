#include "gaa.h"
#include "gaa_core.h"
#include "gaa_debug.h"
#include "gaa_simple.h"

/* ERROR MACROS */

#define GLOBUS_GSI_AUTHZ_NO_CONFIG_FILE(_NULL_) \
    globus_error_put(globus_error_wrap_errno_error( \
        GLOBUS_GSI_AUTHZ_MODULE, \
        errno, \
        GLOBUS_GSI_AUTHZ_ERROR_ERRNO, \
        "%s:%d: GAA-API configuration file ENV missing.", \
        __FILE__, __LINE__))


#define GLOBUS_GSI_AUTHZ_GAA_CALLOUT_GAA_ERROR(__RESULT,__GAA_FUNC, __GAA_STATUS) \
{                                                             \
    char _tmp_str_[512]; \
    globus_libc_snprintf(_tmp_str_, sizeof(_tmp_str_), "%s failed: %s (%s)", \
    __GAA_FUNC, gaa_x_majstat_str(__GAA_STATUS), gaa_get_err()); \
    GLOBUS_GSI_AUTHZ_CALLOUT_ERROR(__RESULT, GLOBUS_GSI_AUTHZ_CALLOUT_AUTHZ_CALLOUT_ERROR, _tmp_str_); \
}

/* DEBUG MACROS */

#ifdef BUILD_DEBUG
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_ERROR 1
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_TRACE 2
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
                2, (globus_i_gsi_authz_gaa_callout_debug_fstream, \
                    "%s entering\n", _function_name_))

#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_EXIT \
            GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF( \
                2, (globus_i_gsi_authz_gaa_callout_debug_fstream, \
                    "%s exiting\n", _function_name_))


#else

#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF2(_LEVEL_, _ONE_, _TWO_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF3(_LEVEL_, _ONE_, _TWO_, _THREE_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF4(_LEVEL_, _ONE_, _TWO_, _THREE_, _FOUR_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_FPRINTF5(_LEVEL_, _ONE_, _TWO_, _THREE_, _FOUR_, _FIVE_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_PRINT(_LEVEL_, _MESSAGE_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLOUT_DEBUG_PRINT_OBJECT(_LEVEL_, _OBJ_NAME_, _OBJ_) {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLBACK_DEBUG_ENTER() {}
#define GLOBUS_I_GSI_AUTHZ_GAA_CALLBACK_DEBUG_EXIT() {}
#endif

typedef struct globus_i_gsi_authz_handle_s
{
    gaa_ptr		gaa;
    gaa_sc_ptr 		sc;
    int			no_cred_extension;
} globus_i_gsi_authz_handle_t;


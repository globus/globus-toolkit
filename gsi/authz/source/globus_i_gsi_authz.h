#include "globus_common.h"
#include "globus_module.h"
#include "globus_callback.h"
#include "globus_gsi_authz_constants.h"
#include "globus_gsi_authz.h"

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
               globus_gsi_cert_utils_create_nstring _MESSAGE_; \
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
           _OBJ_NAME_##_print_fp(globus_i_gsi_authz_debug_fstream, _OBJ_); \
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

#define GLOBUS_GSI_AUTH_HANDLE_MALLOC_ERROR(_LENGTH_) \
    globus_error_put(globus_error_wrap_errno_error( \
        GLOBUS_GSI_AUTHZ_MODULE, \
        errno, \
        GLOBUS_GSI_AUTHZ_ERROR_ERRNO, \
        "%s:%d: Could not allocate enough memory: %d bytes", \
        __FILE__, __LINE__, _LENGTH_))


#define GLOBUS_GSI_AUTHZ_ERROR_NULL_PARAMETER(_CALLBACK_) \
    globus_error_put(globus_error_wrap_errno_error( \
        GLOBUS_GSI_AUTHZ_MODULE, \
        errno, \
        GLOBUS_GSI_AUTHZ_ERROR_ERRNO, \
        "%s:%d: callback function is missing: %s", \
        __FILE__, __LINE__, _CALLBACK_))

#define GLOBUS_GSI_AUTHZ_ERROR_NOT_SUPPORTED(_NOSUPPORT_) \
    globus_error_put(globus_error_wrap_errno_error( \
        GLOBUS_GSI_AUTHZ_MODULE, \
        errno, \
        GLOBUS_GSI_AUTHZ_ERROR_ERRNO, \
        "%s:%d: Cancelling a request is not supported.", \
        __FILE__, __LINE__))


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


#define GLOBUS_GSI_AUTHZ_GAA_FAIL(_MSG_,_ERRORSTAT_, _ERROR_) \
    globus_error_put(globus_error_wrap_errno_error( \
        GLOBUS_GSI_AUTHZ_MODULE, \
        errno, \
        GLOBUS_GSI_AUTHZ_ERROR_ERRNO, \
        "%s:%d: %s: %s: %s", \
        __FILE__, __LINE__, _MSG_, _ERRORSTAT_, _ERROR_))


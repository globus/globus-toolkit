#ifndef GLOBUS_XIO_GSI_DRIVER_INCLUDE
#define GLOBUS_XIO_GSI_DRIVER_INCLUDE

#include "globus_xio_system.h"

#define GlobusXIOErrorWrapGSSFailed(failed_func, major_status, minor_status) \
    globus_error_put(                                                        \
        globus_error_wrap_gssapi_error(                                      \
            GLOBUS_XIO_MODULE,                                               \
            major_status,                                                    \
            minor_status,                                                    \
            GLOBUS_XIO_ERROR_WRAPPED,                                        \
            "[%s:%d] %s failed.",                                            \
            _xio_name, __LINE__, (failed_func)))                            
                                                                     



#endif

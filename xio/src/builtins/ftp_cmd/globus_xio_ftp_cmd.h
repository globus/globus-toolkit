#if !defined GLOBUS_XIO_DRIVER_FTP_CMD_H
#define GLOBUS_XIO_DRIVER_FTP_CMD_H 1

#include "globus_common.h"

enum
{
    GLOBUS_XIO_DRIVER_FTP_CMD_BUFFER
};


extern globus_module_descriptor_t       globus_i_xio_ftp_cmd_module;

#define GLOBUS_XIO_DRIVER_FTP_CMD       (&globus_i_xio_ftp_cmd_module)

#endif

#ifndef GLOBUS_I_GFS_CONTROL_H
#define GLOBUS_I_GFS_CONTROL_H

#include "globus_xio.h"

globus_result_t
globus_i_gfs_control_start(
    globus_xio_handle_t                 handle,
    const char *                        remote_contact);

#endif

#ifndef GLOBUS_I_GFS_CONTROL_H
#define GLOBUS_I_GFS_CONTROL_H

#include "globus_xio.h"

globus_result_t
globus_i_gfs_control_start(
    globus_xio_handle_t                 handle,
    globus_xio_system_handle_t          system_handle,
    const char *                        remote_contact,
    globus_i_gfs_server_close_cb_t      close_func,
    void *                              user_arg);

#endif

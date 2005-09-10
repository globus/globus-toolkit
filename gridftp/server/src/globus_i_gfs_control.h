/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_I_GFS_CONTROL_H
#define GLOBUS_I_GFS_CONTROL_H

#include "globus_xio.h"

globus_result_t
globus_i_gfs_control_start(
    globus_xio_handle_t                 handle,
    globus_xio_system_socket_t          system_handle,
    const char *                        remote_contact,
    const char *                        local_contact,
    globus_i_gfs_server_close_cb_t      close_func,
    void *                              user_arg);

#endif

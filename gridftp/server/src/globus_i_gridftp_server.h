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

#ifndef GLOBUS_I_GRIDFTP_SERVER_H
#define GLOBUS_I_GRIDFTP_SERVER_H

#include "config.h"
#include "globus_gridftp_server.h"
#include "globus_gridftp_server_control.h"
#include "globus_i_gfs_acl.h"
#include "globus_xio.h"
#include "globus_xio_system.h"
#include "globus_xio_tcp_driver.h"
#include "globus_xio_gsi.h"
#include "globus_ftp_control.h"
#include "globus_gsi_authz.h"
#include "globus_usage.h"

typedef void
(*globus_i_gfs_server_close_cb_t)(
    void *                              user_arg);

typedef struct globus_i_gfs_monitor_s
{
    globus_bool_t                       done;
    globus_cond_t                       cond;
    globus_mutex_t                      mutex;
} globus_i_gfs_monitor_t;

void
globus_i_gfs_monitor_init(
    globus_i_gfs_monitor_t *            monitor);

void
globus_i_gfs_monitor_destroy(
    globus_i_gfs_monitor_t *            monitor);

void
globus_i_gfs_monitor_wait(
    globus_i_gfs_monitor_t *            monitor);

void
globus_i_gfs_monitor_signal(
    globus_i_gfs_monitor_t *            monitor);

void
globus_i_gfs_ipc_stop();

void
globus_i_gfs_control_stop();

void
globus_i_gfs_control_init();

globus_result_t
globus_i_gfs_brain_init();

#define GlobusGFSErrorGenericStr(_res, _fmt)                           \
do                                                                     \
{                                                                      \
        char *                          _tmp_str;                      \
        _tmp_str = globus_common_create_string _fmt;                   \
        _res = globus_error_put(                                       \
            globus_error_construct_error(                              \
                GLOBUS_NULL,                                           \
                GLOBUS_NULL,                                           \
                GLOBUS_GFS_ERROR_GENERIC,                              \
                __FILE__,                                              \
                _gfs_name,                                             \
                __LINE__,                                              \
                "%s",                                                  \
                _tmp_str));                                            \
        globus_free(_tmp_str);                                         \
                                                                       \
} while(0)

extern globus_gfs_acl_module_t          globus_gfs_acl_cas_module;
extern globus_gfs_acl_module_t          globus_gfs_acl_test_module;

typedef enum globus_l_gfs_auth_level_e
{
    GLOBUS_L_GFS_AUTH_NONE = 0x00,
    GLOBUS_L_GFS_AUTH_IDENTIFY = 0x01,
    GLOBUS_L_GFS_AUTH_ACTION = 0x02,
    GLOBUS_L_GFS_AUTH_NOSETUID = 0x04,

    GLOBUS_L_GFS_AUTH_ALL = 0xFF
} globus_l_gfs_auth_level_t;


#include "globus_i_gfs_log.h"
#include "globus_i_gfs_control.h"
#include "globus_i_gfs_ipc.h"
#include "globus_i_gfs_data.h"
#include "globus_i_gfs_config.h"

#endif

#ifndef GLOBUS_I_GRIDFTP_SERVER_H
#define GLOBUS_I_GRIDFTP_SERVER_H

#include "globus_gridftp_server.h"
#include "globus_ftp_control.h"
#include "globus_i_gfs_acl.h"


typedef void
(*globus_i_gfs_server_close_cb_t)(
    void *                              user_arg);

typedef struct
{
    globus_xio_handle_t             xio_handle;
    char *                          remote_contact;
    char *                          rnfr_pathname;
    int                             transfer_id;
    globus_gridftp_server_control_op_t op;

    globus_i_gfs_server_close_cb_t  close_func;
    void *                          close_arg;
    
    /* XXX: is this a good place ? */
    void *                          user_data_handle;
    globus_i_gfs_acl_handle_t       acl_handle;
    int                             session_id;

    globus_gridftp_server_control_t server_handle;
} globus_i_gfs_server_instance_t;

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

#include "globus_i_gfs_log.h"
#include "globus_i_gfs_control.h"
#include "globus_i_gfs_ipc.h"
#include "globus_i_gfs_data.h"
#include "globus_i_gfs_config.h"

#endif

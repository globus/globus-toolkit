#ifndef GLOBUS_I_GRIDFTP_SERVER_H
#define GLOBUS_I_GRIDFTP_SERVER_H

#include "config.h"
#include "globus_gridftp_server.h"
#include "globus_ftp_control.h"
#include "globus_i_gfs_acl.h"


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

extern globus_gfs_acl_module_t          globus_gfs_acl_cas_module;
extern globus_gfs_acl_module_t          globus_gfs_acl_test_module;

#include "globus_i_gfs_log.h"
#include "globus_i_gfs_control.h"
#include "globus_i_gfs_ipc.h"
#include "globus_i_gfs_data.h"
#include "globus_i_gfs_config.h"

#endif

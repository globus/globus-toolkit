#ifndef GLOBUS_I_GRIDFTP_SERVER_H
#define GLOBUS_I_GRIDFTP_SERVER_H

#include "globus_gridftp_server.h"
#include "globus_ftp_control.h"
#include "globus_i_gfs_acl.h"

void
globus_i_gfs_server_closed();

typedef struct
{
    globus_xio_handle_t             xio_handle;
    char *                          remote_contact;
    char *                          rnfr_pathname;
    int                             transfer_id;
    globus_gridftp_server_control_op_t op;

    /* XXX: is this a good place ? */
    void *                          user_data_handle;
    globus_i_gfs_acl_handle_t       acl_handle;

    union
    {
        struct
        {
            globus_gridftp_server_control_t server;
            
        } control;
        
        struct
        {
             void * nothing;  
        } data;
    } u;
} globus_i_gfs_server_instance_t;

typedef struct
{
    globus_bool_t                       ipv6;
    int                                 nstreams;
    char                                mode;
    char                                type;
    int                                 tcp_bufsize;
    globus_size_t                       blocksize;
        
    globus_ftp_control_protection_t     prot;
    globus_ftp_control_dcau_t           dcau;
    gss_cred_id_t                       delegated_cred;
} globus_i_gfs_data_attr_t;

typedef struct
{
    /* XXX this shouldn't be passed from control->data*/
    globus_gridftp_server_control_op_t  control_op;

    globus_range_list_t                 range_list;
    globus_off_t                        partial_offset;
    globus_off_t                        partial_length;
            
} globus_i_gfs_op_attr_t;



typedef struct
{
    globus_gfs_command_type_t           command;
    char *                              pathname;

    globus_off_t                        cksm_offset;
    globus_off_t                        cksm_length;
    char *                              cksm_alg;
    char *                              cksm_response;
    
    mode_t                              chmod_mode;
    
    char *                              rnfr_pathname;    
/* XXX use a union here when we get into commands with different args */
            
} globus_i_gfs_cmd_attr_t;

typedef struct
{
    globus_mutex_t                      lock;
    globus_i_gfs_data_attr_t            attr;
    globus_ftp_control_handle_t         data_channel;
    globus_bool_t                       closed;
    int                                 ref;
} globus_i_gfs_data_handle_t;

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

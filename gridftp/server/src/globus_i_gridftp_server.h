#ifndef GLOBUS_I_GRIDFTP_SERVER_H
#define GLOBUS_I_GRIDFTP_SERVER_H

#include "globus_gridftp_server.h"
#include "globus_ftp_control.h"

typedef struct
{
    globus_xio_handle_t             xio_handle;
    char *                          remote_contact;
    
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
} globus_i_gfs_data_attr_t;

typedef struct
{
    globus_mutex_t                      lock;
    globus_i_gfs_data_attr_t            attr;
    globus_ftp_control_handle_t         data_channel;
    globus_bool_t                       closed;
    int                                 ref;
} globus_i_gfs_data_handle_t;

typedef struct
{
    void * nothing;    
} globus_i_gfs_ipc_handle_t;

/* !! if this changes, code will have to corrected as all 3 types here are
 * upcasted/downcasted at will
 */
typedef union
{
    globus_i_gfs_data_handle_t          data;
    globus_i_gfs_ipc_handle_t           ipc;
} globus_i_gfs_ipc_data_handle_t;

typedef enum
{
    GLOBUS_I_GFS_EVENT_TRANSFER_BEGIN,
    GLOBUS_I_GFS_EVENT_DISCONNECTED
} globus_i_gfs_event_t;

#include "globus_i_gfs_log.h"
#include "globus_i_gfs_control.h"
#include "globus_i_gfs_ipc.h"
#include "globus_i_gfs_data.h"
#include "globus_i_gfs_acl.h"
#include "globus_i_gfs_config.h"

#endif

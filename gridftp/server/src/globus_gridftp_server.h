
/* Header file for globus_gridftp_server modules.  
 * 
 * If you are interested in writing a module for this server and want to
 * discuss it's design, or are already writing one and would like support,
 * please subscribe to gridftp-mpd@globus.org by sending a message to 
 * majordomo@globus.org with the line 'subscribe gridftp-mpd' in the body.
 * In fact, we'd like to hear from you even if you don't need any assistance.
 */


#ifndef GLOBUS_GRIDFTP_SERVER_H
#define GLOBUS_GRIDFTP_SERVER_H

#include "globus_common.h"
#include "globus_gridftp_server_control.h"

#define GLOBUS_MAPPING_STRING ":globus-mapping:"

#define _GSSL(s) globus_common_i18n_get_string_by_key(\
		    NULL, \
		    "globus_gridftp_server", \
		    s)

#define _FSSL(s,p) globus_common_i18n_get_string_by_key(\
		     p, \
		    "globus_gridftp_server", \
		    s)

extern globus_module_descriptor_t      globus_i_gfs_module;
#define GLOBUS_GRIDFTP_SERVER_MODULE (&globus_i_gfs_module)

extern globus_extension_registry_t      globus_i_gfs_dsi_registry;
#define GLOBUS_GFS_DSI_REGISTRY         &globus_i_gfs_dsi_registry

#define GLOBUS_GRIDFTP_SERVER_RELEASE_TYPE " ** Development Release **"



/*
 *  globus_gfs_error_type_t
 *
 */
typedef enum globus_gfs_error_type_e
{
    GLOBUS_GFS_ERROR_MEMORY = 1,
    GLOBUS_GFS_ERROR_PARAMETER,
    GLOBUS_GFS_ERROR_SYSTEM_ERROR,
    GLOBUS_GFS_ERROR_WRAPPED,
    GLOBUS_GFS_ERROR_DATA,
    GLOBUS_GFS_ERROR_GENERIC
} globus_gfs_error_type_t;

/*
 *  globus_gfs_operation_type_t
 * 
 * Server operations.
 */
typedef enum globus_gfs_operation_type_e
{
    GLOBUS_GFS_OP_FINAL_REPLY = 1,
    GLOBUS_GFS_OP_EVENT_REPLY,
    GLOBUS_GFS_OP_EVENT,    
    GLOBUS_GFS_OP_SESSION_START,
    GLOBUS_GFS_OP_SESSION_STOP,
    GLOBUS_GFS_OP_RECV,
    GLOBUS_GFS_OP_SEND,
    GLOBUS_GFS_OP_LIST,
    GLOBUS_GFS_OP_COMMAND,
    GLOBUS_GFS_OP_PASSIVE,
    GLOBUS_GFS_OP_ACTIVE,
    GLOBUS_GFS_OP_DESTROY,
    GLOBUS_GFS_OP_TRANSFER,
    GLOBUS_GFS_OP_STAT,
    GLOBUS_GFS_OP_BUFFER_SEND,
    GLOBUS_GFS_OP_HANDSHAKE,
    GLOBUS_GFS_OP_SESSION_START_REPLY
} globus_gfs_operation_type_t;

/*
 *  globus_gfs_command_type_t
 * 
 * Command types.  Commands are generally simple filesystem operations
 * that only return success/failure and at most a single string.
 */
typedef enum globus_gfs_command_type_e
{
    GLOBUS_GFS_CMD_MKD = 1,
    GLOBUS_GFS_CMD_RMD,
    GLOBUS_GFS_CMD_DELE,
    GLOBUS_GFS_CMD_RNTO,
    GLOBUS_GFS_CMD_RNFR,
    GLOBUS_GFS_CMD_CKSM,
    GLOBUS_GFS_CMD_SITE_CHMOD,
    GLOBUS_GFS_CMD_SITE_DSI
} globus_gfs_command_type_t;

/*
 *  globus_gfs_event_type_t
 * 
 * Event types.
 */
typedef enum globus_gfs_event_type_e
{
    GLOBUS_GFS_EVENT_TRANSFER_BEGIN = 0x0001,
    GLOBUS_GFS_EVENT_TRANSFER_ABORT = 0x0002,
    GLOBUS_GFS_EVENT_TRANSFER_COMPLETE = 0x0004,
    GLOBUS_GFS_EVENT_DISCONNECTED = 0x0008,
    GLOBUS_GFS_EVENT_BYTES_RECVD = 0x0010,
    GLOBUS_GFS_EVENT_RANGES_RECVD = 0x0020,
    GLOBUS_GFS_EVENT_TRANSFER_CONNECTED = 0x0040,
    GLOBUS_GFS_EVENT_PARTIAL_EOF_COUNT = 0x0100,
    GLOBUS_GFS_EVENT_FINAL_EOF_COUNT = 0x0200,
    
    GLOBUS_GFS_EVENT_ALL = 0xFFFF
} globus_gfs_event_type_t;

/*
 *  globus_gfs_buffer_type_t
 *
 */
typedef enum globus_gfs_buffer_type_e
{
    GLOBUS_GFS_BUFFER_EOF_INFO = 0x0001,
    GLOBUS_GFS_BUFFER_SERVER_DEFINED = 0xFFFF
    /* user defined types will start at 0x00010000 */
} globus_gfs_buffer_type_t;

/*
 *  globus_gfs_layout_type_t
 * 
 * Striped layout types.
 */
typedef enum globus_gfs_layout_type_e
{
    GLOBUS_GFS_LAYOUT_PARTITIONED = 1,
    GLOBUS_GFS_LAYOUT_BLOCKED
} globus_gfs_layout_type_t;

/*
 *  globus_gfs_stat_t
 * 
 * Similar to a posix struct stat.  Defined in the server-lib.
 *
 * (this comment should not be relied upon, so check the
 *   definition in the server-lib to be sure)
 *  
 * typedef struct globus_gridftp_server_control_stat_s
 * {
 *     int                              mode;
 *     int                              nlink;
 *     char                             name[MAXPATHLEN];
 *     char                             symlink_target[MAXPATHLEN];
 *     uid_t                            uid;
 *     gid_t                            gid;
 *     globus_size_t                    size;
 *     globus_time_t                    atime;
 *     globus_time_t                    ctime;
 *     globus_time_t                    mtime;
 *     int                              dev;
 *     int                              ino;
 * } globus_gridftp_server_control_stat_t;
 */
typedef globus_gridftp_server_control_stat_t    globus_gfs_stat_t;

/*
 *  globus_gfs_data_finished_info_t
 * 
 * Contains specific result info for an active or passive data connection.
 * Note that in most cases this info will simply be passed.
 */
typedef struct globus_gfs_data_finished_info_s
{
    /** unique key for the data_handle */
    void *                              data_arg;
    /** false if the direction of data flow is restricted */
    globus_bool_t                       bi_directional;
    /** is the connection using ipv6? */
    globus_bool_t                       ipv6;
    /** number of contact strings */
    int                                 cs_count;
    /** array of contact strings */
    const char **                       contact_strings;
} globus_gfs_data_finished_info_t;

/*
 *  globus_gfs_cmd_finshed_info_t
 * 
 * Contains specific result info for commands.
 */
typedef struct globus_gfs_cmd_finshed_info_s
{
    /** type of command that has finished */
    globus_gfs_command_type_t           command;
    /** checksum string, for CKSM only */
    char *                              checksum;
    /** full path of the created directory, for MKD only */
    char *                              created_dir;
} globus_gfs_cmd_finshed_info_t;

/*
 *  globus_gfs_stat_finished_info_t
 * 
 * Contains specific result info for a stat.
 */
typedef struct globus_gfs_stat_finished_info_s
{
    /** uid of the user that performed the stat */
    int                                 uid;
    /** count of gids in gid_array */
    int                                 gid_count;
    /** array of gids of which user that performed the stat is a member */
    int *                               gid_array;
    /** number of stat objects in the array */
    int                                 stat_count;
    /** array of stat objects */
    globus_gfs_stat_t *                 stat_array;
} globus_gfs_stat_finished_info_t;

/*
 *  globus_gfs_session_finished_info_t
 * 
 * Contains specific result info for a stat.
 */
typedef struct globus_gfs_session_finished_info_s
{
    /** arg to pass back with each request */
    void *                              session_arg;
    /** local username of authenticated user */
    char *                              username;
    /** home directory of authenticated user */
    char *                              home_dir;
    
} globus_gfs_session_finished_info_t;

/*
 *  globus_gfs_finished_info_t
 * 
 * Final result info for an operation.
 */
typedef struct globus_gfs_finished_info_s
{
    /** type of operation that has completed */
    globus_gfs_operation_type_t         type;
    /** unique key for the op */
    int                                 id;
    /** result code for success or failure of the op */
    int                                 code;
    /** additional message, usually for failure */
    char *                              msg;
    /** result_t */
    globus_result_t                     result;

    union
    {
        globus_gfs_session_finished_info_t session;
        globus_gfs_data_finished_info_t data;
        globus_gfs_cmd_finshed_info_t   command;
        globus_gfs_stat_finished_info_t stat;
    } info;
} globus_gfs_finished_info_t;

/*
 *  globus_gfs_event_info_t
 * 
 * Event info.
 */
typedef struct globus_gfs_event_info_s
{
    /** type of event */
    globus_gfs_event_type_t             type;

    /** arg supplied with the BEGIN_TRANSFER event, 
        will be passed back with each transfer event */
    void *                              event_arg;
    
    /* reply data */
    /** node that event is from */
    int                                 node_ndx;
    /** unique key of transfer request that event is related to */
    int                                 id;
    /** mask of events that should be passed in */
    int                                 event_mask;
    /** number of bytes received for current transfer */
    globus_off_t                        recvd_bytes;
    /** ranges of bytes received for current transfer */
    globus_range_list_t                 recvd_ranges;
    /** arg representing data handle that event is related to */    
    void *                              data_arg;
    
    /* request data */
    /** array of eof counts */    
    int *                               eof_count;
    /** number of nodes (size of eof_count array) */    
    int                                 node_count;
} globus_gfs_event_info_t;

/*
 *  globus_gfs_transfer_info_t
 * 
 * Info needed for transfer operations (list, send, recv).
 */
typedef struct globus_gfs_transfer_info_s
{
    /** pathname being transferred or listed */
    char *                              pathname;    
    /** module name and arguments */
    char *                              module_name;
    char *                              module_args;
    /** type of list requested */
    char *                              list_type;
    
    /** offset of partial transfer */
    globus_off_t                        partial_offset;
    /** length of partial transfer */
    globus_off_t                        partial_length;
    /** list or ranges for a restart */
    globus_range_list_t                 range_list;
    /** length of partial transfer */
    globus_bool_t                       truncate;
    
    /** unique key that identifies the associated data_handle */
    void *                              data_arg;
    /** number of eof that sender should send  xxx might need to be array here */
    int                                 eof_count;
    /** total number of local stripes that will be involved */
    int                                 stripe_count;    
    /** total number of nodes that will be involved */
    int                                 node_count;    
    /** node index */
    int                                 node_ndx;
    /** number of parallel streams */
    int                                 nstreams;   
} globus_gfs_transfer_info_t;

/*
 *  globus_gfs_command_info_t
 * 
 * Info needed for a command operation.
 */
typedef struct globus_gfs_command_info_s
{
    /** command type requested */
    globus_gfs_command_type_t           command; 
    /** pathname to execute the command on */
    char *                              pathname;

    /** offset for cksm command */
    globus_off_t                        cksm_offset;
    /** length of data to read for cksm command   -1 means full file */
    globus_off_t                        cksm_length;
    /** checksum algorithm requested (md5 only currently) */
    char *                              cksm_alg;
    
    /** mode argument to the chmod command */
    mode_t                              chmod_mode;
    
    /** pathname to rename from (to the above pathname)  */
    char *                              rnfr_pathname;    
} globus_gfs_command_info_t;

/*
 *  globus_gfs_data_info_t
 * 
 * Info needed for data operations (active, passive).
 */
typedef struct globus_gfs_data_info_s
{
    /** should this be ipv6? */
    globus_bool_t                       ipv6;
    /** number of parallel streams */
    int                                 nstreams;
    /** data channel mode */
    char                                mode;
    /** data channel type */
    char                                type;
    /** tcp buffersize to use */
    int                                 tcp_bufsize;
    /** blocksize to use */
    int                                 blocksize;
    /** blocksize to use for stripe layout */
    int                                 stripe_blocksize;
    /** stripe layout to use */
    int                                 stripe_layout;

    /** protection mode */
    char                                prot;
    /** dcau mode */
    char                                dcau;
    /** client DN */
    char *                              subject;
    /** pathname that will be transferred (or NULL if not delayed PASV) */
    char *                              pathname;

    /** max number of contact strings to return (for PASV) */
    int                                 max_cs;
    /** number of contact strings (PORT) */
    int                                 cs_count;
    /** array of contact strings (PORT) */
    const char **                       contact_strings;
    /** interface that should be used for data connections */
    char *                              interface;

    /* if this is set, the data channel will use it instead
        of the default session credential */
    gss_cred_id_t                       del_cred;
} globus_gfs_data_info_t;

/*
 *  globus_gfs_stat_info_t
 * 
 * Info needed for a stat operation.
 */
typedef struct globus_gfs_stat_info_s
{
    /** if pathname is a directory, should stat report its info or its contents */
    globus_bool_t                       file_only;
    /** this stat is requested internally -- bypasses authorization checks */
    globus_bool_t                       internal;
    /** pathname to stat */
    char *                              pathname;
} globus_gfs_stat_info_t;

typedef struct globus_gfs_session_info_s
{
    gss_cred_id_t                       del_cred;
    globus_bool_t                       free_cred;
    globus_bool_t                       map_user;
    char *                              username;
    char *                              password;
    char *                              subject;
    char *                              cookie;
    char *                              host_id;
} globus_gfs_session_info_t;


/**************************************************************************
 *  Storage Module API
 * 
 * The storage module API is made up of the interface definition,
 * notification functions, and helper functions below.
 *************************************************************************/

/*
 *  globus_gfs_operation_t
 * 
 * Operation handle.  This handle is passed to and from the storage
 * module.  Its internal data should not be used.
 */
typedef struct globus_l_gfs_data_operation_s *  globus_gfs_operation_t;


/**
 * Interface Definition
 **/
 
/*
 *  init/destroy
 *
 * This will be called upon a new client session.  Any persistent 
 * data that will be needed should be initialized and stored in a
 * user-defined object which should be assigned to out_user_arg.  This
 * object pointer will then be passed back to the module with any other
 * interface call.
 */
typedef void
(*globus_gfs_storage_init_t)(
    globus_gfs_operation_t              op,
    globus_gfs_session_info_t *         session_info);
    
/*
 * This will be called when the client session ends.  Final cleanup 
 * should be done here.
 */
typedef void
(*globus_gfs_storage_destroy_t)(
    void *                              user_arg);

/*
 *  transfer
 *
 * This defines the functions that will be called for list, send, and recv.
 */
typedef void
(*globus_gfs_storage_transfer_t)(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg);

/*
 *  command
 *
 * This defines the function that will be called for commands.  The type
 * member of command_info specifies which command to carry out. 
 */
typedef void
(*globus_gfs_storage_command_t)(
    globus_gfs_operation_t              op,
    globus_gfs_command_info_t *         command_info,
    void *                              user_arg);

/*
 *  stat
 *
 * This defines the function that will be called for a stat lookup. 
 */
typedef void
(*globus_gfs_storage_stat_t)(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg);

/*
 *  data connection
 *
 * This defines the functions that will be called for active and passive
 * data connection creation. 
 */
typedef void
(*globus_gfs_storage_data_t)(
    globus_gfs_operation_t              op,
    globus_gfs_data_info_t *            data_info,
    void *                              user_arg);

/*
 *  data_destroy
 *
 * This defines the function that will be called to signal that a data
 * connection should be destroyed.  Note that there is no corresponding
 * finished notification for data destroy requests.
 */
typedef void
(*globus_gfs_storage_data_destroy_t)(
    void *                              data_arg,
    void *                              user_arg);

/*
 *  data_destroy
 *
 * This defines the function that will be called to signal that a transfer
 * event should occur.  Note that there is no corresponding finished 
 * notification for transfer event requests.
 */
typedef void
(*globus_gfs_storage_trev_t)(
    globus_gfs_event_info_t *           event_info,
    void *                              user_arg);

/*
 *  set cred
 *
 * This defines the function that will be called to pass delegated credentials.
 * XXX more here later XXX
 */
typedef void
(*globus_gfs_storage_set_cred_t)(
    gss_cred_id_t                       del_cred,
    void *                              user_arg);

/*
 *  send user buffer
 *
 * This defines the function that will be called to send a user defined buffer.
 * XXX more here later XXX
 */
typedef void
(*globus_gfs_storage_buffer_send_t)(
    int                                 buffer_type,
    globus_byte_t *                     buffer,
    globus_size_t                       buffer_len,
    void *                              user_arg);


#define GLOBUS_GFS_DSI_DESCRIPTOR_SENDER 0x01
#define GLOBUS_GFS_DSI_DESCRIPTOR_BLOCKING 0x02
/*
 *  globus_gfs_storage_iface_t
 * 
 * Storage interface function pointers.  Only define functions that are
 * implemented.  If a function is not defined, the server will either fail
 * for that particular operation, or in the case of list, data, cred, and 
 * trev funcs, the server will act on those operations itself. 
 */
typedef struct globus_gfs_storage_iface_s
{
    int                                 descriptor;

    /* session initiating functions */
    globus_gfs_storage_init_t           init_func;
    globus_gfs_storage_destroy_t        destroy_func;

    /* transfer functions */
    globus_gfs_storage_transfer_t       list_func;
    globus_gfs_storage_transfer_t       send_func;
    globus_gfs_storage_transfer_t       recv_func;
    globus_gfs_storage_trev_t           trev_func;

    /* data conn funcs */
    globus_gfs_storage_data_t           active_func;
    globus_gfs_storage_data_t           passive_func;
    globus_gfs_storage_data_destroy_t   data_destroy_func;

    globus_gfs_storage_command_t        command_func;
    globus_gfs_storage_stat_t           stat_func;

    globus_gfs_storage_set_cred_t       set_cred_func;
    globus_gfs_storage_buffer_send_t    buffer_send_func;
} globus_gfs_storage_iface_t;


/**
 * Notification Functions
 **/
 
/*
 *  operation finished
 *
 * This is a generic finished notification function.  Either this *or* a
 * specific finished function below must be called upon completion of an 
 * operation with the appropriate data set in the finished_info struct, 
 * including error info if the operation failed.
 */
void
globus_gridftp_server_operation_finished(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_gfs_finished_info_t *        finished_info);

/*
 *  operation event
 *
 * This is a generic event notification function.  Either this *or* a
 * specific event function below must be called upon completion of an 
 * operation with the appropriate event data set in the event_info struct.
 */
void
globus_gridftp_server_operation_event(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_gfs_event_info_t *           event_info);

/*
 * begin transfer event
 * 
 * Speficic event notification for the start of a transfer.
 */ 
globus_result_t
globus_gridftp_server_begin_transfer(
    globus_gfs_operation_t              op,
    int                                 event_mask,
    void *                              event_arg);

/*
 * finished transfer
 * 
 * Speficic finished notification for completion of a transfer.
 */ 
void
globus_gridftp_server_finished_transfer(
    globus_gfs_operation_t              op, 
    globus_result_t                     result);

/*
 * finished command
 * 
 * Speficic finished notification for completion of a command.
 * command_response should be NULL if not used (currently only
 *  used in MKD and CKSM)
 */ 
void
globus_gridftp_server_finished_command(
    globus_gfs_operation_t              op, 
    globus_result_t                     result,
    char *                              command_response);
    
/*
 * finished stat
 * 
 * Speficic finished notification for completion of a stat.
 */ 
void
globus_gridftp_server_finished_stat(
    globus_gfs_operation_t              op, 
    globus_result_t                     result,
    globus_gfs_stat_t *                 stat_array,
    int                                 stat_count);

/*
 * finished stat
 * 
 * Speficic finished notification for completion of a active data creation.
 */ 
void
globus_gridftp_server_finished_active_data(
    globus_gfs_operation_t              op, 
    globus_result_t                     result,
    void *                              data_arg,
    globus_bool_t                       bi_directional);

/*
 * finished stat
 * 
 * Speficic finished notification for completion of a passive data creation.
 */ 
void
globus_gridftp_server_finished_passive_data(
    globus_gfs_operation_t              op, 
    globus_result_t                     result,
    void *                              data_arg,
    globus_bool_t                       bi_directional,
    const char **                       contact_strings,
    int                                 cs_count);



/**
 * Data Read and Write Functions
 **/

/*
 * write
 * 
 * Register a write of specified buffer to the server.  You should use 
 * globus_gridftp_server_get_block_size() 
 * and globus_gridftp_server_get_optimal_concurrency() to determine the 
 * buffer size of each write and the number of writes you should have 
 * pending at all times. (pending meaning you are waiting for the callback).
 */     
typedef void
(*globus_gridftp_server_write_cb_t)(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg);

globus_result_t
globus_gridftp_server_register_write(
    globus_gfs_operation_t              op,
    globus_byte_t *                     buffer,  
    globus_size_t                       length,  
    globus_off_t                        offset,  
    int                                 stripe_ndx,  
    globus_gridftp_server_write_cb_t    callback,  
    void *                              user_arg);

/*
 * read
 * 
 * Register a read of data from the server.  You should use 
 * globus_gridftp_server_get_block_size()  
 * and globus_gridftp_server_get_optimal_concurrency() to determine the 
 * buffer size you should use and the number of reads you should have 
 * pending at all times. (pending meaning you are waiting for the callback).
 */     
typedef void
(*globus_gridftp_server_read_cb_t)(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    globus_off_t                        offset,
    globus_bool_t                       eof,
    void *                              user_arg);
 
globus_result_t
globus_gridftp_server_register_read(
    globus_gfs_operation_t              op,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_gridftp_server_read_cb_t     callback,  
    void *                              user_arg);


/**
 * Helper Functions
 **/

/*
 * update bytes
 * 
 * This should be called during a recv(), after each successful write
 * to the storage system.
 */ 
void
globus_gridftp_server_update_bytes_written(
    globus_gfs_operation_t              op,
    globus_off_t                        offset,
    globus_off_t                        length);

/*
 * get concurrency
 * 
 * This should be called during a recv() and send() in order to know the
 * number of pending reads or writes you should have at once.
 */ 
void
globus_gridftp_server_get_optimal_concurrency(
    globus_gfs_operation_t              op,
    int *                               count);

/*
 * get blocksize
 * 
 * This should be called during a recv() and send() in order to know the
 * size of buffers that you should be passing to the server for reads and
 * writes.
 */ 
void
globus_gridftp_server_get_block_size(
    globus_gfs_operation_t              op,
    globus_size_t *                     block_size);

/*
 * get read_range
 * 
 * This should be called during send() in order to know the specific
 * offset and length of the file to read from the storage system
 * You should continue calling this and transferring the speficied data
 * until it returns a length of 0.
 */ 
void
globus_gridftp_server_get_read_range(
    globus_gfs_operation_t              op,
    globus_off_t *                      offset,
    globus_off_t *                      length);


/*
 * get write_range
 * 
 * This should be called during recv() in order to know the specific
 * offset and length that the data will be written to storage system.
 * globus_gridftp_server_update_bytes_written();  
 */ 
 /* XXX explain better */
void
globus_gridftp_server_get_write_range(
    globus_gfs_operation_t              op,
    globus_off_t *                      offset,
    globus_off_t *                      length);



/* XXX Hack here until module loading framework is in */
extern globus_gfs_storage_iface_t       globus_gfs_file_dsi_iface;
extern globus_gfs_storage_iface_t       globus_gfs_remote_dsi_iface;


/* END Storage Interface API */




/** Error and result object helper macros */   
enum
{
    GLOBUS_GFS_DEBUG_TRACE = 8,
    GLOBUS_GFS_DEBUG_INFO = 16
};

#ifdef __GNUC__
#define GlobusGFSName(func) static const char * _gfs_name __attribute__((__unused__)) = #func
#else
#define GlobusGFSName(func) static const char * _gfs_name = #func
#endif

GlobusDebugDeclare(GLOBUS_GRIDFTP_SERVER);

#define GlobusGFSDebugPrintf(level, message)                                \
    GlobusDebugPrintf(GLOBUS_GRIDFTP_SERVER, level, message)

#define GlobusGFSDebugInfo(_msg)                                            \
    GlobusGFSDebugPrintf(                                                   \
        GLOBUS_GFS_DEBUG_INFO,                                              \
        ("[%s] %s\n", _gfs_name, _msg))

#define GlobusGFSDebugEnter()                                               \
    GlobusGFSDebugPrintf(                                                   \
        GLOBUS_GFS_DEBUG_TRACE,                                             \
        ("[%s] Entering\n", _gfs_name))
        
#define GlobusGFSDebugExit()                                                \
    GlobusGFSDebugPrintf(                                                   \
        GLOBUS_GFS_DEBUG_TRACE,                                             \
        ("[%s] Exiting\n", _gfs_name))

#define GlobusGFSDebugExitWithError()                                       \
    GlobusGFSDebugPrintf(                                                   \
        GLOBUS_GFS_DEBUG_TRACE,                                             \
        ("[%s] Exiting with error\n", _gfs_name))

#define GlobusGFSErrorMemory(mem_name)                                      \
    globus_error_put(GlobusGFSErrorObjMemory(mem_name))                               

#define GlobusGFSErrorParameter(mem_name)                                   \
    globus_error_put(GlobusGFSErrorObjParameter(mem_name)) 

#define GlobusGFSErrorIPC()                                                 \
    globus_error_put(GlobusGFSErrorObjIPC())

#define GlobusGFSErrorObjIPC()                                              \
    globus_error_construct_error(                                           \
        GLOBUS_NULL,                                                        \
        GLOBUS_NULL,                                                        \
        GLOBUS_GFS_ERROR_MEMORY,                                            \
        __FILE__,                                                           \
        _gfs_name,                                                          \
        __LINE__,                                                           \
        "IPC Communication error.")
                                                                            
#define GlobusGFSErrorObjMemory(mem_name)                                   \
    globus_error_construct_error(                                           \
        GLOBUS_NULL,                                                        \
        GLOBUS_NULL,                                                        \
        GLOBUS_GFS_ERROR_MEMORY,                                            \
        __FILE__,                                                           \
        _gfs_name,                                                          \
        __LINE__,                                                           \
        "Memory allocation failed on %s",                                   \
        (mem_name))                               
                                                                            
#define GlobusGFSErrorObjParameter(param_name)                              \
    globus_error_construct_error(                                           \
        GLOBUS_NULL,                                                        \
        GLOBUS_NULL,                                                        \
        GLOBUS_GFS_ERROR_PARAMETER,                                         \
        __FILE__,                                                           \
        _gfs_name,                                                          \
        __LINE__,                                                           \
        "invalid parameter: %s",                                            \
        (param_name))                               
                                                                            
#define GlobusGFSErrorSystemError(system_func, _errno)                      \
    globus_error_put(                                                       \
        globus_error_wrap_errno_error(                                      \
            GLOBUS_NULL,                                                    \
            (_errno),                                                       \
            GLOBUS_GFS_ERROR_SYSTEM_ERROR,                                  \
            __FILE__,                                                       \
            _gfs_name,                                                      \
            __LINE__,                                                       \
            "System error in %s",                                           \
            (system_func)))
                                                                            
#define GlobusGFSErrorWrapFailed(failed_func, result)                       \
    globus_error_put(GlobusGFSErrorObjWrapFailed(failed_func, result))

#define GlobusGFSErrorObjWrapFailed(failed_func, result)                    \
    globus_error_construct_error(                                           \
        GLOBUS_NULL,                                                        \
        globus_error_get((result)),                                         \
        GLOBUS_GFS_ERROR_WRAPPED,                                           \
        __FILE__,                                                           \
        _gfs_name,                                                          \
        __LINE__,                                                           \
        "%s failed.",                                                       \
        (failed_func))

#define GlobusGFSErrorData(reason)                                          \
    globus_error_put(GlobusGFSErrorObjData(reason))                               

#define GlobusGFSErrorObjData(reason)                                       \
    globus_error_construct_error(                                           \
        GLOBUS_NULL,                                                        \
        GLOBUS_NULL,                                                        \
        GLOBUS_GFS_ERROR_DATA,                                              \
        __FILE__,                                                           \
        _gfs_name,                                                          \
        __LINE__,                                                           \
        "%s",                                                               \
        (reason))
 
#define GlobusGFSErrorGeneric(reason)                                       \
    globus_error_put(GlobusGFSErrorObjGeneric(reason))                               

#define GlobusGFSErrorObjGeneric(reason)                                    \
    globus_error_construct_error(                                           \
        GLOBUS_NULL,                                                        \
        GLOBUS_NULL,                                                        \
        GLOBUS_GFS_ERROR_GENERIC,                                           \
        __FILE__,                                                           \
        _gfs_name,                                                          \
        __LINE__,                                                           \
        "%s",                                                               \
        (reason))                             
                                                                                                                                
#endif

#ifndef GLOBUS_GRIDFTP_SERVER_H
#define GLOBUS_GRIDFTP_SERVER_H

#include "globus_common.h"
#include "globus_gridftp_server_control.h"

extern globus_extension_registry_t      globus_i_gfs_dsi_registry;
#define GLOBUS_GFS_DSI_REGISTRY         &globus_i_gfs_dsi_registry

/*
 *  globus_gfs_error_type_t
 *
 */
typedef enum globus_gfs_error_type_e
{
    GLOBUS_GFS_ERROR_MEMORY,
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
    GLOBUS_GFS_OP_FINAL_REPLY,
    GLOBUS_GFS_OP_EVENT_REPLY,
    GLOBUS_GFS_OP_EVENT,    
    GLOBUS_GFS_OP_SESSION_START,
    GLOBUS_GFS_OP_SESSION_STOP,
    GLOBUS_GFS_OP_AUTH,
    GLOBUS_GFS_OP_RECV,
    GLOBUS_GFS_OP_SEND,
    GLOBUS_GFS_OP_LIST,
    GLOBUS_GFS_OP_COMMAND,
    GLOBUS_GFS_OP_PASSIVE,
    GLOBUS_GFS_OP_ACTIVE,
    GLOBUS_GFS_OP_DESTROY,
    GLOBUS_GFS_OP_TRANSFER,
    GLOBUS_GFS_OP_STAT,
    GLOBUS_GFS_OP_USER_BUFFER
} globus_gfs_operation_type_t;

/*
 *  globus_gfs_command_type_t
 * 
 * Command types.  Commands are generally simple filesystem operations
 * that only return success/failure and at most a single string.
 */
typedef enum globus_gfs_command_type_e
{
    GLOBUS_GFS_CMD_MKD,
    GLOBUS_GFS_CMD_RMD,
    GLOBUS_GFS_CMD_DELE,
    GLOBUS_GFS_CMD_RNTO,
    GLOBUS_GFS_CMD_RNFR,
    GLOBUS_GFS_CMD_CKSM,
    GLOBUS_GFS_CMD_SITE_CHMOD
} globus_gfs_command_type_t;

/*
 *  globus_gfs_event_type_t
 * 
 * Event types.
 */
typedef enum globus_gfs_event_type_e
{
    GLOBUS_GFS_EVENT_TRANSFER_BEGIN,
    GLOBUS_GFS_EVENT_DISCONNECTED,
    GLOBUS_GFS_EVENT_BYTES_RECVD,
    GLOBUS_GFS_EVENT_RANGES_RECVD
} globus_gfs_event_type_t;

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
    int                                 data_handle_id;
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
    uid_t                               uid;
    /** number of stat objects in the array */
    int                                 stat_count;
    /** array of stat objects */
    globus_gfs_stat_t *                 stat_array;
} globus_gfs_stat_finished_info_t;

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
    /** result_t (will go away, use above two) */
    globus_result_t                     result;

    int                                 session_id;

    union
    {
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
    /** node that event is from */
    int                                 node_ndx;
    /** unique key of transfer request that event is related to */
    int                                 id;
    /** unique key of transfer op that event is related to */
    int                                 transfer_id;
    /** number of bytes received for current transfer */
    globus_off_t                        recvd_bytes;
    /** ranges of bytes received for current transfer */
    globus_range_list_t                 recvd_ranges;
    int                                 session_id;
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
    const char *                        list_type;
    
    /** offset of partial transfer */
    globus_off_t                        partial_offset;
    /** length of partial transfer */
    globus_off_t                        partial_length;
    /** list or ranges for a restart */
    globus_range_list_t                 range_list;
    /** unique key that identifies the associated data_handle */
    int                                 data_handle_id;
    /** number of eof that sender should send  xxx might need to be array here */
    int                                 eof_count;
    /** total number of local stripes that will be involved */
    int                                 stripe_count;    
    /** total number of nodes that will be involved */
    int                                 node_count;    
    /** node index */
    int                                 node_ndx;    
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
    globus_size_t                       blocksize;

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
    /** pathname to stat */
    char *                              pathname;
} globus_gfs_stat_info_t;




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
typedef globus_result_t
(*globus_gfs_storage_init_t)(
    globus_gfs_operation_t              op,
    const char *                        user_id);
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
typedef globus_result_t
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
typedef globus_result_t
(*globus_gfs_storage_command_t)(
    globus_gfs_operation_t              op,
    globus_gfs_command_info_t *         command_info,
    void *                              user_arg);

/*
 *  stat
 *
 * This defines the function that will be called for a stat lookup. 
 */
typedef globus_result_t
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
typedef globus_result_t
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
    int                                 data_handle_id,
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
    int                                 transfer_id,
    int                                 event_type,
    void *                              user_arg);

/*
 *  set cred
 *
 * This defines the function that will be called to pass delegated credentials.
 * XXX more here later XXX
 */
typedef void
(*globus_gfs_storage_set_cred_t)(
    globus_gfs_operation_t              op,
    gss_cred_id_t                       cred_thing,
    void *                              user_arg);


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
void
globus_gridftp_server_begin_transfer(
    globus_gfs_operation_t              op);

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
    int                                 data_handle_id,
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
    int                                 data_handle_id,
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
 * flush queue
 * 
 * This should be called when you are preparing to abort a transfer.
 */ 
void
globus_gridftp_server_flush_queue(
    globus_gfs_operation_t              op);
    
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
 * offset and length of the file to read from the storage system, as well
 * as the delta from the file offset that you should write to the server.
 * i.e. you would pass (write_delta + current file offset) as the offset 
 * parameter to globus_gridftp_server_register_write()
 * You should continue calling this and transferring the speficied data
 * until it returns a length of 0.
 */ 
void
globus_gridftp_server_get_read_range(
    globus_gfs_operation_t              op,
    globus_off_t *                      offset,
    globus_off_t *                      length,
    globus_off_t *                      write_delta);

/*
 * get write_range
 * 
 * This should be called during recv() in order to know the specific
 * offset and length that the data will be written to storage system, as well
 * as the delta from the server read offset that you should write to the 
 * storage system (write_delta) and the delta from the server read offset to
 * the offset that you should pass to 
 * globus_gridftp_server_update_bytes_written();  
 */ 
 /* XXX explain better */
void
globus_gridftp_server_get_write_range(
    globus_gfs_operation_t              op,
    globus_off_t *                      offset,
    globus_off_t *                      length,
    globus_off_t *                      write_delta,
    globus_off_t *                      transfer_delta);



/* XXX Hack here until module loading framework is in */
extern globus_gfs_storage_iface_t       globus_gfs_file_dsi_iface;
extern globus_gfs_storage_iface_t       globus_gfs_remote_dsi_iface;


/* END Storage Interface API */




/** Error and result object helper macros */   

#ifdef __GNUC__
#define GlobusGFSName(func) static const char * _gfs_name __attribute__((__unused__)) = #func
#else
#define GlobusGFSName(func) static const char * _gfs_name = #func
#endif

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
        "IPC Commincation error.")
                                                                            
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
        "user a bad parameter %s",                                          \
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

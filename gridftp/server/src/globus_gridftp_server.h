#ifndef GLOBUS_GRIDFTP_SERVER_H
#define GLOBUS_GRIDFTP_SERVER_H

#include "globus_common.h"
#include "globus_gridftp_server_control.h"

/* module interface functons */

typedef struct globus_l_gfs_data_operation_s * globus_gridftp_server_operation_t;
typedef globus_gridftp_server_control_stat_t globus_gridftp_server_stat_t;

#define GLOBUS_GFS_FILE_ONLY GLOBUS_GRIDFTP_SERVER_CONTROL_RESOURCE_FILE_ONLY

/* (optional) this is used for listings, size, etc... it is only used in the
 * 'default' module
 */
typedef globus_result_t
(*globus_gridftp_server_resource_t)(
    globus_gridftp_server_operation_t   op,
    const char *                        pathname,
    int                                 mask);

typedef globus_result_t
(*globus_gridftp_server_recv_t)(
    globus_gridftp_server_operation_t   op,
    const char *                        arguments,
    const char *                        pathname);

typedef globus_result_t
(*globus_gridftp_server_send_t)(
    globus_gridftp_server_operation_t   op,
    const char *                        arguments,
    const char *                        pathname);

void
globus_gridftp_server_finished_resource(
    globus_gridftp_server_operation_t   op,
    globus_result_t                     result,
    globus_gridftp_server_stat_t *      stat_info_array,
    int                                 stat_count);

void
globus_gridftp_server_finished_command(
    globus_gridftp_server_operation_t   op,
    globus_result_t                     result,
    const char *                        command_data);

void
globus_gridftp_server_finished_transfer(
    globus_gridftp_server_operation_t   op,
    globus_result_t                     result);

void
globus_gridftp_server_begin_transfer(
    globus_gridftp_server_operation_t   op);

typedef void
(*globus_gridftp_server_write_cb_t)(
    globus_gridftp_server_operation_t   op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg);
    
globus_result_t
globus_gridftp_server_register_write(
    globus_gridftp_server_operation_t   op,
    globus_byte_t *                     buffer,  
    globus_size_t                       length,  
    globus_off_t                        offset,  
    int                                 stripe_ndx,  
    globus_gridftp_server_write_cb_t    callback,  
    void *                              user_arg);

typedef void
(*globus_gridftp_server_read_cb_t)(
    globus_gridftp_server_operation_t   op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    globus_off_t                        offset,
    globus_bool_t                       eof,
    void *                              user_arg);
 
globus_result_t
globus_gridftp_server_register_read(
    globus_gridftp_server_operation_t   op,
    globus_byte_t *                     buffer,
    globus_size_t                       length,
    globus_gridftp_server_read_cb_t     callback,  
    void *                              user_arg);

/* aborts all pending operations and calls callbacks */
void
globus_gridftp_server_flush_queue(
    globus_gridftp_server_operation_t   op);
    
void
globus_gridftp_server_update_bytes_written(
    globus_gridftp_server_operation_t   op,
    int                                 stripe_ndx,
    globus_off_t                        offset,
    globus_off_t                        length);

void
globus_gridftp_server_get_optimal_concurrency(
    globus_gridftp_server_operation_t   op,
    int *                               count);

void
globus_gridftp_server_get_block_size(
    globus_gridftp_server_operation_t   op,
    globus_size_t *                     block_size);

void
globus_gridftp_server_get_read_range(
    globus_gridftp_server_operation_t   op,
    globus_off_t *                      offset,
    globus_off_t *                      length,
    globus_off_t *                      write_delta);

void
globus_gridftp_server_get_write_range(
    globus_gridftp_server_operation_t   op,
    globus_off_t *                      offset,
    globus_off_t *                      length,
    globus_off_t *                      write_delta,
    globus_off_t *                      transfer_delta);

void
globus_i_gfs_server_closed();
   
typedef enum
{
    GLOBUS_GFS_ERROR_MEMORY,
    GLOBUS_GFS_ERROR_SYSTEM_ERROR,
    GLOBUS_GFS_ERROR_WRAPPED,
    GLOBUS_GFS_ERROR_DATA,
    GLOBUS_GFS_ERROR_GENERIC
} globus_gridftp_server_error_t;

#ifdef __GNUC__
#define GlobusGFSName(func) static const char * _gfs_name __attribute__((__unused__)) = #func
#else
#define GlobusGFSName(func) static const char * _gfs_name = #func
#endif

#define GlobusGFSErrorMemory(mem_name)                                      \
    globus_error_put(GlobusGFSErrorObjMemory(mem_name))                               

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

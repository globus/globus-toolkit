#if !defined(GLOBUS_GFORK_H)
#define GLOBUS_GFORK_H 1

#include "globus_common.h"
#include "globus_xio.h"
#include "globus_xio_tcp_driver.h"
#include "globus_xio_mode_e_driver.h"

#ifdef __GNUC__
#define GlobusGForkFuncName(func) static const char * _gfork_func_name __attribute__((__unused__)) = #func
#else
#define GlobusXIOGForkName(func) static const char * _gfork_func_name = #func
#endif

#define GFORK_CHILD_READ_ENV "GFORK_CHILD_READ_ENV"
#define GFORK_CHILD_WRITE_ENV "GFORK_CHILD_WRITE_ENV"
#define GFORK_CHILD_CS_ENV "GFORK_CHILD_CS_ENV"
#define GFORK_CHILD_INSTANCE_ENV "GFORK_CHILD_INSTANCE_ENV"

typedef void *                          gfork_child_handle_t;

typedef enum
{
    GLOBUS_GFORK_DEBUG_ERROR = 1,
    GLOBUS_GFORK_DEBUG_WARNING = 2,
    GLOBUS_GFORK_DEBUG_TRACE = 4,
    GLOBUS_GFORK_DEBUG_INTERNAL_TRACE = 8,
    GLOBUS_GFORK_DEBUG_INFO = 16,
    GLOBUS_GFORK_DEBUG_STATE = 32,
    GLOBUS_GFORK_DEBUG_INFO_VERBOSE = 64
} globus_gfork_debug_levels_t;

/*
 *  server plug in functions
 */

/* whne a connection is accepted */
typedef void 
(*globus_gfork_open_func_t)(
    gfork_child_handle_t                handle,
    void *                              user_arg,
    pid_t                               from_pid);

/* connection cloesd */
typedef void
(*globus_gfork_closed_func_t)(
    gfork_child_handle_t                handle,
    void *                              user_arg,
    pid_t                               from_pid);

typedef void
(*globus_gfork_incoming_cb_t)(
    gfork_child_handle_t                handle,
    void *                              user_arg,
    pid_t                               from_pid,
    globus_byte_t *                     buffer,
    globus_size_t                       len);
    

/* ... other randomly useless function */

/*
 * client functions
 */
globus_result_t
globus_gfork_child_worker_start(
    gfork_child_handle_t *              out_handle,
    const char *                        in_env_suffix,
    globus_gfork_closed_func_t          close_cb,
    globus_gfork_incoming_cb_t          incoming_cb,
    void *                              user_arg);

globus_result_t
globus_gfork_child_master_start(
    gfork_child_handle_t *              out_handle,
    const char *                        in_env_suffix,
    globus_gfork_open_func_t            open_cb,
    globus_gfork_closed_func_t          close_cb,
    globus_gfork_incoming_cb_t          incoming_cb,
    void *                              user_arg);

globus_result_t
globus_gfork_broadcast(
    gfork_child_handle_t                handle,
    globus_xio_iovec_t *                iov,
    int                                 iovc,
    globus_xio_iovec_callback_t         cb,
    void *                              user_arg);

globus_result_t
globus_gfork_send(
    gfork_child_handle_t                handle,
    uid_t                               pid,
    globus_xio_iovec_t *                iov,
    int                                 iovc,
    globus_xio_iovec_callback_t         cb,
    void *                              user_arg);

globus_result_t
globus_gfork_child_stop(
    gfork_child_handle_t                in_handle);

extern globus_module_descriptor_t       globus_i_gfork_parent_module;
#define GLOBUS_GFORK_PARENT_MODULE &globus_i_gfork_parent_module
extern globus_module_descriptor_t       globus_i_gfork_child_module;
#define GLOBUS_GFORK_CHILD_MODULE &globus_i_gfork_child_module

#endif

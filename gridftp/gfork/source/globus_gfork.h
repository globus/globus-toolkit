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

typedef struct gfork_i_child_handle_s * globus_gfork_handle_t;

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

/* when the listener is started */
typedef void 
(*globus_gfork_startup_func_t)(
    void **                             user_arg);

/* whne a connection is accepted */
typedef void 
(*globus_gfork_open_func_t)(
    void *                              user_arg,
    globus_gfork_handle_t               handle,
    void **                             connection_user_arg);

/* connection cloesd */
typedef void
(*globus_gfork_closed_func_t)(
    void *                              user_arg,
    globus_gfork_handle_t               handle,
    void *                              connection_user_arg);

/* listener is closed */
typedef void 
(*globus_gfork_shutdown_func_t)(
    void *                              user_arg);

typedef struct globus_gfork_module_s
{
    globus_gfork_startup_func_t         startup_func;
    globus_gfork_open_func_t            open_func;
    globus_gfork_closed_func_t          close_func;
    globus_gfork_shutdown_func_t        shutdown_func;
} globus_gfork_module_t;

globus_result_t
globus_gfork_get_fd(
    globus_gfork_handle_t               handle,
    int *                               read_fd,
    int *                               write_fd);

globus_result_t
globus_gfork_get_xio(
    globus_gfork_handle_t               handle,
    globus_xio_handle_t *               read_xio_handle,
    globus_xio_handle_t *               write_xio_handle);

globus_result_t
globus_gfork_get_time_open(
    globus_gfork_handle_t               handle,
    time_t *                            time);
/* ... other randomly useless function */

/*
 * client functions
 */

globus_result_t
globus_gfork_child_get_fd(
    int *                               read_fd,
    int *                               write_fd);

globus_result_t
globus_gfork_child_get_xio(
    globus_xio_handle_t *               read_xio_handle,
    globus_xio_handle_t *               write_xio_handle);

extern globus_extension_registry_t      gfork_i_plugin_registry;
extern globus_module_descriptor_t       globus_i_gfork_parent_module;
#define GLOBUS_GFORK_PARENT_MODULE &globus_i_gfork_parent_module
extern globus_module_descriptor_t       globus_i_gfork_child_module;
#define GLOBUS_GFORK_CHILD_MODULE &globus_i_gfork_child_module

#endif

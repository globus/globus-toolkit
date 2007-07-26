#include "globus_common.h"
#include "globus_xio.h"
#include "globus_xio_tcp_driver.h"
#include "globus_xio_file_driver.h"
#include "globus_gfork.h"


#if !defined(GFORK_I_H)
#define GFORK_I_H 1

#ifdef __GNUC__
#define GForkFuncName(func) static const char * _gfork_func_name __attribute__((__unused__)) = #func
#else
#define GForkFuncName(func) static const char * _gfork_func_name = #func
#endif

#define GForkErrorErrno(_msg, _errno) \
    globus_error_put(GForkErrorObjErrno(_msg, _errno))

#define GForkErrorObjErrno(_msg, _errno)                                    \
        globus_error_wrap_errno_error(                                      \
            GLOBUS_GFORK_CHILD_MODULE,                                      \
            (_errno),                                                       \
            GLOBUS_GFORK_ERROR_ERRNO,                                       \
            __FILE__,                                                       \
            _gfork_func_name,                                               \
            __LINE__,                                                       \
            "System error in %s",                                           \
            _msg)

#define GForkErrorStr(_msg) \
    globus_error_put(GForkErrorObjStr(_msg))

#define GForkErrorObjStr(str)                                               \
        globus_error_construct_error(                                       \
            GLOBUS_GFORK_CHILD_MODULE,                                      \
            NULL,                                                           \
            GLOBUS_GFORK_ERROR_STR,                                         \
            __FILE__,                                                       \
            _gfork_func_name,                                               \
            __LINE__,                                                       \
            "GFork error: %s",                                              \
            (str))

GlobusDebugDeclare(GLOBUS_GFORK);

#define GlobusGForkDebugPrintf(level, message)                              \
    GlobusDebugPrintf(GLOBUS_GFORK, level, message)

#define GlobusGForkDebugEnter()                                             \
    GlobusGForkDebugPrintf(                                                 \
        GLOBUS_GFORK_DEBUG_TRACE,                                           \
        ("[%s] Entering\n", _xio_name))

#define GlobusGForkDebugExit()                                              \
    GlobusGForkDebugPrintf(                                                 \
        GLOBUS_GFORK_DEBUG_TRACE,                                           \
        ("[%s] Exiting\n", _xio_name))

#define GlobusGForkDebugExitWithError()                                     \
    GlobusGForkDebugPrintf(                                                 \
        GLOBUS_GFORK_DEBUG_TRACE,                                           \
        ("[%s] Exiting with error\n", _xio_name))

#define GlobusGForkDebugState(_old, _new, _event)                           \
    GlobusGForkDebugPrintf(                                                 \
        GLOBUS_GFORK_DEBUG_STATE,                                           \
        ("State Change from %s to %s when %s\n", _old, _new, _event))

enum
{
    GLOBUS_GFORK_ERROR_ERRNO = 1,
    GLOBUS_GFORK_ERROR_STR
};

typedef enum gfork_i_msg_type_e
{
    GLOBUS_GFORK_MSG_OPEN = 'O',
    GLOBUS_GFORK_MSG_CLOSE = 'C',
    GLOBUS_GFORK_MSG_DATA = 'D'
} gfork_i_msg_type_t;

typedef struct gfork_i_msg_header_s
{
    uint64_t                size;
    pid_t                   from_pid;
    pid_t                   to_pid;
    gfork_i_msg_type_t      type;
} gfork_i_msg_header_t;

typedef struct gfork_i_msg_data_s
{
    int                                 ref;
    globus_byte_t                       buffer[1];
} gfork_i_msg_data_t;

typedef struct gfork_i_msg_s
{
    gfork_i_msg_header_t                header;
    struct gfork_i_child_handle_s *     to_kid;
    struct gfork_i_child_handle_s *     from_kid;
    void *                              user_arg;
    globus_xio_iovec_t *                iov;
    int                                 iovc;
    globus_size_t                       nbytes;
    globus_xio_iovec_t                  write_iov[2];
    globus_xio_iovec_callback_t         client_cb;
    globus_xio_iovec_callback_t         cb;
    gfork_i_msg_data_t *                data;
    globus_byte_t *                     buffer;
    struct gfork_i_lib_handle_s *       lib_handle;
} gfork_i_msg_t;

typedef enum gfork_i_state_e
{
    GFORK_STATE_NONE = 0,
    GFORK_STATE_OPENING,
    GFORK_STATE_OPEN,
    GFORK_STATE_OPENING_AND_CLOSING,
    GFORK_STATE_CLOSING,
    GFORK_STATE_CLOSED,
    GFORK_STATE_COUNT
} gfork_i_state_t;

typedef enum gfork_i_events_s
{
    GFORK_EVENT_NONE = 0,
    GFORK_EVENT_ACCEPT_CB,
    GFORK_EVENT_OPEN_RETURNS,
    GFORK_EVENT_SIGCHILD,
    GFORK_EVENT_CLOSE_RETURNS,
    GFORK_EVENT_COUNT
} gfork_i_events_t;

typedef struct gfork_i_options_s
{
    char *                              id;
    globus_list_t *                     protocol_list;
    char *                              server;
    globus_list_t *                     server_arg_list;
    int                                 port;
    int                                 instances;
    int                                 nice;
    char *                              interface;
    globus_list_t *                     env_list;
    uid_t                               master_user;
    char *                              master;
    globus_list_t *                     master_arg_list;
    void *                              user_arg;
    globus_bool_t                       quiet;
    char *                              conf_file;
    int                                 log_level;
    FILE *                              log_fptr;
} gfork_i_options_t;

typedef struct gfork_i_handle_s
{
    globus_xio_stack_t                  stack;
    char **                             server_argv;
    char **                             master_argv;
    char **                             env_argv;
    globus_list_t *                     loaded_drivers;
    globus_xio_driver_t                 tcp_driver;
    globus_xio_server_t                 server_xio;
    gfork_i_options_t *                 opts;
} gfork_i_handle_t;

typedef struct gfork_i_child_handle_s
{
    pid_t                               pid;
    int                                 write_fd;
    int                                 read_fd;
    globus_xio_handle_t                 write_xio_handle;
    globus_xio_handle_t                 read_xio_handle;
    gfork_i_handle_t *                  whos_my_daddy;
    void *                              user_arg;
    gfork_i_state_t                     state;
    globus_bool_t                       dead;
    globus_fifo_t                       write_q;
    globus_bool_t                       writting;
    globus_bool_t                       master;
} gfork_i_child_handle_t;

typedef struct gfork_i_lib_handle_s
{
    globus_xio_handle_t                 read_xio;
    globus_xio_handle_t                 write_xio;
    gfork_i_msg_header_t                header;
    globus_byte_t *                     data;
    globus_gfork_incoming_cb_t          incoming_cb;
    globus_gfork_open_func_t            open_cb;
    globus_gfork_closed_func_t          close_cb;
    globus_bool_t                       master;
    void *                              user_arg;
    globus_mutex_t                      mutex;
    gfork_i_state_t                     state;
    globus_fifo_t                       write_q;
    globus_bool_t                       writing;
} gfork_i_lib_handle_t;

globus_result_t
gfork_i_make_xio_handle(
    globus_xio_handle_t *               xio_handle,
    int                                 fd);

void
gfork_i_state_init();

gfork_i_state_t
gfork_i_state_next(
    gfork_i_state_t                 current_state,
    gfork_i_events_t                event);

globus_result_t
globus_i_opts_to_handle(
    gfork_i_options_t *                 opts,
    gfork_i_handle_t *                  handle);

extern globus_xio_stack_t               gfork_i_file_stack;
extern globus_xio_attr_t                gfork_i_file_attr;
extern globus_xio_driver_t              gfork_i_file_driver;

extern globus_options_entry_t           gfork_l_opts_table[];

#endif

#if !defined(GLOBUS_I_GRIDFTP_SERVER_CONTROL_H)
#define GLOBUS_I_GRIDFTP_SERVER_CONTROL_H 1

#include "globus_gridftp_server_control.h"

#define GLOBUS_GRIDFTP_SERVER_HASHTABLE_SIZE    256
#define GLOBUS_GRIDFTP_VERSION_CTL              1

GlobusDebugDeclare(GLOBUS_GRIDFTP_SERVER_CONTROL);


#define GlobusGSDebugPrintf(level, message)                                \
    GlobusDebugPrintf(GLOBUS_GRIDFTP_SERVER_CONTROL, level, message)


#define GlobusGridFTPServerDebugEnter()                                     \
    GlobusGSDebugPrintf(                                                    \
        GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_TRACE,                          \
        ("[%s] Entering\n", _gridftp_server_name))

#define GlobusGridFTPServerDebugExit()                                      \
    GlobusGSDebugPrintf(                                                    \
        GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_TRACE,                          \
        ("[%s] Exiting\n", _gridftp_server_name))
    
#define GlobusGridFTPServerDebugExitWithError()                             \
    GlobusGSDebugPrintf(                                                    \
        GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_TRACE,                          \
        ("[%s] Exiting with error\n", _gridftp_server_name))
    
#define GlobusGridFTPServerDebugInternalEnter()                             \
    GlobusGSDebugPrintf(                                                    \
        GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_INTERNAL_TRACE,                 \
        ("[%s] I Entering\n", _gridftp_server_name))

#define GlobusGridFTPServerDebugInternalExit()                              \
    GlobusGSDebugPrintf(                                                    \
        GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_INTERNAL_TRACE,                 \
        ("[%s] I Exiting\n", _gridftp_server_name))
    
#define GlobusGridFTPServerDebugInternalExitWithError()                     \
    GlobusGSDebugPrintf(                                                    \
        GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_INTERNAL_TRACE,                 \
        ("[%s] I Exiting with error\n", _gridftp_server_name))


#define GlobusGridFTPServerErrorParameter(param_name)                       \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_PARAMETER,                  \
            __FILE__,                                                       \
            _gridftp_server_name,                                           \
            __LINE__,                                                       \
            "Bad parameter, %s",                                            \
            (param_name)))

#define GlobusGridFTPServerErrorMemory(mem_name)                            \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_MEMORY,                     \
            __FILE__,                                                       \
            _gridftp_server_name,                                           \
            __LINE__,                                                       \
            "Memory allocation failed on %s",                               \
            (mem_name)))

#define GlobusGridFTPServerErrorState(state)                                \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_STATE,                      \
            __FILE__,                                                       \
            _gridftp_server_name,                                           \
            __LINE__,                                                       \
            "Invalid state: %d",                                            \
            (state)))

#define GlobusGridFTPServerNotAuthenticated()                               \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_NO_AUTH,                          \
            __FILE__,                                                       \
            _gridftp_server_name,                                           \
            __LINE__,                                                       \
            "Not yet authenticated."))

#define GlobusGridFTPServerPostAuthenticated()                              \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_POST_AUTH,                        \
            __FILE__,                                                       \
            _gridftp_server_name,                                           \
            __LINE__,                                                       \
            "Not yet authenticated."))

#define GlobusGridFTPServerNotACommand()                                    \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_NO_COMMAND,                       \
            __FILE__,                                                       \
            _gridftp_server_name,                                           \
            __LINE__,                                                       \
            "Command not implemented."))


#define GlobusGridFTPServerOpSetUserArg(_in_op, _in_arg)                    \
    (_in_op)->user_arg = (_in_arg);                                         \

#define GlobusGridFTPServerOpGetUserArg(_in_op)                             \
    ((_in_op)->user_arg)

#define GlobusGridFTPServerOpGetServer(_in_op)                              \
    ((_in_op)->server)

#define GlobusGridFTPServerOpGetPModArg(_in_op)                             \
    ((_in_op)->pmod_arg)

#define GlobusGridFTPServerOpSetPModArg(_in_op, _in_arg)                    \
    (_in_op)->pmod_arg = (_in_arg);                                         \

struct globus_i_gs_attr_s;

typedef enum globus_gridftp_server_debug_levels_e
{ 
    GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_ERROR = 1,
    GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_WARNING = 2,
    GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_TRACE = 4,
    GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_INTERNAL_TRACE = 8,
    GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_INFO = 16,
    GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_INFO_VERBOSE = 32
} globus_gridftp_server_debug_levels_t;

typedef enum globus_i_gs_state_e
{
    GLOBUS_L_GS_STATE_NONE,
    GLOBUS_L_GS_STATE_OPEN,
    GLOBUS_L_GS_STATE_AUTH,
    GLOBUS_L_GS_STATE_STOPPED,
    GLOBUS_L_GS_STATE_STOPPING,
    GLOBUS_L_GS_STATE_ERROR
} globus_i_gs_state_t;

typedef enum globus_gridftp_server_error_type_e
{
    GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_PARAMETER,
    GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_STATE,
    GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_MEMORY,
    GLOBUS_GRIDFTP_SERVER_CONTROL_NO_AUTH,
    GLOBUS_GRIDFTP_SERVER_CONTROL_POST_AUTH,
    GLOBUS_GRIDFTP_SERVER_CONTROL_NO_COMMAND,
    GLOBUS_GRIDFTP_SERVER_CONTROL_MALFORMED_COMMAND
} globus_gridftp_server_error_type_t;

typedef enum globus_i_gsc_conn_dir_e
{
    GLOBUS_I_GSC_CONN_DIR_PASV,
    GLOBUS_I_GSC_CONN_DIR_PORT
} globus_i_gsc_conn_dir_t;

typedef struct globus_i_gsc_data_s
{
    void *                                          user_handle;
    globus_gridftp_server_control_data_dir_t        data_dir;
    globus_i_gsc_conn_dir_t                         conn_dir;
} globus_i_gsc_data_t;

typedef struct globus_i_gsc_server_s
{
    int                                             version_ctl;

    globus_mutex_t                                  mutex;
    /*
     *  authentication information
     */
    char *                                          username;
    char *                                          pw;
    char *                                          banner;
    gss_cred_id_t                                   cred;
    gss_cred_id_t                                   del_cred;
    globus_gridftp_server_control_auth_callback_t   auth_cb;

    uid_t                                           uid;

    /*
     *  
     */
    char *                                          cwd;
    char                                            type;
    char                                            mode;
    char *                                          modes;
    char *                                          types;
    int                                             parallelism;
    int                                             send_buf;
    int                                             receive_buf;

    globus_hashtable_t                              send_table;
    globus_hashtable_t                              recv_table;
    globus_gridftp_server_control_transfer_func_t   default_stor;
    globus_gridftp_server_control_transfer_func_t   default_retr;

    /*
     *  action functions
     */
    globus_gridftp_server_control_action_func_t     delete_func;
    globus_gridftp_server_control_action_func_t     mkdir_func;
    globus_gridftp_server_control_action_func_t     rmdir_func;
    globus_gridftp_server_control_move_func_t       move_func;

    globus_result_t                                 cached_res;

    /*
     *  static conf strings.
     */
    char *                                          syst;
    char *                                          help;

    void *                                          user_arg;

    globus_bool_t                                   refresh;
    int                                             ref;
    globus_i_gs_state_t                             state;

    globus_i_gsc_data_t *                           data_object;
    globus_fifo_t                                   data_q;
    globus_gridftp_server_control_passive_connect_t passive_func;
    globus_gridftp_server_control_active_connect_t  active_func;
    globus_gridftp_server_control_data_destroy_t    data_destroy_func;

    globus_gridftp_server_control_callback_t        user_stop_func;
    globus_gridftp_server_control_resource_callback_t resource_func;
    globus_gridftp_server_control_callback_t        done_func;
} globus_i_gsc_server_t;

typedef enum globus_i_gsc_op_type_e
{
    GLOBUS_L_GSC_OP_TYPE_AUTH,
    GLOBUS_L_GSC_OP_TYPE_RESOURCE,
    GLOBUS_L_GSC_OP_TYPE_CREATE_PASV,
    GLOBUS_L_GSC_OP_TYPE_CREATE_PORT,
    GLOBUS_L_GSC_OP_TYPE_DESTROY,
    GLOBUS_L_GSC_OP_TYPE_MOVE,
    GLOBUS_L_GSC_OP_TYPE_DELETE,
    GLOBUS_L_GSC_OP_TYPE_MKDIR,
    GLOBUS_L_GSC_OP_TYPE_RMDIR
} globus_i_gsc_op_type_t;

typedef struct globus_i_gsc_op_s
{
    globus_i_gsc_op_type_t                          type;

    globus_i_gsc_server_t *                         server;
    globus_result_t                                 res;

    /* stuff for auth */
    char *                                          username;
    char *                                          password;
    gss_cred_id_t                                   cred;
    gss_cred_id_t                                   del_cred;
    globus_gridftp_server_control_pmod_auth_callback_t auth_cb;
    globus_gridftp_server_control_pmod_stat_callback_t stat_cb;

    /* stuff for resource */
    char *                                          path;
    globus_gridftp_server_control_resource_mask_t   mask;

    /* stuff for port/pasv */
    char **                                         cs;
    int                                             max_cs;
    int                                             net_prt;
    globus_gridftp_server_control_pmod_passive_callback_t passive_cb;
    globus_gridftp_server_control_pmod_port_callback_t  port_cb;

    /* stuff for transfer */
    char *                                          mod_name;
    char *                                          mod_parms;
    globus_gridftp_server_control_transfer_func_t   user_data_cb;
    globus_gridftp_server_control_data_callback_t   data_cb;
    globus_gridftp_server_control_event_callback_t  event_cb;
    globus_bool_t                                   transfer_started;

    void *                                          user_arg;
} globus_i_gsc_op_t;

typedef struct globus_i_gsc_attr_s
{
    int                                             version_ctl;
    globus_hashtable_t                              send_func_table;
    globus_hashtable_t                              recv_func_table;
    globus_gridftp_server_control_resource_callback_t resource_func;
    globus_gridftp_server_control_callback_t        done_func;
    globus_i_gs_state_t                             start_state;
    char *                                          modes;
    char *                                          types;
    char *                                          base_dir;
    globus_gridftp_server_control_auth_callback_t   auth_func;
    globus_gridftp_server_control_passive_connect_t passive_func;
    globus_gridftp_server_control_active_connect_t  active_func;
    globus_gridftp_server_control_data_destroy_t    data_destroy_func;

    globus_gridftp_server_control_action_func_t     delete_func;
    globus_gridftp_server_control_action_func_t     mkdir_func;
    globus_gridftp_server_control_action_func_t     rmdir_func;
    globus_gridftp_server_control_move_func_t       move_func;

    globus_gridftp_server_control_transfer_func_t   default_stor;
    globus_gridftp_server_control_transfer_func_t   default_retr;
} globus_i_gsc_attr_t;


extern globus_hashtable_t               globus_i_gs_default_attr_command_hash;

/*
 *  internal functions for adding commands.
 */

typedef enum globus_gridftp_server_command_desc_e
{
    GLOBUS_GRIDFTP_SERVER_CONTROL_COMMAND_DESC_REFRESH = 0x01,
    GLOBUS_GRIDFTP_SERVER_CONTROL_COMMAND_DESC_POST_AUTH = 0x02,
    GLOBUS_GRIDFTP_SERVER_CONTROL_COMMAND_DESC_PRE_AUTH = 0x04
} globus_gridftp_server_command_desc_t;

/*
 *   959 Structures
 */
typedef enum globus_l_gsc_959_state_e
{
    GLOBUS_L_GSP_959_STATE_OPEN,
    GLOBUS_L_GSP_959_STATE_PROCESSING,
    GLOBUS_L_GSP_959_STATE_ABORTING,
    GLOBUS_L_GSP_959_STATE_ABORTING_STOPPING,
    GLOBUS_L_GSP_959_STATE_STOPPING,
    GLOBUS_L_GSP_959_STATE_STOPPED,
} globus_l_gsc_state_t;

typedef struct globus_l_gsc_959_handle_s
{
    globus_bool_t                           reply_outstanding;
    globus_i_gsc_server_t *                 server;
    globus_xio_handle_t                     xio_handle;
    globus_l_gsc_state_t                    state;
    globus_fifo_t                           read_q;
    globus_fifo_t                           reply_q;
    int                                     abort_cnt;
    globus_hashtable_t                      cmd_table;
    globus_gsc_959_abort_func_t             abort_func;
    void *                                  abort_arg;
    struct globus_gsc_op_959_s *            outstanding_op;
} globus_l_gsc_959_handle_t;

typedef struct globus_l_gsc_959_cmd_ent_s
{
    int                                     cmd;
    char                                    cmd_name[16]; /* only 5 needed */
    globus_gsc_959_command_func_t           cmd_func;
    globus_gsc_959_command_desc_t           desc;
    char *                                  help;
    void *                                  user_arg;
} globus_l_gsc_959_cmd_ent_t;

typedef struct globus_l_gsc_959_reply_ent_s
{
    char *                                  msg;
    globus_bool_t                           final;
    globus_gsc_op_959_t                     op;
} globus_l_gsc_959_reply_ent_t;

typedef struct globus_gsc_op_959_s
{
    globus_l_gsc_959_handle_t *             handle;
    globus_list_t *                         cmd_list;
    char *                                  command;
    globus_i_gsc_server_t *                 server;
} globus_gsc_op_959_t;

/* 
 *  959 reader functions
 */
globus_result_t
globus_i_gsc_959_start(
    globus_i_gsc_server_t *                 server,
    globus_xio_handle_t                     xio_handle);

void
globus_i_gsc_959_terminate(
    globus_l_gsc_959_handle_t *             handle);

globus_result_t
globus_i_gsc_959_command_add(
    globus_l_gsc_959_handle_t *             handle,
    const char *                            command_name,
    globus_gsc_959_command_func_t           command_func,
    globus_gsc_959_command_desc_t           desc,
    const char *                            help,
    void *                                  user_arg);

char *
globus_i_gsc_959_get_help(
    globus_l_gsc_959_handle_t *             handle,
    const char *                            command_name);

globus_result_t
globus_i_gsc_959_intermediate_reply(
    globus_gsc_op_959_t *                   op,
    char *                                  reply_msg);

void
globus_i_gsc_959_finished_op(
    globus_gsc_op_959_t *                   op,
    char *                                  reply_msg);

#endif

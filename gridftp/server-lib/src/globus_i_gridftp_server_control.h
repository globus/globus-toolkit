#if !defined(GLOBUS_I_GRIDFTP_SERVER_CONTROL_H)
#define GLOBUS_I_GRIDFTP_SERVER_CONTROL_H 1

#include "globus_gridftp_server_control.h"
#include "globus_gridftp_server_control_pmod.h"

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
            "[%s:%d] Bad parameter, %s",                                    \
            _gridftp_server_name, __LINE__, (param_name)))

#define GlobusGridFTPServerErrorMemory(mem_name)                            \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_MEMORY,                     \
            "[%s:%d] Memory allocation failed on %s",                       \
            _gridftp_server_name, __LINE__, (mem_name)))

#define GlobusGridFTPServerErrorState(state)                                \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_STATE,                      \
            "[%s:%d] Invalid state: %d",                                    \
            _gridftp_server_name, __LINE__, (state)))

#define GlobusGridFTPServerNotAuthenticated()                               \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_NO_AUTH,                          \
            "[%s:%d] Not yet authenticated.",                               \
            _gridftp_server_name, __LINE__))

#define GlobusGridFTPServerPostAuthenticated()                              \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_POST_AUTH,                        \
            "[%s:%d] Not yet authenticated.",                               \
            _gridftp_server_name, __LINE__))

#define GlobusGridFTPServerNotACommand()                                    \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_NO_COMMAND,                       \
            "[%s:%d] Command not implemented.",                             \
            _gridftp_server_name, __LINE__))


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
    GLOBUS_GRIDFTP_SERVER_CONTROL_DEBUG_INFO_VERBOSE = 32,
} globus_gridftp_server_debug_levels_t;

typedef enum globus_i_gs_state_e
{
    GLOBUS_L_GS_STATE_NONE,
    GLOBUS_L_GS_STATE_OPEN,
    GLOBUS_L_GS_STATE_AUTH,
    GLOBUS_L_GS_STATE_STOPPED,
    GLOBUS_L_GS_STATE_STOPPING,
    GLOBUS_L_GS_STATE_ERROR,
} globus_i_gs_state_t;

typedef enum globus_gridftp_server_error_type_e
{
    GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_PARAMETER,
    GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_STATE,
    GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_MEMORY,
    GLOBUS_GRIDFTP_SERVER_CONTROL_NO_AUTH,
    GLOBUS_GRIDFTP_SERVER_CONTROL_POST_AUTH,
    GLOBUS_GRIDFTP_SERVER_CONTROL_NO_COMMAND,
    GLOBUS_GRIDFTP_SERVER_CONTROL_MALFORMED_COMMAND,
} globus_gridftp_server_error_type_t;

typedef enum globus_i_gsc_conn_dir_e
{
    GLOBUS_I_GSC_CONN_DIR_PASV,
    GLOBUS_I_GSC_CONN_DIR_PORT,
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
    globus_xio_handle_t                             xio_handle;

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
    globus_size_t                                   send_buf;
    globus_size_t                                   receive_buf;

    globus_hashtable_t                              send_table;
    globus_hashtable_t                              recv_table;
    globus_gridftp_server_control_transfer_func_t   default_stor;
    globus_gridftp_server_control_transfer_func_t   default_retr;

    globus_result_t                                 cached_res;

    /*
     *  static conf strings.
     */
    char *                                          syst;
    char *                                          help;

    globus_i_gridftp_server_control_pmod_t *        pmod;
    void *                                          proto_arg;

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
    GLOBUS_L_GSC_OP_TYPE_DATA,
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
    globus_i_gridftp_server_control_pmod_t *        pmod;
    globus_i_gs_state_t                             start_state;
    char *                                          modes;
    char *                                          types;
    char *                                          base_dir;
    globus_gridftp_server_control_auth_callback_t   auth_func;
    globus_gridftp_server_control_passive_connect_t passive_func;
    globus_gridftp_server_control_active_connect_t  active_func;
    globus_gridftp_server_control_data_destroy_t    data_destroy_func;

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
    GLOBUS_GRIDFTP_SERVER_CONTROL_COMMAND_DESC_PRE_AUTH = 0x04,
} globus_gridftp_server_command_desc_t;

globus_result_t
globus_i_gridftp_server_control_get_auth_cb(
    globus_gridftp_server_control_t                 server,
    globus_gridftp_server_control_auth_callback_t * auth_cb);

globus_result_t
globus_i_gridftp_server_control_get_resource_cb(
    globus_gridftp_server_control_t                 server,
    globus_gridftp_server_control_resource_callback_t * resource_cb);

globus_result_t
globus_i_gridftp_server_control_get_status(
    globus_gridftp_server_control_t                 server,
    char **                                         status);

void
globus_i_gridftp_server_control_finished_cmd(
    globus_gridftp_server_control_operation_t       op,
    globus_result_t                                 result,
    void **                                         argv,
    int                                             argc,
    globus_bool_t                                   complete);


#endif

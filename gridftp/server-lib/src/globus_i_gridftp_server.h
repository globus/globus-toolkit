#if !defined(GLOBUS_I_GRIDFTP_SERVER_H)
#define GLOBUS_I_GRIDFTP_SERVER_H 1

#ifdef __GNUC__
#define GlobusGridFTPServerName(func) static const char * _gridftp_server_name __attribute__((__unused__)) = #func
#else
#define GlobusGridFTPServerName(func) static const char * _gridftp_server_name = #func
#endif

#include "globus_gridftp_server.h"

#define GLOBUS_GRIDFTP_SERVER_HASHTABLE_SIZE    256
#define GLOBUS_GRIDFTP_VERSION_CTL              1

GlobusDebugDeclare(GLOBUS_GRIDFTP_SERVER);


#define GlobusGSDebugPrintf(level, message)                                \
    GlobusDebugPrintf(GLOBUS_GRIDFTP_SERVER, level, message)


#define GlobusGridFTPServerDebugEnter()                                     \
    GlobusGSDebugPrintf(                                                    \
        GLOBUS_GRIDFTP_SERVER_DEBUG_TRACE,                                  \
        ("[%s] Entering\n", _gridftp_server_name))

#define GlobusGridFTPServerDebugExit()                                      \
    GlobusGSDebugPrintf(                                                    \
        GLOBUS_GRIDFTP_SERVER_DEBUG_TRACE,                                  \
        ("[%s] Exiting\n", _gridftp_server_name))
    
#define GlobusGridFTPServerDebugExitWithError()                             \
    GlobusGSDebugPrintf(                                                    \
        GLOBUS_GRIDFTP_SERVER_DEBUG_TRACE,                                  \
        ("[%s] Exiting with error\n", _gridftp_server_name))
    
#define GlobusGridFTPServerDebugInternalEnter()                             \
    GlobusGSDebugPrintf(                                                    \
        GLOBUS_GRIDFTP_SERVER_DEBUG_INTERNAL_TRACE,                         \
        ("[%s] I Entering\n", _gridftp_server_name))

#define GlobusGridFTPServerDebugInternalExit()                              \
    GlobusGSDebugPrintf(                                                    \
        GLOBUS_GRIDFTP_SERVER_DEBUG_INTERNAL_TRACE,                         \
        ("[%s] I Exiting\n", _gridftp_server_name))
    
#define GlobusGridFTPServerDebugInternalExitWithError()                     \
    GlobusGSDebugPrintf(                                                    \
        GLOBUS_GRIDFTP_SERVER_DEBUG_INTERNAL_TRACE,                         \
        ("[%s] I Exiting with error\n", _gridftp_server_name))


#define GlobusGridFTPServerErrorParameter(param_name)                       \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_MODULE,                                   \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_ERROR_PARAMETER,                          \
            "[%s:%d] Bad parameter, %s",                                    \
            _gridftp_server_name, __LINE__, (param_name)))

#define GlobusGridFTPServerErrorMemory(mem_name)                            \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_MODULE,                                   \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_ERROR_MEMORY,                             \
            "[%s:%d] Memory allocation failed on %s",                       \
            _gridftp_server_name, __LINE__, (mem_name)))

#define GlobusGridFTPServerErrorState(state)                                \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_MODULE,                                   \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_ERROR_STATE,                              \
            "[%s:%d] Invalid state: %d",                                    \
            _gridftp_server_name, __LINE__, (state)))

#define GlobusGridFTPServerNotAuthenticated()                               \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_MODULE,                                   \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_NO_AUTH,                                  \
            "[%s:%d] Not yet authenticated.",                               \
            _gridftp_server_name, __LINE__))

#define GlobusGridFTPServerNotACommand()                                    \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_MODULE,                                   \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_NO_COMMAND,                               \
            "[%s:%d] Command not implemented.",                             \
            _gridftp_server_name, __LINE__))


#define GlobusGridFTPServerOpSetUserArg(_in_op, _in_arg)                    \
{                                                                           \
    (_in_op)->user_arg = (_in_arg);                                         \
}

#define GlobusGridFTPServerOpGetUserArg(_in_op)                             \
    ((_in_op)->user_arg)

#define GlobusGridFTPServerOpGetServer(_in_op)                              \
    ((_in_op)->server)

struct globus_i_gs_attr_s;

typedef enum
{ 
    GLOBUS_GRIDFTP_SERVER_DEBUG_ERROR = 1,
    GLOBUS_GRIDFTP_SERVER_DEBUG_WARNING = 2,
    GLOBUS_GRIDFTP_SERVER_DEBUG_TRACE = 4,
    GLOBUS_GRIDFTP_SERVER_DEBUG_INTERNAL_TRACE = 8,
    GLOBUS_GRIDFTP_SERVER_DEBUG_INFO = 16,
    GLOBUS_GRIDFTP_SERVER_DEBUG_INFO_VERBOSE = 32,
} globus_gridftp_server_debug_levels_t;

typedef enum
{
    GLOBUS_L_GS_STATE_NONE,
    GLOBUS_L_GS_STATE_OPEN,
    GLOBUS_L_GS_STATE_AUTH,
    GLOBUS_L_GS_STATE_USER_AUTH,
    GLOBUS_L_GS_STATE_STOPPED,
    GLOBUS_L_GS_STATE_STOPPING,
    GLOBUS_L_GS_STATE_ERROR,
} globus_i_gs_state_t;


typedef enum
{
    GLOBUS_GRIDFTP_SERVER_ERROR_PARAMETER,
    GLOBUS_GRIDFTP_SERVER_ERROR_STATE,
    GLOBUS_GRIDFTP_SERVER_ERROR_MEMORY,
    GLOBUS_GRIDFTP_SERVER_NO_AUTH,
    GLOBUS_GRIDFTP_SERVER_NO_COMMAND,
} globus_gridftp_server_error_type_t;

typedef enum
{
    GLOBUS_GRIDFTP_SERVER_COMMAND_COMPLETE,
    GLOBUS_GRIDFTP_SERVER_COMMAND_CONTINUE,
} globus_i_gs_command_complete_code;

typedef struct globus_i_gs_server_s
{
    int                                     version_ctl;

    globus_mutex_t                          mutex;
    globus_xio_handle_t                     xio_handle;

    /*
     *  authentication information
     */
    char *                                  username;
    char *                                  pw;
    gss_cred_id_t                           cred;
    gss_cred_id_t                           del_cred;
    globus_gridftp_server_auth_callback_t   auth_cb;

    /*
     *  
     */
    char *                                  pwd;
    char                                    type;
    char                                    mode;

    globus_hashtable_t                      command_table;
    globus_hashtable_t                      send_table;
    globus_hashtable_t                      recv_table;

    globus_result_t                         cached_res;

    /*
     *  static conf strings.
     */
    char *                                  syst;
    char *                                  help;

    globus_i_gridftp_server_pmod_t *        pmod;
    void *                                  proto_arg;

    void *                                  user_arg;

    globus_bool_t                           refresh;
    int                                     ref;
    globus_i_gs_state_t                     state;

    struct globus_i_gs_attr_s *             attr;

    globus_gridftp_server_callback_t        user_stop_func;
    globus_gridftp_server_resource_func_t   resource_func;
    globus_gridftp_server_error_func_t      user_error_func;
} globus_i_gs_server_t;

typedef struct globus_i_gs_command_entry_s
{
    char *                                  name;

    char *                                  feature;
    char *                                  help;

    int                                     type;

    void *                                  user_arg;

    globus_bool_t                           refresh;
    globus_bool_t                           auth_required;

    globus_gridftp_server_cmd_func_t        func;

    globus_gridftp_server_cmd_func_t        parse_cmd;
} globus_i_gs_cmd_ent_t;

typedef struct globus_i_gs_op_s
{
    globus_i_gs_server_t *                  server;
    globus_i_gs_cmd_ent_t *                 cmd_ent;
    globus_result_t                         res;
    globus_gridftp_server_pmod_command_cb_t cb;
    void *                                  user_arg;

    char *                                  str_arg;

    globus_list_t *                         cmd_list;

    char *                                  command_name;

    va_list                                 ap;

    int                                     mask;
} globus_i_gs_op_t;

typedef struct globus_i_gs_attr_s
{
    int                                     version_ctl;
    globus_hashtable_t                      send_func_table;
    globus_hashtable_t                      recv_func_table;
    globus_hashtable_t                      command_func_table;
    globus_gridftp_server_resource_func_t   resource_func;
    globus_gridftp_server_error_func_t      error_func;
    globus_i_gridftp_server_pmod_t *        pmod;
    globus_i_gs_state_t                     start_state;
} globus_i_gs_attr_t;


extern globus_hashtable_t               globus_i_gs_default_attr_command_hash;


globus_result_t
globus_i_gs_cmd_add_builtins(
    globus_gridftp_server_attr_t            attr);

#endif

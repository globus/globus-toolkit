#if !defined GLOBUS_GRIDFTP_SERVER_H
#define GLOBUS_GRIDFTP_SERVER_H

#include "globus_xio.h"
#include "globus_common.h"
#include "globus_gss_assist.h"

/*
 *  types
 */
struct globus_i_gs_server_s;
struct globus_i_gs_attr_s;
struct globus_i_gs_data_s;
struct globus_i_gs_op_s;

typedef struct globus_i_gs_server_s *       globus_gridftp_server_t;
typedef struct globus_i_gs_attr_s *         globus_gridftp_server_attr_t;
typedef struct globus_i_gs_data_s *         globus_gridftp_server_data_t;
typedef struct globus_i_gs_op_s *           globus_gridftp_server_operation_t;

typedef time_t                              globus_time_t;

typedef struct globus_gridftp_server_stat_s
{
    int                                     st_mode;
    int                                     st_nlink;
    uid_t                                   st_uid;
    gid_t                                   st_gid;
    globus_size_t                           st_size;
    globus_time_t                           mtime;
    globus_time_t                           atime;
    globus_time_t                           ctime;
} globus_gridftp_server_stat_t;

/*
 *  an enumeration of all the protocols currently available to the server
 *  library.
 */
typedef enum globus_gridftp_server_protocol_e
{
    GLOBUS_GRIDFTP_SERVER_PROTOCOL_FTP,
    GLOBUS_GRIDFTP_SERVER_PROTOCOL_GSIFTP,
    GLOBUS_GRIDFTP_SERVER_PROTOCOL_SOAP,
} globus_gridftp_server_protocol_t;

typedef enum globus_gridftp_server_command_desc_e
{
    GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_REFRESH = 0x01,
    GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_POST_AUTH = 0x02,
    GLOBUS_GRIDFTP_SERVER_COMMAND_DESC_PRE_AUTH = 0x04,
} globus_gridftp_server_command_desc_t;

typedef enum globus_gridftp_server_session_command_e
{
    GLOBUS_GRIDFTP_SERVER_SESSION_COMMAND_MKDIR,
    GLOBUS_GRIDFTP_SERVER_SESSION_COMMAND_RMDIR,
    GLOBUS_GRIDFTP_SERVER_SESSION_COMMAND_DELETE,
} globus_gridftp_server_session_command_t;

typedef enum globus_gridftp_server_event_type_e
{
    GLOBUS_GRIDFTP_SERVER_EVENT_TYPE_NONE,
} globus_gridftp_server_event_type_t;

/*
 *  transfer functions
 *
 *  these get registered on the attr
 */
typedef void
(*globus_gridftp_server_data_func_t)(
    globus_gridftp_server_operation_t       op,
    globus_gridftp_server_data_t            data_object,
    const char *                            local_target);

typedef void
(*globus_gridftp_server_auth_func_t)(
    globus_gridftp_server_operation_t       op,
    const char *                            username,
    const char *                            pw,
    gss_cred_id_t                           cred,
    gss_cred_id_t                           delegated_cred);

typedef globus_result_t
(*globus_gridftp_server_resource_func_t)(
    globus_gridftp_server_operation_t       op,
    const char *                            path,
    int                                     mask);

typedef globus_result_t
(*globus_gridftp_server_cmd_func_t)(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    globus_gridftp_server_operation_t       op,
    void **                                 argv,
    int                                     argc);

/***************************************************************************
 *                      start up
 *                      --------
 *  First the user must open a valid xio handle.  See the xio documentation 
 *  for how to do this.  The xio_handle is then used to initialize a server
 *  object, with an attr.  Callbacks are set on this attr (expained later).
 *
 *  If the user wishes to authenticate the make a call to
 *  globus_gridftp_server_authenticate().  This function will authenticate
 *  the connection according to the given protocol.  Once authenticated
 *  the users callback is called.  
 *
 *  Once the server handle starts the user can expect to receive the 
 *  callbacks it registered on the attr (more on this follows).  The user 
 *  stopes the callbacks by calling globus_gridftp_server_stop().   Once
 *  the callback passed into that function returns, no more callbacks will
 *  be dispatched.
 **************************************************************************/

/**
 *  generic server callback
 */
typedef void
(*globus_gridftp_server_callback_t)(
    globus_gridftp_server_t                 server,
    globus_result_t                         res,
    void *                                  user_arg);

/*
 *  attrs
 */
globus_result_t
globus_gridftp_server_attr_init(
    globus_gridftp_server_attr_t *          in_attr);

globus_result_t
globus_gridftp_server_attr_destroy(
    globus_gridftp_server_attr_t            in_attr);

globus_result_t
globus_gridftp_server_attr_copy(
    globus_gridftp_server_attr_t *          dst,
    globus_gridftp_server_attr_t            src);

globus_result_t
globus_gridftp_server_attr_add_recv(
    globus_gridftp_server_attr_t            in_attr,
    const char *                            module_name,
    globus_gridftp_server_data_func_t       recv_func);

globus_result_t
globus_gridftp_server_attr_add_send(
    globus_gridftp_server_attr_t            in_attr,
    const char *                            module_name,
    globus_gridftp_server_data_func_t       send_func);

globus_result_t
globus_gridftp_server_attr_set_resource(
    globus_gridftp_server_attr_t            in_attr,
    globus_gridftp_server_resource_func_t   resource_query_func);

globus_result_t
globus_gridftp_server_attr_set_auth(
    globus_gridftp_server_attr_t            in_attr,
    globus_gridftp_server_auth_func_t       auth_func);

globus_result_t
globus_gridftp_server_attr_command_add(
    globus_gridftp_server_attr_t            server_attr,
    const char *                            command_name,
    globus_gridftp_server_cmd_func_t        func,
    void *                                  user_arg,
    globus_gridftp_server_command_desc_t    cmd_descriptor);

globus_result_t
globus_gridftp_server_attr_set_error(
    globus_gridftp_server_attr_t            server_attr,
    globus_gridftp_server_callback_t        error_cb);

globus_result_t
globus_gridftp_server_attr_set_done(
    globus_gridftp_server_attr_t            server_attr,
    globus_gridftp_server_callback_t        done_cb);

globus_result_t
globus_gridftp_server_ping(
    globus_gridftp_server_t                 server);

/*
 *  globus_gridftp_server_init
 *
 *  Initialize a server object.  This function allocates resources to 
 *  the server object.  it ties in the xio_handle and the callbacks 
 *  contained in the attr structure together.  globus_gridftp_server_destroy()
 *  needs to be called to free up these resources.
 */
globus_result_t
globus_gridftp_server_init(
    globus_gridftp_server_t *               server);

/**
 *  globus_gridftp_server_destroy()
 *
 *  free up the resources associated with the server object.
 */
globus_result_t
globus_gridftp_server_destroy(
    globus_gridftp_server_t                 server);

/** 
 *  globus_gridftp_server_auth_callback_t
 * 
 *  This function is called when the authentication process is complete
 *  res determins if there is an error or not.  Once this is called
 *  the user decides if they want to authenticate the user.  if they do 
 *  they call globus_gridftp_server_start(), if not they can call
 *  globus_gridftp_server_destroy() to free the server object.
 */
typedef globus_result_t
(*globus_gridftp_server_auth_callback_t)(
    globus_gridftp_server_operation_t       op,
    const char *                            user_name,
    const char *                            pw,
    gss_cred_id_t                           cred,
    gss_cred_id_t                           del_cred);

/**
 *  globus_gridftp_server_authenticate
 *
 *  Authenticate a connection.  This starts the authenication process.
 *  Once finished the auth_callback is called.
 */
globus_result_t
globus_gridftp_server_authenticate(
    globus_gridftp_server_t                 server,
    globus_gridftp_server_auth_callback_t   auth_callback,
    void *                                  user_arg);

/**
 *  This function will start reading commands on a server object.
 *  As soon as this command is called the user can expect to get whatever
 *  callbacks they have associated with the server.  If the function returns
 *  successfully the user will have to call globus_gridftp_server_stop()
 *  before destroying the server.  The attr parameter to this function
 *  gives the user an opertunity to override previsously set callbacks.
 *
 *  @param user_arg
 *         will be passed to all callback functions.
 */ 
globus_result_t
globus_gridftp_server_start(
    globus_gridftp_server_t                 server,
    globus_gridftp_server_attr_t            attr,
    globus_xio_handle_t                     xio_handle,
    void *                                  user_arg);

/**
 *  This function asynchrounsly stops the server.  When the
 *  user receives the done_callback the server object is destroyed and
 *  no more callbacks will come associated with that server object.  Once
 *  The callback is called the user is free to call destroy.
 *
 *  @param user_arg
 *         user argument passed to the done callback only
 */
globus_result_t
globus_gridftp_server_stop(
    globus_gridftp_server_t                 server,
    globus_gridftp_server_callback_t        done_callback,
    void *                                  user_arg);

/***************************************************************************
 *  data object
 *
 *  The server uses the following interface functions for communication
 *  with the user data connection needs.  The user is responisible for
 *  bringing up the data connection.  This library will manage when a new
 *  data connection must be created, but it relies on the user to actually
 *  make the connection.
 **************************************************************************/

/**
 *  globus_gridftp_server_data_create_t
 *
 *  This function is called to notify the user that a new data connection
 *  is needed.  The user must query the data_object to find out specific
 *  information about how and where the connection should be made.
 */
typedef globus_result_t
(*globus_gridftp_server_data_create_t)(
    globus_gridftp_server_data_t            data_object);

/**
 *  globus_gridftp_server_data_connected
 *
 *  After a receving notification that a connection should be made via 
 *  the interface function globus_gridftp_server_data_create_t the user
 *  makes the connection.  The user then tells the library that a connection
 *  has been made by calling this function.  The user may also (and will
 *  likely want to) associate its on memory with this data object here.
 */
globus_result_t
globus_gridftp_server_data_connected(
    globus_gridftp_server_data_t            data_object,
    void *                                  user_arg);

/**
 *  globus_gridftp_server_data_destroy_t
 *
 *  The library notifies the user that it no longer needs the data connection
 *  by calling this interface function.  Upon returning from this function
 *  the data object is considered destroyed.
 */
globus_result_t
(*globus_gridftp_server_data_destroy_t)(
    globus_gridftp_server_data_t            data_object);

/**
 *  globus_gridftp_server_data_disconnected
 *
 *  When a data conenction goes away, either intentionally or due to 
 *  network error the user tells the library that it is gone with
 *  this function.  A call to this function will result in 
 *  globus_gridftp_server_data_destroy_t.
 */
globus_result_t
globus_gridftp_server_data_disconnected(
    globus_gridftp_server_data_t            data_object);

/*
 *  accessing information on the data_object
 *
 *  in order to bring up data connections the server needs some basic
 *  information like if this will represent a passive or an active open
 *  and if active the host and port to which to connect.  Additional
 *  ifmation like local target may also be available.  The accessor
 *  functions are defined below.
 */
globus_result_t
globus_gridftp_server_data_get_direction(
    globus_gridftp_server_data_t            data_object,
    int *                                   dir);

globus_result_t
globus_gridftp_server_data_get_type(
    globus_gridftp_server_data_t            data_object,
    char *                                  type);

globus_result_t
globus_gridftp_server_data_get_contact_string(
    globus_gridftp_server_data_t            data_object,
    char *                                  out_cs);

globus_result_t
globus_gridftp_server_set_authentication(
    globus_gridftp_server_t                 server,
    const char *                            username,
    const char *                            pw,
    gss_cred_id_t                           cred,
    gss_cred_id_t                           delegated_cred);

globus_result_t
globus_gridftp_server_get_auth_cb(
    globus_gridftp_server_t                 server,
    globus_gridftp_server_auth_callback_t * auth_cb);

globus_result_t
globus_gridftp_server_get_resource_cb(
    globus_gridftp_server_t                 server,
    globus_gridftp_server_resource_func_t * resource_cb);

globus_result_t
globus_gridftp_server_get_banner(
    globus_gridftp_server_t                 server,
    char **                                 banner);

globus_result_t
globus_gridftp_server_get_status(
    globus_gridftp_server_t                 server,
    char **                                 status);

/***************************************************************************
 *                      user callbacks
 *                      --------------
 *
 *  The user callbacks are the main way that the user interacts with the
 *  library.  The user registers these callbacks with the server and
 *  when the library has received commands that require user interaction
 *  it makes a callout to one of them, typically with a structure that
 *  can be queried for needed information.
 **************************************************************************/

void
globus_gridftp_server_finished_data(
    globus_gridftp_server_operation_t       op,
    globus_result_t                         res);

void 
globus_gridftp_server_finished_auth(
    globus_gridftp_server_operation_t       op,
    globus_result_t                         res);

void
globus_gridftp_server_finished_resource(
    globus_gridftp_server_operation_t       op,
    globus_result_t                         result,
    globus_gridftp_server_stat_t *          stat_info_array,
    int                                     stat_count);

void 
globus_gridftp_server_finished_cmd(
    globus_gridftp_server_operation_t       op,
    globus_result_t                         result,
    void **                                 argv,
    int                                     argc,
    globus_bool_t                           complete);

/***************************************************************************
 *                  Event stuff
 *                  -----------
 *
 *  If the user wished to deal with event notifications they can call
 *  globus_gridftp_server_enable_event().  After this function is called
 *  the user may get callbacks requesting event processing until they call
 *  globus_gridftp_server_disable_event().  Once disable_event returns
 *  no more callbacks will be received.
 *
 *  When user receives and event callback they are being notified that
 *  the client is expecting the 'event_type' to be processed and information
 *  to be sent back to them.  The user can use 
 *  globus_gridftp_server_send_event() to send the requested information 
 *  back to the client.  The suer does not have to respond to every event
 *  callback, nor does it have to be a timely respone but it is recomended. 
 *  The user may also call send_event() any time after nabling callbacks.
 *  it does not have to be in response to an event callback.
 *
 *  Events occur in the lifespan of a data transfer operation.  You must
 *  have a valid globus_gridftp_server_operation_t to do any event
 *  processing.  Once the user finishes the op, it implies that events
 *  on that op are disabled.
 **************************************************************************/
globus_result_t
globus_gridftp_server_send_event(
    globus_gridftp_server_operation_t       op,
    globus_gridftp_server_event_type_t      event_type,
    const char *                            message);
                                                                                
typedef void
(*globus_gridftp_server_event_callback_t)(
    globus_gridftp_server_operation_t       op,
    globus_gridftp_server_event_type_t      event_type,
    void *                                  user_arg);
                                                                                
globus_result_t
globus_gridftp_server_enable_event(
    globus_gridftp_server_operation_t       op,
    globus_gridftp_server_event_type_t      event_type,
    globus_gridftp_server_event_callback_t  event_cb,
    void *                                  user_arg);
                                                                                
globus_result_t
globus_gridftp_server_disable_event(
    globus_gridftp_server_operation_t       op,
    globus_gridftp_server_event_type_t      event_type);

/*********************************************************************
 *                  server handle gets 
 *                  ------------------
 ********************************************************************/
globus_result_t
globus_gridftp_server_get_mode(
    globus_gridftp_server_t                 server,
    char *                                  mode);

globus_result_t
globus_gridftp_server_get_type(
    globus_gridftp_server_t                 server,
    char *                                  type);

globus_result_t
globus_gridftp_server_set_mode(
    globus_gridftp_server_t                 server,
    char                                    mode);

globus_result_t
globus_gridftp_server_set_type(
    globus_gridftp_server_t                 server,
    char                                    type);

globus_result_t
globus_gridftp_server_get_pwd(
    globus_gridftp_server_t                 server,
    char **                                 pwd_string);

globus_result_t
globus_gridftp_server_get_system(
    globus_gridftp_server_t                 server,
    char **                                 syst_string);

globus_result_t
globus_gridftp_server_get_features(
    globus_gridftp_server_t                 server,
    globus_list_t **                        feature_string_list);

globus_result_t
globus_gridftp_server_get_pmod_help(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    char **                                 help_string);

globus_result_t
globus_gridftp_server_get_help(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    char **                                 help_string);

globus_bool_t
globus_gridftp_server_authenticated(
    globus_gridftp_server_t                 server);

/*********************************************************************
 *                  protocol module interface
 *                  -------------------------
 *  There is an abstraction for the protocol module interface.
 ********************************************************************/
/*
 *  teh callback signature the protocol module calls to notify the
 *  library that it has finished.  Once the protocol module calls this
 *  it is signifiny that it will preform no more action with the handle.
 */
typedef void
(*globus_gridftp_server_stop_cb_t)(
    globus_gridftp_server_t                 server);

/*
 *  called when a new server handle is to start
 */
typedef globus_result_t
(*globus_gridftp_server_pmod_start_t)(
    globus_gridftp_server_t                 server,
    globus_xio_handle_t                     xio_handle,
    void **                                 user_arg);

/*
 *  called when a new server handle is to stop
 */
typedef globus_result_t
(*globus_gridftp_server_pmod_stop_t)(
    globus_gridftp_server_t                 server,
    globus_gridftp_server_stop_cb_t         cb,
    void *                                  user_arg);

/*
 *  called on module activate
 */
typedef globus_result_t
(*globus_gridftp_server_pmod_init_t)();

/*
 *  called on module deactivate
 */
typedef globus_result_t
(*globus_gridftp_server_pmod_destroy_t)();

/*
 *  This structure ties all the protocol module interface functions
 *  together.
 */
typedef struct globus_i_gridftp_server_pmod_s
{
    globus_gridftp_server_pmod_init_t       init_func;
    globus_gridftp_server_pmod_destroy_t    destroy_func;
    globus_gridftp_server_pmod_start_t      start_func;
    globus_gridftp_server_pmod_stop_t       stop_func;
} globus_i_gridftp_server_pmod_t;


typedef void
(*globus_gridftp_server_pmod_command_cb_t)(
    globus_gridftp_server_t                 server,
    globus_result_t                         result,
    const char *                            command_name,
    void **                                 argv,
    int                                     argc,
    void *                                  user_arg);

/*
 *  called to request the server libary preform a command, arguements
 *  vary with the command_name
 */
globus_result_t
globus_gridftp_server_pmod_command(
    globus_gridftp_server_t                 server,
    const char *                            command_name,
    globus_gridftp_server_pmod_command_cb_t cb,
    void **                                 argv,
    int                                     argc,
    void *                                  user_arg);

/*
 *  cancel all outstanding commands
 * 
 *  TODO:  implement this
 */
globus_result_t
globus_gridftp_server_pmod_command_cancel(
    globus_gridftp_server_t                 server);

/*
 *  notify the library that the protocol module encountered and error.
 *  This is usually followed up with by a call to the stop interface 
 *  function.
 */
globus_result_t
globus_gridftp_server_pmod_done(
    globus_gridftp_server_t                 server,
    globus_result_t                         res);

extern globus_module_descriptor_t           globus_i_gridftp_server_module;
#define GLOBUS_GRIDFTP_SERVER_MODULE (&globus_i_gridftp_server_module)

#endif

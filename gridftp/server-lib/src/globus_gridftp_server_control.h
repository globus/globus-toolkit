#if !defined GLOBUS_GRIDFTP_SERVER_CONTROL_H
#define GLOBUS_GRIDFTP_SERVER_CONTROL_H

#include "globus_xio.h"
#include "globus_common.h"
#include "globus_gss_assist.h"

typedef struct globus_i_gsc_server_handle_s * globus_gridftp_server_control_t;
typedef struct globus_i_gsc_attr_s *     globus_gridftp_server_control_attr_t;
typedef struct globus_i_gsc_op_s *          globus_gridftp_server_control_op_t;

typedef time_t                              globus_time_t;

/***********************************************************************
 *                          error types
 *                          -----------
 **********************************************************************/
typedef enum globus_gsc_error_type_e
{
    GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_PANIC,
    GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_DATA_CONNECTION,
    GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_SYSTEM_RESOURCE,
    GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_AUTHENTICATION,
    GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_PATH,
    GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_SYNTAX
} globus_gridftp_server_control_error_type_t;

#ifdef __GNUC__
#define GlobusGridFTPServerName(func) static const char * _gridftp_server_name __attribute__((__unused__)) = #func
#else
#define GlobusGridFTPServerName(func) static const char * _gridftp_server_name = #func
#endif


#define GlobusGridFTPServerControlErrorSyntax()                             \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_SYNTAX,                     \
            __FILE__,                                                       \
            _gridftp_server_name,                                           \
            __LINE__,                                                       \
            "Syntax error"))

#define GlobusGridFTPServerControlErrorPanic()                              \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_PANIC,                      \
            __FILE__,                                                       \
            _gridftp_server_name,                                           \
            __LINE__,                                                       \
            "Panic error"))

#define GlobusGridFTPServerControlErrorSytem()                              \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_SYSTEM_RESOURCE,            \
            __FILE__,                                                       \
            _gridftp_server_name,                                           \
            __LINE__,                                                       \
            "Sytem resource error"))

#define GlobusGridFTPServerControlErrorAuthentication()                     \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_AUTHENTICATION,             \
            __FILE__,                                                       \
            _gridftp_server_name,                                           \
            __LINE__,                                                       \
            "Sytem resource error"))

#define GlobusGridFTPServerControlErrorDataConnection()                     \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_DATA_CONNECTION,            \
            __FILE__,                                                       \
            _gridftp_server_name,                                           \
            __LINE__,                                                       \
            "data connection error"))

#define GlobusGridFTPServerControlErrorPath()                               \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE,                           \
            GLOBUS_NULL,                                                    \
            GLOBUS_GRIDFTP_SERVER_CONTROL_ERROR_PATH,                       \
            __FILE__,                                                       \
            _gridftp_server_name,                                           \
            __LINE__,                                                       \
            "path error"))

/**
 *  stat structure
 *  --------------
 *
 *  This structure is exposed to the user.  The user must populate an array
 *  of these structures when a resource query is made to them.  The structure
 *  is very similar to the posix strust stat.
 */
typedef struct globus_gridftp_server_control_stat_s
{
    int                                     mode;
    int                                     nlink;
    char                                    name[MAXPATHLEN];
    uid_t                                   uid;
    gid_t                                   gid;
    globus_size_t                           size;
    globus_time_t                           atime;
    globus_time_t                           ctime;
    globus_time_t                           mtime;
} globus_gridftp_server_control_stat_t;

/**
 *  net protocol type
 *  -----------------
 *
 *  This enumeration defines what network protocol is being used.  At this
 *  point there are only 2 available, ipv4 and ipv6.
 */
typedef enum globus_gridftp_server_control_network_protocol_e
{
    GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV4 = 1,
    GLOBUS_GRIDFTP_SERVER_CONTROL_PROTOCOL_IPV6
} globus_gridftp_server_control_network_protocol_t;

/**
 *  data direction type
 *  -------------------
 *
 *  This type indicates to the library in what direction a user data object
 *  can be used for transfer.  STOR is for receiving data, RETR is for
 *  sending data, and BI is for either direction.  When connecting a data
 *  object the user will use pass in one of these 3 values.  see
 *  globus_gridftp_server_control_finished_transfer().  
 */
typedef enum globus_i_gsc_data_dir_e
{
    GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_RECV = 0x01,
    GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_SEND = 0x02,
    GLOBUS_GRIDFTP_SERVER_CONTROL_DATA_DIR_BI = 0x03
} globus_gridftp_server_control_data_dir_t;

/**
 *  event type
 *  ----------
 *
 *  During a data transfer the user can send events back to the client.
 *  The accepted event types are defined here.
 */
typedef enum globus_gridftp_server_control_event_type_e
{
    GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_PERF_MARKER,
    GLOBUS_GRIDFTP_SERVER_CONTROL_EVENT_BEGIN_TRANSFER = 150
} globus_gridftp_server_control_event_type_t;

/**
 *  authentication callback type
 *  ---------------------------
 *
 *  This funciton is called to tell the user a client is
 *  trying to authenticate with the creditails supplied as parameters.
 *  The user can decided whether or not to accept the user and then call
 *  globus_gridftp_server_control_finished_auth() with the appropriate values.
 */
typedef void
(*globus_gridftp_server_control_auth_cb_t)(
    globus_gridftp_server_control_op_t      op,
    const char *                            user_name,
    const char *                            pw,
    gss_cred_id_t                           cred,
    gss_cred_id_t                           del_cred);

/**
 *  globus_gridftp_server_control_finished_auth()
 *
 *  Once the user decides to the accept the client or not they call this 
 *  function.  The value of result determines if the user is accepted or not.
 */
globus_result_t
globus_gridftp_server_control_finished_auth(
    globus_gridftp_server_control_op_t      op,
    globus_result_t                         res,
    uid_t                                   uid);

/**
 *  mask type.
 *  ----------
 *
 *  This tells the user how the server expects it to query the resource.
 *  Either it is looking for the entire directory listing or simply the 
 *  stat of the file only.
 */
typedef enum globus_gridftp_server_control_resource_mask_e
{
    GLOBUS_GRIDFTP_SERVER_CONTROL_RESOURCE_DIRECTORY_LIST = 1,
    GLOBUS_GRIDFTP_SERVER_CONTROL_RESOURCE_FILE_ONLY      = 2
} globus_gridftp_server_control_resource_mask_t;

/**
 *  generic server callback
 *
 *  used for stop, done, error
 */
typedef void
(*globus_gridftp_server_control_cb_t)(
    globus_gridftp_server_control_t         server,
    globus_result_t                         res,
    void *                                  user_arg);

/**
 *  resource query callback
 *  -----------------------
 *
 *  This function is called when the server needs informatioon about a 
 *  given resource.  The resource is typically a file.  Once the user
 *  has determined the needed information about the rsource they call
 *  globus_gridftp_server_control_finished_resource() with the appropriate
 *  parameters.
 */
typedef void
(*globus_gridftp_server_control_resource_cb_t)(
    globus_gridftp_server_control_op_t      op,
    const char *                            path,
    globus_gridftp_server_control_resource_mask_t mask);

/*
 *  this function is called to tell the user that a data transfer 
 *  has been requested by the client.
 */
typedef void
(*globus_gridftp_server_control_transfer_cb_t)(
    globus_gridftp_server_control_op_t      op,
    void *                                  data_handle,
    const char *                            local_target,
    const char *                            mod_name,
    const char *                            mod_parms);

typedef void
(*globus_gridftp_server_control_abort_cb_t)(
    globus_gridftp_server_control_op_t      op,
    void *                                  user_arg);

/**
 *  data connection interface functions
 *
 */

/** 
 *  create a passive data object
 *
 *  this function is called to tell the user to create a passively 
 *  connection data object.  When the user has completed this request
 *  it calls globus_gridftp_server_control_finished_passive_connect()
 *  with appropriate values.
 *
 *  note:  the user does not have to establish the data pathways at this
 *         point.  They only need provide a contact string upon which a
 *         remote client can connect.
 */
typedef void
(*globus_gridftp_server_control_passive_connect_cb_t)(
    globus_gridftp_server_control_op_t      op,
    globus_gridftp_server_control_network_protocol_t net_prt,
    int                                     max);

/** 
 *  create an active data object
 *
 *  this function is called to tell the user to create an actively
 *  connecting data object.  When the user has completed this request
 *  it calls globus_gridftp_server_control_finished_active_connect()
 *
 *  note:  the user does not have to establish the data pathways at this
 *         point.  They only need to store the information provided and 
 *         verify that they can connect to the contact point.  However if
 *         the user wishes to create the data pathways here that is accepted.
 */
typedef void
(*globus_gridftp_server_control_active_connect_cb_t)(
    globus_gridftp_server_control_op_t      op,
    globus_gridftp_server_control_network_protocol_t net_prt,
    const char **                           cs,
    int                                     cs_count);

/**
 *  data connection destroyed
 *
 *  The library notifies the user that it no longer needs the data connection
 *  by calling this interface function.  Upon returning from this function
 *  the data object is considered destroyed and the library will no reference
 *  it again.
 */
typedef void
(*globus_gridftp_server_control_data_destroy_cb_t)(
    void *                                  user_data_handle);

/**
 *  finished resource query request
 *
 *  Once a user has determined information about a resource they call this
 *  function.  If result is passed != GLOBUS_SUCCESS the user is telling
 *  the library that the resource could not be queried.
 */
globus_result_t
globus_gridftp_server_control_finished_resource(
    globus_gridftp_server_control_op_t      op,
    globus_result_t                         result,
    globus_gridftp_server_control_stat_t *  stat_info_array,
    int                                     stat_count);

/**************************************************************************
 *  attr functions.
 *
 *  self explaintory for now
 *************************************************************************/
globus_result_t
globus_gridftp_server_control_attr_init(
    globus_gridftp_server_control_attr_t *  in_attr);

globus_result_t
globus_gridftp_server_control_attr_destroy(
    globus_gridftp_server_control_attr_t    in_attr);

globus_result_t
globus_gridftp_server_control_attr_copy(
    globus_gridftp_server_control_attr_t *  dst,
    globus_gridftp_server_control_attr_t    src);

globus_result_t
globus_gridftp_server_control_attr_set_resource(
    globus_gridftp_server_control_attr_t    in_attr,
    globus_gridftp_server_control_resource_cb_t resource_cb);

globus_result_t
globus_gridftp_server_control_attr_set_auth(
    globus_gridftp_server_control_attr_t    in_attr,
    globus_gridftp_server_control_auth_cb_t auth_cb);

/*
 *  if module name is NULL then it is the default handler
 */
globus_result_t
globus_gridftp_server_control_attr_add_recv(
    globus_gridftp_server_control_attr_t    in_attr,
    const char *                            module_name,
    globus_gridftp_server_control_transfer_cb_t recv_func);

globus_result_t
globus_gridftp_server_control_attr_add_send(
    globus_gridftp_server_control_attr_t    in_attr,
    const char *                            module_name,
    globus_gridftp_server_control_transfer_cb_t send_func);

globus_result_t
globus_gridftp_server_control_attr_data_functions(
    globus_gridftp_server_control_attr_t                server_attr,
    globus_gridftp_server_control_active_connect_cb_t   active_func,
    globus_gridftp_server_control_passive_connect_cb_t  passive_func,
    globus_gridftp_server_control_data_destroy_cb_t     destroy_func);

/***************************************************************************
 *                      start up
 *                      --------
 *  First the user must open a valid xio handle.  See the xio documentation 
 *  for how to do this.  The xio_handle is then used to initialize a server
 *  object, with an attr.  Callbacks are set on this attr as explained in
 *  the section on attr functions.
 *
 *  Once the server handle starts the user can expect to receive the 
 *  callbacks it registered on the attr.  The user 
 *  stops the callbacks by calling globus_gridftp_server_stop().   Once
 *  the callback passed into that function returns, no more callbacks will
 *  be dispatched in relation to the given handle.
 **************************************************************************/

/**
 *  initialize the server
 *
 *  Initialize a server object.  This function allocates resources to 
 *  the server object.  globus_gridftp_server_control_destroy()
 *  needs to be called to free up these resources.
 */
globus_result_t
globus_gridftp_server_control_init(
    globus_gridftp_server_control_t *       server);

/**
 *  destroy the server
 *
 *  free up the resources associated with the server object.  The object is
 *  no longer valid once this returns with GLOBUS_SUCCESS.
 */
globus_result_t
globus_gridftp_server_control_destroy(
    globus_gridftp_server_control_t         server);

/**
 *  start dispatching callbacks.
 *
 *  This function will start reading commands on a server object.
 *  As soon as this command is called the user can expect to get whatever
 *  callbacks they have associated with the attr.  If the function returns
 *  successfully the user will have to call globus_gridftp_server_control_stop()
 *  before destroying the server.  The attr parameter to this function
 *  provides the means for setting up all callbacks.  The attr overrides
 *  any previously set values.
 */ 
globus_result_t
globus_gridftp_server_control_start(
    globus_gridftp_server_control_t         server,
    globus_gridftp_server_control_attr_t    attr,
    globus_xio_handle_t                     xio_handle,
    globus_gridftp_server_control_cb_t      done_cb,
    void *                                  user_arg);

/**
 *  stop dispatching callbacks
 *
 *  This function asynchrounsly stops the server.  When the
 *  user receives the done_callback the server object is destroyed and
 *  no more callbacks will come associated with that server object.  Once
 *  The callback is called the user is free to call destroy.
 */
globus_result_t
globus_gridftp_server_control_stop(
    globus_gridftp_server_control_t         server);

/*
 *  setters and getters
 */
globus_result_t
globus_gridftp_server_control_get_buffer_size(
    globus_gridftp_server_control_op_t      op,
    globus_size_t *                         out_recv_bs,
    globus_size_t *                         out_send_bs);

globus_result_t
globus_gridftp_server_control_get_parallelism(
    globus_gridftp_server_control_op_t      op,
    int *                                   out_parallelism);

globus_result_t
globus_gridftp_server_control_get_mode(
    globus_gridftp_server_control_op_t      op,
    char *                                  out_mode);

globus_result_t
globus_gridftp_server_control_get_type(
    globus_gridftp_server_control_op_t      op,
    char *                                  ou_type);

globus_result_t
globus_gridftp_server_control_get_cwd(
    globus_gridftp_server_control_t         server,
    char **                                 cwd_string);

globus_bool_t
globus_gridftp_server_control_authenticated(
    globus_gridftp_server_control_t         server);

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
 *  finished active connect request
 *
 *  After a receving notification that a connection should be made via 
 *  the interface function globus_gridftp_server_control_active_connect_t().
 *  The user then tells the library that a connection
 *  has been made by calling this function.  The user may also (and will
 *  likely want to) associate its on memory with this data object here.
 *  If the user cannot make a connection they indicate this with the res
 *  parameter.
 */
globus_result_t
globus_gridftp_server_control_finished_active_connect(
    globus_gridftp_server_control_op_t      op,
    void *                                  user_data_handle,
    globus_result_t                         res,
    globus_gridftp_server_control_data_dir_t data_dir);

/**
 *  finished passive connect request
 *
 *  After a receving notification that a connection should be made via 
 *  the interface function globus_gridftp_server_control_passive_connect_t().
 *  The user then tells the library that a connection
 *  has been made by calling this function.  The user may also (and will
 *  likely want to) associate its on memory with this data object here.
 *  If the user cannot make a connection they indicate this with the res
 *  parameter.
 */
globus_result_t
globus_gridftp_server_control_finished_passive_connect(
    globus_gridftp_server_control_op_t      op,
    void *                                  user_data_handle,
    globus_result_t                         res,
    globus_gridftp_server_control_data_dir_t data_dir,
    const char **                           cs,
    int                                     cs_count);

/**
 *  close a data object
 *
 *  When a data conenction goes away, either intentionally or due to 
 *  network error the user tells the library that it is gone with
 *  this function.  A call to this function will result in 
 *  globus_gridftp_server_data_destroy_t.  The data object is not considered
 *  destroyed until globus_gridftp_server_data_destroy_t is called.
 */
globus_result_t
globus_gridftp_server_control_disconnected(
    globus_gridftp_server_control_t         server,
    void *                                  user_data_handle);

/**
 *  begin a data transfer
 *
 *  once the user is notified that they are to begin a transfer for a given
 *  data module they need to verify the request.  The path and module
 *  parameters should be checked for validity.  If acceptable the user MUST
 *  call this function prior to transfering data along the data pathways.
 *  If it is not acceptable the user must call 
 *  globus_gridftp_server_control_finished_transfer() with the appropriate error.
 */
globus_result_t
globus_gridftp_server_control_begin_transfer(
    globus_gridftp_server_control_op_t      op);

/**
 *  a data transfer requested has been completed.
 *
 *  when a transfer is completed, either successfully or due to
 *  failure the user must call this function to notify the user of
 *  completion.
 */
globus_result_t
globus_gridftp_server_control_finished_transfer(
    globus_gridftp_server_control_op_t      op,
    globus_result_t                         res);

/*
 *  events
 */
globus_result_t
globus_gridft_server_control_send_event(
    globus_gridftp_server_control_op_t      op,
    globus_gridftp_server_control_event_type_t type,
    const char *                            msg);


extern globus_module_descriptor_t      globus_i_gsc_module;

#define GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE (&globus_i_gsc_module)

#endif

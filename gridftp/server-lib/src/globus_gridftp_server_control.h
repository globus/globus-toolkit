#if !defined GLOBUS_GRIDFTP_SERVER_H
#define GLOBUS_GRIDFTP_SERVER_H

#include "globus_xio.h"
#include "globus_common.h"
#include "globus_gss_assist.h"

/*
 *  types
 */
struct globus_i_gsc_server_s;
struct globus_i_gsc_attr_s;
struct globus_i_gsc_data_s;
struct globus_i_gsc_op_s;

typedef struct globus_i_gsc_server_s *      
    globus_gridftp_server_control_t;
typedef struct globus_i_gsc_attr_s *        
    globus_gridftp_server_control_attr_t;
typedef struct globus_i_gsc_data_s *        
    globus_gridftp_server_control_data_t;
typedef struct globus_i_gsc_op_s *          
    globus_gridftp_server_control_operation_t;

typedef time_t                                      globus_time_t;

typedef struct globus_gridftp_server_control_stat_s
{
    int                                             st_mode;
    int                                             st_nlink;
    uid_t                                           st_uid;
    gid_t                                           st_gid;
    globus_size_t                                   st_size;
    globus_time_t                                   mtime;
    globus_time_t                                   atime;
    globus_time_t                                   ctime;
} globus_gridftp_server_control_stat_t;

/*
 *  This funciton is called to tell the user a client is
 *  trying to authenticate with the creditails supplied as parameters.
 *  The user can decided whether or not to accept the user and then call
 *  globus_gridftp_server_control_finished_auth() with the appropriate values.
 */
typedef void
(*globus_gridftp_server_control_auth_callback_t)(
    globus_gridftp_server_control_operation_t       op,
    const char *                                    user_name,
    const char *                                    pw,
    gss_cred_id_t                                   cred,
    gss_cred_id_t                                   del_cred);

/*
 *  globus_gridftp_server_control_finished_auth()
 *
 *  Once the user decides if the accept the client or not they call this 
 *  function.  The value of result determines if the user is accepted or not.
 */
void 
globus_gridftp_server_control_finished_auth(
    globus_gridftp_server_control_operation_t       op,
    globus_result_t                                 res);

/*
 *  mask type.
 *
 *  This tells the user how the server expects it to query the resource
 */
typedef enum globus_gridftp_server_control_resource_mask_e
{
    GLOBUS_GRIDFTP_SERVER_CONTROL_RESOURCE_MASK_NONE,
    GLOBUS_GRIDFTP_SERVER_CONTROL_RESOURCE_MASK_EXPAND_ALL,
    GLOBUS_GRIDFTP_SERVER_CONTROL_RESOURCE_MASK_EXPAND_LEVEL,
} globus_gridftp_server_control_resource_mask_t;

/**
 *  generic server callback
 *
 *  used for stop, done, error
 */
typedef void
(*globus_gridftp_server_control_callback_t)(
    globus_gridftp_server_control_t                 server,
    globus_result_t                                 res,
    void *                                          user_arg);

/*
 *  This function is called when the server needs informatioon about a 
 *  given resource.  The resource is typically a file.  Once the user
 *  has determined the needed information about the rsource they call
 *  globus_gridftp_server_control_finished_resource() with the appropriate
 *  parameters.
 */
typedef void
(*globus_gridftp_server_control_resource_callback_t)(
    globus_gridftp_server_control_operation_t       op,
    const char *                                    path,
    globus_gridftp_server_control_resource_mask_t   mask);

/*
 *  this function is called to tell the user that a data transfer 
 *  has been requested by the client.
 */
typedef void
(*globus_gridftp_server_control_data_func_t)(
    globus_gridftp_server_control_operation_t       op,
    globus_gridftp_server_control_data_t            data_object,
    const char *                                    local_target);

/*
 *  globus_gridftp_server_control_finished_resource()
 *
 *  Once a user has determined information about a resource they call this
 *  function.  If result is passed != GLOBUS_SUCCESS the user is telling
 *  the library that the resource could not be queried.
 */
void
globus_gridftp_server_control_finished_resource(
    globus_gridftp_server_control_operation_t       op,
    globus_result_t                                 result,
    globus_gridftp_server_control_stat_t *          stat_info_array,
    int                                             stat_count);

/*
 *  to be used with care.  its future is uncertain
 */
typedef globus_result_t
(*globus_gridftp_server_control_cmd_func_t)(
    globus_gridftp_server_control_t                 server,
    const char *                                    command_name,
    globus_gridftp_server_control_operation_t       op,
    void **                                         argv,
    int                                             argc);

/**************************************************************************
 *  attr functions.
 *
 *  self explaintory for now
 *************************************************************************/
globus_result_t
globus_gridftp_server_control_attr_init(
    globus_gridftp_server_control_attr_t *          in_attr);

globus_result_t
globus_gridftp_server_control_attr_destroy(
    globus_gridftp_server_control_attr_t            in_attr);

globus_result_t
globus_gridftp_server_control_attr_copy(
    globus_gridftp_server_control_attr_t *          dst,
    globus_gridftp_server_control_attr_t            src);

globus_result_t
globus_gridftp_server_control_attr_set_resource(
    globus_gridftp_server_control_attr_t            in_attr,
    globus_gridftp_server_control_resource_callback_t resource_cb);

globus_result_t
globus_gridftp_server_control_attr_set_auth(
    globus_gridftp_server_control_attr_t            in_attr,
    globus_gridftp_server_control_auth_callback_t   auth_cb);

globus_result_t
globus_gridftp_server_control_attr_set_error(
    globus_gridftp_server_control_attr_t            server_attr,
    globus_gridftp_server_control_callback_t        error_cb);

globus_result_t
globus_gridftp_server_control_attr_set_done(
    globus_gridftp_server_control_attr_t            server_attr,
    globus_gridftp_server_control_callback_t        done_cb);

globus_result_t
globus_gridftp_server_control_attr_add_recv(
    globus_gridftp_server_control_attr_t            in_attr,
    const char *                                    module_name,
    globus_gridftp_server_control_data_func_t       recv_func);

globus_result_t
globus_gridftp_server_attr_add_send(
    globus_gridftp_server_control_attr_t            in_attr,
    const char *                                    module_name,
    globus_gridftp_server_control_data_func_t       send_func);

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

/*
 *  refresh the timeouts
 */
globus_result_t
globus_gridftp_server_control_ping(
    globus_gridftp_server_control_t                 server);

/*
 *  globus_gridftp_server_control_init
 *
 *  Initialize a server object.  This function allocates resources to 
 *  the server object.  it ties in the xio_handle and the callbacks 
 *  contained in the attr structure together.  
 *  globus_gridftp_server_control_destroy()
 *  needs to be called to free up these resources.
 */
globus_result_t
globus_gridftp_server_control_init(
    globus_gridftp_server_control_t *               server);

/**
 *  globus_gridftp_server_control_destroy()
 *
 *  free up the resources associated with the server object.
 */
globus_result_t
globus_gridftp_server_control_destroy(
    globus_gridftp_server_control_t                 server);

/**
 *  This function will start reading commands on a server object.
 *  As soon as this command is called the user can expect to get whatever
 *  callbacks they have associated with the server.  If the function returns
 *  successfully the user will have to call globus_gridftp_server_control_stop()
 *  before destroying the server.  The attr parameter to this function
 *  gives the user an opertunity to override previsously set callbacks.
 *
 *  @param user_arg
 *         will be passed to all callback functions.
 */ 
globus_result_t
globus_gridftp_server_control_start(
    globus_gridftp_server_control_t                 server,
    globus_gridftp_server_control_attr_t            attr,
    globus_xio_handle_t                             xio_handle,
    void *                                          user_arg);

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
globus_gridftp_server_control_stop(
    globus_gridftp_server_control_t                 server,
    globus_gridftp_server_control_callback_t        done_callback,
    void *                                          user_arg);

/*
 *  setters and getters
 */
globus_result_t
globus_gridftp_server_control_set_mode(
    globus_gridftp_server_control_t                 server,
    char                                            mode);

globus_result_t
globus_gridftp_server_control_set_type(
    globus_gridftp_server_control_t                 server,
    char                                            mode);

globus_result_t
globus_gridftp_server_control_get_banner(
    globus_gridftp_server_control_t                 server,
    char **                                         banner);

globus_result_t
globus_gridftp_server_control_get_mode(
    globus_gridftp_server_control_t                 server,
    char *                                          out_mode);

globus_result_t
globus_gridftp_server_control_get_type(
    globus_gridftp_server_control_t                 server,
    char *                                          ou_type);

globus_result_t
globus_gridftp_server_control_get_pwd(
    globus_gridftp_server_control_t                 server,
    char **                                         pwd_string);

globus_result_t
globus_gridftp_server_control_get_system(
    globus_gridftp_server_control_t                 server,
    char **                                         syst_string);

globus_result_t
globus_gridftp_server_control_get_status(
    globus_gridftp_server_control_t                 server,
    char **                                         syst_string);

globus_result_t
globus_gridftp_server_control_get_features(
    globus_gridftp_server_control_t                 server,
    globus_list_t **                                feature_string_list);

globus_result_t
globus_gridftp_server_control_get_help(
    globus_gridftp_server_control_t                 server,
    const char *                                    command_name,
    char **                                         help_string);

globus_bool_t
globus_gridftp_server_control_authenticated(
    globus_gridftp_server_control_t                 server);

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
    globus_gridftp_server_control_data_t            data_object);

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
    globus_gridftp_server_control_data_t            data_object,
    void *                                          user_arg);

/**
 *  globus_gridftp_server_data_destroy_t
 *
 *  The library notifies the user that it no longer needs the data connection
 *  by calling this interface function.  Upon returning from this function
 *  the data object is considered destroyed.
 */
globus_result_t
(*globus_gridftp_server_data_destroy_t)(
    globus_gridftp_server_control_data_t            data_object);

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
    globus_gridftp_server_control_data_t            data_object);

/*
 *  when a transfer is completed, either successfully or due to
 *  failure the user must call this function to notify the user of
 *  completion.
 */
void
globus_gridftp_server_finished_data(
    globus_gridftp_server_control_operation_t       op,
    globus_result_t                                 res);

/*****
 * TODO: check this stuff out
 *
 *  !!!!!!!!!!!!Interface only complete from here up!!!!!!!!!!!!!
 *
 *  Event stuff is not quite right
 ****/
typedef enum globus_gridftp_server_event_type_e
{
    GLOBUS_GRIDFTP_SERVER_EVENT_TYPE_NONE,
} globus_gridftp_server_event_type_t;

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
    globus_gridftp_server_control_operation_t       op,
    globus_gridftp_server_event_type_t      event_type,
    const char *                            message);
                                                                                
typedef void
(*globus_gridftp_server_event_callback_t)(
    globus_gridftp_server_control_operation_t       op,
    globus_gridftp_server_event_type_t      event_type,
    void *                                  user_arg);
                                                                                
globus_result_t
globus_gridftp_server_enable_event(
    globus_gridftp_server_control_operation_t       op,
    globus_gridftp_server_event_type_t      event_type,
    globus_gridftp_server_event_callback_t  event_cb,
    void *                                  user_arg);
                                                                                
globus_result_t
globus_gridftp_server_disable_event(
    globus_gridftp_server_control_operation_t       op,
    globus_gridftp_server_event_type_t      event_type);

/*********************************************************************
 ********************************************************************/
extern globus_module_descriptor_t      globus_i_gridftp_server_control_module;

#define GLOBUS_GRIDFTP_SERVER_CONTROL_MODULE (&globus_i_gridftp_server_control_module)

#endif

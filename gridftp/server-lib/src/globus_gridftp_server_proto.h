#if !defined(GLOBUS_GRIDFTP_SERVER_PROTO_H)
#define GLOBUS_GRIDFTP_SERVER_PROTO_H


/*********************************************************************
 *                  protocol module interface
 *                  -------------------------
 *  There is an abstraction for the protocol module interface.
 ********************************************************************/
typedef void
(*globus_gridftp_server_stop_cb_t)(
    globus_gridftp_server_t                 server);
                                                                                
typedef globus_result_t
(*globus_gridftp_server_protocol_start_t)(
    globus_gridftp_server_t                 server,
    globus_xio_handle_t                     xio_handle,
    void **                                 user_arg);
                                                                                
typedef globus_result_t
(*globus_gridftp_server_protocol_stop_t)(
    globus_gridftp_server_t                 server,
    globus_gridftp_server_stop_cb_t         cb,
    void *                                  user_arg);

/*
 *  commands
 *
 *  The protocol module uses this command interface to tell the library
 *  to processed a command.  The enum globus_gridftp_server_command_type_t
 *  defines what commands exists.  The protocol module uses the same
 *  function: globus_gridftp_server_command(), to tell the library of
 *  the command.  The var args will differ with the type arguement.
 *
 *  Woen the server library has finished processing a command it makes
 *  a call to the callback.  The result code in the callback signature
 *  will be success, or a failure code indicating that the command was
 *  canceled, or that the library experienced some trouble, processing
 *  it.
 */
typedef enum globus_gridftp_server_command_type_e
{
    GLOBUS_GRIDFTP_SERVER_COMMAND_PWD,
    GLOBUS_GRIDFTP_SERVER_COMMAND_AUTHENTICATE,
    GLOBUS_GRIDFTP_SERVER_COMMAND_CD,
    GLOBUS_GRIDFTP_SERVER_COMMAND_PASSIVE,
    GLOBUS_GRIDFTP_SERVER_COMMAND_PORT,
    GLOBUS_GRIDFTP_SERVER_COMMAND_UNKNOWN,
} globus_gridftp_server_command_type_t;
                                                                                
typedef void
(*globus_gridftp_server_command_cb_t)(
    globus_gridftp_server_t                 server,
    globus_result_t                         result,
    globus_gridftp_server_command_type_t    type,
    int                                     reply_code,
    const char *                            reply_message,
    void *                                  user_arg);

globus_result_t
globus_gridftp_server_command(
    globus_gridftp_server_t                 server,
    globus_gridftp_server_command_type_t    type,
    globus_gridftp_server_command_cb_t      cb,
    void *                                  user_arg,
    ...);

/*
 *  This function is called to cancel an outstanding command.  If the server
 *  library can terinamte the outstanding command it will and a call to
 *  its callback will be made with an error indicating early termination.
 */
globus_result_t
globus_gridftp_server_command_cancel(
    globus_gridftp_server_t                 server);

/*
 *  The protocol module calls this function to notify the server library
 *  that it experienced an error that it cannot recover from.  The server
 *  library will respond to this call with a call to _stop().
 */
globus_result_t
globus_gridftp_server_protocol_error(
    globus_gridftp_server_t                 server,
    globus_result_t                         res);
                                                                                
#endif

#if !defined(GLOBUS_I_XIO_H)
#define GLOBUS_I_XIO_H 1

#include "globus_xio.h"
#include "globus_xio_driver.h"
#include "globus_common.h"
#include "globus_xio_util.h"

#define GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE             16
#define GLOBUS_XIO_HANDLE_DEFAULT_OPERATION_COUNT   4
/***************************************************************************
 *                 state and type enumerations
 *                 ---------------------------
 **************************************************************************/

typedef enum globus_i_xio_handle_state_e
{
    GLOBUS_XIO_HANDLE_STATE_OPENING,
    GLOBUS_XIO_HANDLE_STATE_OPEN,
    GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED,
    GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED,
    GLOBUS_XIO_HANDLE_STATE_EOF_RECEIVED_AND_CLOSING,
    GLOBUS_XIO_HANDLE_STATE_EOF_DELIVERED_AND_CLOSING,
    GLOBUS_XIO_HANDLE_STATE_CLOSING,
    GLOBUS_XIO_HANDLE_STATE_CLOSED,
} globus_i_xio_handle_state_t;

typedef enum globus_i_xio_op_state_e
{
    GLOBUS_XIO_OP_STATE_OPERATING,
    GLOBUS_XIO_OP_STATE_TIMEOUT_PENDING,
    GLOBUS_XIO_OP_STATE_FINISH_WAITING,
    GLOBUS_XIO_OP_STATE_FINISHED,
} globus_i_xio_op_state_t;

typedef enum globus_xio_server_state_e
{
    GLOBUS_XIO_SERVER_STATE_OPEN,
    GLOBUS_XIO_SERVER_STATE_ACCEPTING,
    GLOBUS_XIO_SERVER_STATE_COMPLETEING,
    GLOBUS_XIO_SERVER_STATE_CLOSED,
} globus_xio_server_state_t;

typedef enum globus_xio_target_type_e
{
    GLOBUS_XIO_TARGET_TYPE_SERVER,
    GLOBUS_XIO_TARGET_TYPE_CLIENT,
} globus_xio_target_type_t;



/***************************************************************************
 *                  Internally exposed data structures
 *                  ----------------------------------
 **************************************************************************/


struct globus_i_xio_context_s;
struct globus_i_xio_op_s;
struct globus_i_xio_target_s;

typedef struct globus_i_xio_attr_ent_s
{
    globus_xio_driver_t                         driver;
    void *                                      driver_data;
} globus_i_xio_attr_ent_t;

typedef struct globus_i_xio_attr_s
{
    globus_xio_timeout_callback_t               open_timeout_cb;
    globus_reltime_t                            open_timeout_period;
    globus_xio_timeout_callback_t               read_timeout_cb;
    globus_reltime_t                            read_timeout_period;
    globus_xio_timeout_callback_t               write_timeout_cb;
    globus_reltime_t                            write_timeout_period;
    globus_xio_timeout_callback_t               close_timeout_cb;
    globus_reltime_t                            close_timeout_period;

    globus_xio_timeout_server_callback_t        accept_timeout_cb;
    globus_reltime_t                            accept_timeout_period;

    globus_bool_t                               cancel_open;
    globus_bool_t                               cancel_close;
    globus_bool_t                               cancel_read;
    globus_bool_t                               cancel_write;

    globus_callback_space_t                     space;

    int                                         max;
    int                                         ndx;
    globus_i_xio_attr_ent_t *                   entry;
} globus_i_xio_attr_t;

typedef struct globus_i_xio_stack_s
{
    globus_mutex_t                              mutex;
    int                                         size;
    globus_list_t *                             driver_stack;
    globus_xio_driver_t                         transport_driver;
} globus_i_xio_stack_t;


typedef struct globus_i_xio_server_entry_s
{
    globus_xio_driver_t                         driver;
    void *                                      server_handle;
} globus_i_xio_server_entry_t;
/* 
 *  
 */
typedef struct globus_i_xio_server_s
{
    globus_xio_server_state_t                   state;

    globus_xio_timeout_server_callback_t        accept_timeout;
    globus_reltime_t                            accept_timeout_period;
    struct globus_i_xio_op_s *                  op;

    int                                         ref;
    globus_mutex_t                              mutex;
    globus_callback_space_t                     space;

    int                                         stack_size;
    globus_i_xio_server_entry_t                 entry[1];
} globus_i_xio_server_t;

typedef struct globus_i_xio_handle_s
{
    globus_mutex_t                              mutex;
    globus_mutex_t                              cancel_mutex;
    int                                         ref;
    int                                         stack_size;
    struct globus_i_xio_context_s *             context;

    globus_i_xio_handle_state_t                 state;

    /* since only 1 open or close can be outstanding at a time we don't
       need a list */
    globus_list_t *                             write_op_list;
    globus_list_t *                             read_op_list;
    struct globus_i_xio_op_s *                  open_op;
    struct globus_i_xio_op_s *                  close_op;

    struct globus_i_xio_target_s *              target;

    /* counts outstanding read and write operations */
    int                                         outstanding_operations;

    globus_callback_space_t                     space;
    globus_xio_timeout_callback_t               open_timeout_cb;
    globus_reltime_t                            open_timeout_period;
    globus_xio_timeout_callback_t               read_timeout_cb;
    globus_reltime_t                            read_timeout_period;
    globus_xio_timeout_callback_t               write_timeout_cb;
    globus_reltime_t                            write_timeout_period;
    globus_xio_timeout_callback_t               close_timeout_cb;
    globus_reltime_t                            close_timeout_period;
} globus_i_xio_handle_t;

/*
 *  represents an entry in the array of open handles.
 *
 *  each entry is maped to a driver in the stack
 */
typedef struct globus_i_xio_context_entry_s
{
    globus_xio_driver_t                         driver;
    void *                                      driver_handle;

    /* each level must implement the entire state machine */
    globus_i_xio_handle_state_t                 state;
    int                                         outstanding_operations;
    int                                         read_operations;

    /* every level but the top MUST be GLOBAL_SPACE */
    globus_bool_t                               read_eof;

    struct globus_i_xio_op_s *                  open_op;
    struct globus_i_xio_op_s *                  close_op;
    globus_list_t *                             eof_op_list;
    globus_list_t *                             read_op_list;
    struct globus_i_xio_context_s *             whos_my_daddy;
} globus_i_xio_context_entry_t;

/* 
 *  a stretchy array
 */
typedef struct globus_i_xio_context_s
{
    /* handle has a reference and every entry has a reference */
    int                                         ref;
    int                                         stack_size;

    globus_memory_t                             op_memory;
    globus_mutex_t                              mutex;
    globus_i_xio_context_entry_t                entry[1];
} globus_i_xio_context_t;

/* MACROS for accessing the op_entry structure unin elements */
#define _op_ent_data_cb             type_u.handle_s.data_cb
#define _op_ent_wait_for            type_u.handle_s.wait_for_bytes
#define _op_ent_nbytes              type_u.handle_s.nbytes
#define _op_ent_iovec               type_u.handle_s.iovec
#define _op_ent_iovec_count         type_u.handle_s.iovec_count
#define _op_ent_fake_iovec          type_u.handle_s.fake_iovec

#define _op_ent_driver              type_u.target_s.driver;

#define _op_ent_accept_attr         type_u.target_s.accept_attr
/*
 *  represents a entry in an array of operations.  each entry
 *  is mapped to a driver at the same index.
 */
typedef struct globus_i_xio_op_entry_s
{
    /* callback info arrays */
    globus_xio_driver_callback_t                cb;
    void *                                      user_arg;

    union
    {
        /* handle op entries */
        struct
        {
            globus_xio_driver_data_callback_t   data_cb;
            globus_size_t                       wait_for_bytes;
            globus_size_t                       nbytes;
            globus_xio_iovec_t *                iovec;
            int                                 iovec_count;
            globus_xio_iovec_t *                fake_iovec;
        } handle_s;
        /* target op entries */
        struct
        {
            globus_xio_driver_t                 driver;
        } target_s;
    } type_u;
    globus_bool_t                               in_register;
    globus_bool_t                               is_limited;

    void *                                      dd;
    void *                                      target;
    void *                                      attr;
    int                                         caller_ndx;
} globus_i_xio_op_entry_t;


#define _op_data_cb                             data_cb
#define _op_iovec_cb                            iovec_cb
#define _op_cb                                  callback_u.cb
#define _op_accept_cb                           callback_u.accept_cb

#define _op_handle                              type_u.handle_s.handle
#define _op_iovec                               type_u.handle_s.iovec
#define _op_iovec_count                         type_u.handle_s.iovec_count
#define _op_mem_iovec                           type_u.handle_s.mem_iovec
#define _op_context                             type_u.handle_s.context
#define _op_nbytes                              type_u.handle_s.nbytes
#define _op_wait_for                            type_u.handle_s.wait_for
#define _op_handle_timeout_cb                   type_u.handle_s.timeout_cb

#define _op_server                              type_u.target_s.server
#define _op_in_register                         type_u.target_s.in_register
#define _op_server_timeout_cb                   type_u.target_s.timeout_cb

/*
 *  represents a requested io operation (open close read or write).
 */
typedef struct globus_i_xio_op_s
{
    /* operation type */
    globus_xio_operation_type_t                 type;
    globus_i_xio_op_state_t                     state;

    /*
     * user callbacks.  only 1 will be used per operation
     */
    union
    {
        globus_xio_callback_t                   cb;
        globus_xio_accept_callback_t            accept_cb;
    }callback_u;
        globus_xio_data_callback_t              data_cb;
        globus_xio_iovec_callback_t             iovec_cb;
    void *                                      user_arg;
   
    /*
     *  Union target and operation members that will not overlap together
     */
    union
    { 
        /* handle op stuff */
        struct
        {
            globus_i_xio_handle_t *             handle;

            globus_xio_iovec_t *                iovec;
            int                                 iovec_count;
            globus_xio_iovec_t                  mem_iovec;

            globus_size_t                       nbytes;

            /* convience pointer, really owned by handle */
            globus_i_xio_context_t *            context;
            /* data descriptor */
            globus_size_t                       wait_for;
            globus_xio_timeout_callback_t       timeout_cb;
        } handle_s;
        /* target stuff */
        struct
        {
            globus_i_xio_server_t *             server;
            void *                              target;
            globus_bool_t                       in_register;
            globus_xio_timeout_server_callback_t  timeout_cb;
        } target_s;
    } type_u;

    /* flag to determine if cancel should happen */
    globus_bool_t                               progress;

    /* reference count for destruction */
    int                                         ref;

    /* members for cancelation */
    globus_xio_driver_cancel_callback_t         cancel_cb;
    void *                                      cancel_arg;
    globus_bool_t                               canceled;
    globus_bool_t                               block_timeout;

    /* result code saved in op for kickouts */
    globus_result_t                             cached_res;

    /* size of the arrays */
    int                                         stack_size;
    /* current index in the driver stack */
    int                                         ndx;
    /* entry for each thing driver in the stack */
    globus_i_xio_op_entry_t                     entry[1];
} globus_i_xio_op_t;

typedef struct globus_i_xio_target_entry_s
{
    globus_xio_driver_t                         driver;
    void *                                      target;
} globus_i_xio_target_entry_t;

typedef struct globus_i_xio_target_s
{
    globus_xio_target_type_t                    type;
    int                                         stack_size;
    globus_i_xio_target_entry_t                 entry[1];
} globus_i_xio_target_t; 

typedef struct globus_i_xio_driver_s
{
    char *                                              name;
    void *                                              user_data;
    /*
     *  main io interface functions
     */
    globus_xio_driver_transform_open_t                  transform_open_func;
    globus_xio_driver_transport_open_t                  transport_open_func;
    globus_xio_driver_close_t                           close_func;
    globus_xio_driver_read_t                            read_func;
    globus_xio_driver_write_t                           write_func;
    globus_xio_driver_handle_cntl_t                     handle_cntl_func;

    globus_xio_driver_target_init_t                     target_init_func;
    globus_xio_driver_target_cntl_t                     target_cntl_func;
    globus_xio_driver_target_destroy_t                  target_destroy_func;

    /*
     * target init functions.  Must have client or server
     */
    globus_xio_driver_server_init_t                     server_init_func;
    globus_xio_driver_server_accept_t                   server_accept_func;
    globus_xio_driver_server_destroy_t                  server_destroy_func;
    globus_xio_driver_server_cntl_t                     server_cntl_func;

    /*
     *  driver attr functions.  All or none may be NULL
     *
     *   data descriptor is done with attr
     */
    globus_xio_driver_attr_init_t                       attr_init_func;
    globus_xio_driver_attr_copy_t                       attr_copy_func;
    globus_xio_driver_attr_cntl_t                       attr_cntl_func;
    globus_xio_driver_attr_destroy_t                    attr_destroy_func;
} globus_i_xio_driver_t;


/*************************************************************************
 *                     internal function signatures
 ************************************************************************/

void
globus_l_xio_driver_op_read_kickout(
    void *                                      user_arg);

void
globus_l_xio_driver_purge_read_eof(
    globus_i_xio_context_entry_t *              my_context);

void
globus_l_xio_driver_op_write_kickout(
    void *                                      user_arg);

globus_result_t
globus_i_xio_driver_start_close(
    globus_i_xio_op_t *                         op,
    globus_bool_t                               can_fail);

void
globus_l_xio_driver_op_kickout(
    void *                                      user_arg);


/*
 *  time stuff
 */
typedef globus_bool_t
(*globus_i_xio_timer_cb_t)(
    void *                                      datum);

typedef struct globus_i_xio_op_timer_s
{
    globus_reltime_t                                minimal_delay;
    globus_mutex_t                                  mutex;
    globus_cond_t                                   cond;
    globus_list_t *                                 op_list;
    globus_bool_t                                   running;
    globus_callback_handle_t                        periodic_handle;
} globus_i_xio_timer_t;

void
globus_i_xio_timer_init(
    globus_i_xio_timer_t *                      timer);

void
globus_i_xio_timer_destroy(
    globus_i_xio_timer_t *                      timer);

void
globus_i_xio_timer_register_timeout(
    globus_i_xio_timer_t *                      timer,
    void *                                      datum,
    globus_bool_t *                             progress_ptr,
    globus_i_xio_timer_cb_t                     timeout_cb,
    globus_reltime_t *                          timeout);

globus_bool_t
globus_i_xio_timer_unregister_timeout(
    globus_i_xio_timer_t *                      timer,
    void *                                      datum);

globus_i_xio_context_t *
globus_i_xio_context_create(
    globus_i_xio_target_t *                     xio_target);

void
globus_i_xio_context_destroy(
    globus_i_xio_context_t *                    xio_context);

extern globus_i_xio_timer_t                    globus_l_xio_timeout_timer;

/**************************************************************************
 *                      MACRO MAGIC FOLLOWS
 *                      -------------------
 *************************************************************************/
#if defined(BUILD_DEBUG)

#   define GlobusXIODebugSetOut(_dst, _src) *(_dst) = (_src)

    void
    globus_xio_driver_pass_accept_DEBUG(
        globus_result_t *                           _out_res,
        globus_xio_operation_t                      _in_op,
        globus_xio_driver_callback_t                _in_cb,
        void *                                      _in_user_arg);

    void
    globus_xio_driver_finished_accept_DEBUG(
        globus_xio_operation_t                      _in_op,
        void *                                      _in_target,
        globus_result_t                             _in_res);

    void
    globus_xio_driver_pass_open_DEBUG(
        globus_result_t *                           _out_res,
        globus_xio_context_t *                      _out_context,
        globus_xio_operation_t                      _in_op,
        globus_xio_driver_callback_t                _in_cb,
        void *                                      _in_user_arg);

    void
    globus_xio_driver_finished_open_DEBUG(
        globus_xio_context_t                        _in_context,
        void *                                      _in_dh,
        globus_xio_operation_t                      _in_op,
        globus_result_t                             _in_res);

    void
    globus_xio_driver_finished_close_DEBUG(
        globus_xio_operation_t                      op,
        globus_result_t                             res);

    void
    globus_xio_driver_pass_close_DEBUG(
        globus_result_t *                           _out_res,
        globus_xio_operation_t                      _in_op,
        globus_xio_driver_callback_t                _in_cb,
        void *                                      _in_user_arg);

    void
    globus_xio_driver_pass_write_DEBUG(
        globus_result_t *                           _out_res,
        globus_xio_operation_t                      _in_op,
        globus_xio_iovec_t *                        _in_iovec,
        int                                         _in_iovec_count,
        globus_size_t                               _in_wait_for,
        globus_xio_driver_data_callback_t           _in_cb,
        void *                                      _in_user_arg);

    void
    globus_xio_driver_finished_write_DEBUG(
        globus_xio_operation_t                      op,
        globus_result_t                             result,
        globus_size_t                               nbytes);

    void
    globus_xio_driver_write_deliver_DEBUG(
        globus_xio_operation_t                      op);


    void
    globus_xio_driver_pass_read_DEBUG(
        globus_result_t *                           _out_res,
        globus_xio_operation_t                      _in_op,
        globus_xio_iovec_t *                        _in_iovec,
        int                                         _in_iovec_count,
        globus_size_t                               _in_wait_for,
        globus_xio_driver_data_callback_t           _in_cb,
        void *                                      _in_user_arg);

    void
    globus_xio_driver_finished_read_DEBUG(
        globus_xio_operation_t                      op,
        globus_result_t                             result,
        globus_size_t                               nbytes);

    void
    globus_xio_driver_read_deliver_DEBUG(
        globus_xio_operation_t                      op);

#   define GlobusXIODriverFinishedAccept(_in_op, _in_target, _in_res)         \
            globus_xio_driver_finished_accept_DEBUG(_in_op, _in_target, _in_res)

#   define GlobusXIODriverPassAccept(_out_res, _in_op, _in_cb, _in_user_arg)  \
            globus_xio_driver_pass_accept_DEBUG(                              \
                &_out_res, _in_op, _in_cb, _in_user_arg)
            

#   define GlobusXIODriverPassOpen(                                         \
            _out_res, _out_context, _in_op, _in_cb, _in_user_arg)           \
        globus_xio_driver_pass_open_DEBUG(                                  \
            &_out_res, &_out_context,  _in_op, _in_cb, _in_user_arg)

#   define GlobusXIODriverFinishedOpen(                                     \
            _in_context, _in_dh, _in_op, _in_res)                           \
        globus_xio_driver_finished_open_DEBUG(                              \
            _in_context, _in_dh, _in_op, _in_res)

#   define GlobusXIODriverPassClose(                                        \
            _out_res, _in_op, _in_cb, _in_ua)                               \
        globus_xio_driver_pass_close_DEBUG(                                 \
            &_out_res, _in_op, _in_cb, _in_ua)

#   define GlobusXIODriverFinishedClose(op, res)                            \
            globus_xio_driver_finished_close_DEBUG(op, res)


#   define GlobusXIODriverPassWrite(                                        \
            _out_res, _in_op, _in_iovec, _in_iovec_count,                   \
            _in_wait_for, _in_cb, _in_user_arg)                             \
        globus_xio_driver_pass_write_DEBUG(                                 \
            &_out_res, _in_op, _in_iovec, _in_iovec_count,                  \
            _in_wait_for, _in_cb, _in_user_arg)

#   define GlobusXIODriverFinishedWrite(op, res, nbytes)                    \
            globus_xio_driver_finished_write_DEBUG(op, res, nbytes)

#   define GlobusIXIODriverWriteDeliver(op)                                 \
            globus_xio_driver_write_deliver_DEBUG(op)


#   define GlobusXIODriverPassRead(                                         \
            _out_res, _in_op, _in_iovec, _in_iovec_count,                   \
            _in_wait_for, _in_cb, _in_user_arg)                             \
        globus_xio_driver_pass_read_DEBUG(                                  \
            &_out_res, _in_op, _in_iovec, _in_iovec_count,                  \
            _in_wait_for, _in_cb, _in_user_arg)

#   define GlobusXIODriverFinishedRead(op, res, nbytes)                     \
            globus_xio_driver_finished_read_DEBUG(op, res, nbytes)

#   define GlobusIXIODriverReadDeliver(op) \
            globus_xio_driver_read_deliver_DEBUG(op)

#else /* BUILD_DEBUG */
#   include "globus_xio_macro_magic.h"
#endif /* BUILD_DEBUG */

#define GlobusXIODebugPrintf(level, message) GlobusDebugPrintf(GLOBUS_XIO, level, message)

#endif /* GLOBUS_I_XIO_H */

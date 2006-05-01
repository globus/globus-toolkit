/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if !defined(GLOBUS_I_XIO_H)
#define GLOBUS_I_XIO_H 1

#include "globus_xio.h"
#include "globus_xio_driver.h"
#include "globus_common.h"
#include "globus_xio_util.h"
#include "globus_xio_load.h"

#define GLOBUS_XIO_ATTR_ARRAY_BASE_SIZE             16
#define GLOBUS_XIO_HANDLE_DEFAULT_OPERATION_COUNT   4

/***************************************************************************
 *                         internal macros
 *                         ---------------
 **************************************************************************/

#ifdef BUILD_LITE
#define GlobusXIOThreadSelf()                                               \
    globus_callback_space_get_depth(GLOBUS_CALLBACK_GLOBAL_SPACE)
#else
#define GlobusXIOThreadSelf()   globus_thread_self()
#endif

GlobusDebugDeclare(GLOBUS_XIO);

#define GlobusXIODebugPrintf(level, message)                                \
    GlobusDebugPrintf(GLOBUS_XIO, level, message)

#define GlobusXIOOpInc(_in_op)                                              \
do                                                                          \
{                                                                           \
    (_in_op)->ref++;                                                        \
    GlobusXIODebugPrintf(                                                   \
        GLOBUS_XIO_DEBUG_STATE,                                             \
        ("[%s:%d] Op @ 0x%x ref increased to %d:\n", _xio_name, __LINE__,   \
         (_in_op), (_in_op)->ref));                                         \
} while(0)

#define GlobusXIOOpDec(_in_op)                                              \
do                                                                          \
{                                                                           \
    (_in_op)->ref--;                                                        \
    GlobusXIODebugPrintf(                                                   \
        GLOBUS_XIO_DEBUG_STATE,                                             \
        ("[%s:%d] Op @ 0x%x ref decreased to %d:\n", _xio_name, __LINE__,   \
         (_in_op), (_in_op)->ref));                                         \
} while(0)

#define GlobusXIOObjToResult(_in_obj)                                       \
    (_in_obj == NULL ? GLOBUS_SUCCESS : globus_error_put(_in_obj))

#define GlobusXIOResultToObj(_in_res)                                       \
    (_in_res == GLOBUS_SUCCESS ? NULL : globus_error_get(_in_res))

#define GlobusXIOHandleStateChange(_h, _new)                                \
do                                                                          \
{                                                                           \
    globus_i_xio_handle_t *             _l_h;                               \
                                                                            \
    _l_h = (_h);                                                            \
    GlobusXIODebugPrintf(                                                   \
        GLOBUS_XIO_DEBUG_STATE,                                             \
        ("[%s:%d] Handle @ 0x%x state change:\n"                            \
         "    From:%s\n"                                                    \
         "    to:  %s\n",                                                   \
            _xio_name,                                                      \
            __LINE__,                                                       \
            _l_h,                                                           \
            globus_i_xio_handle_state_name_table[_l_h->state],              \
            globus_i_xio_handle_state_name_table[_new]));                   \
   _l_h->state = _new;                                                      \
} while(0)

#define GlobusXIOOpStateChange(_op, _new)                                   \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                 _l_op;                              \
                                                                            \
    _l_op = (_op);                                                          \
    GlobusXIODebugPrintf(                                                   \
        GLOBUS_XIO_DEBUG_STATE,                                             \
        ("[%s:%d] Op @ 0x%x state change:\n"                                \
         "    From:%s\n"                                                    \
         "    to:  %s\n",                                                   \
            _xio_name,                                                      \
            __LINE__,                                                       \
            _l_op,                                                          \
            globus_i_xio_op_state_name_table[_l_op->state],                 \
            globus_i_xio_op_state_name_table[_new]));                       \
   _l_op->state = _new;                                                     \
} while(0)

#define GlobusXIOContextStateChange(_c, _new)                               \
do                                                                          \
{                                                                           \
    globus_i_xio_context_entry_t *      _l_context;                         \
                                                                            \
    _l_context = (_c);                                                      \
    GlobusXIODebugPrintf(                                                   \
        GLOBUS_XIO_DEBUG_STATE,                                             \
        ("[%s:%d] Context @ 0x%x state change:\n"                           \
         "    From:%s\n"                                                    \
         "    to:  %s\n",                                                   \
            _xio_name,                                                      \
            __LINE__,                                                       \
            _l_context,                                                     \
            globus_i_xio_context_state_name_table[_l_context->state],       \
            globus_i_xio_context_state_name_table[_new]));                  \
   _l_context->state = _new;                                                \
} while(0)

#define GlobusXIODebugEnter()                                               \
    GlobusXIODebugPrintf(                                                   \
        GLOBUS_XIO_DEBUG_TRACE,                                             \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIODebugExit()                                                \
    GlobusXIODebugPrintf(                                                   \
        GLOBUS_XIO_DEBUG_TRACE,                                             \
        ("[%s] Exiting\n", _xio_name))

#define GlobusXIODebugExitWithError()                                       \
    GlobusXIODebugPrintf(                                                   \
        GLOBUS_XIO_DEBUG_TRACE,                                             \
        ("[%s] Exiting with error\n", _xio_name))

#define GlobusXIODebugInternalEnter()                                       \
    GlobusXIODebugPrintf(                                                   \
        GLOBUS_XIO_DEBUG_INTERNAL_TRACE,                                    \
        ("[%s] I Entering\n", _xio_name))

#define GlobusXIODebugInternalExit()                                        \
    GlobusXIODebugPrintf(                                                   \
        GLOBUS_XIO_DEBUG_INTERNAL_TRACE,                                    \
        ("[%s] I Exiting\n", _xio_name))

#define GlobusXIODebugInternalExitWithError()                               \
    GlobusXIODebugPrintf(                                                   \
        GLOBUS_XIO_DEBUG_INTERNAL_TRACE,                                    \
        ("[%s] I Exiting with error\n", _xio_name))

#define GlobusXIODebugInregisterOneShot()                                   \
    GlobusXIODebugPrintf(                                                   \
        GLOBUS_XIO_DEBUG_INFO,                                              \
        ("[%s] Registering one shot due to in_register.\n", _xio_name))

#define GlobusXIODebugDelayedFinish()                                       \
    GlobusXIODebugPrintf(                                                   \
        GLOBUS_XIO_DEBUG_INFO,                                              \
        ("[%s] Delaying finish due to in_register and blocking op.\n",      \
        _xio_name))

#define GlobusXIOOperationCreate(_out_op, _in_c)                            \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                 _X_op;                              \
    globus_i_xio_context_t *            _X_c;                               \
                                                                            \
    _X_c = (_in_c);                                                         \
    _X_op = (globus_i_xio_op_t * )                                          \
            globus_memory_pop_node(&_X_c->op_memory);                       \
    if(_X_op != NULL)                                                       \
    {                                                                       \
        /* sets deliver_op to NONE */                                       \
        memset(_X_op, '\0', sizeof(globus_i_xio_op_t) +                     \
            (sizeof(globus_i_xio_op_entry_t) * (_X_c->stack_size - 1)));    \
        _X_op->_op_context = _X_c;                                          \
        _X_op->stack_size = _X_c->stack_size;                               \
        _X_op->progress = GLOBUS_TRUE;                                      \
        _X_op->_op_ent_offset = -1;                                         \
    }                                                                       \
    _out_op = _X_op;                                                        \
} while(0)


/* if index == the level at which a cancel was requested then we reset the 
 * canceled flag for the operation. 
 */
#define GlobusIXIOClearCancel(op)                                           \
do                                                                          \
{                                                                           \
    globus_i_xio_op_t *                 _op = (op);                         \
    /* op->ndx is source_ndx + 1, canceled is source_ndx + 2 */             \
    /* so, source_ndx == op->ndx + 1                         */             \
    /* see globus_i_xio_operation_cancel                     */             \
    if(_op->canceled)                                                       \
    {                                                                       \
        globus_mutex_lock(&_op->_op_context->cancel_mutex);                 \
        if(_op->canceled == _op->ndx + 1)                                   \
        {                                                                   \
            _op->canceled = 0;                                              \
        }                                                                   \
        globus_mutex_unlock(&_op->_op_context->cancel_mutex);               \
    }                                                                       \
} while(0)

/***************************************************************************
 *                 state and type enumerations
 *                 ---------------------------
 **************************************************************************/

extern char * globus_i_xio_context_state_name_table[];

typedef enum globus_i_xio_context_state_e
{
    GLOBUS_XIO_CONTEXT_STATE_NONE,
    GLOBUS_XIO_CONTEXT_STATE_OPENING,
    GLOBUS_XIO_CONTEXT_STATE_OPEN,
    GLOBUS_XIO_CONTEXT_STATE_OPEN_FAILED,
    GLOBUS_XIO_CONTEXT_STATE_EOF_RECEIVED,
    GLOBUS_XIO_CONTEXT_STATE_EOF_DELIVERED,
    GLOBUS_XIO_CONTEXT_STATE_EOF_RECEIVED_AND_CLOSING,
    GLOBUS_XIO_CONTEXT_STATE_EOF_DELIVERED_AND_CLOSING,
    GLOBUS_XIO_CONTEXT_STATE_CLOSING,
    GLOBUS_XIO_CONTEXT_STATE_OPENING_AND_CLOSING,
    GLOBUS_XIO_CONTEXT_STATE_CLOSED
} globus_i_xio_context_state_t;

extern char * globus_i_xio_handle_state_name_table[];

typedef enum globus_i_xio_handle_state_e
{
    GLOBUS_XIO_HANDLE_STATE_NONE,
    GLOBUS_XIO_HANDLE_STATE_CLIENT,
    GLOBUS_XIO_HANDLE_STATE_ACCEPTED,
    GLOBUS_XIO_HANDLE_STATE_OPENING,
    GLOBUS_XIO_HANDLE_STATE_OPENING_FAILED,
    GLOBUS_XIO_HANDLE_STATE_OPENING_AND_CLOSING,
    GLOBUS_XIO_HANDLE_STATE_OPEN,
    GLOBUS_XIO_HANDLE_STATE_OPEN_FAILED,
    GLOBUS_XIO_HANDLE_STATE_CLOSING,
    GLOBUS_XIO_HANDLE_STATE_CLOSED
} globus_i_xio_handle_state_t;

extern char * globus_i_xio_op_state_name_table[];

typedef enum globus_i_xio_op_state_e
{
    GLOBUS_XIO_OP_STATE_NONE,
    GLOBUS_XIO_OP_STATE_OPERATING,
    GLOBUS_XIO_OP_STATE_TIMEOUT_PENDING,
    GLOBUS_XIO_OP_STATE_FINISH_WAITING,
    GLOBUS_XIO_OP_STATE_FINISHED
} globus_i_xio_op_state_t;

typedef enum globus_xio_server_state_e
{
    GLOBUS_XIO_SERVER_STATE_NONE,
    GLOBUS_XIO_SERVER_STATE_OPEN,
    GLOBUS_XIO_SERVER_STATE_ACCEPTING,
    GLOBUS_XIO_SERVER_STATE_COMPLETING,
    GLOBUS_XIO_SERVER_STATE_CLOSE_PENDING,
    GLOBUS_XIO_SERVER_STATE_CLOSING,
    GLOBUS_XIO_SERVER_STATE_CLOSED
} globus_xio_server_state_t;

/***************************************************************************
 *                  Internally exposed data structures
 *                  ----------------------------------
 **************************************************************************/


struct globus_i_xio_context_s;
struct globus_i_xio_op_s;

typedef struct globus_i_xio_monitor_s
{
    int                                 count;
} globus_i_xio_monitor_t;

void
globus_i_xio_monitor_init(
    globus_i_xio_monitor_t *            monitor);

void
globus_i_xio_monitor_destroy(
    globus_i_xio_monitor_t *            monitor);

typedef struct globus_i_xio_attr_ent_s
{
    globus_xio_driver_t                 driver;
    void *                              driver_data;
} globus_i_xio_attr_ent_t;

typedef struct globus_i_xio_attr_s
{
    globus_bool_t                       unloaded;
    
    globus_xio_timeout_callback_t       open_timeout_cb;
    globus_reltime_t                    open_timeout_period;
    globus_xio_timeout_callback_t       read_timeout_cb;
    globus_reltime_t                    read_timeout_period;
    globus_xio_timeout_callback_t       write_timeout_cb;
    globus_reltime_t                    write_timeout_period;
    globus_xio_timeout_callback_t       close_timeout_cb;
    globus_reltime_t                    close_timeout_period;

    globus_xio_timeout_server_callback_t accept_timeout_cb;
    globus_reltime_t                    accept_timeout_period;

    globus_bool_t                       cancel_open;
    globus_bool_t                       cancel_close;
    globus_bool_t                       cancel_read;
    globus_bool_t                       cancel_write;

    globus_bool_t                       no_cancel;
    void *                              timeout_arg;

    globus_callback_space_t             space;

    int                                 max;
    int                                 ndx;
    globus_i_xio_attr_ent_t *           entry;
} globus_i_xio_attr_t;

typedef struct globus_i_xio_stack_s
{
    int                                 size;
    globus_list_t *                     driver_stack;
    globus_xio_driver_t                 pushing_driver;
} globus_i_xio_stack_t;


typedef struct globus_i_xio_server_entry_s
{
    globus_xio_driver_t                 driver;
    void *                              server_handle;
} globus_i_xio_server_entry_t;
/* 
 *  
 */
typedef struct globus_i_xio_server_s
{
    globus_i_xio_monitor_t *            sd_monitor;
    
    globus_xio_server_state_t           state;

    globus_xio_timeout_server_callback_t accept_timeout;
    globus_reltime_t                    accept_timeout_period;
    struct globus_i_xio_op_s *          op;

    globus_xio_server_callback_t        cb;
    void *                              user_arg;

    int                                 outstanding_operations;

    int                                 ref;
    globus_mutex_t                      mutex;
    globus_callback_space_t             space;

    globus_bool_t                       blocking;
    char *                              contact_string;
    
    int                                 stack_size;
    globus_i_xio_server_entry_t         entry[1];
} globus_i_xio_server_t;

typedef struct globus_i_xio_handle_s
{
    globus_i_xio_monitor_t *            sd_monitor;

    globus_list_t *                     cb_list;
    int                                 ref;
    struct globus_i_xio_context_s *     context;

    globus_i_xio_handle_state_t         state;

    /* since only 1 open or close can be outstanding at a time we don't
       need a list */
    globus_list_t *                     write_op_list;
    globus_list_t *                     read_op_list;
    struct globus_i_xio_op_s *          open_op;
    struct globus_i_xio_op_s *          close_op;

    void *                              timeout_arg;

    globus_callback_space_t             space;
    globus_xio_timeout_callback_t       open_timeout_cb;
    globus_reltime_t                    open_timeout_period;
    globus_xio_timeout_callback_t       read_timeout_cb;
    globus_reltime_t                    read_timeout_period;
    globus_xio_timeout_callback_t       write_timeout_cb;
    globus_reltime_t                    write_timeout_period;
    globus_xio_timeout_callback_t       close_timeout_cb;
    globus_reltime_t                    close_timeout_period;
} globus_i_xio_handle_t;

/*
 *  represents an entry in the array of open handles.
 *
 *  each entry is maped to a driver in the stack
 */
typedef struct globus_i_xio_context_entry_s
{
    globus_xio_driver_t                 driver;
    void *                              driver_handle;

    /* each level must implement the entire state machine */
    globus_i_xio_context_state_t        state;
    int                                 outstanding_operations;
    int                                 read_operations;
    int                                 eof_operations;
    int                                 pending_reads;

    /* is this hacky? */
    globus_bool_t                       close_started;

    struct globus_i_xio_op_s *          open_op;
    struct globus_i_xio_op_s *          close_op;
    globus_list_t *                     eof_op_list;
    globus_fifo_t                       pending_read_queue;
    struct globus_i_xio_context_s *     whos_my_daddy;
} globus_i_xio_context_entry_t;

/* 
 *  a stretchy array
 */
typedef struct globus_i_xio_context_s
{
    /* handle has a reference and every entry has a reference */
    int                                 ref;
    int                                 stack_size;

    globus_memory_t                     op_memory;
    globus_mutex_t                      mutex;
    globus_mutex_t                      cancel_mutex;
    globus_i_xio_context_entry_t        entry[1];
} globus_i_xio_context_t;

/* MACROS for accessing the op_entry structure unin elements */
#define _op_ent_data_cb                 type_u.handle_s.data_cb
#define _op_ent_wait_for                type_u.handle_s.wait_for_bytes
#define _op_ent_offset                  type_u.handle_s.offset
#define _op_ent_nbytes                  type_u.handle_s.nbytes
#define _op_ent_iovec                   type_u.handle_s.iovec
#define _op_ent_iovec_count             type_u.handle_s.iovec_count
#define _op_ent_fake_iovec              type_u.handle_s.fake_iovec

/*
 *  represents a entry in an array of operations.  each entry
 *  is mapped to a driver at the same index.
 */
typedef struct globus_i_xio_op_entry_s
{
    /* callback info arrays */
    globus_xio_operation_type_t         type;
    globus_xio_driver_callback_t        cb;
    void *                              user_arg;

    union
    {
        /* handle op entries */
        struct
        {
            globus_xio_driver_data_callback_t data_cb;
            globus_size_t               wait_for_bytes;
            globus_size_t               nbytes;
            globus_xio_iovec_t *        iovec;
            int                         iovec_count;
            globus_xio_iovec_t *        fake_iovec;
        } handle_s;
    } type_u;
    globus_bool_t                       in_register;
    globus_bool_t                       is_limited;

    void *                              dd;
    void *                              link;
    void *                              open_attr;
    void *                              close_attr;
    int                                 prev_ndx;
    int                                 next_ndx;

    globus_xio_operation_type_t *       deliver_type;
} globus_i_xio_op_entry_t;


#define _op_data_cb                     data_cb
#define _op_iovec_cb                    iovec_cb
#define _op_cb                          callback_u.cb
#define _op_accept_cb                   callback_u.accept_cb

#define _op_handle                      type_u.handle_s.handle
#define _op_iovec                       type_u.handle_s.iovec
#define _op_iovec_count                 type_u.handle_s.iovec_count
#define _op_mem_iovec                   type_u.handle_s.mem_iovec
#define _op_context                     type_u.handle_s.context
#define _op_nbytes                      type_u.handle_s.nbytes
#define _op_wait_for                    type_u.handle_s.wait_for
#define _op_handle_timeout_cb           type_u.handle_s.timeout_cb

#define _op_server                      type_u.server_s.server
#define _op_server_timeout_cb           type_u.server_s.timeout_cb

/*
 *  represents a requested io operation (open close read or write).
 */
typedef struct globus_i_xio_op_s
{
    /* operation type */
    globus_xio_operation_type_t         type;
    globus_i_xio_op_state_t             state;

    globus_bool_t                       is_user_dd;

    /*
     * user callbacks.  only 1 will be used per operation
     */
    union
    {
        globus_xio_callback_t           cb;
        globus_xio_accept_callback_t    accept_cb;
    }callback_u;

    globus_xio_data_callback_t          data_cb;
    globus_xio_iovec_callback_t         iovec_cb;
    void *                              user_arg;
   
    /*
     *  Union operation members that will not overlap together
     */
    union
    { 
        /* handle op stuff */
        struct
        {
            globus_i_xio_handle_t *     handle;

            globus_xio_iovec_t *        iovec;
            int                         iovec_count;
            globus_xio_iovec_t          mem_iovec;

            globus_size_t               nbytes;

            /* convience pointer, really owned by handle */
            globus_i_xio_context_t *    context;
            /* data descriptor */
            globus_size_t               wait_for;
            globus_off_t                offset;
            globus_xio_timeout_callback_t timeout_cb;
        } handle_s;
        /* server op stuff */
        struct
        {
            globus_i_xio_server_t *     server;
            globus_xio_timeout_server_callback_t timeout_cb;
        } server_s;
    } type_u;

    /* flag to determine if timeout should happen */
    globus_bool_t                       progress;

    /* reference count for destruction */
    int                                 ref;

    /* members for cancelation */
    globus_xio_driver_cancel_callback_t cancel_cb;
    void *                              cancel_arg;
    int                                 canceled;
    globus_bool_t                       block_timeout;

    globus_bool_t                       restarted;
    globus_bool_t                       blocking;
    globus_thread_t                     blocked_thread;
    globus_bool_t                       finished_delayed;
    
    /* result code saved in op for kickouts */
    globus_object_t *                   cached_obj;

    /* size of the arrays */
    int                                 stack_size;
    /* current index in the driver stack */
    int                                 ndx;
    /* entry for each thing driver in the stack */
    globus_i_xio_op_entry_t             entry[1];
} globus_i_xio_op_t;

typedef struct globus_i_xio_driver_s
{
    char *                              name;
    void *                              user_data;
    void *                              wrap_data;
    /* these are filled in by the driver loader */
    globus_xio_driver_hook_t *          hook;
    globus_extension_handle_t           extension_handle;
    globus_bool_t                       extension_activated;
    
    /*
     *  main io interface functions
     */
    globus_xio_driver_transform_open_t  transform_open_func;
    globus_xio_driver_transport_open_t  transport_open_func;
    globus_xio_driver_close_t           close_func;
    globus_xio_driver_read_t            read_func;
    globus_xio_driver_write_t           write_func;
    globus_xio_driver_handle_cntl_t     handle_cntl_func;

    globus_xio_driver_push_driver_t     push_driver_func;

    /*
     * server
     */
    globus_xio_driver_server_init_t     server_init_func;
    globus_xio_driver_server_accept_t   server_accept_func;
    globus_xio_driver_server_destroy_t  server_destroy_func;
    globus_xio_driver_server_cntl_t     server_cntl_func;
    globus_xio_driver_link_cntl_t       link_cntl_func;
    globus_xio_driver_link_destroy_t    link_destroy_func;

    /*
     *  driver attr functions.  All or none may be NULL
     *
     *   data descriptor is done with attr
     */
    globus_xio_driver_attr_init_t       attr_init_func;
    globus_xio_driver_attr_copy_t       attr_copy_func;
    globus_xio_driver_attr_cntl_t       attr_cntl_func;
    globus_xio_driver_attr_destroy_t    attr_destroy_func;
} globus_i_xio_driver_t;


/*
 *  wrapper struct
 */
typedef struct globus_i_xio_blocking_s
{
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;
    globus_bool_t                       done;
    globus_size_t                       nbytes;
    globus_i_xio_op_t *                 op;
    globus_xio_handle_t                 accepted_handle;
    globus_xio_data_descriptor_t        data_desc;
    globus_object_t *                   error_obj;
} globus_i_xio_blocking_t;

typedef struct globus_i_xio_restart_s
{
    globus_i_xio_op_t *                 op;
    globus_bool_t                       restarted;
} globus_i_xio_restart_t;

globus_i_xio_blocking_t *
globus_i_xio_blocking_alloc();

void
globus_i_xio_blocking_destroy(
    globus_i_xio_blocking_t *           info);

/*************************************************************************
 *                     internal function signatures
 ************************************************************************/
globus_result_t
globus_i_xio_server_close(
    globus_xio_server_t                 xio_server,
    globus_xio_server_callback_t        cb,
    void *                              user_arg);

void
globus_l_xio_driver_purge_read_eof(
    globus_i_xio_context_entry_t *      my_context);

void
globus_l_xio_driver_op_write_kickout(
    void *                              user_arg);

void
globus_l_xio_driver_op_read_kickout(
    void *                              user_arg);

globus_result_t
globus_i_xio_driver_start_close(
    globus_i_xio_op_t *                 op,
    globus_bool_t                       can_fail);

void
globus_l_xio_driver_op_close_kickout(
    void *                              user_arg);

void
globus_l_xio_driver_op_accept_kickout(
    void *                              user_arg);

void
globus_l_xio_driver_open_op_kickout(
    void *                              user_arg);

void
globus_i_xio_driver_resume_op(
    globus_i_xio_op_t *                 op);
    
/*
 *  time stuff
 */
typedef globus_bool_t
(*globus_i_xio_timer_cb_t)(
    void *                              datum);

typedef struct globus_i_xio_op_timer_s
{
    globus_reltime_t                    minimal_delay;
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;
    globus_list_t *                     op_list;
    globus_bool_t                       running;
    globus_callback_handle_t            periodic_handle;
} globus_i_xio_timer_t;

void
globus_i_xio_timer_init(
    globus_i_xio_timer_t *              timer);

void
globus_i_xio_timer_destroy(
    globus_i_xio_timer_t *              timer);

void
globus_i_xio_timer_register_timeout(
    globus_i_xio_timer_t *              timer,
    void *                              datum,
    globus_bool_t *                     progress_ptr,
    globus_i_xio_timer_cb_t             timeout_cb,
    globus_reltime_t *                  timeout);

globus_bool_t
globus_i_xio_timer_unregister_timeout(
    globus_i_xio_timer_t *              timer,
    void *                              datum);

globus_i_xio_context_t *
globus_i_xio_context_create(
    int                                 stack_size);

void
globus_i_xio_context_destroy(
    globus_i_xio_context_t *            xio_context);

void
globus_i_xio_will_block_cb(
    int                                 space,
    globus_thread_callback_index_t      ndx,
    void *                              user_args);

void
globus_i_xio_pass_failed(
    globus_i_xio_op_t *                 op,
    globus_i_xio_context_entry_t *      my_context,
    globus_bool_t *                     close,
    globus_bool_t *                     destroy_handle);

void
globus_i_xio_handle_destroy(
    globus_i_xio_handle_t *             handle);

void
globus_i_xio_handle_dec(
    globus_i_xio_handle_t *             handle,
    globus_bool_t *                     destroy_handle);

void
globus_i_xio_op_destroy(
    globus_i_xio_op_t *                 op,
    globus_bool_t *                     destroy_handle);

globus_result_t
globus_i_xio_repass_write(
    globus_i_xio_op_t *                 op);

globus_result_t
globus_i_xio_repass_read(
    globus_i_xio_op_t *                 op);

void
globus_i_xio_register_oneshot(
    globus_i_xio_handle_t *             handle,
    globus_callback_func_t              cb,
    void *                              user_arg,
    globus_callback_space_t             space);


typedef struct globus_i_xio_space_info_s
{
    globus_bool_t                       unregister;
    globus_i_xio_handle_t *             handle;
    globus_callback_handle_t            ch;
    globus_callback_func_t              func;
    void *                              user_arg;
} globus_i_xio_space_info_t;

void
globus_i_xio_close_handles(
    globus_xio_driver_t                 driver);

globus_result_t
globus_i_xio_operation_cancel(
    globus_i_xio_op_t *                 op,
    int                                 source_ndx);

void
globus_i_xio_driver_deliver_op(
    globus_i_xio_op_t *                 op,
    int                                 ndx,
    globus_xio_operation_type_t         deliver_type);

void
globus_xio_driver_open_delivered(
    globus_xio_operation_t              in_op,
    int                                 in_ndx,
    globus_xio_operation_type_t *       deliver_type);

void
globus_xio_driver_write_delivered(
    globus_xio_operation_t              in_op,
    int                                 in_ndx,
    globus_xio_operation_type_t *       deliver_type);

void
globus_xio_driver_read_delivered(
    globus_xio_operation_t              op,
    int                                 in_ndx,
    globus_xio_operation_type_t *       deliver_type);

globus_result_t
globus_i_xio_driver_dd_cntl(
    globus_i_xio_op_t *                 op,
    globus_xio_driver_t                 driver,
    globus_xio_operation_type_t         type,
    int                                 cmd,
    va_list                             ap);

globus_result_t
globus_i_xio_driver_handle_cntl(
    globus_i_xio_context_t *            context,
    int                                 start_ndx,
    globus_xio_driver_t                 driver,
    int                                 cmd,
    va_list                             ap);

globus_result_t
globus_i_xio_driver_attr_cntl(
    globus_i_xio_attr_t *               attr,
    globus_xio_driver_t                 driver,
    int                                 cmd,
    va_list                             ap);


extern globus_i_xio_timer_t             globus_i_xio_timeout_timer;
extern globus_list_t *                  globus_i_xio_outstanding_handles_list;
extern globus_list_t *                  globus_i_xio_outstanding_servers_list;
extern globus_list_t *                  globus_i_xio_outstanding_attrs_list;
extern globus_list_t *                  globus_i_xio_outstanding_dds_list;
extern globus_mutex_t                   globus_i_xio_mutex;
extern globus_cond_t                    globus_i_xio_cond;

#endif /* GLOBUS_I_XIO_H */

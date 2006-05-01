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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_io_core.c Core File Descriptor Management of globus_io.
 *
 * This contains handle-type independent code for managing a list of
 * file descriptors, and the event polling interface.
 *
 * $Source$
 * $Date$
 * $Revision$
 * $State$
 * $Author$
 */

/**
 * RCS Indentification of this file
 */
static char *rcsid = "$Header$";

#endif

/**
 * @defgroup event Event Driver
 *
 * The API functions in this section provide the low level interface
 * to the Globus I/O event driver.
 */

/*
 * Include header files
 */
#include "globus_l_io.h"
#include "version.h"

/*
 * Define module specific constants
 */
#ifdef HAVE_SYSCONF
#   define GLOBUS_L_IO_NUM_FDS sysconf(_SC_OPEN_MAX)
#else
#ifdef TARGET_ARCH_WIN32
#   define GLOBUS_L_IO_NUM_FDS 2048
#else /* TARGET_ARCH_WIN32 */
#   define GLOBUS_L_IO_NUM_FDS 256
#endif /* TARGET_ARCH_WIN32 */
#endif

/*
 *  NETLOGGER
 */
globus_bool_t                      g_globus_i_io_use_netlogger = GLOBUS_FALSE;

/*
 * Type definitions
 */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * The select info structure contains information about a handle
 * registered with the Globus I/O system.
 *
 * The read, write, and except callbacks are called when the fd associated
 * with the handle is ready for the event (reads only when the
 * read_select and bit is true).
 *
 * When read_select is GLOBUS_FALSE, the select info is put into
 * a list of callbacks to be called when the event dispatch function is
 * called by the globus_callback event driver. (This was added to support
 * reading data from an SSL stream, where buffering may occur)
 *
 */

typedef struct globus_io_operation_info_s
{
    globus_io_handle_t *                handle;
    globus_i_io_operation_type_t        op;
    globus_bool_t                       canceled;
    globus_bool_t                       need_select;
    globus_callback_handle_t            callback_handle;
    
    globus_io_callback_t                callback;
    void *                              arg;
    globus_io_destructor_t              arg_destructor;
    
    int                                 refs;
#ifdef TARGET_ARCH_WIN32
	globus_result_t						result;
#endif
} globus_io_operation_info_t;

typedef struct globus_io_select_info_s
{
    globus_io_operation_info_t *        read;
    globus_io_operation_info_t *        write;
    globus_io_operation_info_t *        except;
#ifdef TARGET_ARCH_WIN32
	globus_io_handle_t *				handle;
#endif
} globus_io_select_info_t;

#endif

typedef struct globus_io_cancel_info_s
{
    globus_io_handle_t *                handle;
    globus_callback_handle_t            callback_handle;
    
    globus_io_operation_info_t *        read;
    globus_io_operation_info_t *        write;
    globus_io_operation_info_t *        except;
    
    globus_io_callback_t                callback;
    void *                              arg;
    globus_io_destructor_t              arg_destructor;
    
    struct globus_io_cancel_info_s *    next;
} globus_io_cancel_info_t;

typedef struct
{
    globus_i_io_operation_type_t        op;
    globus_io_callback_t		callback_func;
    void *				callback_arg;
    globus_io_destructor_t              arg_destructor;
} globus_i_io_quick_operation_info_t;

static 
void
globus_l_io_poll(
    void *                              user_args);

/*
 * Skip poll structures and prototypes 
 */
typedef struct globus_l_io_adaptive_skip_poll_s
{
    char *                env_variable;
    globus_reltime_t         start_delay;
    globus_reltime_t         max_delay;
    globus_reltime_t         current_delay;
    int                   events_handled;
} globus_l_io_adaptive_skip_poll_t;

static globus_bool_t
globus_l_io_adaptive_skip_poll_init(
    globus_l_io_adaptive_skip_poll_t *              skip_poll_info,
    char *                                          env_variable);

static globus_bool_t
globus_l_io_adaptive_skip_poll_adjust(
    globus_l_io_adaptive_skip_poll_t *              skip_poll_info,
    int                                             events_handled);

static globus_bool_t
globus_l_io_adaptive_skip_poll_get_delay(
    globus_l_io_adaptive_skip_poll_t *              skip_poll_info,
    globus_reltime_t *                              current_delay);


/*
 * Module Descriptor
 */
static globus_bool_t globus_l_io_activate(void);
static globus_bool_t globus_l_io_deactivate(void);

globus_module_descriptor_t globus_i_io_module =
{
    "globus_io",
    globus_l_io_activate,
    globus_l_io_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/*
 * Module specific variables
 */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Debugging level
 *
 * Currently this isn't terribly well defined. The idea is that 0 is no
 * debugging output, and 9 is a whole lot.
 */
int globus_i_io_debug_level=0;

/**
 * Maximum number of fds that system supports
 */
static globus_size_t			globus_l_io_fd_tablesize;
/**
 * The highest fd number we've ever used.
 *
 * This is used as the first parameter to select().
 */
static globus_size_t			globus_l_io_highest_fd;
/**
 * The FD table.
 *
 * A globus_io_select_info_t pointer is available for each
 * FD corresponding to an I/O handle.
 */
static globus_io_select_info_t **	globus_l_io_fd_table;

static globus_memory_t              globus_l_io_operation_info_memory;
/**
 * The read FD mask for select().
 */
static fd_set *				globus_l_io_read_fds;
/**
 * The write FD mask for select().
 */
static fd_set *				globus_l_io_write_fds;
/**
 * The exception FD mask for select().
 */
static fd_set *				globus_l_io_except_fds;
/**
 * The read FD mask result from select().
 *
 * This is file-scoped instead of local to globus_l_io_handle_events()
 * so that it can be allocated at activation time, and then freed then,
 * instead of each time the event driver is used.
 */
static fd_set *				globus_l_io_active_read_fds;
/**
 * The write FD mask result from select().
 *
 * This is file-scoped instead of local to globus_l_io_handle_events()
 * so that it can be allocated at activation time, and then freed then,
 * instead of each time the event driver is used.
 */
static fd_set *				globus_l_io_active_write_fds;
/**
 * The except FD mask result from select().
 *
 * This is file-scoped instead of local to globus_l_io_handle_events()
 * so that it can be allocated at activation time, and then freed then,
 * instead of each time the event driver is called.
 */
static fd_set *				globus_l_io_active_except_fds;
/**
 * The number of FDs currently registered for some callback.
 * This is used to determine whether or not to do the select() when
 * the event driver is called.
 */
static int				globus_l_io_fd_num_set;

/**
 * Set to GLOBUS_TRUE whenever the fd table changes.  This signals the
 * handler thread which is blocked in a select that the fd_table is 
 * different than when it was called, and therefore should not be trusted.
 */
static globus_bool_t		        globus_l_io_fd_table_modified;
/**
 * Queue of pending cancels to be dispatched at the next pass through
 * the event driver
 */
static globus_io_cancel_info_t *	globus_l_io_cancel_list;
/**
 * The tail of globus_l_io_cancel_list queue.
 */
static globus_io_cancel_info_t *	globus_l_io_cancel_tail;
/**
 * A free list of globus_io_cancel_info_t structures used to
 * reduce the number of malloc/frees done.
 */
static globus_io_cancel_info_t *	globus_l_io_cancel_free_list;
/**
 * The cancel structures that have callbacks waiting to fire them
 */
static globus_io_cancel_info_t *	globus_l_io_cancel_pending_list;

/**
 * List of pending read operations which do not need the select to be
 * done in order to complete them. This is used to dispatch buffered
 * reads, which were introduced to support GSSAPI wrapping of messages.
 */
static globus_list_t *			globus_l_io_operations;
/**
 * Number of times select has been called. This is used to work
 * around an IRIX bug which caused hangage when closing a FD
 * currently being monitored by select().
 */
static int	          	        globus_l_io_select_count;
/**
 * Flag which lets us know if a blocking select() is happening
 * right now. We use this to decide whether to write to the pipe
 * to wake it up if we change the select mask.
 */
static globus_bool_t	                globus_l_io_select_active;
/**
 * Flag which lets us know if wakeup has been sent to the event
 * handler already, so that we don't repeat it.
 */
static globus_bool_t	                globus_l_io_wakeup_pending;
/**
 * Flag which lets us know if deactivation is in progress, so that
 * we don't re-register again.
 */
static globus_bool_t	                globus_l_io_shutdown_called;
/**
 * memory for callback_info structures
 */
#define GLOBUS_L_IO_CALLBACK_MEMORY_BLOCK_COUNT 256

#ifndef TARGET_ARCH_WIN32
/**
 * Pipe to myself.
 *
 * This is used to wakeup the select() loop when the FD masks have changed;
 * <br>globus_l_io_wakeup_pip[0] = read
 * <br>globus_l_io_wakeup_pip[1] = write
 */
static int			        globus_l_io_wakeup_pipe[2];
/**
 * Pipe to myself.
 *
 * This is the handle that corresponds to the "read" end of the pipe.
 * This is used so that it can be registered properly.
 */
static globus_io_handle_t	        globus_l_io_wakeup_pipe_handle;
#else
static globus_io_handle_t	        winWakeUpHandle;
#endif

/**
 * Handle to the periodic event registered with the globus_callback
 * interface.
 *
 * This handle is used to unregister the event handling function
 * at shutdown time.
 */
static globus_callback_handle_t         globus_l_io_callback_handle;

static int                              globus_l_io_pending_count;

globus_bool_t *                         globus_i_io_tcp_used_port_table;
globus_bool_t *                         globus_i_io_udp_used_port_table;
unsigned short                          globus_i_io_tcp_used_port_min;
unsigned short                          globus_i_io_tcp_used_port_max;
unsigned short                          globus_i_io_udp_used_port_min;
unsigned short                          globus_i_io_udp_used_port_max;

globus_mutex_t                          globus_i_io_mutex;
globus_cond_t                           globus_i_io_cond;
int                                     globus_i_io_mutex_cnt;
int                                     globus_i_io_cond_cnt;

static globus_l_io_adaptive_skip_poll_t globus_l_io_skip_poll_info;
static globus_bool_t                    globus_l_io_use_skip_poll;

#endif


/******************************************************************************
		       Module specifc Macros
******************************************************************************/
#define globus_l_io_enqueue(Qhead, Qtail, Item) \
{ \
    if (Qhead) \
    { \
	(Qtail)->next = (Item); \
	(Qtail) = (Item); \
    } \
    else \
    { \
	(Qhead) = (Qtail) = (Item); \
    } \
}

#define globus_l_io_dequeue(Qhead, Qtail, Item) \
{ \
    (Item) = (Qhead); \
    (Qhead) = (Qhead)->next; \
}

#ifndef TARGET_ARCH_WIN32
#define globus_l_io_read_isregistered(handle) \
    (FD_ISSET(handle->fd, globus_l_io_read_fds))
#define globus_l_io_write_isregistered(handle) \
    (FD_ISSET(handle->fd, globus_l_io_write_fds))
#define globus_l_io_except_isregistered(handle) \
    (FD_ISSET(handle->fd, globus_l_io_except_fds))
#else
#define globus_l_io_read_isregistered(handle) \
    (FD_ISSET(handle->io_handle, globus_l_io_read_fds))
#define globus_l_io_write_isregistered(handle) \
    (FD_ISSET(handle->io_handle, globus_l_io_write_fds))
#define globus_l_io_except_isregistered(handle) \
    (FD_ISSET(handle->io_handle, globus_l_io_except_fds))
#endif

/******************************************************************************
		       Module specific callbacks
******************************************************************************/
static void globus_l_io_wakeup_pipe_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result);


/******************************************************************************
		       Module specific prototypes
******************************************************************************/
static
globus_result_t
globus_l_io_table_remove_fd(
    int					fd);

static
int
globus_l_io_handle_events(
    globus_reltime_t *                  time_left);

#ifdef TARGET_ARCH_WIN32
// Windows-specific helper functions
int globus_l_io_get_table_index( globus_io_handle_t * handle );
int globus_l_io_get_first_available_table_slot( void );
void globus_l_io_remove_handle_from_table( globus_io_handle_t * handle );
#endif

/******************************************************************************
				Local Support Functions
******************************************************************************/

/*
 * Function:	globus_l_io_select_wakeup()
 *
 * Description:	
 *		Note: the FD mutex must be acquired before calling this func
 *
 * Parameters:	
 *
 * Returns:	
 */
static
globus_bool_t
globus_l_io_select_wakeup(void)
{
#if !defined(BUILD_LITE)
    char				byte = '\0';
    int					rc;

    globus_i_io_debug_printf(3, 
        (stderr, "globus_l_io_select_wakeup(): entering\n"));

    if(!globus_l_io_mutex_acquired())
    {
    globus_i_io_debug_printf(3, 
        (stderr, "globus_l_io_select_wakeup(): mutex ! acquired\n"));
	return GLOBUS_FALSE;
    }

    if (!globus_l_io_select_active || globus_l_io_wakeup_pending)
    {
    globus_i_io_debug_printf(3, 
        (stderr, "globus_l_io_select_wakeup(): select_active=%d wakeup_pending=%d\n", globus_l_io_select_active, globus_l_io_wakeup_pending));
	rc = GLOBUS_TRUE;
	goto fn_exit;
    }

    globus_i_io_debug_printf(5,
        (stderr, "globus_l_io_select_wakeup(): poking handler thread\n"));

#ifndef TARGET_ARCH_WIN32
   while ((rc = globus_libc_write(globus_l_io_wakeup_pipe[1],
				   &byte,
				   sizeof(char))) == -1 &&
	   errno == EINTR)
    {
	/* do nothing */
    }

    if (rc > 0)
    {
	globus_l_io_wakeup_pending = GLOBUS_TRUE;
	rc = GLOBUS_TRUE;
    }
    else
    {
	rc = GLOBUS_FALSE;
    }
#else /* TARGET_ARCH_WIN32 */
	// post a fake completion packet so that GetQueuedCompletionStatus()
	// will return
	rc= globus_i_io_windows_post_completion( &winWakeUpHandle, 
	 WinIoWakeup );
	if ( rc ) // error occurred
		rc= GLOBUS_FALSE;
	else
    {
		globus_l_io_wakeup_pending = GLOBUS_TRUE;
		rc = GLOBUS_TRUE;
    }
#endif /* TARGET_ARCH_WIN32 */

  fn_exit:
    globus_i_io_debug_printf(3, 
        (stderr, "globus_l_io_select_wakeup(): exiting\n"));

    return rc;
#else /* BUILD_LITE */
    return GLOBUS_FALSE;
#endif /* BUILD_LITE */
}
/* globus_l_io_select_wakeup() */

/*
 * Function:	globus_l_io_internal_handle_create()
 *
 * Description:	
 *		Note: the FD mutex must be acquired before calling this func
 *
 * Parameters:
 *		fd - the file descriptor to be converted to an untyped handle
 *		handle - the handle to be added to the file descriptor table
 *
 * Returns:	
 */
static
globus_bool_t
globus_l_io_internal_handle_create(
    int					fd,
    globus_io_handle_t *		handle)
{
    globus_i_io_debug_printf(3,
        (stderr, "globus_l_io_handle_create(): entering, fd=%d\n", fd));

    /*    GlobusAssert2((globus_l_io_mutex_acquired()),
     *			("globus_l_io_table_add()\n"));
     */

    handle->fd = fd;
    handle->type = GLOBUS_IO_HANDLE_TYPE_INTERNAL;
    handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;
    
    handle->socket_attr.space = GLOBUS_CALLBACK_GLOBAL_SPACE;
    
    handle->read_operation = GLOBUS_NULL;
    handle->write_operation = GLOBUS_NULL;
    handle->except_operation = GLOBUS_NULL;
    
    globus_i_io_debug_printf(3,
        (stderr, "globus_l_io_internal_handle_create(): exiting\n"));

    return GLOBUS_SUCCESS;
}
/* globus_l_io_internal_handle_create() */

/*
 * Function:	globus_l_io_table_add()
 *
 * Description:	
 *		Note: the FD mutex must be acquired before calling this func
 *
 * Parameters:
 *		handle - the handle to be added to the file descriptor table
 *
 * Returns:	
 */
static
void
globus_l_io_table_add(
    globus_io_handle_t *        handle)
{
    globus_io_select_info_t *       select_info;
#ifdef TARGET_ARCH_WIN32
	int index;
#endif

    /*    GlobusAssert2((globus_l_io_mutex_acquired()),
     *          ("globus_l_io_table_add()\n"));
     */

#ifdef TARGET_ARCH_WIN32
	// check whether there is already an entry in the table for this
	// socket/file
	// if so, set fd to that index
	// else, find the index of the first available slot
	index= globus_l_io_get_table_index( handle );
	if ( index != -1 ) // found it!
		handle->fd= index;
	else // not in the table yet- get the first available slot
	{
		handle->fd= globus_l_io_get_first_available_table_slot();
		if (handle->fd < 0)
		{
		    printf("Globus error: File table overflow.\n");
		    exit(0);
		}
	}
#endif

    if (globus_l_io_fd_table[handle->fd])
    {
#ifdef TARGET_ARCH_WIN32
		// set the table entry to point to this handle just in case
		// it doesn't already (it might just be a reused entry in the
		// table)
		globus_l_io_fd_table[handle->fd]->handle= handle;
#endif
        return;
    }
    
    select_info = (globus_io_select_info_t *)
        globus_malloc(sizeof(globus_io_select_info_t));
    
    select_info->read = GLOBUS_NULL;
    select_info->write = GLOBUS_NULL;
    select_info->except = GLOBUS_NULL;
#ifdef TARGET_ARCH_WIN32
	select_info->handle= handle;
#endif

    globus_l_io_fd_table[handle->fd] = select_info;
    if(globus_l_io_highest_fd < handle->fd)
    {
        globus_l_io_highest_fd = handle->fd;
    }
}
/* globus_l_io_table_add() */


#if 0
/*
 * Function:	globus_l_io_table_remove()
 *
 * Description:	free up table resources being held for a file descriptor
 *
 *		Note: the FD mutex must be acquired before calling this func
 *
 * Parameters:	handle		the handle to be removedd
 *
 * Returns:	none
 */
static
globus_result_t
globus_l_io_table_remove(
    globus_io_handle_t *		handle)
{
    globus_i_io_debug_printf(3,
        (stderr, "globus_l_io_table_remove(): entering, fd=%d\n", handle->fd));

    globus_l_io_table_remove_fd(handle->fd);

    globus_i_io_debug_printf(3, 
        (stderr, "globus_l_io_table_remove(): exiting\n"));
    return GLOBUS_SUCCESS;
}
/* globus_l_io_table_remove() */
#endif

/*
 * Function:	globus_l_io_table_fd_remove()
 *
 * Description:	free up table resources being held for a file descriptor
 *
 *		Note: the FD mutex must be acquired before calling this func
 *
 * Parameters:	fd		file descriptor
 *
 * Returns:	none
 */
static
globus_result_t
globus_l_io_table_remove_fd(
    int					fd)
{
    globus_io_select_info_t *		select_info;

    globus_i_io_debug_printf(3,
        (stderr, "globus_l_io_table_remove_fd(): entering, fd=%d\n", fd));

    /*
     *    GlobusAssert2((globus_l_io_mutex_acquired()),
     *		 ("globus_l_io_table_remove()\n"));
     */
    select_info = globus_l_io_fd_table[fd];
    if (select_info != GLOBUS_NULL)
    {
	globus_l_io_fd_table[fd] = (void *) GLOBUS_NULL;
	globus_l_io_fd_table_modified = GLOBUS_TRUE;
	
	globus_free(select_info);
    }

    globus_i_io_debug_printf(3,
        (stderr, "globus_l_io_table_remove_fd(): exiting\n"));
    return GLOBUS_SUCCESS;
}
/* globus_l_io_table_remove() */

/* Helper Functions for Windows
*/
#ifdef TARGET_ARCH_WIN32

int globus_l_io_get_table_index( globus_io_handle_t * handle )
{
	int i;

	if ( handle == GLOBUS_NULL )
		return -1;

	// iterate through the table to find an entry containing this handle
	for ( i= 0; i < globus_l_io_fd_tablesize; i++ )
	{
		if ( globus_l_io_fd_table[i] && 
		 globus_l_io_fd_table[i]->handle &&
		 globus_l_io_fd_table[i]->handle->io_handle == handle->io_handle )
			return i;
	}
	return -1;
}

int globus_l_io_get_first_available_table_slot( void )
{
	int i;

	// iterate through the table to find the first null entry
	for ( i= 0; i < globus_l_io_fd_tablesize; i++ )
	{
		if ( globus_l_io_fd_table[i] == GLOBUS_NULL )
			return i;
	}
	// none of the entries are null, so iterate again to find
	// the first entry that contains a handle that is null
	for ( i= 0; i < globus_l_io_fd_tablesize; i++ )
	{
		if ( globus_l_io_fd_table[i]->handle == GLOBUS_NULL )
			return i;
	}

	// all full at the inn
	return -1;
}

void globus_l_io_remove_handle_from_table( globus_io_handle_t * handle )
{
	// verify that the handle exists and that it has been added to the
	// table- fd will be -1 if it has never been added to the table
	if ( handle && handle->fd >= 0 )
		globus_l_io_fd_table[handle->fd]->handle= GLOBUS_NULL;
}

#endif /* TARGET_ARCH_WIN32 */

globus_result_t
globus_i_io_start_operation(
    globus_io_handle_t *                handle,
    globus_i_io_operation_type_t        ops)
{
    globus_io_select_info_t *           select_info;
    globus_io_operation_info_t *        operation_info;
    globus_result_t                     result;
    static char *                       myname = 
        "globus_i_io_start_operation";

    globus_i_io_debug_printf(3,
        (stderr, "%s(): entering, fd=%d\n", myname, handle->fd));
    
    if(ops & GLOBUS_I_IO_READ_OPERATION && handle->read_operation)
    {
        result = globus_error_put(
            globus_io_error_construct_read_already_registered(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle));
        
        goto exit_error;
    }
    
    if(ops & GLOBUS_I_IO_WRITE_OPERATION && handle->write_operation)
    {
        result = globus_error_put(
            globus_io_error_construct_write_already_registered(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle));
        
        goto exit_error;
    }
    
    if(ops & GLOBUS_I_IO_EXCEPT_OPERATION && handle->except_operation)
    {
        result = globus_error_put(
            globus_io_error_construct_except_already_registered(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle));
        
        goto exit_error;
    }
    
    operation_info = (globus_io_operation_info_t *)
        globus_memory_pop_node(&globus_l_io_operation_info_memory);
    
    operation_info->handle = handle;
    operation_info->canceled = GLOBUS_FALSE;
    operation_info->callback = GLOBUS_NULL;
    operation_info->refs = 0;
    
    globus_l_io_table_add(handle);
    select_info = globus_l_io_fd_table[handle->fd];
    
    if(ops & GLOBUS_I_IO_READ_OPERATION)
    {
        select_info->read = operation_info;
        handle->read_operation = operation_info;
    }
    
    if(ops & GLOBUS_I_IO_WRITE_OPERATION)
    {
        select_info->write = operation_info;
        handle->write_operation = operation_info;
    }
    
    if(ops & GLOBUS_I_IO_EXCEPT_OPERATION)
    {
        select_info->except = operation_info;
        handle->except_operation = operation_info;
    }

    globus_i_io_debug_printf(3,
        (stderr, "%s(): exiting, fd=%d\n", myname, handle->fd));

    return GLOBUS_SUCCESS;
    
exit_error:
    globus_i_io_debug_printf(3,
        (stderr, "%s(): exiting with error, fd=%d\n", myname, handle->fd));
    
    return result;
}

void
globus_i_io_end_operation(
    globus_io_handle_t *                handle,
    globus_i_io_operation_type_t        ops)
{
    globus_io_select_info_t *           select_info;
    globus_io_operation_info_t *        operation_info;
    static char *                       myname = 
        "globus_i_io_end_operation";

    globus_i_io_debug_printf(3,
        (stderr, "%s(): entering, fd=%d\n", myname, handle->fd));
    
    operation_info = GLOBUS_NULL;
    
    if(ops & GLOBUS_I_IO_READ_OPERATION)
    {
        operation_info = handle->read_operation;
    }
    else if(ops & GLOBUS_I_IO_WRITE_OPERATION)
    {
        operation_info = handle->write_operation;
    }
    else if(ops & GLOBUS_I_IO_EXCEPT_OPERATION)
    {
        operation_info = handle->except_operation;
    }
    
    if(!operation_info)
    {
        globus_assert(0 && "operation never started");
    }
    
    /* clear out all operations bound to this structure */
    if(handle->read_operation == operation_info)
    {
        handle->read_operation = GLOBUS_NULL;
    }
    
    if(handle->write_operation == operation_info)
    {
        handle->write_operation = GLOBUS_NULL;
    }
    
    if(handle->except_operation == operation_info)
    {
        handle->except_operation = GLOBUS_NULL;
    }
        
    if(!operation_info->canceled)
    {
        select_info = globus_l_io_fd_table[handle->fd];
        
        if(select_info->read == operation_info)
        {
            select_info->read = GLOBUS_NULL;
        }
        
        if(select_info->write == operation_info)
        {
            select_info->write = GLOBUS_NULL;
        }
        
        if(select_info->except == operation_info)
        {
            select_info->except = GLOBUS_NULL;
        }
    }
    
    globus_memory_push_node(
        &globus_l_io_operation_info_memory, operation_info);
    
    globus_i_io_debug_printf(3,
        (stderr, "%s(): exiting, fd=%d\n", myname, handle->fd));
}

globus_result_t
globus_i_io_register_operation(
    globus_io_handle_t *                handle,
    globus_io_callback_t                callback_func,
    void *                              callback_arg,
    globus_io_destructor_t              arg_destructor,
    globus_bool_t                       needs_select,
    globus_i_io_operation_type_t        op)
{
    globus_io_operation_info_t *        operation_info;
    globus_result_t                     result;
    static char *                       myname =
        "globus_i_io_register_operation";

    globus_i_io_debug_printf(3,
        (stderr, "%s(): entering, fd=%d, op=%d\n", myname, handle->fd, op));
    
    switch(op)
    {
      case GLOBUS_I_IO_READ_OPERATION:
        operation_info = handle->read_operation;
        break;
      
      case GLOBUS_I_IO_WRITE_OPERATION:
        operation_info = handle->write_operation;
        break;
        
      case GLOBUS_I_IO_EXCEPT_OPERATION:
        operation_info = handle->except_operation;
        break;
        
      default:
        globus_assert(0 && "invalid op");
        break;
    }
    
    if(!operation_info)
    {
        result = globus_error_put(
            globus_io_error_construct_internal_error(
	            GLOBUS_IO_MODULE,
	            GLOBUS_NULL,
	            myname));
        
        goto exit_error;
    }
    
    if(operation_info->canceled)
    {
        result = globus_error_put(
            globus_io_error_construct_io_cancelled(
                GLOBUS_IO_MODULE,
                GLOBUS_NULL,
                handle));
        
        goto exit_error;
    }
    
    switch(op)
    {
      case GLOBUS_I_IO_READ_OPERATION:
        if(operation_info->callback)
        {
            result = globus_error_put(
                globus_io_error_construct_read_already_registered(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    handle));
            
            goto exit_error;
        }
        
#ifndef TARGET_ARCH_WIN32
        FD_SET(handle->fd, globus_l_io_read_fds);
#else
	    FD_SET( (SOCKET)handle->io_handle, globus_l_io_read_fds);
#endif
        break;
      
      case GLOBUS_I_IO_WRITE_OPERATION:
        if(operation_info->callback)
        {
            result = globus_error_put(
                globus_io_error_construct_write_already_registered(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    handle));
            
            goto exit_error;
        }
        
#ifndef TARGET_ARCH_WIN32
        FD_SET(handle->fd, globus_l_io_write_fds);
#else
	    FD_SET( (SOCKET)handle->io_handle, globus_l_io_write_fds);
#endif
        break;
        
      case GLOBUS_I_IO_EXCEPT_OPERATION:
        if(operation_info->callback)
        {
            result = globus_error_put(
                globus_io_error_construct_except_already_registered(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    handle));
            
            goto exit_error;
        }
        
#ifndef TARGET_ARCH_WIN32
        FD_SET(handle->fd, globus_l_io_except_fds);
#else
	    FD_SET( (SOCKET)handle->io_handle, globus_l_io_except_fds);
#endif
        break;
    }
    
    globus_l_io_fd_num_set++;
    
    operation_info->op = op;
    operation_info->callback = callback_func;
    operation_info->arg = callback_arg;
    operation_info->arg_destructor = arg_destructor;
    operation_info->need_select = needs_select;
    operation_info->callback_handle = GLOBUS_NULL_HANDLE;
    operation_info->refs++;

    if(!needs_select)
    {
        globus_list_insert(&globus_l_io_operations, operation_info);
    }
    
    if(globus_l_io_select_active)
    {
        globus_l_io_select_wakeup();
    }
    
    globus_i_io_debug_printf(3,
        (stderr, "%s(): exiting, fd=%d\n", myname, handle->fd));
    
    return GLOBUS_SUCCESS;
    
exit_error:
    globus_i_io_debug_printf(3,
        (stderr, "%s(): exiting with error, fd=%d\n", myname, handle->fd));
    
    return result;
}
    
globus_result_t
globus_i_io_unregister_operation(
    globus_io_handle_t *                handle,
    globus_bool_t                       call_destructor,
    globus_i_io_operation_type_t        op)
{
    globus_io_operation_info_t *        operation_info;
    globus_result_t                     result;
    static char *                       myname =
        "globus_i_io_unregister_operation";

    globus_i_io_debug_printf(3,
        (stderr, "%s(): entering, fd=%d\n", myname, handle->fd));
    
    switch(op)
    {
      case GLOBUS_I_IO_READ_OPERATION:
        operation_info = handle->read_operation;
        break;
      
      case GLOBUS_I_IO_WRITE_OPERATION:
        operation_info = handle->write_operation;
        break;
        
      case GLOBUS_I_IO_EXCEPT_OPERATION:
        operation_info = handle->except_operation;
        break;
        
      default:
        globus_assert(0 && "invalid op");
        break;
    }
    
    if(!operation_info || operation_info->op != op)
    {
        result = globus_error_put(
            globus_io_error_construct_internal_error(
	            GLOBUS_IO_MODULE,
	            GLOBUS_NULL,
	            myname));
        
        goto exit_error;
    }
    
    switch(op)
    {
      case GLOBUS_I_IO_READ_OPERATION:
#ifndef TARGET_ARCH_WIN32
        if(!FD_ISSET(handle->fd, globus_l_io_read_fds))
#else
        if(!FD_ISSET(handle->io_handle, globus_l_io_read_fds))
#endif
        {
            result = globus_error_put(
                globus_io_error_construct_internal_error(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    myname));
            
            goto exit_error;
        }
        
#ifndef TARGET_ARCH_WIN32
        FD_CLR(handle->fd, globus_l_io_read_fds);
#else
        FD_CLR((SOCKET)handle->io_handle, globus_l_io_read_fds);
#endif
        break;
      
      case GLOBUS_I_IO_WRITE_OPERATION:
#ifndef TARGET_ARCH_WIN32
		if(!FD_ISSET(handle->fd, globus_l_io_write_fds))
#else
		if(!FD_ISSET(handle->io_handle, globus_l_io_write_fds))
#endif
        {
            result = globus_error_put(
                globus_io_error_construct_internal_error(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    myname));
            
            goto exit_error;
        }

#ifndef TARGET_ARCH_WIN32
        FD_CLR(handle->fd, globus_l_io_write_fds);
#else
        FD_CLR((SOCKET)handle->io_handle, globus_l_io_write_fds);
#endif
        break;
        
      case GLOBUS_I_IO_EXCEPT_OPERATION:
#ifndef TARGET_ARCH_WIN32
        if(!FD_ISSET(handle->fd, globus_l_io_except_fds))
#else
        if(!FD_ISSET(handle->io_handle, globus_l_io_except_fds))
#endif
        {
            result = globus_error_put(
                globus_io_error_construct_internal_error(
                    GLOBUS_IO_MODULE,
                    GLOBUS_NULL,
                    myname));
            
            goto exit_error;
        }
        
#ifndef TARGET_ARCH_WIN32
        FD_CLR(handle->fd, globus_l_io_except_fds);
#else
        FD_CLR((SOCKET)handle->io_handle, globus_l_io_except_fds);
#endif
        break;
    }
    
    if(!operation_info->need_select)
    {
        globus_list_remove(&globus_l_io_operations,
               globus_list_search(globus_l_io_operations, operation_info));
    }
    
    if(call_destructor)
    {
        if(operation_info->arg_destructor && operation_info->arg)
        {
            operation_info->arg_destructor(operation_info->arg);
        }
        
        globus_i_io_end_operation(handle, op);
    }

    globus_l_io_fd_num_set--;
    globus_l_io_fd_table_modified = GLOBUS_TRUE;
    
    globus_i_io_debug_printf(3,
        (stderr, "%s(): exiting, fd=%d\n", myname, handle->fd));
    
    return GLOBUS_SUCCESS;
    
exit_error:
    globus_i_io_debug_printf(3,
        (stderr, "%s(): exiting with error, fd=%d\n", myname, handle->fd));
    
    return result;
}

void
globus_i_io_quick_operation_destructor(
    void *				arg)
{
    globus_i_io_quick_operation_info_t *quick_info;
    
    quick_info = (globus_i_io_quick_operation_info_t *) arg;
    
    if(quick_info->arg_destructor && quick_info->callback_arg)
    {
        quick_info->arg_destructor(quick_info->callback_arg);
    }
    
    globus_free(quick_info);
}

void
globus_i_io_quick_operation_kickout(
    void *				callback_arg,
    globus_io_handle_t *		handle,
    globus_result_t			result)
{
    globus_i_io_quick_operation_info_t *quick_info;
    
    quick_info = (globus_i_io_quick_operation_info_t *) callback_arg;
    
    globus_i_io_end_operation(handle, quick_info->op);
    
    quick_info->callback_func(quick_info->callback_arg, handle, result);
    
    globus_free(quick_info);
}

/* this handles the start, register and end operation steps 
 * only good for one step operations
 */
globus_result_t
globus_i_io_register_quick_operation(
    globus_io_handle_t *                handle,
    globus_io_callback_t                callback_func,
    void *                              callback_arg,
    globus_io_destructor_t              arg_destructor,
    globus_bool_t                       needs_select,
    globus_i_io_operation_type_t        op)
{
    globus_i_io_quick_operation_info_t *quick_info;
    globus_result_t                     rc;
    
    rc = globus_i_io_start_operation(handle, op);
    if(rc != GLOBUS_SUCCESS)
    {
        return rc;
    }
        
    quick_info = (globus_i_io_quick_operation_info_t *)
        globus_malloc(sizeof(globus_i_io_quick_operation_info_t));
    quick_info->op = op;
    quick_info->callback_func = callback_func;
    quick_info->callback_arg = callback_arg;
    quick_info->arg_destructor = arg_destructor;
    
    rc = globus_i_io_register_operation(
        handle,
        globus_i_io_quick_operation_kickout,
        quick_info,
        globus_i_io_quick_operation_destructor,
        needs_select,
        op);
    if(rc != GLOBUS_SUCCESS)
    {
        globus_free(quick_info);
        globus_i_io_end_operation(handle, op);
    }
    
    return rc;
}

/*
 * Function:	globus_i_io_close()
 *
 * Description:	close the specified handle
 *
 *		Note: the FD mutex must be acquired before calling this func
 *                    also, any outstanding registrations must be cancelled
 *
 *
 * Parameters:	fd			file descriptor to close
 *
 * Returns:	
 */
globus_result_t
globus_i_io_close(
    globus_io_handle_t *		handle)
{
    int					save_errno = 0;
    globus_result_t			rc = GLOBUS_SUCCESS;
    globus_object_t *			err;
    static char *			myname="globus_i_io_close";
    int					flags;
    
    globus_i_io_debug_printf(3,
        (stderr, "%s(): entering, fd=%d\n", myname, handle->fd));

    /*
     *    GlobusAssert2((globus_l_io_mutex_acquired()),
     *		 ("globus_i_io_close()\n"));
     */

    if(globus_l_io_read_isregistered(handle))
    {
        globus_i_io_unregister_operation(
            handle, GLOBUS_TRUE, GLOBUS_I_IO_READ_OPERATION);

        /* Don't create an error if we are closing the pipe
         * handle
         */
        if(handle->type != GLOBUS_IO_HANDLE_TYPE_INTERNAL)
        {
	    err = globus_io_error_construct_internal_error(
	        GLOBUS_IO_MODULE,
	        GLOBUS_NULL,
	        myname);

	    rc = globus_error_put(err);
	}
    }

    if(globus_l_io_write_isregistered(handle))
    {
        globus_i_io_unregister_operation(
            handle, GLOBUS_TRUE, GLOBUS_I_IO_WRITE_OPERATION);
            
	if(rc == GLOBUS_SUCCESS)
	{
	    err = globus_io_error_construct_internal_error(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		myname);
	    rc = globus_error_put(err);
	}
    }

    if(globus_l_io_except_isregistered(handle))
    {
        globus_i_io_unregister_operation(
            handle, GLOBUS_TRUE, GLOBUS_I_IO_EXCEPT_OPERATION);
            
	if(rc == GLOBUS_SUCCESS)
	{
	    err = globus_io_error_construct_internal_error(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		myname);
	    rc = globus_error_put(err);
	}
    }

    /*
     * Remove this FD from the FD table
     */
#   if 0
    {
	/* Disabled to reduce number of mallocs */
	globus_l_io_table_remove(handle);
    }
#   endif

#ifdef TARGET_ARCH_WIN32
	// remove the handle from the table by nullifying its reference
	globus_l_io_remove_handle_from_table( handle );
#endif

    /*
     * Force the handler thread to return from the select() before attempting
     * to close() listeners.  This is necessary because we may be in the
     * select() and some machines like the SGI running IRIX 6.4 hang if close()
     * is called on a FD which is also being monitored by select().
     */
    if (globus_l_io_select_active && globus_l_io_fd_table_modified)
    {
	unsigned			cnt = globus_l_io_select_count;
	
	globus_l_io_select_wakeup();

	while(cnt == globus_l_io_select_count)
	{
	    globus_l_io_cond_wait();
	}
    }

#ifndef TARGET_ARCH_WIN32
    /*
     * Close() the FD. First we set it to blocking, so that any data
     * in the file descriptor's kernel buffers gets written before
     * the close returns.
     */
    while ((flags = fcntl(handle->fd,
			  F_GETFL,
			  0)) < 0)
    {
	save_errno = errno;
	if(save_errno != EINTR)
	{
	    if(rc != GLOBUS_SUCCESS)
	    {
		err = globus_io_error_construct_internal_error(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    myname);
		
		rc = globus_error_put(err);
	    }
	    goto close_fd;
	}
    }
    
#   if defined(TARGET_ARCH_HPUX)
    {
	flags &= ~O_NONBLOCK;
    }
#   else
    {
	flags &= ~O_NDELAY;
    }
#   endif
    
    while (fcntl(handle->fd,
		 F_SETFL,
		 flags) < 0)
    {
	save_errno = errno;
	if(save_errno != EINTR)
	{
	    if(rc != GLOBUS_SUCCESS)
	    {
		err = globus_io_error_construct_internal_error(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    myname);
		
		rc = globus_error_put(err);
	    }
	    goto close_fd;
	}
    }
    
 close_fd:
    while (globus_libc_close(handle->fd) < 0)
    {
	save_errno = errno;
	if (save_errno != EINTR)
	{
	    if(rc != GLOBUS_SUCCESS)
	    {
		err = globus_io_error_construct_internal_error(
		    GLOBUS_IO_MODULE,
		    GLOBUS_NULL,
		    myname);
		
		rc = globus_error_put(err);
	    }
	    break;
	}
    }
#else
	globus_i_io_windows_close( handle );
#endif /* TARGET_ARCH_WIN32 */

    globus_i_io_debug_printf(3, (stderr, "%s(): exiting\n",myname));

    return(rc);
}
/* globus_i_io_close() */

/******************************************************************************
*******************************************************************************
				 API Functions
*******************************************************************************
******************************************************************************/

/*
 * globus_io_fd_tablesize()
 *
 * Return the file descriptor table size
 */
globus_size_t
globus_io_fd_tablesize()
{
    return(globus_l_io_fd_tablesize);
}
/* globus_io_fd_tablesize() */

/**
 * Register functions to be called when the handle is ready for
 * I/O.
 *
 * @param handle
 * I/O handle to register
 * @param read_callback_func
 * Function to be called when the handle is ready for reading
 * @param read_callback_arg
 * Parameter to be passed as the callback_arg to the read_callback_func
 * @param write_callback_func
 * Function to be called when the handle is ready for writing
 * @param read_callback_arg
 * Parameter to be passed as the callback_arg to the write_callback_func
 * @param 
 * Function to be called when an exceptional condition is ready to be
 * handled.
 * @param except_callback_arg
 * Parameter to be passed as the callback_arg to the except_callback_func
 *
 * @return
 * This function returns GLOBUS_SUCCESS if successful, or a globus_result_t
 * indicating the error that occurred. If an error occurs when
 * processing any of the callback registrations, then they all will fail.
 * @retval GLOBUS_IO_ERROR_TYPE_NULL_PARAMETER
 * The handle was GLOBUS_NULL.
 * @retval GLOBUS_IO_ERROR_TYPE_NOT_INITIALIZED
 * The handle structure was not initialized for use.
 * @retval GLOBUS_IO_ERROR_TYPE_READ_ALREADY_REGISTERED
 * A read callback is already registered with the handle.
 * @retval GLOBUS_IO_ERROR_TYPE_READ_ALREADY_REGISTERED
 * A write callback is already registered with the handle.
 * @retval GLOBUS_IO_ERROR_TYPE_READ_ALREADY_REGISTERED
 * An exception callback is already registered with the handle.
 *
 * @see globus_io_register_read(), globus_io_register_write()
 * @ingroup event
 */
#ifndef TARGET_ARCH_WIN32
globus_result_t
globus_io_register_select(
    globus_io_handle_t *		handle,
    globus_io_callback_t		read_callback_func,
    void *				read_callback_arg,
    globus_io_callback_t		write_callback_func,
    void *				write_callback_arg,
    globus_io_callback_t		except_callback_func,
    void *				except_callback_arg)
{
    globus_result_t			rc = GLOBUS_SUCCESS;
    static char *			myname="globus_io_register_select";
    
    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"handle",
		1,
		myname));
    }
    
    globus_i_io_debug_printf(3, (stderr, "%s(): entering\n",myname));

    globus_i_io_mutex_lock();

    switch(handle->state)
    {
      case GLOBUS_IO_HANDLE_STATE_INVALID:
	rc = globus_error_put(globus_io_error_construct_not_initialized(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname));
        goto error_exit;
      case GLOBUS_IO_HANDLE_STATE_CLOSING:
	rc = globus_error_put(globus_io_error_construct_close_already_registered(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    handle));
        goto error_exit;
      default:
        break;
    }
    
    if(read_callback_func)
    {
        rc = globus_i_io_register_quick_operation(
            handle,
            read_callback_func,
            read_callback_arg,
            GLOBUS_NULL,
            GLOBUS_TRUE,
            GLOBUS_I_IO_READ_OPERATION);
        if(rc != GLOBUS_SUCCESS)
        {
            goto read_failed;
        }
    }

    if(write_callback_func)
    {
        rc = globus_i_io_register_quick_operation(
            handle,
            write_callback_func,
            write_callback_arg,
            GLOBUS_NULL,
            GLOBUS_TRUE,
            GLOBUS_I_IO_WRITE_OPERATION);
        if(rc != GLOBUS_SUCCESS)
        {
            goto write_failed;
        }
    }
    
    if(except_callback_func)
    {
        rc = globus_i_io_register_quick_operation(
            handle,
            except_callback_func,
            except_callback_arg,
            GLOBUS_NULL,
            GLOBUS_TRUE,
            GLOBUS_I_IO_EXCEPT_OPERATION);
        if(rc != GLOBUS_SUCCESS)
        {
            goto except_failed;
        }
    }

    globus_i_io_mutex_unlock();
    globus_i_io_debug_printf(3, 
        (stderr, "%s(): exiting\n", myname));
        
    return GLOBUS_SUCCESS;
			 
  except_failed:
    if (write_callback_func != GLOBUS_NULL)
    {
        rc = globus_i_io_unregister_operation(
            handle, GLOBUS_TRUE, GLOBUS_I_IO_WRITE_OPERATION);
        globus_assert(rc == GLOBUS_SUCCESS);
    }
  write_failed:
    if (read_callback_func != GLOBUS_NULL)
    {
        rc = globus_i_io_unregister_operation(
            handle, GLOBUS_TRUE, GLOBUS_I_IO_READ_OPERATION);
        globus_assert(rc == GLOBUS_SUCCESS);
    }
  read_failed:
  error_exit:
    globus_i_io_mutex_unlock();
    globus_i_io_debug_printf(3, 
        (stderr, "%s(): exiting with error\n", myname));

    return rc;
}
#endif /* TARGET_ARCH_WIN32 */
/* globus_io_register_select() */

/* the entire globus io cancel method has been completely complicated by the
 * new 'register all callbacks' method of firing user callbacks.
 *
 * an operation can be canceled in one of 4 places...
 * 1 - before a callback is ever registered
 * 2 - after the callback is registered but before the kickout callback is 
 *     fired (globus_callback_unregister active == false)
 * 3 - after the kickout callback is fired, but before user callback is called
 * 4 - after user callback is called
 *
 * this entire file really should just be re-written before ever trying to
 * understand it
 * JL
 */
void
globus_i_io_register_cancel(
    globus_io_handle_t *                handle,
    globus_bool_t                       perform_callbacks,
    globus_io_callback_t                cancel_callback,
    void *                              cancel_arg,
    globus_io_destructor_t              cancel_destructor)
{
    globus_io_select_info_t *           select_info;
    globus_io_cancel_info_t *           cancel_info = GLOBUS_NULL;
    globus_io_operation_info_t *        operation_info;
    globus_bool_t                       active;
    
    globus_l_io_table_add(handle);

    select_info = globus_l_io_fd_table[handle->fd];
    
    if(cancel_callback || perform_callbacks)
    {
    /* create data structure to be used in the next poll to perform
     * the callbacks
     */
        if(globus_l_io_cancel_free_list)
        {
            cancel_info = globus_l_io_cancel_free_list;
            
            globus_l_io_cancel_free_list = globus_l_io_cancel_free_list->next;
        }
        else
        {
            cancel_info = globus_malloc(sizeof(globus_io_cancel_info_t));
        }
        memset(cancel_info, '\0', sizeof(globus_io_cancel_info_t));
    }
    
    operation_info = select_info->read;
    if(operation_info && operation_info->op == GLOBUS_I_IO_READ_OPERATION)
    { 
        if(operation_info->callback)
        {
            if(globus_l_io_read_isregistered(handle))
            {
                /* 1 */
                globus_i_io_unregister_operation(
                    handle,
                    GLOBUS_FALSE,
                    GLOBUS_I_IO_READ_OPERATION);
                
                operation_info->refs--;
            }
            else
            {
                /* cancel pending callback */
                globus_callback_unregister(
                    operation_info->callback_handle,
                    GLOBUS_NULL,
                    GLOBUS_NULL,
                    &active);
                
                if(!active)
                {
                    /* 2 */
                    operation_info->refs--;
                    globus_l_io_pending_count--;
                }
                /* else */
                /* 3 */
            }
            
            if(perform_callbacks)
            {
                cancel_info->read = operation_info;
                operation_info->refs++;
            }
            else
            {
                if(operation_info->arg_destructor && operation_info->arg)
                {
                    operation_info->arg_destructor(operation_info->arg);
                }
            }
        
            if(operation_info->refs == 0)
            {
                globus_i_io_end_operation(
                    handle, GLOBUS_I_IO_READ_OPERATION);
            }
        }
        /* else */
        /* 4 */
        
        operation_info->canceled = GLOBUS_TRUE;
    }
    
    operation_info = select_info->write;
    if(operation_info && operation_info->op == GLOBUS_I_IO_WRITE_OPERATION)
    { 
        if(operation_info->callback)
        {
            if(globus_l_io_write_isregistered(handle))
            {
                /* 1 */
                globus_i_io_unregister_operation(
                    handle,
                    GLOBUS_FALSE,
                    GLOBUS_I_IO_WRITE_OPERATION);
                
                operation_info->refs--;
            }
            else
            {
                /* cancel pending callback */
                globus_callback_unregister(
                    operation_info->callback_handle,
                    GLOBUS_NULL,
                    GLOBUS_NULL,
                    &active);
                
                if(!active)
                {
                    /* 2 */
                    operation_info->refs--;
                    globus_l_io_pending_count--;
                }
                /* else */
                /* 3 */
            }
            
            if(perform_callbacks)
            {
                cancel_info->write = operation_info;
                operation_info->refs++;
            }
            else
            {
                if(operation_info->arg_destructor && operation_info->arg)
                {
                    operation_info->arg_destructor(operation_info->arg);
                }
            }
            
            if(operation_info->refs == 0)
            {
                globus_i_io_end_operation(
                    handle, GLOBUS_I_IO_WRITE_OPERATION);
            }
        }
        /* else */
        /* 4 */
        
        operation_info->canceled = GLOBUS_TRUE;
    }
    
    operation_info = select_info->except;
    if(operation_info && operation_info->op == GLOBUS_I_IO_EXCEPT_OPERATION)
    { 
        if(operation_info->callback)
        {
            if(globus_l_io_except_isregistered(handle))
            {
                /* 1 */
                globus_i_io_unregister_operation(
                    handle,
                    GLOBUS_FALSE,
                    GLOBUS_I_IO_EXCEPT_OPERATION);
                
                operation_info->refs--;
            }
            else
            {
                /* cancel pending callback */
                globus_callback_unregister(
                    operation_info->callback_handle,
                    GLOBUS_NULL,
                    GLOBUS_NULL,
                    &active);
                
                if(!active)
                {
                    /* 2 */
                    operation_info->refs--;
                    globus_l_io_pending_count--;
                }
                /* else */
                /* 3 */
            }
            
            if(perform_callbacks)
            {
                cancel_info->except = operation_info;
                operation_info->refs++;
            }
            else
            {
                if(operation_info->arg_destructor && operation_info->arg)
                {
                    operation_info->arg_destructor(operation_info->arg);
                }
            }
            
            if(operation_info->refs == 0)
            {
                globus_i_io_end_operation(
                    handle, GLOBUS_I_IO_EXCEPT_OPERATION);
            }
        }
        /* else */
        /* 4 */
        
        operation_info->canceled = GLOBUS_TRUE;
    }
    
    select_info->read = GLOBUS_NULL;
    select_info->write = GLOBUS_NULL;
    select_info->except = GLOBUS_NULL;
    
    /* if we are performing any callbacks, add ourselves to the list */
    if(cancel_info)
    {
        cancel_info->handle = handle;
        cancel_info->callback_handle = GLOBUS_NULL_HANDLE;
        cancel_info->callback = cancel_callback;
        cancel_info->arg = cancel_arg;
        cancel_info->arg_destructor = cancel_destructor;
        
        globus_l_io_enqueue(
            globus_l_io_cancel_list,
            globus_l_io_cancel_tail,
            cancel_info);
    }

    /* wake up select loop
     */
    globus_l_io_select_wakeup();
}

/**
 * Cancel all Globus I/O operations for a handle.
 * @ingroup globus_io_common
 */
globus_result_t
globus_io_register_cancel(
    globus_io_handle_t *		handle,
    globus_bool_t			perform_callbacks,
    globus_io_callback_t		cancel_callback,
    void *				cancel_arg)
{
    globus_object_t *			err;
    static char *			myname="globus_io_register_cancel";

    globus_i_io_debug_printf(3, (stderr, "%s(): entering\n", myname));

    if(handle == GLOBUS_NULL)
    {
	return globus_error_put(
	    globus_io_error_construct_null_parameter(
		GLOBUS_IO_MODULE,
		GLOBUS_NULL,
		"handle",
		1,
		myname));
    }
    
    globus_i_io_mutex_lock();
    switch(handle->state)
    {
      case GLOBUS_IO_HANDLE_STATE_INVALID:
	err = globus_io_error_construct_not_initialized(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    "handle",
	    1,
	    myname);
	goto error_exit;
      case GLOBUS_IO_HANDLE_STATE_CLOSING:
	err = globus_io_error_construct_close_already_registered(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    handle);
	
	goto error_exit;
      default:
        break;
    }

    globus_i_io_register_cancel(handle,
				perform_callbacks,
				cancel_callback,
				cancel_arg,
				GLOBUS_NULL);
    
    globus_i_io_mutex_unlock();
    globus_i_io_debug_printf(3,
        (stderr, "globus_io_register_cancel(): exiting\n"));
    
    return(GLOBUS_SUCCESS);

  error_exit:
    globus_i_io_mutex_unlock();
    return globus_error_put(err);
}
/* globus_io_register_cancel() */

static
void
globus_l_io_kickout_cb(
    void *                              user_args)
{
    globus_io_operation_info_t *        operation_info;
    globus_io_callback_t                callback;
    globus_io_handle_t *                handle;
    
    operation_info = (globus_io_operation_info_t *) user_args;
    
    handle = operation_info->handle;
    
    globus_i_io_debug_printf(6, (stderr, 
        "globus_l_io_kickout_cb(): entering, fd=%d\n", handle->fd));
        
    /* see if I was canceled */
    globus_i_io_mutex_lock();
    {
        operation_info->refs--;
        
        if(!operation_info->canceled && !globus_l_io_shutdown_called)
        {
            globus_callback_unregister(
                operation_info->callback_handle,
                GLOBUS_NULL,
                GLOBUS_NULL,
                GLOBUS_NULL);
            
            callback = operation_info->callback;
            
            operation_info->callback = GLOBUS_NULL;
            operation_info->arg_destructor = GLOBUS_NULL;
        }
        else
        {
            if(operation_info->canceled && operation_info->refs == 0)
            {
                globus_i_io_end_operation(handle, operation_info->op);
            }
            
            /* someone canceled me */
            goto exit;
        }
    }
    globus_i_io_mutex_unlock();

#ifndef TARGET_ARCH_WIN32
    callback(operation_info->arg, handle, GLOBUS_SUCCESS);
#else
	callback(operation_info->arg, handle, operation_info->result);
#endif

    globus_i_io_mutex_lock();
    {
exit:
        globus_i_io_debug_printf(6, (stderr, 
            "globus_l_io_kickout_cb(): exiting, fd=%d\n", 
            handle->fd));
    
        globus_l_io_pending_count--;
        if(globus_l_io_shutdown_called && globus_l_io_pending_count == 0)
        {
            globus_l_io_cond_signal();
        }
    }
    globus_i_io_mutex_unlock();
}

static
void
globus_l_io_kickout_cancel_cb(
    void *                              user_args)
{
    globus_io_cancel_info_t *           cancel_info;
    globus_object_t *                   err;
    globus_io_handle_t *                handle;
    globus_io_operation_info_t *        read_operation_info;
    globus_io_operation_info_t *        write_operation_info;
    globus_io_operation_info_t *        except_operation_info;
    globus_bool_t                       clean_up;
    globus_callback_space_t             space;
    globus_result_t                     result;
    
    cancel_info = (globus_io_cancel_info_t *) user_args;

    globus_i_io_mutex_lock();
    {
        globus_io_cancel_info_t **          ci;
        
        if(globus_l_io_shutdown_called)
        {
            goto exit;
        }
        
        handle = cancel_info->handle;
        
        globus_i_io_debug_printf(6, (stderr, 
            "globus_l_io_kickout_cancel_cb(): entering, fd=%d\n", handle->fd));

        globus_callback_unregister(
            cancel_info->callback_handle,
            GLOBUS_NULL,
            GLOBUS_NULL,
            GLOBUS_NULL);
        
        /* need to see if a two phase cancel is going to be necessary */
        clean_up = GLOBUS_TRUE;
        globus_callback_space_get(&space);
        
        /* if this were a blocking cancel, the first phase callback would be
         * registered to global space regardless of user's space
         */
        if(space != handle->socket_attr.space)
        {
            read_operation_info = GLOBUS_NULL;
            write_operation_info = GLOBUS_NULL;
            except_operation_info = GLOBUS_NULL;
            
            if(cancel_info->read)
            {
                /* blocking calls are registered to global space too */
                if(handle->blocking_read)
                {
                    read_operation_info = cancel_info->read;
                    
                    cancel_info->read = GLOBUS_NULL;
                }
                else
                {
                    clean_up = GLOBUS_FALSE;
                }
            }
            
            if(cancel_info->write)
            {
                if(handle->blocking_write)
                {
                    write_operation_info = cancel_info->write;
                    
                    cancel_info->write = GLOBUS_NULL;
                }
                else
                {
                    clean_up = GLOBUS_FALSE;
                }
            }
            
            if(cancel_info->except)
            {
                if(handle->blocking_except)
                {
                    except_operation_info = cancel_info->except;
                    
                    cancel_info->except = GLOBUS_NULL;
                }
                else
                {
                    clean_up = GLOBUS_FALSE;
                }
            }
            
            /* since the cancel callback might call the internal close callback
             * I need to save a ref to the space for the two phase cancel
             */
            if(!clean_up)
            {
                space = handle->socket_attr.space;
                globus_callback_space_reference(space);
            }
        }
        else
        {
            read_operation_info = cancel_info->read;
            write_operation_info = cancel_info->write;
            except_operation_info = cancel_info->except;
        }
        
        /* remove from pending list */
        ci = &globus_l_io_cancel_pending_list;
        while(*ci && *ci != cancel_info)
        {
            ci = &(*ci)->next;
        }
        
        if(*ci)
        {
            *ci = (*ci)->next;
        }
    }
    globus_i_io_mutex_unlock();
    
    if(read_operation_info)
    {
        globus_i_io_debug_printf(6, (stderr, 
            "globus_l_io_kickout_cancel_cb(): cancel read, fd=%d\n",
            handle->fd));

        err = globus_io_error_construct_io_cancelled(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle);

        read_operation_info->callback(
            read_operation_info->arg,
            handle,
            globus_error_put(err));
    }
    
    if(write_operation_info)
    {
        globus_i_io_debug_printf(6, (stderr, 
            "globus_l_io_kickout_cancel_cb(): cancel write, fd=%d\n",
            handle->fd));

        err = globus_io_error_construct_io_cancelled(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle);

        write_operation_info->callback(
            write_operation_info->arg,
            handle,
            globus_error_put(err));
    }
    
    if(except_operation_info)
    {
        globus_i_io_debug_printf(6, (stderr, 
            "globus_l_io_kickout_cancel_cb(): cancel except, fd=%d\n",
            handle->fd));

        err = globus_io_error_construct_io_cancelled(
            GLOBUS_IO_MODULE,
            GLOBUS_NULL,
            handle);

        except_operation_info->callback(
            except_operation_info->arg,
            handle,
            globus_error_put(err));
    }
    
    if(cancel_info->callback)
    {
        globus_i_io_debug_printf(6, (stderr, 
            "globus_l_io_kickout_cancel_cb(): cancel kickout, fd=%d\n",
            handle->fd));

        cancel_info->callback(
            cancel_info->arg,
            handle,
            GLOBUS_SUCCESS);
        
        cancel_info->callback = GLOBUS_NULL;
    }
    
    /* push cancel info */
    globus_i_io_mutex_lock();
    {
        if(clean_up)
        {
            cancel_info->next = globus_l_io_cancel_free_list;
            globus_l_io_cancel_free_list = cancel_info;
        }
        else if(!globus_l_io_shutdown_called)
        {
            /* need to register for second phase of this cancel... this will
             * provide callbacks to reads/writes registered to a user's space
             */
            cancel_info->next = globus_l_io_cancel_pending_list;
            globus_l_io_cancel_pending_list = cancel_info;
            
            globus_l_io_pending_count++;
            
            result = globus_callback_space_register_oneshot(
                &cancel_info->callback_handle,
                GLOBUS_NULL,
                globus_l_io_kickout_cancel_cb,
                cancel_info,
                handle->socket_attr.space);
            globus_assert(result == GLOBUS_SUCCESS);
        }
        else
        {
            /* we're shutting down, put this on cancel list so destructors can
             * be called
             */
            cancel_info->next = globus_l_io_cancel_list;
            globus_l_io_cancel_list = cancel_info;
        }
        
        /* destroy the extra reference now */
        if(!clean_up)
        {
            globus_callback_space_destroy(space);
        }
        
        globus_i_io_debug_printf(6, (stderr, 
            "globus_l_io_kickout_cancel_cb(): exiting, fd=%d\n", handle->fd));
exit:
        globus_l_io_pending_count--;
        if(globus_l_io_shutdown_called && globus_l_io_pending_count == 0)
        {
            globus_l_io_cond_signal();
        }
    }
    globus_i_io_mutex_unlock();
}

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * Main Globus I/O event driver.
 *
 * This function dispatches any pending events on the handles registered
 * with Globus I/O, or which are in the queue to cancel.
 *
 * This function first dispatches callbacks associated with cancelled
 * events or reads which are already satisfied by buffered data. These
 * should be moved to oneshot callbacks, but first we need to add a way
 * to make sure that the callbacks are completed, in order to have a 
 * clean shutdown happen. If any events are dispatched because of this,
 * the select timeout is set to 0 to make sure that we don't unneccessarily
 * block when the user's code could otherwise make progress.
 *
 * After the non-select callbacks are dispatched, this functions polls
 * the file descriptors by calling select(). If a fully blocking, or timed
 * select is done, then the FD mutex is unlocked during the select. In
 * a multi-threaded environment, the FD mask could change here; if that
 * happens we immediately retry the select.
 *
 * Once we have a valid select, we dispatch any callbacks which are
 * in the active and registered FD masks. We check both because
 * we modify the registered FD mask by unregistering FDs before we
 * do the callbacks, and the user can also modify the FD mask in his
 * callback.
 *
 * This code is called as a periodic callback function. It handles
 * thread restarts triggered by I/O callbacks; otherwise, the code
 * is not reentrant. 
 *
 * @return This function returns GLOBUS_TRUE if any events were handled;
 * otherwise it returns GLOBUS_FALSE.
 *
 * @see globus_l_io_callback_poll()
 */
static
int
globus_l_io_handle_events(
    globus_reltime_t *                  time_left)
{
    globus_bool_t                       done;
    int                                 n_ready;
    int                                 n_checked;
    globus_io_handle_t *                handle;
    int                                 select_errno;
    globus_io_select_info_t *           select_info;
    globus_io_operation_info_t *        operation_info;
    static char *                       myname="globus_l_io_handle_events";
    globus_bool_t                       use_timeout;
    int                                 n_fdcopy;
    globus_bool_t                       time_left_is_zero;
    globus_bool_t                       handled_something = GLOBUS_FALSE;
    int                                 select_highest_fd;
    globus_result_t                     result;
#ifdef TARGET_ARCH_WIN32
	int rc;
	DWORD numberOfBytes;
	OVERLAPPED * overlappedPtr;
	WinIoOperation * winIoOperationPtr; // for the io operation object returned by GetQueuedCompletionStatus()
	DWORD winTimeout;
	globus_object_t * err;
#endif
    
    globus_i_io_debug_printf(5,
        (stderr, "%s(): entering\n", myname));

#ifdef TARGET_ARCH_WIN32
	// TESTING!!!
	n_ready= -1; // because of the Runtime checks
	// END TESTING
#endif

    done = GLOBUS_FALSE;
    while(!done && !globus_l_io_shutdown_called)
    {
        if(globus_reltime_cmp(time_left, &globus_i_reltime_zero) == 0)
        {
            time_left_is_zero = GLOBUS_TRUE;
        }
        else
        {
            time_left_is_zero = GLOBUS_FALSE;
        }
        
        /* Handle any cancel or secure read callbacks right away.
         * They do not need to block on the select but will 
         * kick out events.
         */
        while(!globus_list_empty(globus_l_io_operations))
        {
            operation_info = (globus_io_operation_info_t *)
                globus_list_first(globus_l_io_operations);
            
            handle = operation_info->handle;
            
            globus_i_io_debug_printf(5,
                (stderr, "%s(): non-selecting read, fd=%d\n",
                    myname, handle->fd));
                       
            /* this removes operation_info from globus_l_io_operations */
            result = globus_i_io_unregister_operation(
                handle, GLOBUS_FALSE, operation_info->op);
            globus_assert(result == GLOBUS_SUCCESS);
            
            globus_l_io_pending_count++;
            
#ifdef TARGET_ARCH_WIN32
	    operation_info->result= GLOBUS_SUCCESS;
#endif
            result = globus_callback_space_register_oneshot(
                &operation_info->callback_handle,
                GLOBUS_NULL,
                globus_l_io_kickout_cb,
                operation_info,
                handle->blocking_read
                    ? GLOBUS_CALLBACK_GLOBAL_SPACE
                    : handle->socket_attr.space);
            globus_assert(result == GLOBUS_SUCCESS);
            
            /* We've handled an event, so we don't need to
             * block in the select
             */
            if(!time_left_is_zero)
            {
                GlobusTimeReltimeCopy(*time_left, globus_i_reltime_zero);
                time_left_is_zero = GLOBUS_TRUE;
            }
            handled_something = GLOBUS_TRUE;
        }
        
        while(globus_l_io_cancel_list)
        {
            globus_io_cancel_info_t *   cancel_info;
    
            cancel_info = globus_l_io_cancel_list;
            globus_l_io_dequeue(
                globus_l_io_cancel_list,
                globus_l_io_cancel_tail,
                cancel_info);
                
            cancel_info->next = globus_l_io_cancel_pending_list;
            globus_l_io_cancel_pending_list = cancel_info;
            
            globus_l_io_pending_count++;
            
            result = globus_callback_space_register_oneshot(
                &cancel_info->callback_handle,
                GLOBUS_NULL,
                globus_l_io_kickout_cancel_cb,
                cancel_info,
                cancel_info->handle->blocking_cancel
                    ? GLOBUS_CALLBACK_GLOBAL_SPACE
                    : cancel_info->handle->socket_attr.space);
            globus_assert(result == GLOBUS_SUCCESS);
        
            if(!time_left_is_zero)
            {
                GlobusTimeReltimeCopy(*time_left, globus_i_reltime_zero);
                time_left_is_zero = GLOBUS_TRUE;
            }
            handled_something = GLOBUS_TRUE;
        }
    
		/* NOTE: While it seems like a sensible course of action to
		 * bail out of this function if there are no I/O operations to
		 * wait for, we cannot do so on Windows in a multi-threaded
		 * build. If we bail now, globus_l_io_poll() still holds the 
		 * mutex. Because nothing has been handled, globus_l_io_poll() 
		 * will again call globus_l_io_handle_events() even though it 
		 * would not be possible for any operations to have been 
		 * registered. Consequently, we will end up in a continual 
		 * loop until the timeout has expired, which might be a very 
		 * long time. The reason that this race condition has not been 
		 * encountered on the POSIX side is because of the wakeup pipe 
		 * that is used to force select to return. In order to use the 
		 * pipe, a read operation on the pipe must be registered at all
		 * times. Consequently, there will always be an I/O handle to 
		 * select on and globus_l_io_fd_num_set will always be > 0. 
		 * Because we do not use the wakeup pipe in Windows, it is 
		 * possible for globus_l_io_fd_num_set to be 0, which at times 
		 * will allow this race condition to have effect.
		 */
#ifndef TARGET_ARCH_WIN32
        if (globus_l_io_fd_num_set <= 0)
        {
            done = GLOBUS_TRUE;
            continue;
        }
#endif

        /*
         * round the highest fd to the nearest 64 bits, since we
         * do not know where in the struct it will be located
         * because of endian differences
         */
        globus_l_io_fd_table_modified = GLOBUS_FALSE;
        
#ifndef TARGET_ARCH_WIN32
        n_fdcopy = (globus_l_io_highest_fd+63)/8;
        memcpy(globus_l_io_active_read_fds, globus_l_io_read_fds, n_fdcopy);
        memcpy(globus_l_io_active_write_fds, globus_l_io_write_fds, n_fdcopy);
        memcpy(globus_l_io_active_except_fds, globus_l_io_except_fds, n_fdcopy);
#endif /* TARGET_ARCH_WIN32 */

#ifndef TARGET_ARCH_WIN32
#       if !defined(HAVE_THREAD_SAFE_SELECT)
        {
            if(!time_left_is_zero)
            {
                GlobusTimeReltimeCopy(*time_left, globus_i_reltime_zero);
                time_left_is_zero = GLOBUS_TRUE;
            }
        }
#       endif
#endif
    
        if(globus_time_reltime_is_infinity(time_left))
        {
            use_timeout = GLOBUS_FALSE;
        }   
        else
        {
            use_timeout = GLOBUS_TRUE;
        }
#ifdef TARGET_ARCH_WIN32
		if ( time_left_is_zero )
		{
			winTimeout= 0;
		}
		else if ( use_timeout )
		{
			GlobusTimeReltimeToMilliSec( winTimeout, *time_left );
		}
		else
			winTimeout= INFINITE;
#endif
        
        /*
         * If we were using a timeout on select() then we must release the
         * FD mutex so that other threads can do some work
         */
        select_highest_fd = globus_l_io_highest_fd;
        if(!time_left_is_zero)
        {
            globus_l_io_select_active = GLOBUS_TRUE;
            globus_i_io_mutex_unlock();
        }
        
#ifndef TARGET_ARCH_WIN32
        globus_i_io_debug_printf(5,
            (stderr, "%s(): Calling select()\n",myname));
        n_ready = select(select_highest_fd + 1,
                 NEXUS_FD_SET_CAST globus_l_io_active_read_fds,
                 NEXUS_FD_SET_CAST globus_l_io_active_write_fds,
                 NEXUS_FD_SET_CAST globus_l_io_active_except_fds,
                 (use_timeout ? time_left : GLOBUS_NULL));
#else
		globus_i_io_debug_printf(1,("%s(): Calling GetQueuedCompletionStatus()\n",myname));
		//errno= 0; // reset state just to make sure
		// the completion key will be the globus I/O handle
		// TESTING!!!
		//fprintf( stderr, "winTimeout is %lu\n", winTimeout );
		// END TESTING
		rc= GetQueuedCompletionStatus( completionPort, &numberOfBytes,
		 (PULONG_PTR)&handle, &overlappedPtr, winTimeout );
#endif
        select_errno = errno;
        globus_i_io_debug_printf(5,
            (stderr, "%s(): select() returned\n",myname));
    
        /*
         * If we were using a timeout on select() then we must reacquire the
         * FD mutex and verify that our state hasn't changed
         */
        if(!time_left_is_zero)
        {
            globus_i_io_mutex_lock();
            globus_l_io_select_active = GLOBUS_FALSE;
                
            /*
             * Increase the select() counter and signal any waiting threads
             * that the current select has completed.  The select() counter is
             * used by routines like globus_i_io_close() to determine when it's
             * file descriptor has been removed from the select list.
             */
            globus_l_io_select_count++;
            globus_l_io_cond_broadcast();
    
            /*
             * If the FD table has been modified in a way which invalidates the
             * information returned by select(), then reset the modification
             * flag and retry the select()
             */
            if(globus_l_io_fd_table_modified)
            {
                globus_l_io_fd_table_modified = GLOBUS_FALSE;
                globus_callback_get_timeout(time_left);
				/* We must NOT throw away the completion packet in
					Windows */
#ifndef TARGET_ARCH_WIN32			
				continue;
#endif
            }
    
            /*
             * If shutdown has been called, then just bail out, ignoring any
             * pending communication requests
             */
            if(globus_l_io_shutdown_called)
            {
                break;
            }
        }
            
                        
#ifndef TARGET_ARCH_WIN32 /* no pipe for Windows */
        if(n_ready < 0)
        {
            if(select_errno == EINTR)
            {
                globus_callback_get_timeout(time_left);
                continue;
            }
            else
            {
                goto handle_abort;
            }
        }

        /* see if we were woken up by pipe 
         * this needs to happen immediately and cant be 'registered' like
         * the rest of the callbacks
         */
        if(n_ready > 0 && FD_ISSET(
            globus_l_io_wakeup_pipe_handle.fd, globus_l_io_active_read_fds))
        {
            FD_CLR(
                globus_l_io_wakeup_pipe_handle.fd,
                globus_l_io_active_read_fds);
        
            globus_l_io_wakeup_pipe_callback(
                GLOBUS_NULL,
                &globus_l_io_wakeup_pipe_handle,
                GLOBUS_SUCCESS);
            
            n_ready--;
        }
#endif

#ifdef TARGET_ARCH_WIN32
		n_ready= 1; // presume we got a completion packet back
		if ( overlappedPtr == NULL ) 
		{
			// no completion packet was dequeued; either the call
			// timed out or something went horribly wrong
			int lastError= globus_i_io_windows_get_last_error();
			if ( lastError != WAIT_TIMEOUT )
				goto handle_abort;
			// TESTING!!!
			//if ( count > countMax )
				//fprintf( stderr, "GetQueuedCompletionStatus() timed out; winTimeout is %d\n", winTimeout );
			// END TESTING
			n_ready= 0;	// dispel the presumption
		}
		else if ( rc == 0 ) // an error occurred in the I/O operation
		{
			int error;
			error= globus_i_io_windows_get_last_error();
			if ( errno == GLOBUS_WIN_EOF )
			{
				err = globus_io_error_construct_eof(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle);
			}
			else
				err= globus_io_error_construct_system_failure(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle,
						errno );
			result= globus_error_put(err);
		}
		else
			result= GLOBUS_SUCCESS;

		if ( n_ready )
		{
			handled_something = GLOBUS_TRUE;

			// retrieve the I/O operation struct
			// NOTE: Although the I/O operation struct is a member of
			// the handle, we will use the following code to retrieve
			// it for purposes of memorializing the alternative method.
			// If we eventually separate the I/O operation struct from
			// the handle, such as because we decide to associate 
			// multiple I/O operations with a single handle, then we
			// have the necessary code available.
			winIoOperationPtr= CONTAINING_RECORD( overlappedPtr, 
				WinIoOperation, overlapped );
			switch( winIoOperationPtr->state )
			{
				case WinIoListening: // this is really checking whether
									 // a listening socket has an
									 // incoming connection request
					// TESTING!!!
					//fprintf( stderr, "state is WinIoListening\n" );
					// END TESTING
					// first, check whether we're still interested in
					// this socket operation
					if ( !FD_ISSET( handle->io_handle, 
					 globus_l_io_read_fds ) )
						break;
					globus_i_io_debug_printf(5,
						(stderr, "%s(): listen, fd=%d\n", myname, handle->fd));
					// check whether a connection request is
					// pending by checking the readability of
					// this socket
					rc= globus_i_io_winsock_socket_is_readable( 
						(SOCKET)handle->io_handle, 500 );
                    select_info = globus_l_io_fd_table[handle->fd];
                    operation_info = select_info->read;
					if ( rc == 0 ) // success- socket is readable
					{
						// register the callback                                                
						operation_info->result= GLOBUS_SUCCESS;

                        result = globus_i_io_unregister_operation(
                            handle, GLOBUS_FALSE, GLOBUS_I_IO_READ_OPERATION);
                        globus_assert(result == GLOBUS_SUCCESS);
                                               
                        result = globus_callback_space_register_oneshot(
                            &operation_info->callback_handle,
                            GLOBUS_NULL,
                            globus_l_io_kickout_cb,
                            operation_info,
                            handle->blocking_read
                                ? GLOBUS_CALLBACK_GLOBAL_SPACE
                                : handle->socket_attr.space);
                        globus_assert(result == GLOBUS_SUCCESS);
						
						globus_l_io_pending_count++;
					}
					else if ( rc == WSAETIMEDOUT )
					{
						// repost a packet
						int rc= globus_i_io_windows_post_completion( 
									handle, 
									WinIoListening );
						if ( rc ) // a fatal error occurred
						{
							// unregister the read operation
							result = globus_i_io_unregister_operation(
								handle, GLOBUS_FALSE, GLOBUS_I_IO_READ_OPERATION);
							globus_assert(result == GLOBUS_SUCCESS);

							err = globus_io_error_construct_system_failure(
									GLOBUS_IO_MODULE,
									GLOBUS_NULL,
									handle,
									rc );
							result= globus_error_put(err);

							operation_info->result= result;

							result = globus_callback_space_register_oneshot(
								&operation_info->callback_handle,
								GLOBUS_NULL,
								globus_l_io_kickout_cb,
								operation_info,
								handle->blocking_read
									? GLOBUS_CALLBACK_GLOBAL_SPACE
									: handle->socket_attr.space);
							globus_assert(result == GLOBUS_SUCCESS);
							
							globus_l_io_pending_count++;
						}
						// if there are no other operations pending,
						// reset the n_ready flag so that the loop ends
						fprintf( stderr, 
						 "listening socket is not readable, globus_l_io_fd_num_set is %d\n", 
						 globus_l_io_fd_num_set );
						
						//if ( globus_l_io_fd_num_set == 1 )
							//n_ready= 0;
					}
					else // a fatal error occurred
					{
						// unregister the read operation
						result = globus_i_io_unregister_operation(
							handle, GLOBUS_FALSE, GLOBUS_I_IO_READ_OPERATION);
						globus_assert(result == GLOBUS_SUCCESS);

						err = globus_io_error_construct_system_failure(
								GLOBUS_IO_MODULE,
								GLOBUS_NULL,
								handle,
								rc );
						result= globus_error_put(err);

						operation_info->result= result;

						result = globus_callback_space_register_oneshot(
							&operation_info->callback_handle,
							GLOBUS_NULL,
							globus_l_io_kickout_cb,
							operation_info,
							handle->blocking_read
								? GLOBUS_CALLBACK_GLOBAL_SPACE
								: handle->socket_attr.space);
						globus_assert(result == GLOBUS_SUCCESS);
						
						globus_l_io_pending_count++;
					}
					break;
				case WinIoConnecting:
					// TESTING!!!
					//fprintf( stderr, "state is WinIoConnecting\n" );
					// END TESTING
					// this operation must trigger a callback registered
					// as a write operation
					if ( !FD_ISSET( handle->io_handle, 
					 globus_l_io_write_fds ) )
						break; // we don't care about this handle any longer
                    globus_i_io_debug_printf(5,
                        (stderr, "%s(): connect, fd=%d\n", myname, handle->fd));

                    select_info = globus_l_io_fd_table[handle->fd];
                    operation_info = select_info->write;
                                                       
					// WARNING: This state currently assumes that the
					// call to connect() blocks and therefore this
					// point in the code will not be reached unless the
					// call to connect() succeeds. When the attempt to
					// connect is made asynchronous, this assumption 
					// will no longer be true and the actual state of
					// the socket must be checked
					operation_info->result= GLOBUS_SUCCESS;

                    result = globus_i_io_unregister_operation(
                        handle, GLOBUS_FALSE, GLOBUS_I_IO_WRITE_OPERATION);
                    globus_assert(result == GLOBUS_SUCCESS);
                    
                    result = globus_callback_space_register_oneshot(
                        &operation_info->callback_handle,
                        GLOBUS_NULL,
                        globus_l_io_kickout_cb,
                        operation_info,
                        handle->blocking_write
                            ? GLOBUS_CALLBACK_GLOBAL_SPACE
                            : handle->socket_attr.space);
                    globus_assert(result == GLOBUS_SUCCESS);

                    globus_l_io_pending_count++;
					break;
				case WinIoAccepting:
					// TESTING!!!
					//fprintf( stderr, "****state is WinIoAccepting\n" );
					// END TESTING
					/* WARNING: The callback was registered in 
					 *  globus_io_tcp_register_accept()
					 *	as a write operation, so we must use the
					 *	appropriate callback according to the "write"
					 *  blocking attribute. (Sorry, no pun intended)
					 */
					if ( !FD_ISSET( handle->io_handle, 
					 globus_l_io_read_fds ) )
						break; // we don't care about this handle any longer
                    globus_i_io_debug_printf(5,
                        (stderr, "%s(): accept, fd=%d\n", myname, handle->fd));

					select_info = globus_l_io_fd_table[handle->fd];
                    operation_info = select_info->read;
                                                       
					operation_info->result= result;

                    result = globus_i_io_unregister_operation(
                        handle, GLOBUS_FALSE, GLOBUS_I_IO_READ_OPERATION);
                    globus_assert(result == GLOBUS_SUCCESS);
                    
                    result = globus_callback_space_register_oneshot(
                        &operation_info->callback_handle,
                        GLOBUS_NULL,
                        globus_l_io_kickout_cb,
                        operation_info,
                        handle->blocking_read
                            ? GLOBUS_CALLBACK_GLOBAL_SPACE
                            : handle->socket_attr.space);
                    globus_assert(result == GLOBUS_SUCCESS);

                    globus_l_io_pending_count++;
					break;
				case WinIoReading:
					// TESTING!!!
					//fprintf( stderr, "state is WinIoReading\n" );
					/*
					if ( result == GLOBUS_SUCCESS &&
					 handle->winIoOperation_read.operationAttempted == 1 )
						fprintf( stderr, "Read completed; number of bytes read is %d\n", numberOfBytes );
					else
						fprintf( stderr, "fake read completed\n" );
					//*/
					// END TESTING
					if ( !FD_ISSET( handle->io_handle, 
					 globus_l_io_read_fds ) )
						break; // we don't care about this handle any longer
                    globus_i_io_debug_printf(5,
                        (stderr, "%s(): read, fd=%d\n", myname, handle->fd));                    
					// check for the EOF condition (which indicates a
					// graceful close by the other side in the case of
					// a socket); we need to make sure that an actual
					// I/O operation was attempted, otherwise this
					// completion packet is the result of a call to
					// PostQueuedCompletionStatus(). NOTE: In the case
					// of a file handle, we may receive a zero byte
					// read. This result does *NOT* indicate EOF, so
					// it must be treated an as ordinary read.
					if ( result == GLOBUS_SUCCESS && numberOfBytes == 0 
						&& handle->winIoOperation_read.operationAttempted 
						== 1 && handle->type != 
						GLOBUS_IO_HANDLE_TYPE_FILE )
					{
						err = globus_io_error_construct_eof(
								GLOBUS_IO_MODULE,
								GLOBUS_NULL,
								handle);
						result= globus_error_put(err);
					}
					if ( result == GLOBUS_SUCCESS )
						handle->winIoOperation_read.numberOfBytesProcessed= 
						 numberOfBytes;
					select_info = globus_l_io_fd_table[handle->fd];
                    operation_info = select_info->read;
                    
					operation_info->result= result;

                    result = globus_i_io_unregister_operation(
                        handle, GLOBUS_FALSE, GLOBUS_I_IO_READ_OPERATION);
                    globus_assert(result == GLOBUS_SUCCESS);
                                               
                    result = globus_callback_space_register_oneshot(
                        &operation_info->callback_handle,
                        GLOBUS_NULL,
                        globus_l_io_kickout_cb,
                        operation_info,
                        handle->blocking_read
                            ? GLOBUS_CALLBACK_GLOBAL_SPACE
                            : handle->socket_attr.space);
                    globus_assert(result == GLOBUS_SUCCESS);
					
					globus_l_io_pending_count++;
					break;
				case WinIoWriting:
					// TESTING!!!
					//fprintf( stderr, "state is WinIoWriting\n" );
					// END TESTING
					if ( !FD_ISSET( handle->io_handle, 
					 globus_l_io_write_fds ) )
						break; // we don't care about this handle any longer
                    globus_i_io_debug_printf(5,
                        (stderr, "%s(): write, fd=%d\n", myname, handle->fd));
					if( result == GLOBUS_SUCCESS )
					{
						handle->winIoOperation_write.numberOfBytesProcessed= 
						 numberOfBytes;
					}
					select_info = globus_l_io_fd_table[handle->fd];
                    operation_info = select_info->write;

					operation_info->result= result;
                                                       
                    result = globus_i_io_unregister_operation(
                        handle, GLOBUS_FALSE, GLOBUS_I_IO_WRITE_OPERATION);
                    globus_assert(result == GLOBUS_SUCCESS);
                    
                    result = globus_callback_space_register_oneshot(
                        &operation_info->callback_handle,
                        GLOBUS_NULL,
                        globus_l_io_kickout_cb,
                        operation_info,
                        handle->blocking_write
                            ? GLOBUS_CALLBACK_GLOBAL_SPACE
                            : handle->socket_attr.space);
                    globus_assert(result == GLOBUS_SUCCESS);

                    globus_l_io_pending_count++;
					break;
				case WinIoWakeup:
				    globus_l_io_wakeup_pending = GLOBUS_FALSE;
					break;
				default:
					// TESTING!!!
					//fprintf( stderr, "ERROR: invalid winIOOperation state\n" );
					n_ready= 0;
					// END TESTING
			} // end switch
		} // end if
#endif /* TARGET_ARCH_WIN32*/

#ifndef TARGET_ARCH_WIN32
        if(n_ready > 0)
        {
            int fd;
            
            done = GLOBUS_TRUE;
            handled_something = GLOBUS_TRUE;
        
            for(fd = 0, n_checked = 0; n_checked < n_ready; fd++)
            {
                if(FD_ISSET(fd, globus_l_io_active_read_fds))
                {
                    n_checked++;

                    /* Only do the callback if we are still interested
                     * in the FD
                     */
                    if(FD_ISSET(fd, globus_l_io_read_fds))
                    {
                        select_info = globus_l_io_fd_table[fd];
                        operation_info = select_info->read;
                        
                        globus_i_io_debug_printf(5,
                            (stderr, "%s(): read, fd=%d\n", myname, fd));
                        
                        handle = operation_info->handle;    
                        
                        result = globus_i_io_unregister_operation(
                            handle, GLOBUS_FALSE, GLOBUS_I_IO_READ_OPERATION);
                        globus_assert(result == GLOBUS_SUCCESS);
                        
                        globus_l_io_pending_count++;
                        
                        result = globus_callback_space_register_oneshot(
                            &operation_info->callback_handle,
                            GLOBUS_NULL,
                            globus_l_io_kickout_cb,
                            operation_info,
                            handle->blocking_read
                                ? GLOBUS_CALLBACK_GLOBAL_SPACE
                                : handle->socket_attr.space);
                        globus_assert(result == GLOBUS_SUCCESS);
                    }

                    if(n_checked == n_ready)
                    {
                        break;
                    }
                }
                
                if(FD_ISSET(fd, globus_l_io_active_write_fds))
                {
                    n_checked++;
        
                    /* Only do the callback if we are still interested
                     * in the FD
                     */
                    if(FD_ISSET(fd, globus_l_io_write_fds))
                    {
                        select_info = globus_l_io_fd_table[fd];
                        operation_info = select_info->write;
                        
                        globus_i_io_debug_printf(5,
                            (stderr, "%s(): write, fd=%d\n", myname, fd));
                        
                        handle = operation_info->handle;    
                                
                        result = globus_i_io_unregister_operation(
                            handle, GLOBUS_FALSE, GLOBUS_I_IO_WRITE_OPERATION);
                        globus_assert(result == GLOBUS_SUCCESS);

                        globus_l_io_pending_count++;
                        
                        result = globus_callback_space_register_oneshot(
                            &operation_info->callback_handle,
                            GLOBUS_NULL,
                            globus_l_io_kickout_cb,
                            operation_info,
                            handle->blocking_write
                                ? GLOBUS_CALLBACK_GLOBAL_SPACE
                                : handle->socket_attr.space);
                        globus_assert(result == GLOBUS_SUCCESS);
                    }
                    
                    if(n_checked == n_ready)
                    {
                        break;
                    }
                }
                
                if(FD_ISSET(fd, globus_l_io_active_except_fds))
                {
                    n_checked++;
        
                    /* Only do the callback if we are still interested
                     * in the FD
                     */
                    if(FD_ISSET(fd, globus_l_io_except_fds))
                    {
                        select_info = globus_l_io_fd_table[fd];
                        operation_info = select_info->except;
                        
                        globus_i_io_debug_printf(5,
                            (stderr, "%s(): except, fd=%d\n", myname, fd));
                        
                        handle = operation_info->handle;    
                                
                        result = globus_i_io_unregister_operation(
                            handle, GLOBUS_FALSE, GLOBUS_I_IO_EXCEPT_OPERATION);
                        globus_assert(result == GLOBUS_SUCCESS);
                        
                        globus_l_io_pending_count++;
                        
                        result = globus_callback_space_register_oneshot(
                            &operation_info->callback_handle,
                            GLOBUS_NULL,
                            globus_l_io_kickout_cb,
                            operation_info,
                            handle->blocking_except
                                ? GLOBUS_CALLBACK_GLOBAL_SPACE
                                : handle->socket_attr.space);
                        globus_assert(result == GLOBUS_SUCCESS);
                    }
        
                    if(n_checked == n_ready)
                    {
                        break;
                    }
                }
            } /* for */
        } /* endif */
#endif /* !TARGET_ARCH_WIN32 */
    
        if(n_ready == 0)
        {
            done = GLOBUS_TRUE;
        }
#ifdef TARGET_ARCH_WIN32
        else if(!time_left_is_zero)
        {
            /* we handled something and we didnt timeout
             * set the timeleft to zero and keep getting completion packets
             * until we would block
             */
            GlobusTimeReltimeCopy(*time_left, globus_i_reltime_zero);
            time_left_is_zero = GLOBUS_TRUE;
        }
#endif
    }

handle_abort:
    globus_i_io_debug_printf(5, (stderr, "%s(): exiting\n",myname));
    return handled_something;
}
/* globus_l_io_handle_events */
#endif

/*
 * globus_l_io_wakeup_pipe_callback()
 *
 *  This is the function that gets called when the pipe to self gets signaled
 *  during shutdown.  We don't really want to do anything except to guarantee
 *  that select() will wake after globus_l_io_shutdown_called is set to true.
 */
static
void
globus_l_io_wakeup_pipe_callback(
    void *				arg,
    globus_io_handle_t *		handle,
    globus_result_t			result)
{
#ifndef TARGET_ARCH_WIN32
    char				buf[64];
    ssize_t				done = 0;

    globus_i_io_debug_printf(3, 
        (stderr, "globus_l_io_wakeup_pipe_callback(): entering\n"));

    do
    {
	done = globus_libc_read(handle->fd, buf, sizeof(buf));
    } while(done == -1 && errno == EINTR);

    globus_l_io_wakeup_pending = GLOBUS_FALSE;
    
    globus_i_io_debug_printf(3, 
        (stderr, "globus_l_io_wakeup_pipe_callback(): exiting\n"));
#endif /* TARGET_ARCH_WIN32 */
}
/* globus_l_io_wakeup_pipe_callback() */


static 
void
globus_l_io_poll(
    void *                              user_args)
{
    int                                 events_handled=0;
    globus_reltime_t                    time_left;
    
    globus_callback_get_timeout(&time_left);
    globus_i_io_mutex_lock();
    
    do
    {
        events_handled = 
            globus_l_io_handle_events(&time_left);
    }
    while(events_handled == 0 &&
	  !globus_l_io_shutdown_called &&
          !globus_callback_get_timeout(&time_left));

    /* adjust skip-poll delay */
#   if defined(BUILD_LITE)
    {
	if(globus_l_io_use_skip_poll &&
	   !globus_l_io_shutdown_called)
	{
            globus_reltime_t                  new_period;

            globus_l_io_adaptive_skip_poll_adjust(
                &globus_l_io_skip_poll_info,                           
                events_handled);
            if(globus_l_io_adaptive_skip_poll_get_delay(
                &globus_l_io_skip_poll_info,                           
                &new_period)) 
            {
                globus_callback_adjust_period(
                    globus_l_io_callback_handle,
                    &new_period);
            }
        }
    }
#   endif

    globus_i_io_mutex_unlock();
}

/*
 * Function:	globus_l_io_activate()
 *
 * Description:	Init all the global variables and setup mutexes.
 *
 * Parameters:	
 *
 * Returns:	GLOBUS_SUCCESS if module activated properly, otherwise,
 *		non-zero return code.
 *
 *  
 */
static
globus_bool_t
globus_l_io_activate(void)
{
    int					i;
    int					rc = 0;
    char *                              tmp_string;
    int                                 tmp_i1;
    int                                 tmp_i2;
    char *                              p;
    int                                 fd_allocsize;
    int					num_fds;
    globus_reltime_t                    delay;
    globus_result_t                     result;
#ifdef TARGET_ARCH_WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
#else
    int                                 save_errno;
#endif

    /* In the pre-activation of the thread module, we
     * are setting up some code to block the SIGPIPE
     * signal. This is necessary because some of
     * the TCP protocols we are using do not have
     * a mode in which we can safely detect a remotely-
     * closing socket.
     */
    globus_module_activate(GLOBUS_ERROR_MODULE);
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
       return rc;
    }
    rc = globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
       return rc;
    }
    
    tmp_string = globus_module_getenv("GLOBUS_IO_DEBUG_LEVEL");
    if(tmp_string != GLOBUS_NULL)
    {
	globus_i_io_debug_level = atoi(tmp_string);

	if(globus_i_io_debug_level < 0)
	{
	    globus_i_io_debug_level = 0;
	}
    }

    /*
     *  Determine if netlogger is on or off
     */
#   if defined(GLOBUS_BUILD_WITH_NETLOGGER)
    {
        tmp_string = globus_module_getenv("GLOBUS_NETLOGGER");
        if(tmp_string != GLOBUS_NULL)
        {
            g_globus_i_io_use_netlogger = GLOBUS_TRUE;
        }
    }
#   else
    {
        g_globus_i_io_use_netlogger = GLOBUS_FALSE;
    }
#   endif

#ifdef TARGET_ARCH_WIN32
	/* Startup the Winsock DLL */
	wVersionRequested = MAKEWORD( 2, 0 ); /* version 2.0 */	 
	rc= WSAStartup( wVersionRequested, &wsaData );
	if ( rc != 0 ) /* error- Winsock not available */
		return GLOBUS_FAILURE;

	/* Create the completion port */
	completionPort= CreateIoCompletionPort( INVALID_HANDLE_VALUE, NULL, 0, 0 );
	if ( completionPort == NULL )
		return GLOBUS_FAILURE;
#endif

    globus_i_io_debug_printf(3,
        (stderr, "globus_l_io_activate(): entering\n"));
    
    globus_l_io_shutdown_called = GLOBUS_FALSE;

    globus_mutex_init(&globus_i_io_mutex, (globus_mutexattr_t *) GLOBUS_NULL);
    globus_cond_init(&globus_i_io_cond, (globus_condattr_t *) GLOBUS_NULL);
    
    globus_memory_init(
        &globus_l_io_operation_info_memory,
        sizeof(globus_io_operation_info_t),
        64);
    
    globus_l_io_cancel_list = GLOBUS_NULL;
    globus_l_io_cancel_tail = GLOBUS_NULL;
    globus_l_io_cancel_free_list = GLOBUS_NULL;
    globus_l_io_cancel_pending_list = GLOBUS_NULL;

    globus_l_io_operations = GLOBUS_NULL;

    /* set up used port table */
    globus_i_io_tcp_used_port_table = GLOBUS_NULL;
    if(globus_i_common_get_env_pair("GLOBUS_TCP_PORT_RANGE", 
				    &tmp_i1,
				    &tmp_i2))
    {
	int ctr;

	globus_i_io_tcp_used_port_min = (unsigned short) tmp_i1;
	globus_i_io_tcp_used_port_max = (unsigned short) tmp_i2;

        globus_i_io_tcp_used_port_table = (globus_bool_t *)
				         globus_malloc(
					    (globus_i_io_tcp_used_port_max -
				             globus_i_io_tcp_used_port_min + 1) *
					    sizeof(globus_bool_t));

        for(ctr = 0; 
	    ctr <= globus_i_io_tcp_used_port_max - globus_i_io_tcp_used_port_min;
	    ctr++)
        {
            globus_i_io_tcp_used_port_table[ctr] = GLOBUS_FALSE;
        }
    }
    globus_i_io_udp_used_port_table = GLOBUS_NULL;
    if(globus_i_common_get_env_pair("GLOBUS_UDP_PORT_RANGE", 
				 &tmp_i1,
				 &tmp_i2))
    {
	int ctr;

	globus_i_io_udp_used_port_min = (unsigned short) tmp_i1;
	globus_i_io_udp_used_port_max = (unsigned short) tmp_i2;

        globus_i_io_udp_used_port_table = (globus_bool_t *)
				         globus_malloc(
					    (globus_i_io_udp_used_port_max -
				             globus_i_io_udp_used_port_min + 1) *
					    sizeof(globus_bool_t));

        for(ctr = 0; 
	    ctr < globus_i_io_udp_used_port_max - globus_i_io_udp_used_port_min + 1;
	    ctr++)
        {
            globus_i_io_udp_used_port_table[ctr] = GLOBUS_FALSE;
        }
    }

    /* setup default attributes */
    globus_i_io_attr_activate();

    globus_l_io_fd_table_modified = GLOBUS_FALSE;
    globus_l_io_select_count = 0;
    globus_l_io_select_active = GLOBUS_FALSE;
    globus_l_io_wakeup_pending = GLOBUS_FALSE;
    globus_i_io_mutex_cnt = 0;
    globus_i_io_cond_cnt = 0;

    globus_i_io_mutex_lock();

    /* Initialize the fd tables and fd_set's */
    globus_l_io_fd_tablesize = GLOBUS_L_IO_NUM_FDS;
    globus_l_io_highest_fd = 0;
    globus_l_io_pending_count = 0;

    /*
     * Make windows use the max num of fds with stdio too.
     */
    #ifdef TARGET_ARCH_WIN32
    if (_setmaxstdio(GLOBUS_L_IO_NUM_FDS) < 0)
    {
    globus_i_io_debug_printf(3, 
        (stderr, "Warning: _setmaxstdio(%d) failed\n"),GLOBUS_L_IO_NUM_FDS);
    }
    #endif /* TARGET_ARCH_WIN32 */
    
    globus_l_io_fd_table = (globus_io_select_info_t **)
        globus_malloc(sizeof(globus_io_select_info_t *) *
            globus_l_io_fd_tablesize);
    
    for (i = 0; i < globus_l_io_fd_tablesize; i++)
    {
		globus_l_io_fd_table[i] = GLOBUS_NULL;
    }
    globus_l_io_fd_table_modified = GLOBUS_FALSE;

    /*
     * On some machines (SGI Irix at least), the fd_set structure isn't
     * necessarily large enough to hold the maximum number of open file
     * descriptors.  This ensures that it will be.
     */
    fd_allocsize = sizeof(fd_set);
    num_fds=GLOBUS_L_IO_NUM_FDS;
    if(fd_allocsize*8 < num_fds){
	/* Conservatively round up to 64 bits */
	fd_allocsize = ((num_fds+63)&(~63))/8;
    }
    p=globus_malloc(fd_allocsize*6);
    globus_l_io_read_fds=(fd_set*)p;
    globus_l_io_write_fds=(fd_set*)(p+fd_allocsize);
    globus_l_io_except_fds=(fd_set*)(p+fd_allocsize*2);
    globus_l_io_active_read_fds=(fd_set*)(p+fd_allocsize*3);
    globus_l_io_active_write_fds=(fd_set*)(p+fd_allocsize*4);
    globus_l_io_active_except_fds=(fd_set*)(p+fd_allocsize*5);
    FD_ZERO(globus_l_io_read_fds);
    FD_ZERO(globus_l_io_write_fds);
    FD_ZERO(globus_l_io_except_fds);
    /*
     * FD_ZERO may not clear all of the fds.  We not explicitly
     * clear them.
     */
    for (i = 0; i < num_fds; i++)
    {
	FD_CLR(i, globus_l_io_read_fds);
	FD_CLR(i, globus_l_io_write_fds);
	FD_CLR(i, globus_l_io_except_fds);
    }

    globus_l_io_fd_num_set = 0;

#ifndef TARGET_ARCH_WIN32        
    /*
     * Create a pipe to myself, so that I can wake up the thread that is
     * blocked on a select().
     */
    if (pipe(globus_l_io_wakeup_pipe) != 0)
    {
        rc = -1;
        goto unlock_and_abort;
    }

    while ((rc = fcntl(globus_l_io_wakeup_pipe[0], F_SETFD, FD_CLOEXEC)) < 0)
    {
	save_errno = errno;
	if(save_errno != EINTR)
	{
	    goto unlock_and_abort;
	}
    }
    while ((rc = fcntl(globus_l_io_wakeup_pipe[1], F_SETFD, FD_CLOEXEC)) < 0)
    {
	save_errno = errno;
	if(save_errno != EINTR)
	{
            rc = -1;
	    goto unlock_and_abort;
	}
    }

    rc = globus_l_io_internal_handle_create(globus_l_io_wakeup_pipe[0],
					    &globus_l_io_wakeup_pipe_handle);
    if(rc != 0)
    {
	rc = -2;
	goto unlock_and_abort;
    }
    
    globus_i_io_setup_nonblocking(&globus_l_io_wakeup_pipe_handle);
    
    /* not using a callback here... just holding a place for this fd */
    result = globus_i_io_start_operation(
        &globus_l_io_wakeup_pipe_handle,
        GLOBUS_I_IO_READ_OPERATION);
    
    if(result == GLOBUS_SUCCESS)
    {
        result = globus_i_io_register_operation(
            &globus_l_io_wakeup_pipe_handle,
            GLOBUS_NULL,
            GLOBUS_NULL,
            GLOBUS_NULL,
            GLOBUS_TRUE,
            GLOBUS_I_IO_READ_OPERATION);
    }
    
    if(result != GLOBUS_SUCCESS)
    {
        rc = -3;
	    goto unlock_and_abort;
    }
#else /* TARGET_ARCH_WIN32 */
	// initialize the wakeup handle
	// first, create a dummy socket
    winWakeUpHandle.io_handle = (HANDLE)socket( AF_INET,
	 SOCK_STREAM, 0 );
    if( (SOCKET)winWakeUpHandle.io_handle == INVALID_SOCKET )
    {
		rc = -2;
		goto unlock_and_abort;
    }
	// initialize the WinIoOperation structs
	globus_i_io_windows_init_io_operations( &winWakeUpHandle );
	/* associate the wakeup handle with the completion port */
	if ( CreateIoCompletionPort( winWakeUpHandle.io_handle,
		completionPort, (ULONG_PTR)&winWakeUpHandle, 0 ) == NULL )
	{
		rc = -2;
		globus_i_io_windows_close( &winWakeUpHandle );
		goto unlock_and_abort;	
	}
#endif /* TARGET_ARCH_WIN32 */
    
    /* if not using skip poll register as periodic for efficiency */

    /* get skip poll value */
    globus_l_io_use_skip_poll = GLOBUS_FALSE;
#if  defined(BUILD_LITE)
    if(globus_l_io_adaptive_skip_poll_init(
	      &globus_l_io_skip_poll_info,
	      "GLOBUS_IO_POLL_FREQUENCY"))
    {
        globus_l_io_use_skip_poll = GLOBUS_TRUE;
    }
#endif
    GlobusTimeReltimeSet(delay, 0, 0);
    result = globus_callback_register_periodic(
			     &globus_l_io_callback_handle,
                             &delay,
                             &delay,
               		     globus_l_io_poll,
			     GLOBUS_NULL);
    globus_assert(result == GLOBUS_SUCCESS);
	    
  unlock_and_abort:
    globus_i_io_mutex_unlock();

    globus_i_io_debug_printf(3, (stderr, "globus_l_io_activate(): exiting\n"));
    
    return rc;
}
/* globus_l_io_activate() */

/**
 * unregister callback callback
 */
static
void
globus_l_unregister_periodic_cb(
    void *                              user_args)
{
    globus_i_io_mutex_lock();
    {
        globus_l_io_pending_count--;
        if(globus_l_io_pending_count == 0)
        {
            globus_l_io_cond_signal();
        }
    }
    globus_i_io_mutex_unlock();
}

/*
 * globus_l_io_deactivate()
 *
 * Make sure the select() wakes up and set the globus_l_io_shutdown_called flag
 * to TRUE
 */
static
globus_bool_t
globus_l_io_deactivate(void)
{
    int					fd;
    int					rc = 0;
    globus_bool_t                   active;
    
    globus_i_io_debug_printf(3, (stderr, "globus_l_io_deactivate(): entering\n"));

    globus_i_io_mutex_lock();

    globus_l_io_shutdown_called = GLOBUS_TRUE;

    /* Wakeup the handler thread from the select(), and close the pipe to
     * ourself.
     */
    if (globus_l_io_select_active)
    {
	globus_l_io_select_wakeup();
    }
    
    /* cancel any outstanding callbacks */
    for (fd = 0; fd < globus_l_io_fd_tablesize; fd++)
    {
        globus_io_select_info_t *	    select_info;
        globus_io_operation_info_t *    operation_info;
        
        select_info = globus_l_io_fd_table[fd];
        
        if(select_info)
        {
            operation_info = select_info->read;
            if(operation_info && operation_info->callback)
            {
                if(operation_info->callback_handle != GLOBUS_NULL_HANDLE)
                {
                    /* cancel pending callback */
                    globus_callback_unregister(
                        operation_info->callback_handle,
                        GLOBUS_NULL,
                        GLOBUS_NULL,
                        &active);
                    
                    if(!active)
                    {
                        globus_l_io_pending_count--;
                    }
                }
                
                if(operation_info->arg_destructor && operation_info->arg)
                {
                    operation_info->arg_destructor(operation_info->arg);
            	}
            	
            	operation_info->callback = GLOBUS_NULL;
            }
            
            operation_info = select_info->write;
            if(operation_info && operation_info->callback)
            {
                if(operation_info->callback_handle != GLOBUS_NULL_HANDLE)
                {
                    /* cancel pending callback */
                    globus_callback_unregister(
                        operation_info->callback_handle,
                        GLOBUS_NULL,
                        GLOBUS_NULL,
                        &active);
                    
                    if(!active)
                    {
                        globus_l_io_pending_count--;
                    }
                }
                
                if(operation_info->arg_destructor && operation_info->arg)
                {
                    operation_info->arg_destructor(operation_info->arg);
            	}
            	
            	operation_info->callback = GLOBUS_NULL;
            }
            
            operation_info = select_info->except;
            if(operation_info && operation_info->callback)
            {
                if(operation_info->callback_handle != GLOBUS_NULL_HANDLE)
                {
                    /* cancel pending callback */
                    globus_callback_unregister(
                        operation_info->callback_handle,
                        GLOBUS_NULL,
                        GLOBUS_NULL,
                        &active);
                    
                    if(!active)
                    {
                        globus_l_io_pending_count--;
                    }
                }
                
                if(operation_info->arg_destructor && operation_info->arg)
                {
                    operation_info->arg_destructor(operation_info->arg);
            	}
            	
            	operation_info->callback = GLOBUS_NULL;
            }
        }
    }
    
    /* cancel any outstanding cancels */
    while(globus_l_io_cancel_pending_list)
    {
        globus_io_cancel_info_t *	cancel_info;
        
        cancel_info = globus_l_io_cancel_pending_list;
        
        globus_callback_unregister(
            cancel_info->callback_handle,
            GLOBUS_NULL,
            GLOBUS_NULL,
            &active);
        
        if(!active)
        {
            globus_l_io_pending_count--;
        }
        
        /* take this out of the pending list and put it on the 
         * active list so the destructors can be called later
         */
        globus_l_io_cancel_pending_list = cancel_info->next;
        
        cancel_info->next = globus_l_io_cancel_list;
        globus_l_io_cancel_list = cancel_info;
    }
    /*
     * Wait for any outstanding calls into the handler (or handler thread)
     * to complete. 
     */
    globus_l_io_pending_count++;
    globus_callback_unregister(
        globus_l_io_callback_handle,
        globus_l_unregister_periodic_cb,
        GLOBUS_NULL,
        GLOBUS_NULL);
    
    while(globus_l_io_pending_count > 0)
    {
        globus_l_io_cond_wait();
    }

#ifndef TARGET_ARCH_WIN32
    globus_i_io_close(&globus_l_io_wakeup_pipe_handle);
    
    while(globus_libc_close(globus_l_io_wakeup_pipe[1]) < 0)
    {
        if(errno != EINTR)
        {
            break;
        }
    }
#else
	globus_i_io_windows_close( &winWakeUpHandle );
#endif /* TARGET_ARCH_WIN32 */    
    
    /*
     * free up table resources
     */
    for (fd = 0; fd < globus_l_io_fd_tablesize; fd++)
    {
        if(globus_l_io_fd_table[fd])
        {
            globus_l_io_table_remove_fd(fd);
        }
    }
    globus_free(globus_l_io_fd_table);

    /* free any cancel data structures */
    while(globus_l_io_cancel_list)
    {
        globus_io_cancel_info_t *       tmp;
        globus_io_operation_info_t *    operation_info;
        
        globus_l_io_dequeue(
            globus_l_io_cancel_list,
            globus_l_io_cancel_tail,
            tmp);
        
        operation_info = tmp->read;
        if(operation_info &&
            operation_info->callback &&
            operation_info->arg_destructor &&
            operation_info->arg)
        {
            operation_info->arg_destructor(operation_info->arg);
        }
        
        operation_info = tmp->write;
        if(operation_info &&
            operation_info->callback &&
            operation_info->arg_destructor &&
            operation_info->arg)
        {
            operation_info->arg_destructor(operation_info->arg);
        }
        
        operation_info = tmp->except;
        if(operation_info &&
            operation_info->callback &&
            operation_info->arg_destructor &&
            operation_info->arg)
        {
            operation_info->arg_destructor(operation_info->arg);
        }

        if(tmp->callback &&
            tmp->arg_destructor &&
            tmp->arg)
        {
            tmp->arg_destructor(tmp->arg);
        }
        globus_free(tmp);
    }
    
    while(globus_l_io_cancel_free_list)
    {
        globus_io_cancel_info_t *   tmp;
        globus_l_io_dequeue(globus_l_io_cancel_free_list, GLOBUS_NULL, tmp);
        globus_free(tmp);
    }

    /* Free up list of non-selecting reads */
    globus_list_free(globus_l_io_operations);
    
    if(globus_i_io_tcp_used_port_table) 
    {
        globus_free(globus_i_io_tcp_used_port_table);
    }
    if(globus_i_io_udp_used_port_table) 
    {
        globus_free(globus_i_io_udp_used_port_table);
    }
    
    globus_memory_destroy(&globus_l_io_operation_info_memory);
    
    globus_i_io_mutex_unlock();
    globus_i_io_debug_printf(3,
        (stderr, "globus_l_io_deactivate(): exiting\n"));

    globus_module_deactivate(GLOBUS_ERROR_MODULE);
    globus_mutex_destroy(&globus_i_io_mutex);
    globus_cond_destroy(&globus_i_io_cond);
    globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
#ifdef TARGET_ARCH_WIN32
	WSACleanup();
	CloseHandle( completionPort );
#endif

    return GLOBUS_SUCCESS;
}
/* globus_l_io_deactivate() */

globus_result_t
globus_i_io_setup_nonblocking(
    globus_io_handle_t *		handle)
{
    int					save_errno=0;
    int					flags;
    globus_result_t			rc = GLOBUS_SUCCESS;
    globus_object_t *			err;
    static char *			myname="globus_i_io_setup_nonblocking";
    
#ifdef TARGET_ARCH_WIN32
	u_long argp= 1;
	int rcWin;

	rcWin= ioctlsocket( (SOCKET)handle->io_handle, FIONBIO, &argp );
	if ( rcWin == SOCKET_ERROR )
	{
		err = globus_io_error_construct_internal_error(
				GLOBUS_IO_MODULE,
				GLOBUS_NULL,
				myname);
		return globus_error_put(err);
	}
	return GLOBUS_SUCCESS;
#else

    while ((flags = fcntl(handle->fd,
		       F_SETFD,
		       FD_CLOEXEC)) < 0)
    {
	save_errno = errno;
	if(save_errno != EINTR)
	{
	    goto error_exit;
	}
    }

    while ((flags = fcntl(handle->fd,
		       F_GETFL,
		       0)) < 0)
    {
	save_errno = errno;
	if(save_errno != EINTR)
	{
	    goto error_exit;
	}
    }

#   if defined(TARGET_ARCH_HPUX)
    {
	flags |= O_NONBLOCK;
    }
#   else
    {
	flags |= O_NDELAY;
    }
#   endif
    
    while (fcntl(handle->fd,
		 F_SETFL,
		 flags) < 0)
    {
	save_errno = errno;
	if(save_errno != EINTR)
	{
	    goto error_exit;
	}
    }

    return GLOBUS_SUCCESS;
    
  error_exit:
    if(save_errno != 0)
    {
	err = globus_io_error_construct_internal_error(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    myname);
	rc = globus_error_put(err);
    }
    return rc;
#endif /* TARGET_ARCH_WIN32 */
}
/* globus_i_io_setup_nonblocking() */


globus_bool_t
globus_i_common_get_env_pair(
    char *                       env_name,
    int *                        min,
    int *                        max)
{
    char * min_max;
    char * c_ndx;
    int x1, x2;

    min_max = globus_module_getenv(env_name);

    if(min_max == GLOBUS_NULL)
      {
        return GLOBUS_FALSE;
      }
    else
      {
        c_ndx = strchr(min_max, ',');
        if(c_ndx != GLOBUS_NULL)
        {
            *c_ndx = ' ';
        }
        if(sscanf(min_max, "%d %d", &x1, &x2) < 2)
	  {
            return GLOBUS_FALSE;
	  }

        *min = x1;
        *max = x2;
      }

    return GLOBUS_TRUE;
}

/*************  Skip poll functions *************/
static globus_bool_t
globus_l_io_adaptive_skip_poll_init(
    globus_l_io_adaptive_skip_poll_t *              skip_poll_info,
    char *                                          env_variable)
{
    int                            tmp_i1;
    int                            tmp_i2;

    skip_poll_info->env_variable = env_variable;

    if(globus_i_common_get_env_pair(
				env_variable,
		                &tmp_i1,
			        &tmp_i2))
    {
        GlobusTimeReltimeSet(skip_poll_info->start_delay, 0, tmp_i1);
        GlobusTimeReltimeSet(skip_poll_info->current_delay, 0, tmp_i1);
        GlobusTimeReltimeSet(skip_poll_info->max_delay, 0, tmp_i2);
        skip_poll_info->events_handled = 0;
	return GLOBUS_TRUE;
    }
    else
    {
        return GLOBUS_FALSE;
    }
}

static globus_bool_t
globus_l_io_adaptive_skip_poll_adjust(
    globus_l_io_adaptive_skip_poll_t *              skip_poll_info,
    int                                             events_handled)
{
    /* 
     * if last time there was nothing and this time there is nothing
     * double the delay
     */

    if(skip_poll_info->events_handled < 0 &&
       events_handled < 0)
    {
         GlobusTimeReltimeMultiply(skip_poll_info->current_delay, 2);

	 if(globus_reltime_cmp(&skip_poll_info->current_delay, 
                               &skip_poll_info->max_delay) > 0)
	 {
             skip_poll_info->current_delay = skip_poll_info->max_delay;
             GlobusTimeReltimeCopy(skip_poll_info->current_delay, 
                                   skip_poll_info->max_delay);
	 }

    }
    /*
     * if last time there was something and this time 
     * there is something half the delay
     */
    else if(skip_poll_info->events_handled > 0 &&
            events_handled > 0)
    {
         GlobusTimeReltimeDivide(skip_poll_info->current_delay, 2);
    }
    /*
     * if last time something and this time nothing or
     * otherway around then delay is good
     */
    else
    {
    }
    skip_poll_info->events_handled = events_handled;

    return GLOBUS_TRUE;
}

static
globus_bool_t
globus_l_io_adaptive_skip_poll_get_delay(
    globus_l_io_adaptive_skip_poll_t *              skip_poll_info,
    globus_reltime_t *                              current_delay)
{
    GlobusTimeReltimeCopy(*current_delay, skip_poll_info->current_delay);

    return GLOBUS_TRUE;
}

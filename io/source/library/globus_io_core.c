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
# ifndef TARGET_ARCH_WIN32
#   define GLOBUS_L_IO_NUM_FDS 256
# else
#   define GLOBUS_L_IO_NUM_FDS 256
# endif
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
typedef struct globus_io_select_info_s
{
    globus_io_handle_t *	handle;

    globus_io_callback_t	read_callback;
    void *			read_arg;
    globus_io_destructor_t	read_destructor;
    globus_bool_t		read_select;

    globus_io_callback_t	write_callback;
    void *			write_arg;
    globus_io_destructor_t	write_destructor;

    globus_io_callback_t	except_callback;
    void *			except_arg;
} globus_io_select_info_t;
#endif

typedef struct globus_io_cancel_info_s
{
    globus_io_handle_t *		handle;
    globus_io_callback_t 		read_callback;
    void *				read_arg;
    globus_bool_t			read_dispatched;
    globus_io_destructor_t		read_destructor;
    globus_io_callback_t		write_callback;
    void *				write_arg;
    globus_bool_t			write_dispatched;
    globus_io_destructor_t		write_destructor;
    globus_io_callback_t		except_callback;
    void *				except_arg;
    globus_bool_t			except_dispatched;
    globus_io_callback_t		cancel_callback;
    void *				cancel_arg;
    globus_bool_t			cancel_dispatched;
    globus_io_destructor_t		cancel_destructor;
    struct globus_io_cancel_info_s *	next;
} globus_io_cancel_info_t;

static void
globus_l_io_handler_wakeup(void *arg);

static globus_bool_t
globus_l_io_poll(
    globus_abstime_t *                  time_stop,
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

/* This is the old module descriptor: */
/*
globus_module_descriptor_t globus_i_io_module =
{
    "globus_io",
    globus_l_io_activate,
    globus_l_io_deactivate,
    GLOBUS_NULL
};
*/

/* This is the new module descriptor: */

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
static volatile globus_bool_t		globus_l_io_fd_table_modified;
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
 * List of pending read operations which do not need the select to be
 * done in order to complete them. This is used to dispatch buffered
 * reads, which were introduced to support GSSAPI wrapping of messages.
 */
static globus_list_t *			globus_l_io_reads;
/**
 * Number of times select has been called. This is used to work
 * around an IRIX bug which caused hangage when closing a FD
 * currently being monitored by select().
 */
static volatile int	          	globus_l_io_select_count;
/**
 * Flag which lets us know if a blocking select() is happening
 * right now. We use this to decide whether to write to the pipe
 * to wake it up if we change the select mask.
 */
static volatile globus_bool_t	        globus_l_io_select_active;
/**
 * Flag which lets us know if wakeup has been sent to the event
 * handler already, so that we don't repeat it.
 */
static volatile globus_bool_t	        globus_l_io_wakeup_pending;
/**
 * Flag which lets us know if deactivation is in progress, so that
 * we don't re-register again.
 */
static volatile globus_bool_t	        globus_l_io_shutdown_called;

#ifndef TARGET_ARCH_WIN32
/**
 * Pipe to myself.
 *
 * This is used to wakeup the select() loop when the FD masks have changed;
 * <br>globus_l_io_wakeup_pip[0] = read
 * <br>globus_l_io_wakeup_pip[0] = write
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

globus_bool_t *                         globus_i_io_tcp_used_port_table;
globus_bool_t *                         globus_i_io_udp_used_port_table;
unsigned short                          globus_i_io_tcp_used_port_min;
unsigned short                          globus_i_io_tcp_used_port_max;
unsigned short                          globus_i_io_udp_used_port_min;
unsigned short                          globus_i_io_udp_used_port_max;

globus_mutex_t                          globus_i_io_mutex;
globus_cond_t                           globus_i_io_cond;
volatile int                            globus_i_io_mutex_cnt;
volatile int                            globus_i_io_cond_cnt;

globus_wakeup_func_t                    globus_l_io_core_wakeup_func_ptr;
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
globus_l_io_handle_events(void);

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

    globus_i_io_debug_printf(3, ("globus_l_io_select_wakeup(): entering\n"));

    if(!globus_l_io_mutex_acquired())
    {
		return GLOBUS_FALSE;
    }

    if (!globus_l_io_select_active || globus_l_io_wakeup_pending)
    {
		rc = GLOBUS_TRUE;
		goto fn_exit;
    }

    globus_i_io_debug_printf(5,
		       ("globus_l_io_select_wakeup(): poking handler thread\n"));

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
#else
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
#endif

  fn_exit:
    globus_i_io_debug_printf(3, ("globus_l_io_select_wakeup(): exiting\n"));

    return rc;
#else
    return GLOBUS_FALSE;
#endif
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
		       ("globus_l_io_handle_create(): entering, fd=%d\n",
			fd));

    /*    GlobusAssert2((globus_l_io_mutex_acquired()),
     *			("globus_l_io_table_add()\n"));
     */

    handle->fd = fd;
    handle->type = GLOBUS_IO_HANDLE_TYPE_INTERNAL;
    handle->state = GLOBUS_IO_HANDLE_STATE_CONNECTED;
    
    globus_i_io_debug_printf(3, ("globus_l_io_internal_handle_create(): exiting\n"));

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
    globus_io_handle_t *		handle)
{
    globus_io_select_info_t *		select_info;
#ifdef TARGET_ARCH_WIN32
	int index;
#endif

    globus_i_io_debug_printf(3,
		       ("globus_l_io_table_add(): entering, fd=%d\n",
			handle->fd));

    /*    GlobusAssert2((globus_l_io_mutex_acquired()),
     *			("globus_l_io_table_add()\n"));
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
		handle->fd= globus_l_io_get_first_available_table_slot();
		// TODO: We should check this return value- it could be invalid!
#endif

    if (globus_l_io_fd_table[handle->fd])
    {
		globus_l_io_fd_table[handle->fd]->handle = handle;

		goto fn_exit;
    }
    select_info = (globus_io_select_info_t *)
	globus_malloc(sizeof(globus_io_select_info_t));
    
    select_info->handle = handle;
    select_info->read_callback = GLOBUS_NULL;
    select_info->read_arg = GLOBUS_NULL;
    select_info->write_callback = GLOBUS_NULL;
    select_info->write_arg = GLOBUS_NULL;
    select_info->except_callback = GLOBUS_NULL;
    select_info->except_arg = GLOBUS_NULL;

    globus_l_io_fd_table[handle->fd] = select_info;
    if(globus_l_io_highest_fd < handle->fd)
    {
		globus_l_io_highest_fd = handle->fd;
    }

  fn_exit:
    globus_i_io_debug_printf(3, ("globus_l_io_table_add(): exiting\n"));
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
		       ("globus_l_io_table_remove(): entering, fd=%d\n",
			handle->fd));

    globus_l_io_table_remove_fd(handle->fd);

    globus_i_io_debug_printf(3, ("globus_l_io_table_remove(): exiting\n"));
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
		       ("globus_l_io_table_remove_fd(): entering, fd=%d\n",
			fd));

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

    globus_i_io_debug_printf(3, ("globus_l_io_table_remove_fd(): exiting\n"));
    return GLOBUS_SUCCESS;
}
/* globus_l_io_table_remove() */

/*
 * Function:	globus_i_io_register_read_func()
 *
 * Description:	add the specified file descriptor to the read select list and
 *		register an associated callback function
 *
 *		Note: the FD mutex must be acquired before calling this func
 *
 * Parameters:	
 *
 *Returns:	
 */
globus_result_t
globus_i_io_register_read_func(
    globus_io_handle_t *		handle,
    globus_io_callback_t		callback_func,
    void *				callback_arg,
    globus_io_destructor_t		arg_destructor,
    globus_bool_t			register_select)
{
    globus_io_select_info_t *		select_info;
    static char *			myname="globus_i_io_register_read_func";

    globus_i_io_debug_printf(3,
		       ("%s(): entering, fd=%d\n", myname, handle->fd));

    globus_l_io_table_add(handle);
    select_info = globus_l_io_fd_table[handle->fd];

#ifndef TARGET_ARCH_WIN32
    if(FD_ISSET(handle->fd, globus_l_io_read_fds))
#else
    if(FD_ISSET(handle->io_handle, globus_l_io_read_fds))
#endif
    {
		globus_object_t *		err;

		err = globus_io_error_construct_read_already_registered(
			GLOBUS_IO_MODULE,
			GLOBUS_NULL,
			handle);
		
		return globus_error_put(err);
    }
    
    select_info->read_callback = callback_func;
    select_info->read_arg = callback_arg;
    select_info->read_destructor = arg_destructor;
    select_info->read_select = register_select;
    
#ifndef TARGET_ARCH_WIN32
    FD_SET(handle->fd, globus_l_io_read_fds);
#else
    FD_SET( (SOCKET)handle->io_handle, globus_l_io_read_fds);
#endif
    globus_l_io_fd_num_set++;

    if(!register_select)
    {
	globus_list_insert(&globus_l_io_reads,
			   select_info);
    }
    
    if (globus_l_io_select_active)
    {
	globus_l_io_select_wakeup();
    }

    globus_i_io_debug_printf(3, ("%s(): exiting\n",myname));
    return GLOBUS_SUCCESS;
}
/* globus_i_io_register_read_func() */


/*
 * Function:	globus_i_io_unregister_read()
 *
 * Description:	
 *
 *		Note: the FD mutex must be acquired before calling this func
 *
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_i_io_unregister_read(
    globus_io_handle_t *		handle,
    globus_bool_t			call_destructor)
{
    globus_io_select_info_t *		select_info;
    static char *			myname="globus_i_io_unregister_read";

    globus_i_io_debug_printf(3,
		       ("%s(): entering, fd=%d\n", myname, handle->fd));

    globus_l_io_table_add(handle);
    select_info = globus_l_io_fd_table[handle->fd];

#ifndef TARGET_ARCH_WIN32
    if(!FD_ISSET(handle->fd, globus_l_io_read_fds))
#else
    if(!FD_ISSET(handle->io_handle, globus_l_io_read_fds))
#endif
    {
	globus_object_t *		err;

#ifndef TARGET_ARCH_WIN32
	globus_assert(FD_ISSET(handle->fd, globus_l_io_read_fds));
#else
	globus_assert(FD_ISSET(handle->io_handle, globus_l_io_read_fds));
#endif

	err = globus_io_error_construct_internal_error(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    myname);

	return globus_error_put(err);
    }
    else if( (!select_info->read_select) &&
	     select_info->read_callback )
    {
	globus_list_remove(&globus_l_io_reads,
			   globus_list_search(globus_l_io_reads,
					      select_info));
    }
    
    select_info->read_callback = GLOBUS_NULL;
    select_info->read_select = GLOBUS_FALSE;

    if(call_destructor != GLOBUS_FALSE &&
       select_info->read_destructor != GLOBUS_NULL &&
       select_info->read_arg)
    {
	select_info->read_destructor(select_info->read_arg);
    }
    select_info->read_arg = GLOBUS_NULL;
    select_info->read_destructor = GLOBUS_NULL;

#ifndef TARGET_ARCH_WIN32
    FD_CLR(handle->fd, globus_l_io_read_fds);
#else
    FD_CLR( (SOCKET)handle->io_handle, globus_l_io_read_fds);
#endif
    globus_l_io_fd_num_set--;
    globus_l_io_fd_table_modified = GLOBUS_TRUE;
    
    globus_i_io_debug_printf(3, ("%s(): exiting\n",myname));
    return GLOBUS_SUCCESS;
}
/* globus_i_io_unregister_read() */


/*
 * Function:	globus_i_io_register_write_func()
 *
 * Description:	add the specified file descriptor to the write select list and
 *		register an associated callback function
 *
 *		Note: the FD mutex must be acquired before calling this func
 *
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_i_io_register_write_func(
    globus_io_handle_t *		handle,
    globus_io_callback_t		callback_func,
    void *				callback_arg,
    globus_io_destructor_t		write_destructor)
{
    globus_io_select_info_t *		select_info;
    static char *			myname="globus_i_io_register_write_func";

    globus_i_io_debug_printf(3,
		       ("%s(): entering, fd=%d\n", myname, handle->fd));

    /*
     *    GlobusAssert2((globus_l_io_mutex_acquired()),
     *		 ("globus_i_io_register_write_func()\n"));
     */
    globus_l_io_table_add(handle);
    select_info = globus_l_io_fd_table[handle->fd];
#ifndef TARGET_ARCH_WIN32
    if(FD_ISSET(handle->fd, globus_l_io_write_fds))
#else
    if(FD_ISSET(handle->io_handle, globus_l_io_write_fds))
#endif
    {
		globus_object_t *		err;

		err = globus_io_error_construct_write_already_registered(
			GLOBUS_IO_MODULE,
			GLOBUS_NULL,
			handle);

		return globus_error_put(err);
    }
    
#ifndef TARGET_ARCH_WIN32
    FD_SET(handle->fd, globus_l_io_write_fds);
#else
    FD_SET( (SOCKET)handle->io_handle, globus_l_io_write_fds);
#endif
    select_info->write_callback = callback_func;
    select_info->write_arg = callback_arg;
    select_info->write_destructor = write_destructor;
    
    globus_l_io_fd_num_set++;

    if (globus_l_io_select_active)
    {
	globus_l_io_select_wakeup();
    }

    globus_i_io_debug_printf(3, ("%s(): exiting\n", myname));
    return GLOBUS_SUCCESS;
}
/* globus_i_io_register_write_func() */


/*
 *
 * Function:	globus_i_io_unregister_write()
 *
 * Description:	
 *
 *		Note: the FD mutex must be acquired before calling this func
 *
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_i_io_unregister_write(
    globus_io_handle_t *		handle,
    globus_bool_t			call_destructor)
{
    globus_io_select_info_t *		select_info;
    static char *			myname="globus_i_io_unregister_write";

    globus_i_io_debug_printf(3, ("%s(): entering, fd=%d\n",
				 myname,
				 handle->fd));
    /* 
     *    GlobusAssert2((globus_l_io_mutex_acquired()),
     *		 ("globus_i_io_unregister_write()\n"));
     */
    globus_l_io_table_add(handle);
    select_info = globus_l_io_fd_table[handle->fd];

#ifndef TARGET_ARCH_WIN32
	if(!FD_ISSET(handle->fd, globus_l_io_write_fds))
#else
	if(!FD_ISSET(handle->io_handle, globus_l_io_write_fds))
#endif
    {
		globus_object_t *		err;

#ifndef TARGET_ARCH_WIN32
		globus_assert(FD_ISSET(handle->fd, globus_l_io_write_fds));
#else
		globus_assert(FD_ISSET(handle->io_handle, globus_l_io_write_fds));
#endif

		err = globus_io_error_construct_internal_error(
			GLOBUS_IO_MODULE,
			GLOBUS_NULL,
			myname);

		return globus_error_put(err);
    }
    
    select_info->write_callback = GLOBUS_NULL;
    if(call_destructor != GLOBUS_FALSE &&
       select_info->write_destructor != GLOBUS_NULL &&
       select_info->write_arg)
    {
	select_info->write_destructor(select_info->write_arg);
    }
    select_info->write_arg = GLOBUS_NULL;
    select_info->write_destructor = GLOBUS_NULL;

#ifndef TARGET_ARCH_WIN32
    FD_CLR(handle->fd, globus_l_io_write_fds);
#else
    FD_CLR( (SOCKET)handle->io_handle, globus_l_io_write_fds);
#endif
    globus_l_io_fd_num_set--;
    globus_l_io_fd_table_modified = GLOBUS_TRUE;
    
    globus_i_io_debug_printf(3, ("%s(): exiting\n",myname));

    return GLOBUS_SUCCESS;
}
/* globus_i_io_unregister_write() */


/*
 * Function:	globus_i_io_register_except_func()
 * 
 * Description:	add the specified file descriptor to the exception select list
 *		and register an associated callback function
 *
 *		Note: the FD mutex must be acquired before calling this func
 *
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_i_io_register_except_func(
    globus_io_handle_t *		handle,
    globus_io_callback_t		callback_func,
    void *				callback_arg)
{
    globus_io_select_info_t *		select_info;
    static char *			myname = "globus_i_io_register_except_func";

    globus_i_io_debug_printf(3,
			     ("%s(): entering, fd=%d\n", myname, handle->fd));
    /*
     *    GlobusAssert2((globus_l_io_mutex_acquired()),
     *		 ("globus_i_io_register_except_func()\n"));
     */
    globus_l_io_table_add(handle);
    select_info = globus_l_io_fd_table[handle->fd];

#ifndef TARGET_ARCH_WIN32
    if(FD_ISSET(handle->fd, globus_l_io_except_fds))
#else
    if(FD_ISSET(handle->io_handle, globus_l_io_except_fds))
#endif
    {
	globus_object_t *		err;

	err = globus_io_error_construct_except_already_registered(
	    GLOBUS_IO_MODULE,
	    GLOBUS_NULL,
	    handle);

	return globus_error_put(err);
    }
    
    select_info->except_callback = callback_func;
    select_info->except_arg = callback_arg;

#ifndef TARGET_ARCH_WIN32
    FD_SET(handle->fd, globus_l_io_except_fds);
#else
    FD_SET( (SOCKET)handle->io_handle, globus_l_io_except_fds);
#endif
    globus_l_io_fd_num_set++;

    if (globus_l_io_select_active)
    {
		globus_l_io_select_wakeup();
    }

    globus_i_io_debug_printf(3, ("%s(): exiting\n",myname));
    return GLOBUS_SUCCESS;
}
/* globus_i_io_register_except_func() */


/*
 * Function:	globus_i_io_unregister_except()
 *
 * Description:	
 *
 *		Note: the FD mutex must be acquired before calling this func
 *
 * Parameters:	
 *
 * Returns:	
 */
globus_result_t
globus_i_io_unregister_except(
    globus_io_handle_t *		handle)
{
    globus_io_select_info_t *		select_info;
    static char *			myname="globus_i_io_unregister_except";

    globus_i_io_debug_printf( 3, ("%s(): entering, fd=%d\n",
				  myname,
				  handle->fd));

    /*
     *      GlobusAssert2((globus_l_io_mutex_acquired()),
     *		 ("globus_i_io_unregister_except()\n"));
     */
    globus_l_io_table_add(handle);
    select_info = globus_l_io_fd_table[handle->fd];

#ifndef TARGET_ARCH_WIN32
    if(!FD_ISSET(handle->fd, globus_l_io_except_fds))
#else
    if(!FD_ISSET(handle->io_handle, globus_l_io_except_fds))
#endif
    {
		globus_object_t *		err;

#ifndef TARGET_ARCH_WIN32
		globus_assert(!FD_ISSET(handle->fd, globus_l_io_except_fds));
#else
		globus_assert(!FD_ISSET(handle->io_handle, globus_l_io_except_fds));
#endif
		err = globus_io_error_construct_internal_error(
			GLOBUS_IO_MODULE,
			GLOBUS_NULL,
			myname);

		return globus_error_put(err);
    }
    
    select_info->except_callback = GLOBUS_NULL;
    select_info->except_arg = GLOBUS_NULL;

#ifndef TARGET_ARCH_WIN32
    FD_CLR(handle->fd, globus_l_io_except_fds);
#else
    FD_CLR( (SOCKET)handle->io_handle, globus_l_io_except_fds);
#endif
    globus_l_io_fd_num_set--;
    globus_l_io_fd_table_modified = GLOBUS_TRUE;
    
    globus_i_io_debug_printf(3, ("%s(): exiting\n",myname));
    return GLOBUS_SUCCESS;
}
/* globus_i_io_unregister_except() */

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
    
    globus_i_io_debug_printf(3, ("%s(): entering, fd=%d\n",
				 myname,
				 handle->fd));

    /*
     *    GlobusAssert2((globus_l_io_mutex_acquired()),
     *		 ("globus_i_io_close()\n"));
     */

    if(globus_l_io_read_isregistered(handle))
    {
		globus_i_io_unregister_read(handle, GLOBUS_TRUE);

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
		globus_i_io_unregister_write(handle, GLOBUS_TRUE);
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
		globus_i_io_unregister_except(handle);
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

    globus_i_io_debug_printf(3, ("%s(): exiting\n",myname));

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
    globus_object_t *			err = GLOBUS_NULL;
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
    
    globus_i_io_debug_printf(3, ("%s(): entering\n",myname));

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
    if (read_callback_func != GLOBUS_NULL)
    {
	rc = globus_i_io_register_read_func(handle,
					    read_callback_func,
					    read_callback_arg,
					    GLOBUS_NULL,
					    GLOBUS_TRUE);
	if(rc != GLOBUS_SUCCESS)
	{
	   err = globus_error_get(rc);

	   goto read_failed;
	}
    }

    if (write_callback_func != GLOBUS_NULL)
    {
	rc = globus_i_io_register_write_func(handle,
					write_callback_func,
					write_callback_arg,
					GLOBUS_FALSE);

	if(rc != GLOBUS_SUCCESS)
	{
	    err = globus_error_get(rc);

	    goto write_failed;
	}
    }

    if (except_callback_func != GLOBUS_NULL)
    {
	rc = globus_i_io_register_except_func(handle,
					 except_callback_func,
					 except_callback_arg);
	if(rc != GLOBUS_SUCCESS)
	{
	    err = globus_error_get(rc);

	    goto except_failed;
	}
    }

    goto done;
			 
  except_failed:
    if (write_callback_func != GLOBUS_NULL)
    {
	rc = globus_i_io_unregister_write(handle,
					  GLOBUS_FALSE);
	
	globus_assert(rc == GLOBUS_SUCCESS);
    }
  write_failed:
    if (write_callback_func != GLOBUS_NULL)
    {
	rc = globus_i_io_unregister_read(handle,
					  GLOBUS_FALSE);
	globus_assert(rc == GLOBUS_SUCCESS);
    }
  read_failed:
  error_exit:
    globus_i_io_mutex_unlock();
    globus_i_io_debug_printf(3, ("%s(): exiting\n", myname));

    return(globus_error_put(err));

  done:
    globus_i_io_mutex_unlock();
    return GLOBUS_SUCCESS;
}
/* globus_io_register_select() */

void
globus_i_io_register_cancel(
    globus_io_handle_t *		handle,
    globus_bool_t			perform_callbacks,
    globus_io_callback_t		cancel_callback,
    void *				cancel_arg,
    globus_io_destructor_t		cancel_destructor)
{
    globus_io_select_info_t *		select_info;
    globus_io_cancel_info_t *		cancel_info = GLOBUS_NULL;

    globus_l_io_table_add(handle);

    select_info = globus_l_io_fd_table[handle->fd];
    
    if(cancel_callback != GLOBUS_NULL ||
       perform_callbacks)
    {
		/* create data structure to be used in the next poll to perform
		* the callbacks
		*/
		if(globus_l_io_cancel_free_list)
		{
			cancel_info = globus_l_io_cancel_free_list;
		    
			globus_l_io_cancel_free_list =
			globus_l_io_cancel_free_list->next;
		    
			cancel_info->next = GLOBUS_NULL;
		}
		else
		{
			cancel_info = globus_malloc(sizeof(globus_io_cancel_info_t));
		}
		memset(cancel_info,
			'\0',
			sizeof(globus_io_cancel_info_t));

		cancel_info->handle = select_info->handle;
    }
    
    /* store any callbacks in the cancel_info structure, and unregister
     * from the select masks
     */
    if (globus_l_io_read_isregistered(select_info->handle))
    {
		globus_bool_t			call_destructor = GLOBUS_FALSE;
		
		if(perform_callbacks)
		{
			cancel_info->read_callback = select_info->read_callback;
			cancel_info->read_arg = select_info->read_arg;
			cancel_info->read_dispatched = GLOBUS_FALSE;
			cancel_info->read_destructor = select_info->read_destructor;
		}
		else if(select_info->read_destructor != GLOBUS_NULL)
		{
			call_destructor = GLOBUS_TRUE;
			cancel_info->read_destructor = GLOBUS_NULL;
		}
		
		globus_i_io_unregister_read(select_info->handle,
						call_destructor);
    }

    if (globus_l_io_write_isregistered(select_info->handle))
    {
		globus_bool_t			call_destructor = GLOBUS_FALSE;
		
		if(perform_callbacks)
		{
			cancel_info->write_callback = select_info->write_callback;
			cancel_info->write_arg = select_info->write_arg;
			cancel_info->write_dispatched = GLOBUS_FALSE;
			cancel_info->write_destructor = select_info->write_destructor;
		}
		else if(select_info->write_destructor != GLOBUS_NULL)
		{
			call_destructor = GLOBUS_TRUE;
			cancel_info->write_destructor = GLOBUS_NULL;
		}
		
		globus_i_io_unregister_write(select_info->handle,
						call_destructor);
    }
    
    if (globus_l_io_except_isregistered(select_info->handle))
    {
		if(perform_callbacks)
		{
			cancel_info->except_callback = select_info->except_callback;
			cancel_info->except_arg = select_info->except_arg;
			cancel_info->except_dispatched = GLOBUS_FALSE;
		}
		
		globus_i_io_unregister_except(select_info->handle);
    }

    /* if we are performing any callbacks, add ourselves to the list */
    if(cancel_info)
    {
		cancel_info->cancel_dispatched = GLOBUS_FALSE;
		cancel_info->cancel_callback = cancel_callback;
		cancel_info->cancel_arg = cancel_arg;
		cancel_info->cancel_destructor = cancel_destructor;
		
		globus_l_io_enqueue(globus_l_io_cancel_list,
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

    globus_i_io_debug_printf(3, ("%s(): entering\n", myname));

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
				GLOBUS_FALSE);
    
    globus_i_io_mutex_unlock();
    globus_i_io_debug_printf(3, ("globus_io_register_cancel(): exiting\n"));
    
    return(GLOBUS_SUCCESS);

  error_exit:
    globus_i_io_mutex_unlock();
    return globus_error_put(err);
}
/* globus_io_register_cancel() */


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
globus_l_io_handle_events(void)
{
    globus_bool_t			done;
    int					n_ready;
    int					n_checked;
    globus_io_handle_t *		handle;
    int					select_errno;
    globus_io_select_info_t *		select_info;
    void *				arg;
    globus_io_callback_t		callback;
    static char *			myname="globus_l_io_handle_events";
    globus_reltime_t                    time_left;
    globus_bool_t                       use_timeout;
    int					n_fdcopy;
    globus_bool_t                       time_left_is_zero = GLOBUS_FALSE;
    globus_bool_t			handled_something = GLOBUS_FALSE;
    int                                 select_highest_fd;
#ifdef TARGET_ARCH_WIN32
	int rc;
	DWORD numberOfBytes;
	OVERLAPPED * overlappedPtr;
	WinIoOperation * winIoOperationPtr; // for the io operation object returned by GetQueuedCompletionStatus()
	DWORD winTimeout;
	globus_object_t * err;
	globus_result_t result;
#endif

    globus_i_io_debug_printf(5,
		       ("%s(): entering\n",
			myname));

    globus_callback_get_timeout(&time_left);

    globus_l_io_fd_table_modified = GLOBUS_FALSE;

    done = GLOBUS_FALSE;
    while (!done && !globus_l_io_shutdown_called)
    {
		/* Handle any cancel or secure read callbacks right away.
		* They do not need to block on the select but will 
		* kick out events.
		*/
		while(!globus_list_empty(globus_l_io_reads))
		{
			globus_io_select_info_t *	select_info;

			select_info = globus_list_first(globus_l_io_reads);
			handle = select_info->handle;
			callback = select_info->read_callback;
			arg = select_info->read_arg;
			globus_i_io_debug_printf(5,
						("%s(): non-selecting read, fd=%d\n",
						myname, handle->fd));
			globus_i_io_unregister_read(handle,
						GLOBUS_FALSE);
			globus_i_io_mutex_unlock();
			(*callback)(arg, handle, GLOBUS_SUCCESS);
			globus_i_io_mutex_lock();

			/* We've handled an event, so we don't need to
			* block in the select
			*/
			GlobusTimeReltimeSet(time_left, 0, 0);
			handled_something = GLOBUS_TRUE;

			/* Drop out of handling events if we've been
			* restarted, or we are deactivating
			*/
			if(globus_l_io_shutdown_called ||
			globus_callback_was_restarted())
			{
				goto handle_abort;
			}
		} /* end while */
		while(globus_l_io_cancel_list)
		{
			globus_io_cancel_info_t *	cancel_info;
			globus_object_t *		err;

			/*
			* We can safely peek at the head of the cancel list
			* until we've been restarted.
			*/
			cancel_info = globus_l_io_cancel_list;

			if(cancel_info->read_dispatched == GLOBUS_FALSE &&
			cancel_info->read_callback)
			{
				cancel_info->read_dispatched = GLOBUS_TRUE;
				handle = cancel_info->handle;
				callback = cancel_info->read_callback;
				arg = cancel_info->read_arg;

				err = globus_io_error_construct_io_cancelled(
					GLOBUS_IO_MODULE,
					GLOBUS_NULL,
					handle);

				globus_i_io_mutex_unlock();
				(*callback)(arg, handle, globus_error_put(err));
				globus_i_io_mutex_lock();

				handled_something = GLOBUS_TRUE;
				if(globus_callback_was_restarted() ||
				globus_l_io_shutdown_called)
				{
					goto end_cancel_handling;
				}
			}
			if(cancel_info->write_dispatched == GLOBUS_FALSE &&
			cancel_info->write_callback)
			{
				cancel_info->write_dispatched = GLOBUS_TRUE;
				handle = cancel_info->handle;
				callback = cancel_info->write_callback;
				arg = cancel_info->write_arg;

				err = globus_io_error_construct_io_cancelled(
					GLOBUS_IO_MODULE,
					GLOBUS_NULL,
					handle);
				globus_i_io_mutex_unlock();
				(*callback)(arg, handle, globus_error_put(err));
				globus_i_io_mutex_lock();

				handled_something = GLOBUS_TRUE;
				if(globus_callback_was_restarted() ||
				globus_l_io_shutdown_called)
				{
					goto end_cancel_handling;
				}
			}
			if(cancel_info->except_dispatched == GLOBUS_FALSE &&
			cancel_info->except_callback)
			{
				cancel_info->except_dispatched = GLOBUS_TRUE;
				handle = cancel_info->handle;
				callback = cancel_info->except_callback;
				arg = cancel_info->except_arg;
				
				err = globus_io_error_construct_io_cancelled(
					GLOBUS_IO_MODULE,
					GLOBUS_NULL,
					handle);
				globus_i_io_mutex_unlock();
				(*callback)(arg, handle, globus_error_put(err));
				globus_i_io_mutex_lock();

				handled_something = GLOBUS_TRUE;
				if(globus_callback_was_restarted() ||
				globus_l_io_shutdown_called)
				{
					goto end_cancel_handling;
				}
			}
			if(cancel_info->cancel_dispatched == GLOBUS_FALSE &&
			cancel_info->cancel_callback)
			{
				cancel_info->cancel_dispatched = GLOBUS_TRUE;
				handle = cancel_info->handle;
				callback = cancel_info->cancel_callback;
				arg = cancel_info->cancel_arg;
				globus_i_io_mutex_unlock();
				(*callback)(arg, handle, GLOBUS_SUCCESS);
				globus_i_io_mutex_lock();

				handled_something = GLOBUS_TRUE;
			}
			if(!globus_callback_was_restarted())
			{
				/*
				* remove it from the fifo after we've dispatched
				* all of the callbacks for this cancel_info.
				*/
				globus_assert(globus_l_io_cancel_list == cancel_info);
				globus_l_io_dequeue(globus_l_io_cancel_list,
							globus_l_io_cancel_tail,
							cancel_info);
				
				cancel_info->next = globus_l_io_cancel_free_list;
				globus_l_io_cancel_free_list = cancel_info;
			}

		end_cancel_handling:
			if(handled_something)
			{
					GlobusTimeReltimeSet(time_left, 0, 0);
			}
			/* Drop out of handling events if we've been
			* restarted, or we are deactivating
			*/
			if(globus_l_io_shutdown_called ||
			globus_callback_was_restarted())
			{
				goto handle_abort;
			}
		} /* end while */

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
#if !defined(TARGET_ARCH_WIN32) || defined(BUILD_LITE)
		if (globus_l_io_fd_num_set <= 0)
		{
			done = GLOBUS_TRUE;
			continue;
		}
#endif

#ifndef TARGET_ARCH_WIN32
		/*
		* round the highest fd to the nearest 64 bits, since we
		* do not know where in the struct it will be located
		* because of endian differences
		*/
		n_fdcopy = (globus_l_io_highest_fd+63)/8;
		memcpy(globus_l_io_active_read_fds, globus_l_io_read_fds, n_fdcopy);
		memcpy(globus_l_io_active_write_fds, globus_l_io_write_fds, n_fdcopy);
		memcpy(globus_l_io_active_except_fds, globus_l_io_except_fds, n_fdcopy);
#endif
#       if !defined(HAVE_THREAD_SAFE_SELECT)
		{
			GlobusTimeReltimeSet(time_left, 0, 0);
		}
#       endif

        if(globus_reltime_cmp(
               &time_left, 
               (globus_reltime_t *)&globus_i_reltime_infinity) == 0)
        {
            use_timeout = GLOBUS_FALSE;
        }	
        else
        {
            use_timeout = GLOBUS_TRUE;
        }
	
        if (globus_reltime_cmp(&time_left, 
                           (globus_reltime_t *) &globus_i_reltime_zero) == 0)
        {
            time_left_is_zero = GLOBUS_TRUE;
        }
#ifdef TARGET_ARCH_WIN32
		// For now, make sure the timeout is not zero; otherwise, this
		// loop could chew up 100% of the CPU time (it happened in
		// testing)
		if ( time_left_is_zero )
		{
			time_left_is_zero= GLOBUS_FALSE;
			winTimeout= 500;
		}
		else if ( use_timeout )
		{
			GlobusTimeReltimeToMilliSec( winTimeout, time_left );
		}
		else
			winTimeout= INFINITE;
#endif
		/*
		* If we were using a timeout on select() then we must release the
		* FD mutex so that other threads can do some work
		*/
		select_highest_fd = globus_l_io_highest_fd;
		if (!time_left_is_zero)
		{
			globus_l_io_select_active = GLOBUS_TRUE;
			globus_i_io_mutex_unlock();
		}
#ifndef TARGET_ARCH_WIN32
		globus_i_io_debug_printf(1,("%s(): Calling select()\n",myname));
		n_ready = select(select_highest_fd + 1,
				NEXUS_FD_SET_CAST globus_l_io_active_read_fds,
				NEXUS_FD_SET_CAST globus_l_io_active_write_fds,
				NEXUS_FD_SET_CAST globus_l_io_active_except_fds,
				(use_timeout ? &time_left : GLOBUS_NULL));
#else
		globus_i_io_debug_printf(1,("%s(): Calling GetQueuedCompletionStatus()\n",myname));
		//errno= 0; // reset state just to make sure
		// the completion key will be the globus I/O handle
		rc= GetQueuedCompletionStatus( completionPort, &numberOfBytes,
		 (PULONG_PTR)&handle, &overlappedPtr, winTimeout );
#endif
		select_errno = errno;

		globus_i_io_debug_printf(1,
				("%s(): select() returned\n",myname));

		/*
		* If we were using a timeout on select() then we must reacquire the
		* FD mutex and verify that our state hasn't changed
		*/
		if (!time_left_is_zero)
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
			globus_l_io_cond_signal();

			/*
			* If the FD table has been modified in a way which invalidates the
			* information returned by select(), then reset the modification
			* flag and retry the select()
			*/
			if (globus_l_io_fd_table_modified)
			{
				globus_l_io_fd_table_modified = GLOBUS_FALSE;
				globus_callback_get_timeout(&time_left);
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
			if (globus_l_io_shutdown_called)
			{
				break;
			}
		} /* end if */

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
			//fprintf( stderr, "GetQueuedCompletionStatus() timed out\n" );
			// END TESTING
			n_ready= 0;	// dispel the presumption
		}
		else if ( rc == 0 ) // an error occurred in the I/O operation
		{
			globus_i_io_windows_get_last_error();
			if ( errno == GLOBUS_WIN_EOF )
				err = globus_io_error_construct_eof(
						GLOBUS_IO_MODULE,
						GLOBUS_NULL,
						handle);
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
					// check whether a connection request is
					// pending by checking the readability of
					// this socket
					rc= globus_i_io_winsock_socket_is_readable( 
						(SOCKET)handle->io_handle, 500 );
					if ( rc == 0 ) // success- socket is readable
					{
						// call the callback
						select_info = globus_l_io_fd_table[handle->fd];
						callback = select_info->read_callback;
						arg = select_info->read_arg;
						globus_i_io_unregister_read(handle, GLOBUS_FALSE);

						globus_i_io_mutex_unlock();
						(*callback)( arg, handle, result );
						globus_i_io_mutex_lock();
					}
					else if ( rc == WSAETIMEDOUT )
					{
						// repost a packet
						int rc= globus_i_io_windows_post_completion( 
									handle, 
									WinIoListening );
						if ( rc ) // a fatal error occurred
						{
							// unregister the read callback
							globus_i_io_unregister_read( handle, GLOBUS_FALSE );

							err = globus_io_error_construct_system_failure(
									GLOBUS_IO_MODULE,
									GLOBUS_NULL,
									handle,
									rc );
							result= globus_error_put(err);
							globus_i_io_mutex_unlock();
							(*callback)( arg, handle, result );
							globus_i_io_mutex_lock();
						}
					}
					else // a fatal error occurred
					{
						// unregister the read callback
						globus_i_io_unregister_read( handle, GLOBUS_FALSE );

						err = globus_io_error_construct_system_failure(
								GLOBUS_IO_MODULE,
								GLOBUS_NULL,
								handle,
								rc );
						result= globus_error_put(err);
						globus_i_io_mutex_unlock();
						(*callback)( arg, handle, result );
						globus_i_io_mutex_lock();
					}
					break;
				case WinIoConnecting:
					// TESTING!!!
					//fprintf( stderr, "state is WinIoConnecting\n" );
					// END TESTING
					// WARNING: This state currently assumes that the
					// call to connect() blocks and therefore this
					// point in the code will not be reached unless the
					// call to connect() succeeds. When the attempt to
					// connect is made asynchronous, this assumption 
					// will no longer be true and the actual state of
					// the socket must be checked
					// this operation must trigger a callback registered
					// with globus_i_io_register_write_func()
					if ( !FD_ISSET( handle->io_handle, 
					 globus_l_io_write_fds ) )
						break; // we don't care about this handle any longer
					globus_i_io_debug_printf(5,
							("%s(): write, fd=%d\n", myname, handle->fd));
					select_info = globus_l_io_fd_table[handle->fd];
					callback = select_info->write_callback;
					arg = select_info->write_arg;
					globus_i_io_unregister_write(handle, GLOBUS_FALSE);

					globus_i_io_mutex_unlock();
					(*callback)( arg, handle, result );
					globus_i_io_mutex_lock();
					break;
				case WinIoAccepting:
					// TESTING!!!
					//fprintf( stderr, "state is WinIoAccepting\n" );
					// END TESTING
					/* WARNING: For now, this state occurs only after
					 *	a call to accept() has succeeded and the socket
					 *	does not authenticate. The callback was
					 *	registered in globus_io_tcp_register_accept()
					 *	using globus_i_io_register_write_func(), so we
					 *	must callback the "write" callback. (Sorry, no
					 *	pun intended)
					 */
					if ( !FD_ISSET( handle->io_handle, 
					 globus_l_io_write_fds ) )
						break; // we don't care about this handle any longer
					globus_i_io_debug_printf(5,
							("%s(): write, fd=%d\n", myname, handle->fd));
					select_info = globus_l_io_fd_table[handle->fd];
					callback = select_info->write_callback;
					arg = select_info->write_arg;
					globus_i_io_unregister_write(handle, GLOBUS_FALSE);

					globus_i_io_mutex_unlock();
					(*callback)( arg, handle, result );
					globus_i_io_mutex_lock();
					break;
				case WinIoReading:
					// TESTING!!!
					//fprintf( stderr, "state is WinIoReading\n" );
					//if ( result == GLOBUS_SUCCESS &&
						//handle->winIoOperation.operationAttempted == 1 )
					//fprintf( stderr, "Read completed; number of bytes read is %d\n", numberOfBytes );
					// END TESTING
					if ( !FD_ISSET( handle->io_handle, 
					 globus_l_io_read_fds ) )
						break; // we don't care about this handle any longer
					globus_i_io_debug_printf(5,
							("%s(): read, fd=%d\n", myname, handle->fd));
					// check for the EOF condition (which indicates a
					// graceful close by the other side in the case of
					// a socket); we need to make sure that an actual
					// I/O operation was attempted, otherwise this
					// completion packet is the result of a call to
					// PostQueuedCompletionStatus().
					if ( result == GLOBUS_SUCCESS && numberOfBytes == 0 
						//&& winIoOperationPtr->operationAttempted == 1 )
						&& handle->winIoOperation.operationAttempted == 1 )
					{
						err = globus_io_error_construct_eof(
								GLOBUS_IO_MODULE,
								GLOBUS_NULL,
								handle);
						result= globus_error_put(err);
					}
					if ( result == GLOBUS_SUCCESS )
						handle->winIoOperation.numberOfBytesProcessed= 
						 numberOfBytes;
					select_info = globus_l_io_fd_table[handle->fd];
					callback = select_info->read_callback;
					arg = select_info->read_arg;
					globus_i_io_unregister_read(handle, GLOBUS_FALSE);

					globus_i_io_mutex_unlock();
					(*callback)( arg, handle, result );
					globus_i_io_mutex_lock();

					break;
				case WinIoWriting:
					// TESTING!!!
					//fprintf( stderr, "state is WinIoWriting\n" );
					// END TESTING
					if ( !FD_ISSET( handle->io_handle, 
					 globus_l_io_write_fds ) )
						break; // we don't care about this handle any longer
					globus_i_io_debug_printf(5,
							("%s(): write, fd=%d\n", myname, handle->fd));
					if ( result == GLOBUS_SUCCESS )
						handle->winIoOperation.numberOfBytesProcessed= 
						 numberOfBytes;
					select_info = globus_l_io_fd_table[handle->fd];
					callback = select_info->write_callback;
					arg = select_info->write_arg;
					globus_i_io_unregister_write(handle, GLOBUS_FALSE);

					globus_i_io_mutex_unlock();
					(*callback)( arg, handle, result );
					globus_i_io_mutex_lock();
					break;
				case WinIoWakeup:
				    globus_l_io_wakeup_pending = GLOBUS_FALSE;
					break;
			} // end switch

			if (globus_callback_was_restarted())
				goto handle_abort;
		} // end if
#endif /* TARGET_ARCH_WIN32*/

#ifndef TARGET_ARCH_WIN32
		if (n_ready < 0)
		{
			if (select_errno == EINTR)
			{
				continue;
			}
			else
			{
				goto handle_abort;
			}
		}
		else if (n_ready > 0)
		{
			int fd;
		   
			done = GLOBUS_TRUE;
			handled_something = GLOBUS_TRUE;
	    
			for (n_checked = 0, fd = globus_l_io_select_count%(select_highest_fd+1);
			n_checked < n_ready;
			fd++)
			{
				if(fd == select_highest_fd+1)
				{
					fd = 0;
				}
				if (FD_ISSET(fd, globus_l_io_active_read_fds))
				{
                    n_checked++;

                    /* Only do the callback if we are still interested
                     * in the FD
                     */
                    if (FD_ISSET(fd, globus_l_io_read_fds))
                    {
						select_info = globus_l_io_fd_table[fd];
						handle = select_info->handle;
						callback = select_info->read_callback;
						arg = select_info->read_arg;
						globus_i_io_debug_printf(5,
								("%s(): read, fd=%d\n", myname, fd));
						globus_i_io_unregister_read(handle,
									GLOBUS_FALSE);

						globus_i_io_mutex_unlock();
						(*callback)(arg, handle, GLOBUS_SUCCESS);
						globus_i_io_mutex_lock();

						if (globus_callback_was_restarted())
						{
							goto handle_abort;
						}
                    }

                    if (n_checked == n_ready)
					{
						break;
					}
				}
				if (FD_ISSET(fd, globus_l_io_active_write_fds))
				{
					n_checked++;

                    /* Only do the callback if we are still interested
                     * in the FD
                     */
                    if (FD_ISSET(fd, globus_l_io_write_fds))
                    {
						globus_i_io_debug_printf(5,
								("%s(): write, fd=%d\n", myname, fd));
						select_info = globus_l_io_fd_table[fd];
						handle = select_info->handle;
						callback = select_info->write_callback;
						arg = select_info->write_arg;
						globus_i_io_unregister_write(handle, GLOBUS_FALSE);

						globus_i_io_mutex_unlock();
						(*callback)(arg, handle, GLOBUS_SUCCESS);
						globus_i_io_mutex_lock();

						if (globus_callback_was_restarted())
						{
							goto handle_abort;
						}
					}
					if (n_checked == n_ready)
					{
						break;
					}
				}
				if (FD_ISSET(fd, globus_l_io_active_except_fds))
				{
					n_checked++;

                    /* Only do the callback if we are still interested
                     * in the FD
                     */
					if (FD_ISSET(fd, globus_l_io_except_fds))
                    {
						globus_i_io_debug_printf(5,
								("%s(): except, fd=%d\n", myname, fd));
						select_info = globus_l_io_fd_table[fd];
						handle = select_info->handle;
						callback = select_info->except_callback;
						arg = select_info->except_arg;
						globus_i_io_unregister_except(handle);

						globus_i_io_mutex_unlock();
						(*callback)(arg, handle, GLOBUS_SUCCESS);
						globus_i_io_mutex_lock();

						if (globus_callback_was_restarted())
						{
							goto handle_abort;
						}
					}

					if (n_checked == n_ready)
					{
					break;
					}
				}
		    } /* for */
		} /* endif */
#endif /* !TARGET_ARCH_WIN32 */

		if ( n_ready == 0 )
		{
			done = GLOBUS_TRUE;
		}
    } /* end while */

handle_abort:
    globus_i_io_debug_printf(5, ("%s(): exiting\n",myname));
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
    char				buf;
    ssize_t				done = 0;

    while (!done)
    {
		done = globus_libc_read(handle->fd, &buf, sizeof(buf));
		if (done == -1)
		{
			const int			errno_save = errno;

			if (errno_save == EINTR)
			{
				done = 0;
			}
			else if (errno_save != EAGAIN && errno_save != EWOULDBLOCK)
			{
			/* XXX: badness has happened; do something about it */
			}
		}
    }

    globus_i_io_mutex_lock();
    globus_l_io_wakeup_pending = GLOBUS_FALSE;
    if(globus_l_io_shutdown_called == GLOBUS_FALSE)
    {	
	globus_i_io_register_read_func(handle,
				       globus_l_io_wakeup_pipe_callback,
				       GLOBUS_NULL,
				       GLOBUS_NULL,
				       GLOBUS_TRUE);
    }
    globus_i_io_mutex_unlock();
#endif /* TARGET_ARCH_WIN32 */
}
/* globus_l_io_wakeup_pipe_callback() */


static globus_bool_t
globus_l_io_poll(
    globus_abstime_t *                  time_stop,
    void *                              user_args)
{
    int                                 events_handled=0;

    globus_i_io_mutex_lock();
    do
    {
        events_handled = 
            globus_l_io_handle_events();
    }
    while(events_handled == 00 &&
	  !globus_l_io_shutdown_called &&
          !globus_callback_has_time_expired());

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
                    &globus_l_io_callback_handle,
                    &new_period);
            }
        }
    }
#   endif

    globus_i_io_mutex_unlock();
    return (events_handled > 0);
}

static void
globus_l_io_handler_wakeup(void *arg)
{
    globus_l_io_shutdown_called = GLOBUS_TRUE;
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
#ifdef TARGET_ARCH_WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
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

    globus_i_io_debug_printf(3, ("globus_l_io_activate(): entering\n"));

    globus_l_io_core_wakeup_func_ptr = GLOBUS_NULL;
    globus_l_io_shutdown_called = GLOBUS_FALSE;

    globus_mutex_init(&globus_i_io_mutex, (globus_mutexattr_t *) GLOBUS_NULL);
    globus_cond_init(&globus_i_io_cond, (globus_condattr_t *) GLOBUS_NULL);

    globus_l_io_cancel_list = GLOBUS_NULL;
    globus_l_io_cancel_tail = GLOBUS_NULL;
    globus_l_io_cancel_free_list = GLOBUS_NULL;

    globus_l_io_reads = GLOBUS_NULL;

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

#   if defined (HAVE_THREAD_SAFE_SELECT)
    {
        globus_l_io_core_wakeup_func_ptr = globus_l_io_handler_wakeup;
    }
#   endif


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

    globus_l_io_fd_table = (globus_io_select_info_t **)
	globus_malloc(sizeof(globus_io_select_info_t *) *
		      globus_l_io_fd_tablesize);
    
    for (i = 0; i < globus_l_io_fd_tablesize; i++)
    {
		globus_l_io_fd_table[i] = (globus_io_select_info_t *) GLOBUS_NULL;
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
/* The pipe references were taken out in order to compile an
 * initial version of Globus IO on Windows.
 * -- Michael Lebman, 3-2-02
 */
    /*
     * Create a pipe to myself, so that I can wake up the thread that is
     * blocked on a select().
     */
    if (pipe(globus_l_io_wakeup_pipe) != 0)
    {
        rc = -1;
        goto unlock_and_abort;
    }
    rc = globus_l_io_internal_handle_create(globus_l_io_wakeup_pipe[0],
					    &globus_l_io_wakeup_pipe_handle);
    if(rc != 0)
    {
		rc = -2;
		goto unlock_and_abort;
    }
    
    globus_i_io_setup_nonblocking(&globus_l_io_wakeup_pipe_handle);
    globus_i_io_register_read_func(&globus_l_io_wakeup_pipe_handle,
				   globus_l_io_wakeup_pipe_callback,
				   GLOBUS_NULL,
				   GLOBUS_NULL,
				   GLOBUS_TRUE);
#else
	// initialize the wakeup handle
	// first, create a dummy socket
    winWakeUpHandle.io_handle = (HANDLE)socket( AF_INET,
	 SOCK_STREAM, 0 );
    if( (SOCKET)winWakeUpHandle.io_handle == INVALID_SOCKET )
    {
		rc = -2;
		goto unlock_and_abort;
    }
	// initialize the WinIoOperation struct
	globus_i_io_windows_init_io_operation( 
	 &(winWakeUpHandle.winIoOperation) );
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
    globus_callback_register_periodic(
			     &globus_l_io_callback_handle,
                             &delay,
                             &delay,
               		     globus_l_io_poll,
			     GLOBUS_NULL,
			     globus_l_io_core_wakeup_func_ptr,
			     GLOBUS_NULL);

  unlock_and_abort:
    globus_i_io_mutex_unlock();

    globus_i_io_debug_printf(3, ("globus_l_io_activate(): exiting\n"));
    
    return rc;
}
/* globus_l_io_activate() */

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

    globus_i_io_debug_printf(3, ("globus_l_io_deactivate(): entering\n"));

    globus_i_io_mutex_lock();

    globus_l_io_shutdown_called = GLOBUS_TRUE;

    /* Wakeup the handler thread from the select(), and close the pipe to
     * ourself.
     */
    if (globus_l_io_select_active)
    {
		globus_l_io_select_wakeup();
    }

    /*
     * Wait for any outstanding calls into the handler (or handler thread)
     * to complete. This will deadlock if the deactivate is called from
     * a handler thread.
     */
    globus_i_io_mutex_unlock();
    {
		globus_i_callback_blocking_cancel(&globus_l_io_callback_handle);
    }
    globus_i_io_mutex_lock();

#ifndef TARGET_ARCH_WIN32
/* The pipe references were taken out in order to compile an
 * initial version of Globus IO on Windows.
 * -- Michael Lebman, 3-2-02
 */
    globus_i_io_close(&globus_l_io_wakeup_pipe_handle);
    
    while(globus_libc_close(globus_l_io_wakeup_pipe[1]) < 0)
    {
		int save_errno = errno;
		if(save_errno != EINTR)
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
		globus_io_select_info_t *	select_info;

		select_info = globus_l_io_fd_table[fd];

		if(select_info != GLOBUS_NULL)
		{
			if(select_info->read_arg &&
			 select_info->read_destructor)
			{
				select_info->read_destructor(select_info->read_arg);
			}
			if(select_info->write_arg &&
			 select_info->write_destructor)
			{
				select_info->write_destructor(select_info->write_arg);
			}
			globus_l_io_table_remove_fd(fd);
		}
    }
    globus_free(globus_l_io_fd_table);

    /* free any cancel data structures */
    while(globus_l_io_cancel_list)
    {
		globus_io_cancel_info_t *	tmp;

		globus_l_io_dequeue(globus_l_io_cancel_list,
					globus_l_io_cancel_tail,
					tmp);
		
		if(tmp->read_arg &&
		tmp->read_destructor &&
		(!tmp->read_dispatched))
		{
			tmp->read_destructor(tmp->read_arg);
		}
		if(tmp->write_arg &&
		tmp->write_destructor &&
		(!tmp->write_dispatched))
		{
			tmp->write_destructor(tmp->write_arg);
		}
		if(tmp->cancel_arg &&
		tmp->cancel_destructor &&
		(!tmp->cancel_dispatched))
		{
			tmp->cancel_destructor(tmp->cancel_arg);
		}
		globus_free(tmp);
    }
    while(globus_l_io_cancel_free_list)
    {
		globus_io_cancel_info_t *	tmp;
		globus_l_io_dequeue(globus_l_io_cancel_free_list,
					GLOBUS_NULL,
					tmp);
		globus_free(tmp);
    }

    /* Free up list of non-selecting reads */
    globus_list_free(globus_l_io_reads);
    
    if(globus_i_io_tcp_used_port_table) 
    {
        globus_free(globus_i_io_tcp_used_port_table);
    }
    if(globus_i_io_udp_used_port_table) 
    {
        globus_free(globus_i_io_udp_used_port_table);
    }
    globus_i_io_mutex_unlock();
    globus_i_io_debug_printf(3, ("globus_l_io_deactivate(): exiting\n"));

    globus_module_deactivate(GLOBUS_ERROR_MODULE);
    globus_mutex_destroy(&globus_i_io_mutex);
    globus_cond_destroy(&globus_i_io_cond);
    rc = globus_module_deactivate(GLOBUS_COMMON_MODULE);
#ifdef TARGET_ARCH_WIN32
	WSACleanup();
	CloseHandle( completionPort );
#endif
    if(rc != GLOBUS_SUCCESS)
    {
       return rc;
    }

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

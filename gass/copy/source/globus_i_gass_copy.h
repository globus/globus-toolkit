
#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * valid URL schemes
 */
typedef enum
{
    GLOBUS_I_GASS_COPY_URL_SCHEME_UNSUPPORTED,
    GLOBUS_I_GASS_COPY_URL_SCHEME_FTP,
    GLOBUS_I_GASS_COPY_URL_SCHEME_HTTP,
    GLOBUS_I_GASS_COPY_URL_SCHEME_FILE,
} globus_i_gass_copy_url_scheme_t;

/**
 * valid target modes
 */
typedef enum
{
    GLOBUS_I_GASS_COPY_TARGET_MODE_FTP,
    GLOBUS_I_GASS_COPY_TARGET_MODE_GASS,
    GLOBUS_I_GASS_COPY_TARGET_MODE_IO,
} globus_i_gass_copy_target_mode_t;

/**
 * target status
 */
typedef enum
{
    GLOBUS_I_GASS_COPY_TARGET_INITIAL,
    GLOBUS_I_GASS_COPY_TARGET_READY,
    GLOBUS_I_GASS_COPY_TARGET_DONE,
} globus_i_gass_copy_target_status_t;


/** 
 * valid state numbers (aka states)
 */
typedef enum
{
    GLOBUS_I_GASS_COPY_STATE_INITIAL,
    GLOBUS_I_GASS_COPY_STATE_SOURCE_READY,
    GLOBUS_I_GASS_COPY_STATE_TRANSFER_IN_PROGRESS,
    GLOBUS_I_GASS_COPY_STATE_READ_COMPLETE,
    GLOBUS_I_GASS_COPY_STATE_WRITE_COMPLETE,
} globus_i_gass_copy_state_number_t;

/**
 * The buffer structure used for read/write queue entries
 */
typedef struct
{
    globus_byte_t *                     bytes;
    globus_size_t                       nbytes;
    globus_size_t                       offset;
    globus_bool_t                       last_data;
} globus_i_gass_copy_buffer_t;

/**
 * The state monitor struct
 */
typedef struct
{
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;
    volatile globus_bool_t              done;
} globus_i_gass_copy_monitor_t;

/**
 * GASS copy target (e.g. source, destination) transfer information.
 */
typedef struct globus_i_gass_copy_state_target_s
{
    /**
     * url for file transfer
     */
    char *					url;

    /**
     * attributes to control file transfer
     */
    globus_gass_copy_attr_t			attr;

    /**
     * coordinates the modifying of the target structure
     */
    globus_mutex_t                              mutex;

    /**
     * a queue to manage the reading/writing of data buffers
     */
    globus_fifo_t                               queue;

    /**
     * Used for keeping track of  reads/writes in the read/write queue
     */
    int                                 n_pending;

    /**
     * Used to limit the number of n_pending
     */
    int                                 n_simultaneous;

    /**
     * signifies the target has been successfully setup
     */
    globus_i_gass_copy_target_status_t         status;

    /**
     * mode used to identify the below target union struct.
     */
    globus_i_gass_copy_target_mode_t		mode;

    /**
     * data required to perform each type of transfer
     */
    union
    {
        /**
         * ftp specific data
         */

	struct /* GLOBUS_I_GASS_COPY_TARGET_MODE_FTP */
	{
#ifdef USE_FTP
	    globus_ftp_handle *			handle;
#endif
	    int					n_channels;
	    int					n_reads_posted;
	} ftp;
	
        /**
         * GASS specific data
         */
	struct /* GLOBUS_I_GASS_COPY_TARGET_MODE_GASS */
	{
            /**
             * GASS equivelent of a handle
             */
	    globus_gass_transfer_request_t	request;
	} gass;
	
        /**
         * IO specific data
         */
	struct /* GLOBUS_I_GASS_COPY_TARGET_MODE_IO */
	{

	    globus_io_handle_t *		handle;

            /**
             * If the IO handle was passed as an argument then FALSE
             * If the IO handle was created internally then TRUE
             */
	    globus_bool_t			free_handle;

            /**
             * Can globus_io_file_seek() be performed on this handle?
             */
	    globus_bool_t			seekable;
	} io;
    } data;
} globus_i_gass_copy_target_t;


/**
 * The state structure contains all that is required to perform a file transfer
 * from a source to a destination.
 */
typedef struct globus_i_gass_copy_state_s
{
    /**
     * handle.  Useful for saving ftp server connections when doing multiple
     * globus_gass_copy_* calls to/from the same url's
     */
    globus_gass_copy_handle_t *		handle;

    /**
     * Source information for the file transfer
     */
    globus_i_gass_copy_target_t	source;

    /**
     * Dest information for the file transfer
     */
    globus_i_gass_copy_target_t	dest;

    /**
     * Used for keeping state of the transfer.
     * (state.state seemed like a bad idea. ;-)
     */
    globus_i_gass_copy_state_number_t	number;

    /**
     * Used for signalling from the various callback functions
     */
    globus_i_gass_copy_monitor_t        monitor;

    /*
     * total number of read/write buffers that can be used at a time
     */
    int                                 max_buffers;
    /*
     * number of buffers that have been allocated for reading/writing
     */
    int                                 n_buffers;
    /*
     * size of the buffers
     */
    int                                 buffer_length;

    /*
     * pointer to user callback function
     */
    globus_gass_copy_callback_t         user_callback;
    /*
     * pointer to user argument to user callback function
     */
    void *                              callback_arg;

    /*
     * the result of the data transfer, error or otherwise
     */
    globus_result_t                     result;

    int                                 err;

    /**
     * coordinates the modifying of the state,  aside from the target structures
     */
    globus_mutex_t                      mutex;
    
} globus_i_gass_copy_state_t;


#endif


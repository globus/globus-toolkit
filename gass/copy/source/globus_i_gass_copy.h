/**
 * @file globus_i_gass_copy.h
 * Globus GASS Copy Library
 */
#include "globus_gass_copy.h"
#include "globus_common.h"

#ifndef GLOBUS_L_INCLUDE_GLOBUS_GASS_COPY_H
#define GLOBUS_L_INCLUDE_GLOBUS_GASS_COPY_H

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

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

typedef enum
{
    GLOBUS_I_GASS_COPY_CANCEL_FALSE,
    GLOBUS_I_GASS_COPY_CANCEL_TRUE,
    GLOBUS_I_GASS_COPY_CANCEL_CALLED,
    GLOBUS_I_GASS_COPY_CANCEL_DONE,
} globus_i_gass_copy_cancel_status_t;


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
  globus_bool_t                       use_err;
  globus_object_t *                   err;
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

    /* If the attr was passed as an argument then FALSE
     * If the attr was created internally then TRUE
     */
  globus_bool_t			                free_attr;

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
     * Used to compute the offset for ftp writes
     */
    int                                 n_complete;

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
	  /* FIXX - not sure that any of this is needed
	   * same as n_simultaneous and n_pending, and there's
	   * already an ftp_handle in the copy_handle
	   */
	    globus_ftp_client_handle_t *		handle;
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

    globus_i_gass_copy_cancel_status_t cancel;
} globus_i_gass_copy_target_t;


/**
 * The state structure contains all that is required to perform a file transfer
 * from a source to a destination.
 */
struct globus_gass_copy_state_s
{
    /**
     * Source information for the file transfer
     */
    globus_i_gass_copy_target_t	source;

    /**
     * Dest information for the file transfer
     */
    globus_i_gass_copy_target_t	dest;

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
  
    /**
     * coordinates the modifying of the state,  aside from the target structures
     */
    globus_mutex_t                      mutex;
    
};


#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

EXTERN_C_END

#endif /*GLOBUS_L_INCLUDE_GLOBUS_GASS_COPY_H */

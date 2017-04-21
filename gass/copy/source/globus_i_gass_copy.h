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

#ifndef GLOBUS_I_GASS_COPY_H
#define GLOBUS_I_GASS_COPY_H

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * @file globus_i_gass_copy.h
 * @brief Globus GASS Copy Library Internals
 */

#include "globus_gass_copy.h"
#include "globus_common.h"
#include "globus_error_string.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * target status
 */
typedef enum
{
    GLOBUS_I_GASS_COPY_TARGET_INITIAL,
    GLOBUS_I_GASS_COPY_TARGET_READY,
    GLOBUS_I_GASS_COPY_TARGET_DONE,
    GLOBUS_I_GASS_COPY_TARGET_FAILED
} globus_i_gass_copy_target_status_t;

typedef enum
{
    GLOBUS_I_GASS_COPY_CANCEL_FALSE,
    GLOBUS_I_GASS_COPY_CANCEL_TRUE,
    GLOBUS_I_GASS_COPY_CANCEL_CALLED
} globus_i_gass_copy_cancel_status_t;


/**
 * The buffer structure used for read/write queue entries
 */
typedef struct
{
    globus_byte_t *                     bytes;
    globus_size_t                       nbytes;
    globus_off_t                        offset;
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
 * gass copy cancel struct
 */
typedef struct globus_i_gass_copy_cancel_s
{
  /*
   * the gass copy handle
   */
  globus_gass_copy_handle_t * handle;

  /*
   * Indicates which side of the transfer to cancel
   * If TRUE then cancelling the source otherwise the destination.
   */
  globus_bool_t              canceling_source;

} globus_i_gass_copy_cancel_t;

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
    globus_gass_copy_attr_t *			attr;

    /* If the attr was passed as an argument then FALSE
     * If the attr was created internally then TRUE
     */
    globus_bool_t		                free_attr;
    globus_bool_t                               free_ftp_attr;
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
    int                                         n_pending;

    /**
     * Used to limit the number of n_pending
     */
    int                                         n_simultaneous;

    /**
     * Used to compute the offset for ftp writes
     */
    int                                         n_complete;

    /**
     * signifies the target has been successfully setup
     */
    globus_i_gass_copy_target_status_t          status;

    /**
     * mode used to identify the below target union struct.
     */
    globus_gass_copy_url_mode_t	                mode;

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
	    globus_ftp_client_handle_t *        handle;
	    globus_bool_t                       completed;
	    int					n_channels;
	    int					n_reads_posted;
	    globus_object_t *                   data_err;
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
     * active transfer with valid targets
     */
    globus_bool_t                       active;

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

    /**
     * indicates the status of the cancel operation.
     */
    globus_i_gass_copy_cancel_status_t cancel;

    /**
    * Handle to compare checksum on source and dest files after transfer.
    */
    struct globus_gass_copy_handle_s    *cksm_handle;   
    
    /**
    * Stored checksum of the source file
    */
    char                                *checksum;
    
    /**
    * Checksum algorithm
    */
    char                                *algorithm;
};

globus_result_t
globus_i_gass_copy_state_new(
    globus_gass_copy_handle_t *handle);

#ifdef __cplusplus
}
#endif

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

#endif /* GLOBUS_I_GASS_COPY_H */

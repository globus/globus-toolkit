 /**
 * @mainpage
 *
 * The Globus GASS Copy library is motivated by the desire to provide a
 * uniform interface to transfer files specified by different protocols.
 *
 * The goals in doing this are to:

 *   - Provide a robust way to describe and apply file transfer properties
 * for a variety of protocols. These include the standard HTTP, FTP and
 * GSIFTP options.  Some of the new file transfer capabilities in GSIFTP are
 * parallel, striping, authentication and TCP buffer sizing.
 *   - Provide a service to support nonblocking file transfer and handle
 * asynchronous file and network events.
 *   - Provide a simple and portable way to implement file transfers.
 *
 * Any program that uses Globus GASS Copy functions must include
 * "globus_gass_copy.h".
 *
 * @htmlonly
 * <a href="main.html" target="_top">View documentation without frames</a><br>
 * <a href="index.html" target="_top">View documentation with frames</a><br>
 * @endhtmlonly
 */

#include "globus_gass_transfer.h"
#include "globus_ftp_client.h"
#include "globus_io.h"


#ifndef GLOBUS_INCLUDE_GLOBUS_GASS_COPY_H
#define GLOBUS_INCLUDE_GLOBUS_GASS_COPY_H

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

/** Module descriptor
 *
 * Globus GASS Copy uses standard Globus module activation and deactivation.
 * Before any Globus GASS Copy functions are called, the following function
 * must be called:
 *
 * @code
 *      globus_module_activate(GLOBUS_GASS_COPY_MODULE)
 * @endcode
 *
 *
 * This function returns GLOBUS_SUCCESS if Globus GASS Copy was successfully
 * initialized, and you are therefore allowed to subsequently call
 * Globus GASS Copy functions.  Otherwise, an error code is returned, and
 * Globus GASS Copy functions should not be subsequently called. This
 * function may be called multiple times.
 *
 * To deactivate Globus GASS Copy, the following function must be called:
 *
 * @code
 *    globus_module_deactivate(GLOBUS_GASS_COPY_MODULE)
 * @endcode
 *
 * This function should be called once for each time Globus GASS Copy was
 * activated.
 *
 */
#define GLOBUS_GASS_COPY_MODULE (&globus_i_gass_copy_module)

extern
globus_module_descriptor_t        globus_i_gass_copy_module;

typedef struct globus_gass_copy_state_s globus_gass_copy_state_t;
typedef struct globus_gass_copy_handle_s globus_gass_copy_handle_t;
typedef struct globus_gass_copy_perf_info_s globus_gass_copy_perf_info_t;

/**
 * Gass copy transfer performance callback
 *
 * This callback is registered with 'globus_gass_copy_register_performance_cb'
 * It will be called during a transfer to supply performance information on
 * current transfer.  Its frequency will be at most one per second, but
 * it is possible to receive no callbacks. This is possible in very short
 * transfers and in ftp transfers in which the server does not provide
 * performance information.
 *
 * @param handle
 *        the gass copy handle this transfer is occurring on
 *
 * @param user_arg
 *        a user pointer registered with
 *        'globus_gass_copy_register_performance_cb'
 *
 * @param total_bytes
 *        the total number of bytes transfer so far
 *
 * @param instantaneous_throughput
 *        instantaneous rate of transfer (since last callback or start)
 *        (bytes / sec)
 *
 * @param avg_throughput
 *        the avg thoughput calculated since the start of the transfer
 *        (bytes / sec)
 *
 * @return
 *        - n/a
 */

typedef void (*globus_gass_copy_performance_cb_t)(
    void *                                          user_arg,
    globus_gass_copy_handle_t *                     handle,
    globus_off_t                                    total_bytes,
    float                                           instantaneous_throughput,
    float                                           avg_throughput);

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

/**
 * Signature of a callback from globus_gass_copy_register_*() functions.
 * (asynchronous transfer functions)
 */
typedef void (*globus_gass_copy_callback_t)(
    void * callback_arg,
    globus_gass_copy_handle_t * handle,
    globus_object_t * error);

/**
 * valid state status (aka states)
 */
typedef enum
{
    GLOBUS_GASS_COPY_STATUS_NONE,
    GLOBUS_GASS_COPY_STATUS_PENDING,
    GLOBUS_GASS_COPY_STATUS_INITIAL,
    GLOBUS_GASS_COPY_STATUS_SOURCE_READY,
    GLOBUS_GASS_COPY_STATUS_TRANSFER_IN_PROGRESS,
    GLOBUS_GASS_COPY_STATUS_READ_COMPLETE,
    GLOBUS_GASS_COPY_STATUS_WRITE_COMPLETE,
    GLOBUS_GASS_COPY_STATUS_DONE,
    GLOBUS_GASS_COPY_STATUS_FAILURE,
    GLOBUS_GASS_COPY_STATUS_CANCEL,
    GLOBUS_GASS_COPY_STATUS_DONE_SUCCESS,
    GLOBUS_GASS_COPY_STATUS_DONE_FAILURE,
    GLOBUS_GASS_COPY_STATUS_DONE_CANCELLED
} globus_gass_copy_status_t;

/**
 * valid url modes
 */
typedef enum
{
    GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED,
    GLOBUS_GASS_COPY_URL_MODE_FTP,
    GLOBUS_GASS_COPY_URL_MODE_GASS,
    GLOBUS_GASS_COPY_URL_MODE_IO
} globus_gass_copy_url_mode_t;

/**
 * gass copy handle
 */
struct globus_gass_copy_handle_s
{
  /*
   * the status of the current transfer
   */
  globus_gass_copy_status_t  status;

  /*
   * pointer to the state structure which contains internal info related to a
   * transfer
   */
  globus_gass_copy_state_t * state;

  /*
   * pointer to user data
   */
  void *		     user_pointer;

  /* pointer to perf_info structure used to provide the user transfer
   * performance information
   */
  globus_gass_copy_perf_info_t * performance;

  /*
   * indicates if the 3rd party transfer is done by this library or externally
   * to this library.
   */
  globus_bool_t         external_third_party;

  /*
   * pointer to user callback function
   */
  globus_gass_copy_callback_t         user_callback;

  /*
   * pointer to user argument to user callback function
   */
  void *                              callback_arg;

  /*
   * pointer to user cancel callback function
   */
  globus_gass_copy_callback_t         user_cancel_callback;

  /*
   * pointer to user argument to user cancel callback function
   */
  void *                              cancel_callback_arg;

  /*
   * Error object to pass to the callback function
   */
  globus_object_t *                   err;

  /*
   * size of the buffers to be used in the transfers
   */
  int                                 buffer_length;

  /*
   * says whether third_party transfers should be used (for ftp to
   * ftp transfers).  if set to FALSE, the default,
   * globus_ftp_client_third_party_transfer() will be used.  if set to
   * TRUE, gass_copy will manage the transfer
   */
  globus_bool_t                       no_third_party_transfers;

  globus_ftp_client_handle_t	      ftp_handle;
  /* this handle only used when no_third_party_transfers is true (for 3pt) */
  globus_ftp_client_handle_t	      ftp_handle_2;
};

/**
 * GASS Copy attribute structure.  Contains any/all attributes that are
 * required to perform the supported transfer methods (ftp, gass, io).
 */
typedef struct globus_gass_copy_attr_s
{
  globus_ftp_client_operationattr_t * ftp_attr;
  globus_io_attr_t * io;
  globus_gass_transfer_requestattr_t * gass_requestattr;
} globus_gass_copy_attr_t;

/**
 * GASS Copy Handle attribute structure. Contains any/all attributes that
 * are required to create lower-level handles (ftp, gass, io).
 */
typedef struct globus_gass_copy_handleattr_s
{
  globus_ftp_client_handleattr_t *	ftp_attr;
} globus_gass_copy_handleattr_t;

/** initialization and destruction of GASS Copy handle */
globus_result_t
globus_gass_copy_handle_init(
    globus_gass_copy_handle_t * handle,
    globus_gass_copy_handleattr_t * handle_attr);

globus_result_t
globus_gass_copy_handle_destroy(
    globus_gass_copy_handle_t * handle);

globus_result_t
globus_gass_copy_handleattr_init(
    globus_gass_copy_handleattr_t * handle_attr);

globus_result_t
globus_gass_copy_handleattr_destroy(
    globus_gass_copy_handleattr_t * handle_attr);

globus_result_t
globus_gass_copy_handleattr_set_ftp_attr(
    globus_gass_copy_handleattr_t * handle_attr,
    globus_ftp_client_handleattr_t * ftp_attr);

/** set the size of the buffer to be used for the transfers */
globus_result_t
globus_gass_copy_set_buffer_length(
    globus_gass_copy_handle_t * handle,
    int length);

/** get the size of the buffer being used for the transfers */
globus_result_t
globus_gass_copy_get_buffer_length(
    globus_gass_copy_handle_t * handle,
    int * length);

/** sets whether third_party transfers should be used for ftp to
  * ftp transfers */
globus_result_t
globus_gass_copy_set_no_third_party_transfers(
    globus_gass_copy_handle_t * handle,
    globus_bool_t no_third_party_transfers);

/** get the size of the buffer being used for the transfers */
globus_result_t
globus_gass_copy_get_no_third_party_transfers(
    globus_gass_copy_handle_t * handle,
    globus_bool_t * no_third_party_transfers);


/* find out what transfer mode will be used for a given url, so that the proper attributes may be passed to one of the copy function */
globus_result_t
globus_gass_copy_get_url_mode(
    char * url,
    globus_gass_copy_url_mode_t * mode);

/** initialize the attr structure */
globus_result_t
globus_gass_copy_attr_init(
    globus_gass_copy_attr_t * attr);

/** functions for setting attributes for specific protocols */
globus_result_t
globus_gass_copy_attr_set_ftp(
    globus_gass_copy_attr_t * attr,
    globus_ftp_client_operationattr_t * ftp_attr);

globus_result_t
globus_gass_copy_attr_set_io(
    globus_gass_copy_attr_t * attr,
    globus_io_attr_t * io_attr);

globus_result_t
globus_gass_copy_attr_set_gass(
    globus_gass_copy_attr_t * attr,
    globus_gass_transfer_requestattr_t * gass_attr);

/**
 * copy functions (blocking)
 */
globus_result_t
globus_gass_copy_url_to_url(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    globus_gass_copy_attr_t * source_attr,
    char * dest_url,
    globus_gass_copy_attr_t * dest_attr);

globus_result_t
globus_gass_copy_url_to_handle(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    globus_gass_copy_attr_t * source_attr,
    globus_io_handle_t * dest_handle);

globus_result_t
globus_gass_copy_handle_to_url(
    globus_gass_copy_handle_t * handle,
    globus_io_handle_t * source_handle,
    char * dest_url,
    globus_gass_copy_attr_t * dest_attr);

/**
 * copy functions (asyncronous)
 */
globus_result_t
globus_gass_copy_register_url_to_url(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    globus_gass_copy_attr_t * dest_attr,
    char * dest_url,
    globus_gass_copy_attr_t * source_attr,
    globus_gass_copy_callback_t callback_func,
    void * callback_arg);

globus_result_t
globus_gass_copy_register_url_to_handle(
    globus_gass_copy_handle_t * handle,
    char * source_url,
    globus_gass_copy_attr_t * source_attr,
    globus_io_handle_t * dest_handle,
    globus_gass_copy_callback_t callback_func,
    void * callback_arg);

globus_result_t
globus_gass_copy_register_handle_to_url(
    globus_gass_copy_handle_t * handle,
    globus_io_handle_t * source_handle,
    char * dest_url,
    globus_gass_copy_attr_t * dest_attr,
    globus_gass_copy_callback_t callback_func,
    void * callback_arg);

/**
 * get the status code of the current transfer
 */
globus_result_t
globus_gass_copy_get_status(
    globus_gass_copy_handle_t * handle,
    globus_gass_copy_status_t *status);

/**
 * get the status string of the current transfer
 */

const char *
globus_gass_copy_get_status_string(
    globus_gass_copy_handle_t * handle);

/**
 * cancel the current transfer
 */
globus_result_t
globus_gass_copy_cancel(
     globus_gass_copy_handle_t * handle,
     globus_gass_copy_callback_t cancel_callback,
     void * cancel_callback_arg);

/**
 * cache handles functions
 *
 * Use this when transferring mulitple files from or to the same host
 */
globus_result_t
globus_gass_copy_cache_url_state(
    globus_gass_copy_handle_t * handle,
    char * url);

globus_result_t
globus_gass_copy_flush_url_state(
    globus_gass_copy_handle_t * handle,
    char * url);

/**
 *  get/set user pointers from/to GASS Copy handles
 */
globus_result_t
globus_gass_copy_set_user_pointer(
    globus_gass_copy_handle_t * handle,
    void * user_data);

globus_result_t
globus_gass_copy_get_user_pointer(
    globus_gass_copy_handle_t * handle,
    void ** user_data);

globus_result_t
globus_gass_copy_register_performance_cb(
    globus_gass_copy_handle_t *         handle,
    globus_gass_copy_performance_cb_t   callback,
    void *                              user_arg);

/**
 * Set Attribute functions
 */

#ifdef USE_FTP
/* TCP buffer/window size */
globus_result_t
globus_gass_copy_attr_set_tcpbuffer(
    globus_gass_copy_attr_t * attr,
    globus_ftp_control_tcpbuffer_t * tcpbuffer_info);

/* parallel transfer options */
globus_result_t
globus_gass_copy_attr_set_parallelism(
    globus_gass_copy_attr_t * attr,
    globus_ftp_control_parallelism_t * parallelism_info);

/* striping options */
globus_result_t
globus_gass_copy_attr_set_striping(
    globus_gass_copy_attr_t * attr,
    globus_ftp_control_striping_t * striping_info);

/* authorization options */
globus_result_t
globus_gass_copy_attr_set_authorization(
    globus_gass_copy_attr_t * attr,
    globus_io_authorization_t * authorization_info);

/* secure channel options */
globus_result_t
globus_gass_copy_attr_set_secure_channel(
    globus_gass_copy_attr_t * attr,
    globus_io_secure_channel_t * secure_channel_info);
#endif
/**
 * Get Attribute functions
 */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_GLOBUS_GASS_COPY_H */

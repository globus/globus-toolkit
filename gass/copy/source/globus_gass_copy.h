 /**
 * @file globus_gass_copy.h
 *
 * @brief Globus GASS copy API 
 *
 *
 * The globus GASS copy library is motivated by the desire to provide a
 * uniform interface to transfer files specified by different protocols.
 *
 * The goals in doing this are to:
 
 *   - Provide a robust way to describe and apply file transfer properties
 * for a variety of protocols. These include the standard HTTP, FTP and 
 * GSIFTP options.  Some of the new file transfer capabilities in GSIFTP are
 * parallel, striping, authentication and TCP buffer sizing.
 *
 *   - Provide a service to support nonblocking file transfer and handle
 * asynchronous file and network events.
 *
 *   - Provide a simple and portable way to implement file transfers.
 * 
 * Any program that uses Globus GASS copy functions must include
 * "globus_gass_copy.h".
 *
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
 * Globus GASS copy uses standard Globus module activation and deactivation.
 * Before any Globus GASS copy functions are called, the following function
 * must be called:
 *
 * @code
 *      globus_module_activate(GLOBUS_GASS_COPY_MODULE)
 * @endcode
 *
 *
 * This function returns GLOBUS_SUCCESS if Globus GASS copy was successfully
 * initialized, and you are therefore allowed to subsequently call
 * Globus GASS copy functions.  Otherwise, an error code is returned, and
 * Globus GASS copy functions should not be subsequently called. This
 * function may be called multiple times.
 *
 * To deactivate Globus GASS copy, the following function must be called:
 *
 * @code
 *    globus_module_deactivate(GLOBUS_GASS_COPY_MODULE)
 * @endcode
 *
 * This function should be called once for each time Globus GASS copy was
 * activated.
 *
 */
extern int
globus_i_gass_copy_activate(void);

extern int
globus_i_gass_copy_deactivate(void);

#define GLOBUS_GASS_COPY_MODULE (&globus_gass_copy_module)
extern globus_module_descriptor_t        globus_gass_copy_module;

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

typedef struct globus_gass_copy_state_s globus_gass_copy_state_t;
typedef struct globus_gass_copy_handle_s globus_gass_copy_handle_t;
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
    GLOBUS_GASS_COPY_STATUS_FAILURE = -1,
    GLOBUS_GASS_COPY_STATUS_NONE,
    GLOBUS_GASS_COPY_STATUS_INITIAL,
    GLOBUS_GASS_COPY_STATUS_SOURCE_READY,
    GLOBUS_GASS_COPY_STATUS_TRANSFER_IN_PROGRESS,
    GLOBUS_GASS_COPY_STATUS_READ_COMPLETE,
    GLOBUS_GASS_COPY_STATUS_WRITE_COMPLETE,
    GLOBUS_GASS_COPY_STATUS_DONE,
} globus_gass_copy_status_t;

/**
 * valid url modes
 */
typedef enum
{
    GLOBUS_GASS_COPY_URL_MODE_UNSUPPORTED,
    GLOBUS_GASS_COPY_URL_MODE_FTP,
    GLOBUS_GASS_COPY_URL_MODE_GASS,
    GLOBUS_GASS_COPY_URL_MODE_IO,
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
   * pointer to the state structure which contains internal info related to a transfer
   */
  globus_gass_copy_state_t * state;
  
  /*
   * pointer to user data
   */
  void *		     user_pointer;
  /*
   * pointer to user callback function
   */
  globus_gass_copy_callback_t         user_callback;
  /*
   * pointer to user argument to user callback function
   */
  void *                              callback_arg;

  /*
   * Error object to pass to the callback function
   */
  globus_object_t *                   err;

  /*
   * size of the buffers to be used in the transfers
   */
  int                                 buffer_length;

 
  globus_ftp_client_handle_t	      ftp_handle;
  
};

/**
 * GASS copy attribute structure.  Contains any/all attributes that are
 * required to perform the supported transfer methods (ftp, gass, io).
 */
typedef struct globus_gass_copy_attr_s
{
    /*
      globus_io_file_type                 file_type;
    globus_io_authorization_t	        io_auth;
    globus_io_secure_channel_t          secure_channel_info;
    
    globus_ftp_control_striping_t       stripe_info;
    globus_ftp_control_parallel_t       parallel_info;
    globus_ftp_control_tcpbuffer_t      tcpbuffer_info;
    */
  globus_ftp_client_attr_t * ftp_attr;
  globus_io_attr_t * io;
  globus_gass_transfer_requestattr_t * gass_requestattr;
} globus_gass_copy_attr_t;

/*  ????
 *   globus_size_t                       block_size;
 *   globus_bool_t                       connection_reuse;
 *   int                                 sndbuf;
 *   int                                 rcvbuf;
 *   globus_bool_t                       nodelay;
 */



/** initialization and destruction of GASS copy handle */
globus_result_t
globus_gass_copy_init(
    globus_gass_copy_handle_t * handle);

globus_result_t
globus_gass_copy_destroy(
    globus_gass_copy_handle_t * handle);

/** set the size of the buffer to be used for the transfers */
globus_result_t
globus_gass_copy_set_buffer_length(
    globus_gass_copy_handle_t * handle,
    int length);

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
    globus_ftp_client_attr_t * ftp_attr);

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
 * get the status of the current transfer
 */
globus_result_t
globus_gass_copy_get_status(
    globus_gass_copy_handle_t * handle,
    globus_gass_copy_status_t *status);

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
 *  get/set user pointers from/to GASS copy handles
 */
globus_result_t
globus_gass_copy_set_user_pointer(
    globus_gass_copy_handle_t * handle,
    void * user_data);

globus_result_t
globus_gass_copy_get_user_pointer(
    globus_gass_copy_handle_t * handle,
    void * user_data);


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

#ifndef GLOBUS_INCLUDE_FTP_CLIENT_PERF_PLUGIN_H
#define GLOBUS_INCLUDE_FTP_CLIENT_PERF_PLUGIN_H

#include "globus_ftp_client.h"
#include "globus_ftp_client_plugin.h"

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

/**
 * Transfer begin callback
 *
 * This callback is called when a get, put, or third party transfer is
 * started.
 *
 * @param handle
 *        this the client handle that this transfer will be occurring on
 *
 * @param user_specific
 *        this is user specific data either created by the copy method,
 *        or, if a copy method was not specified, the value passed to
 *        init
 *
 * @return
 *        - n/a
 */

typedef void (*globus_ftp_client_perf_plugin_begin_cb_t)(
    globus_ftp_client_handle_t *                    handle,
    void *                                          user_specific);

/**
 * Performance marker received callback
 *
 * This callback is called for every performance marker that is received
 *
 * @param handle
 *        this the client handle that this transfer is occurring on
 *
 * @param user_specific
 *        this is user specific data either created by the copy method,
 *        or, if a copy method was not specified, the value passed to
 *        init
 *
 * @param time_stamp
 *        the timestamp specified on the performance marker received
 *
 * @param stripe_ndx
 *        the stripe index specified by the performance marker received
 *
 * @param num_stripes total number of stripes involved in this transfer as
 *        specified by the performance marker received
 *
 * @param nbytes
 *        the total bytes transfered on this stripe as specified by the
 *        performance marker received
 *
 * @return
 *        - n/a
 */

typedef void (*globus_ftp_client_perf_plugin_marker_cb_t)(
    globus_ftp_client_handle_t *                    handle,
    void *                                          user_specific,
    time_t                                          time_stamp,
    int                                             stripe_ndx,
    int                                             num_stripes,
    globus_size_t                                   nbytes);

/**
 * Transfer complete callback
 *
 * This callback will be called upon transfer completion (successful or
 * otherwise)
 *
 * @param handle
 *        this the client handle that this transfer was occurring on
 *
 * @param user_specific
 *        this is user specific data either created by the copy method,
 *        or, if a copy method was not specified, the value passed to
 *        init
 *
 * @return
 *        - n/a
 */

typedef void (*globus_ftp_client_perf_plugin_complete_cb_t)(
    globus_ftp_client_handle_t *                    handle,
    void *                                          user_specific);

/**
 * Copy constructor
 *
 * This callback will be called when a copy of this plugin is made,
 * it is intended to allow initialization of a new user_specific data
 *
 * @param user_specific
 *        this is user specific data either created by this copy
 *        method, or the value passed to init
 *
 * @return
 *        - a pointer to a user specific piece of data
 *        - GLOBUS_NULL (does not indicate error)
 */

typedef void * (*globus_ftp_client_perf_plugin_user_copy_cb_t)(
    void *                                          user_specific);

/**
 * Destructor
 *
 * This callback will be called when a copy of this plugin is destroyed,
 * it is intended to allow the user to free up any memory associated with
 * the user specific data
 *
 * @param user_specific
 *        this is user specific data created by the copy method
 *
 * @return
 *        - n/a
 */

typedef void (*globus_ftp_client_perf_plugin_user_destroy_cb_t)(
    void *                                          user_specific);

globus_result_t
globus_ftp_client_perf_plugin_init(
    globus_ftp_client_plugin_t *                    plugin,
    globus_ftp_client_perf_plugin_begin_cb_t        begin_cb,
    globus_ftp_client_perf_plugin_marker_cb_t       marker_cb,
    globus_ftp_client_perf_plugin_complete_cb_t     complete_cb,
    globus_ftp_client_perf_plugin_user_copy_cb_t    copy_cb,
    globus_ftp_client_perf_plugin_user_destroy_cb_t destroy_cb,
    void *                                          user_specific);

globus_result_t
globus_ftp_client_perf_plugin_destroy(
    globus_ftp_client_plugin_t *                    plugin);

globus_result_t
globus_ftp_client_perf_plugin_get_user_specific(
    globus_ftp_client_plugin_t *                    plugin,
    void **                                         user_specific);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_FTP_CLIENT_PERF_PLUGIN_H */

#ifndef GLOBUS_INCLUDE_FTP_CLIENT_THROUGHPUT_PLUGIN_H
#define GLOBUS_INCLUDE_FTP_CLIENT_THROUGHPUT_PLUGIN_H

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

/** Module descriptor
 */
#define GLOBUS_FTP_CLIENT_THROUGHPUT_PLUGIN_MODULE (&globus_i_ftp_client_throughput_plugin_module)

extern
globus_module_descriptor_t globus_i_ftp_client_throughput_plugin_module;

/**
 * Transfer begin callback
 *
 * This callback will be called when a transfer begins
 *
 * @param handle
 *        The client handle associated with this transfer
 *
 * @param user_arg
 *        User argument passed to globus_ftp_client_throughput_plugin_init
 *
 * @return
 *        - n/a
 */

typedef void (*globus_ftp_client_throughput_plugin_begin_cb_t)(
    globus_ftp_client_handle_t *                    handle,
    void *                                          user_arg);

/**
 * Stripe performace throughput callback
 *
 * This callback will be called with every performance callback that is
 * received by the perf plugin. The first
 * callback for each stripe_ndx will have an instantaneous_throughput
 * based from the time the command was sent.
 *
 * @param handle
 *        The client handle associated with this transfer
 *
 * @param user_arg
 *        User argument passed to globus_ftp_client_throughput_plugin_init
 *
 * @param bytes
 *        The total number of bytes received on this stripe
 *
 * @param instantaneous_throughput
 *        Instanteous throughput on this stripe
 *
 * @param avg_throughput
 *        Average throughput on this stripe
 *
 * @param stripe_ndx
 *        This stripe's index
 *
 */

typedef void (*globus_ftp_client_throughput_plugin_stripe_cb_t)(
    globus_ftp_client_handle_t *                    handle,
    void *                                          user_arg,
    int                                             stripe_ndx,
    globus_size_t                                   bytes,
    float                                           instantaneous_throughput,
    float                                           avg_throughput);

/**
 * Total performace throughput callback
 *
 * This callback will be called with every performance callback that is
 * received by the perf plugin. The first
 * callback for will have an instantaneous_throughput based from the time
 * the command was sent.  This callback will be called after the per_stripe_cb
 *
 * @param handle
 *        The client handle associated with this transfer
 *
 * @param user_arg
 *        User argument passed to globus_ftp_client_throughput_plugin_init
 *
 * @param bytes
 *        The total number of bytes received on all stripes
 *
 * @param instantaneous_throughput
 *        Total instanteous throughput on all stripes
 *
 * @param avg_throughput
 *        Average total throughput on all stripes
 *
 */

typedef void (*globus_ftp_client_throughput_plugin_total_cb_t)(
    globus_ftp_client_handle_t *                    handle,
    void *                                          user_arg,
    globus_size_t                                   bytes,
    float                                           instantaneous_throughput,
    float                                           avg_throughput);

/**
 * Transfer complete callback
 *
 * This callback will be called upon transfer completion (successful or
 * otherwise)
 *
 * @param handle
 *        The client handle associated with this transfer
 *
 * @param user_arg
 *        User argument passed to globus_ftp_client_throughput_plugin_init
 *
 * @return
 *        - n/a
 */

typedef void (*globus_ftp_client_throughput_plugin_complete_cb_t)(
    globus_ftp_client_handle_t *                    handle,
    void *                                          user_arg);

globus_result_t
globus_ftp_client_throughput_plugin_init(
    globus_ftp_client_plugin_t *                        plugin,
    globus_ftp_client_throughput_plugin_begin_cb_t      begin_cb,
    globus_ftp_client_throughput_plugin_stripe_cb_t     per_stripe_cb,
    globus_ftp_client_throughput_plugin_total_cb_t      total_cb,
    globus_ftp_client_throughput_plugin_complete_cb_t   complete_cb,
    void *                                              user_arg);

globus_result_t
globus_ftp_client_throughput_plugin_destroy(
    globus_ftp_client_plugin_t *                            plugin);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_FTP_CLIENT_THROUGHPUT_PLUGIN_H */

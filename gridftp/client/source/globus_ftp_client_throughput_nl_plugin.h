#ifndef GLOBUS_INCLUDE_FTP_CLIENT_THROUGHPUT_NL_PLUGIN_H
#define GLOBUS_INCLUDE_FTP_CLIENT_THROUGHPUT_NL_PLUGIN_H
#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_ftp_client_throughput_nl_plugin.h GridFTP Netlogger Throughput Plugin
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 * $Author$
 */
#endif

/**
 * @defgroup globus_ftp_client_throughput_nl_plugin Netlogger Throughput Plugin
 * @ingroup globus_ftp_client_plugins
 *
 * This plugins allows a user to easily use the throughput plugin to log
 * performance data vi Netlogger.
 *
 * The plugin will log the following Event Types with its coressponding info
 *
 * TransferPerfTotal : This event type will be sent everytime a throughput
 *      plugin total callback is received.
 *
 * URL.SOURCE   <string>  Source url of transfer
 * URL.DEST     <string>  Dest url of transfer
 * BYTES        <int>     Total bytes transfered thus far
 * BW.CURRENT   <float>   Current (instantaneous) bandwidth
 * BW.AVG       <float>   Average (instantaneous) bandwidth
 *
 * TransferPerfStripe  : This event type will be sent everytime a throughput
 *      plugin stripe callback is received.
 *
 * URL.SOURCE   <string>  Source url of transfer
 * URL.DEST     <string>  Dest url of transfer
 * INDEX        <int>     The stripe index the event applies to
 * BYTES        <int>     Total bytes transfered thus far on this stripe
 * BW.CURRENT   <float>   Current (instantaneous) bandwidth on this stripe
 * BW.AVG       <float>   Average (instantaneous) bandwidth on this stripe
 *
 * TransferBegin  : This event type will be sent everytime a throughput
 *      plugin begin callback is received.
 *
 * URL.SOURCE   <string>  Source url of transfer
 * URL.DEST     <string>  Dest url of transfer
 *
 * TransferEnd  : This event type will be sent everytime a throughput
 *      plugin complete callback is received.
 *
 * SUCCESS      <bool>    Completion status
 *
 */



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
 * @ingroup globus_ftp_client_throughput_nl_plugin
 */
#define GLOBUS_FTP_CLIENT_THROUGHPUT_NL_PLUGIN_MODULE (&globus_i_ftp_client_throughput_nl_plugin_module)

extern
globus_module_descriptor_t globus_i_ftp_client_throughput_nl_plugin_module;

globus_result_t
globus_ftp_client_throughput_nl_plugin_init(
    globus_ftp_client_plugin_t *			plugin,
    const char *                                        nl_host,
    unsigned short                                      nl_port,
    const char *                                        prog_name,
    const char *                                        opaque_string);

globus_result_t
globus_ftp_client_throughput_nl_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_FTP_CLIENT_THROUGHPUT_NL_PLUGIN_H */

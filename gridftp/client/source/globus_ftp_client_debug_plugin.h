#ifndef GLOBUS_INCLUDE_FTP_CLIENT_DEBUG_PLUGIN_H
#define GLOBUS_INCLUDE_FTP_CLIENT_DEBUG_PLUGIN_H
#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file
 */
#endif

/**
 * @defgroup globus_ftp_client_debug_plugin Debugging Plugin
 * @ingroup globus_ftp_client_plugins
 *
 * The FTP Debugging plugin provides a way for the user to trace FTP
 * protocol messages which occur while the GridFTP client library
 * processes an FTP operation. This may be useful for debugging FTP
 * configuration problems.
 *
 * When this plugin is used for a GridFTP Client operation, information
 * will be printed to the file stream associated with the plugin when a user
 * begins an operation, for all data buffers which pass through while
 * handling a data transfer, and for all protocol messages which are sent and
 * received.
 *
 * <b>Example Usage:</b>
 *
 * @code
 * int main(int argc, char *argv[])
 * {
 *     globus_ftp_client_plugin_t restart_plugin;
 *     globus_ftp_client_handleattr_t handleattr;
 *     globus_ftp_client_handle_t handle;
 *     FILE * log;
 *     char text[256];
 *
 *     log = fopen("gridftp.log", "a");
 *     sprintf(text, "%s:%ld", argv[0], (long) getpid());
 *
 *     globus_ftp_client_debug_plugin_init(&debug_plugin, log, text);
 *
 *     globus_ftp_client_handleattr_init(&handleattr);
 *     globus_ftp_client_handleattr_add_plugin(&handleattr, &debug_plugin);
 *     globus_ftp_client_handle_init(&handle, &handleattr);
 *
 *     globus_ftp_client_get(&handle,
 *                           "ftp://ftp.globus.org/pub/globus/README",
 *                           GLOBUS_NULL,
 *                           GLOBUS_NULL,
 *                           callback_fn,
 *                           GLOBUS_NULL);
 * }
 * @endcode
 *
 */

#include "globus_ftp_client_plugin.h"

globus_result_t
globus_ftp_client_debug_plugin_init(
    globus_ftp_client_plugin_t *		plugin,
    FILE *					stream,
    const char *				text);

globus_result_t
globus_ftp_client_debug_plugin_destroy(
    globus_ftp_client_plugin_t *		plugin);

#endif /* GLOBUS_INCLUDE_FTP_CLIENT_DEBUG_PLUGIN_H */

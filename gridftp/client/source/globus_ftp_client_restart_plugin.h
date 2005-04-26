/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_INCLUDE_FTP_CLIENT_RESTART_PLUGIN_H
#define GLOBUS_INCLUDE_FTP_CLIENT_RESTART_PLUGIN_H
#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file
 */
#endif

/**
 * @defgroup globus_ftp_client_restart_plugin Restart Plugin
 * @ingroup globus_ftp_client_plugins
 *
 * The restart plugin implements one scheme for providing reliability
 * functionality for the FTP Client library. Other plugins may be developed
 * to provide other methods of reliability.
 *
 * The specific functionality of this plugin is
 * to restart any FTP operation when a fault occurs. The plugin's operation
 * is parameterized to control how often and when to attempt to restart
 * the operation.
 *
 * This restart plugin will restart an FTP operation if a noticable
 * fault has occurred---a connection timing out, a failure by the server
 * to process a command, a protocol error, an authentication error.
 *
 * This plugin has three user-configurable parameters; these are
 * the maximum number of retries to attempt, the interval to wait between
 * retries, and the deadline after which no further retries will be attempted.
 * These are set by initializing a restart plugin instance with the function
 * globus_ftp_client_restart_plugin_init().
 *
 * <h2>Example Usage</h2>
 *
 * The following example illustrates a typical use of the restart plugin.
 * In this case, we configure a plugin instance to restart the operation
 * for up to an hour, using an exponential back-off between retries.
 *
 * \include globus_ftp_client_restart_plugin.example
 */

#include "globus_ftp_client.h"

EXTERN_C_BEGIN

/** Module descriptor
 * @ingroup globus_ftp_client_restart_plugin
 */
#define GLOBUS_FTP_CLIENT_RESTART_PLUGIN_MODULE \
        (&globus_i_ftp_client_restart_plugin_module)
extern globus_module_descriptor_t globus_i_ftp_client_restart_plugin_module;

globus_result_t
globus_ftp_client_restart_plugin_init(
    globus_ftp_client_plugin_t *		plugin,
    int						max_retries,
    globus_reltime_t *				interval,
    globus_abstime_t *				deadline);

globus_result_t
globus_ftp_client_restart_plugin_destroy(
    globus_ftp_client_plugin_t *		plugin);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_FTP_CLIENT_RESTART_PLUGIN_H */

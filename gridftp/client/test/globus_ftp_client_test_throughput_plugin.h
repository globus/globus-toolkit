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

/**
 * throughput plugin
 *
 * Allow the throughput performance data be retrieved to a callback.
 */

#ifndef GLOBUS_INCLUDE_FTP_CLIENT_TEST_THROUGHPUT_PLUGIN_H
#define GLOBUS_INCLUDE_FTP_CLIENT_TEST_THROUGHPUT_PLUGIN_H

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
#define GLOBUS_FTP_CLIENT_TEST_THROUGHPUT_PLUGIN_MODULE (&globus_i_ftp_client_test_throughput_plugin_module)

extern
globus_module_descriptor_t globus_i_ftp_client_test_throughput_plugin_module;

globus_result_t
globus_ftp_client_test_throughput_plugin_init(
    globus_ftp_client_plugin_t *			plugin);

globus_result_t
globus_ftp_client_test_throughput_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin);

EXTERN_C_END

#endif /* GLOBUS_INCLUDE_FTP_CLIENT_TEST_THROUGHPUT_PLUGIN_H */

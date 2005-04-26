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

#include "globus_ftp_client_test_perf_plugin.h"
#include "globus_ftp_client_perf_plugin.h"

static globus_bool_t globus_l_ftp_client_test_perf_plugin_activate(void);
static globus_bool_t globus_l_ftp_client_test_perf_plugin_deactivate(void);

globus_module_descriptor_t globus_i_ftp_client_test_perf_plugin_module =
{
    "globus_ftp_client_test_perf_plugin",
    globus_l_ftp_client_test_perf_plugin_activate,
    globus_l_ftp_client_test_perf_plugin_deactivate,
    GLOBUS_NULL
};

static
int
globus_l_ftp_client_test_perf_plugin_activate(void)
{
    int rc;

    rc = globus_module_activate(GLOBUS_FTP_CLIENT_PERF_PLUGIN_MODULE);
    return rc;
}

static
int
globus_l_ftp_client_test_perf_plugin_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_FTP_CLIENT_PERF_PLUGIN_MODULE);
}

static
void perf_plugin_begin_cb(
    void *                                          user_specific,
    globus_ftp_client_handle_t *                    handle,
    const char *                                    source_url,
    const char *                                    dest_url,
    globus_bool_t                                   restart)
{
    globus_libc_fprintf(stderr, "perf_plugin_begin_cb\n");
}

static
void perf_plugin_marker_cb(
    void *                                          user_specific,
    globus_ftp_client_handle_t *                    handle,
    long                                            time_stamp_int,
    char                                            time_stamp_tength,
    int                                             stripe_ndx,
    int                                             num_stripes,
    globus_off_t                                    nbytes)
{
    globus_libc_fprintf(stderr, "perf_plugin_marker_cb\n");
    globus_libc_fprintf(stderr, "time_stamp   %ld.%d\n", time_stamp_int, time_stamp_tength);
    globus_libc_fprintf(stderr, "stripe_ndx   %d\n", stripe_ndx);
    globus_libc_fprintf(stderr, "num_stripes  %d\n", num_stripes);
    globus_libc_fprintf(stderr, "nbytes       %" GLOBUS_OFF_T_FORMAT "\n", nbytes);
}

static
void perf_plugin_complete_cb(
    void *                                          user_specific,
    globus_ftp_client_handle_t *                    handle,
    globus_bool_t                                   success)
{
    globus_libc_fprintf(stderr, "perf_plugin_complete_cb\n");
}

globus_result_t
globus_ftp_client_test_perf_plugin_init(
    globus_ftp_client_plugin_t *			plugin)
{
    return globus_ftp_client_perf_plugin_init(
        plugin,
        perf_plugin_begin_cb,
        perf_plugin_marker_cb,
        perf_plugin_complete_cb,
        GLOBUS_NULL);
}

globus_result_t
globus_ftp_client_test_perf_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin)
{
    return globus_ftp_client_perf_plugin_destroy(plugin);
}

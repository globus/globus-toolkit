#include "globus_ftp_client_test_throughput_plugin.h"
#include "globus_ftp_client_throughput_plugin.h"

static globus_bool_t globus_l_ftp_client_test_throughput_plugin_activate(void);
static globus_bool_t globus_l_ftp_client_test_throughput_plugin_deactivate(void);

globus_module_descriptor_t globus_i_ftp_client_test_throughput_plugin_module =
{
    "globus_ftp_client_test_throughput_plugin",
    globus_l_ftp_client_test_throughput_plugin_activate,
    globus_l_ftp_client_test_throughput_plugin_deactivate,
    GLOBUS_NULL
};

static
int
globus_l_ftp_client_test_throughput_plugin_activate(void)
{
    int rc;

    rc = globus_module_activate(GLOBUS_FTP_CLIENT_THROUGHPUT_PLUGIN_MODULE);
    return rc;
}

static
int
globus_l_ftp_client_test_throughput_plugin_deactivate(void)
{
    return globus_module_deactivate(GLOBUS_FTP_CLIENT_THROUGHPUT_PLUGIN_MODULE);
}

static
void throughput_plugin_begin_cb(
    globus_ftp_client_handle_t *                    handle,
    void *                                          user_specific)
{
    globus_libc_fprintf(stderr, "throughput_plugin_begin_cb\n");
}

static
void throughput_plugin_stripe_cb(
    globus_ftp_client_handle_t *                    handle,
    void *                                          user_arg,
    int                                             stripe_ndx,
    globus_size_t                                   bytes,
    float                                           instantaneous_throughput,
    float                                           avg_throughput)
{
    globus_libc_fprintf(stderr, "throughput_plugin_stripe_cb\n");
    globus_libc_fprintf(stderr, "stripe_ndx                %d\n", stripe_ndx);
    globus_libc_fprintf(stderr, "bytes                     %d\n", bytes);
    globus_libc_fprintf(stderr, "instantaneous_throughput  %.3f\n", instantaneous_throughput);
    globus_libc_fprintf(stderr, "avg_throughput            %.3f\n", avg_throughput);
}

static
void throughput_plugin_total_cb(
    globus_ftp_client_handle_t *                    handle,
    void *                                          user_arg,
    globus_size_t                                   bytes,
    float                                           instantaneous_throughput,
    float                                           avg_throughput)
{
    globus_libc_fprintf(stderr, "throughput_plugin_total_cb\n");
    globus_libc_fprintf(stderr, "bytes                     %d\n", bytes);
    globus_libc_fprintf(stderr, "instantaneous_throughput  %.3f\n", instantaneous_throughput);
    globus_libc_fprintf(stderr, "avg_throughput            %.3f\n", avg_throughput);
}

static
void throughput_plugin_complete_cb(
    globus_ftp_client_handle_t *                    handle,
    void *                                          user_specific)
{
    globus_libc_fprintf(stderr, "throughput_plugin_complete_cb\n");
}

globus_result_t
globus_ftp_client_test_throughput_plugin_init(
    globus_ftp_client_plugin_t *			plugin)
{
    return globus_ftp_client_throughput_plugin_init(
        plugin,
        throughput_plugin_begin_cb,
        throughput_plugin_stripe_cb,
        throughput_plugin_total_cb,
        throughput_plugin_complete_cb,
        GLOBUS_NULL);
}

globus_result_t
globus_ftp_client_test_throughput_plugin_destroy(
    globus_ftp_client_plugin_t *			plugin)
{
    return globus_ftp_client_throughput_plugin_destroy(plugin);
}

#include "globus_common.h"
#include "globus_options.h"
#include "globus_i_gfork.h"
#include "version.h"

static
globus_result_t
gfork_l_opts_help(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_options_help(opts_handle);
    exit(0);
}

static
globus_result_t
gfork_l_opts_port(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    int                                 sc;
    int                                 port;
    gfork_i_options_t *                 gfork_h;
    globus_result_t                     result;

    gfork_h = (gfork_i_options_t *) arg;

    sc = sscanf(opt[0], "%d", &port);
    if(sc != 1)
    {
        goto error_format;
    }

    result = globus_xio_attr_cntl(
        gfork_i_tcp_attr,
        gfork_i_tcp_driver,
        GLOBUS_XIO_TCP_SET_PORT,
        port);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_attr;
    }
    gfork_h->port = port;

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;

error_attr:
error_format:
    *out_parms_used = 0;

    return 0x1;
}

static
globus_result_t
gfork_l_opts_plugin(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    gfork_i_options_t *                 gfork_h;

    gfork_h = (gfork_i_options_t *) arg;

    gfork_h->plugin_name = opt[0];

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfork_l_opts_exe(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    int                                 i;
    gfork_i_options_t *                 gfork_h;
    globus_list_t *                     list = NULL;

    gfork_h = (gfork_i_options_t *) arg;

    list = globus_list_from_string(opt[0], ' ', NULL);

    i = globus_list_size(list);
    gfork_h->argv = (char **) globus_calloc(i+1, sizeof(char *));

    gfork_h->argc = i;
    i--;
    while(i >= 0)
    {
        gfork_h->argv[i] = (char *) globus_list_remove(&list, list);
        i--;
    }

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfork_l_opts_version(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
 /* print the version and exit */
    globus_version_print(
        "gfork",
        &local_version,
        stderr,
        GLOBUS_TRUE);
    globus_module_print_activated_versions(stderr, GLOBUS_TRUE);
    *out_parms_used = 0;
    exit(0);
}

globus_options_entry_t                   gfork_l_opts_table[] =
{
    {"port", "p", NULL, "<listener port number>",
        "The port number for the TCP listener",
        1, gfork_l_opts_port},
    {"executable", "e", NULL, "<program name>",
        "The port number for the TCP listener",
        1, gfork_l_opts_exe},
    {"plugin", "P", NULL, "<plugin name>",
        "The name of the plugin",
        1, gfork_l_opts_plugin},
    {"version", "v", NULL, NULL,
        "Print version information.",
        0, gfork_l_opts_version},
    {"help", "h", NULL, NULL,
        "print the help message",
        0, gfork_l_opts_help},
    {NULL, NULL, NULL, NULL, NULL, 0, NULL}
};

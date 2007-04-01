#include "globus_i_gwtftp.h"
#include "globus_common.h"
#include "globus_options.h"

static
globus_result_t
gwtftp_l_opts_quiet(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_gwtftp_cmd_opts_t *      opts;

    opts = (globus_i_gwtftp_cmd_opts_t *) arg;
    opts->quiet = GLOBUS_TRUE;
    *out_parms_used = 0;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
gwtftp_l_opts_daemon(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_gwtftp_cmd_opts_t *      opts;

    opts = (globus_i_gwtftp_cmd_opts_t *) arg;
    opts->daemon = GLOBUS_TRUE;
    *out_parms_used = 0;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
gwtftp_l_opts_child(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_gwtftp_cmd_opts_t *        opts;

    opts = (globus_i_gwtftp_cmd_opts_t *) arg;
    opts->child = GLOBUS_TRUE;
    *out_parms_used = 0;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
gwtftp_l_opts_ip_mask(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_gwtftp_cmd_opts_t *        opts;
    GlobusFTP2GridFuncName(gwtftp_l_opts_ip_mask);

    opts = (globus_i_gwtftp_cmd_opts_t *) arg;

    opts->ip_list = globus_list_from_string(opt[0], (int)',', NULL);

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}


static
globus_result_t
gwtftp_l_opts_port(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_gwtftp_cmd_opts_t *      opts;
    int                                 port;
    int                                 sc;
    GlobusFTP2GridFuncName(gwtftp_l_opts_port);

    opts = (globus_i_gwtftp_cmd_opts_t *) arg;
    sc = sscanf(opt[0], "%d", &port);
    if(sc != 1)
    {
        goto error;
    }
    if(port < 0)
    {
        goto error;
    }
    opts->port = port;
    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
error:
    return GlobusFTP2GridError(
        "The port must be an integer.",
        GLOBUS_FTP2GRID_ERROR_PARM);
}


static
globus_result_t
gwtftp_l_opts_logmask(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_gwtftp_cmd_opts_t *      opts;
    int                                 log_mask;
    int                                 sc;
    GlobusFTP2GridFuncName(gwtftp_l_opts_logmask);

    opts = (globus_i_gwtftp_cmd_opts_t *) arg;
    sc = sscanf(opt[0], "%d", &log_mask);
    if(sc != 1)
    {
        goto error;
    }
    if(log_mask < 0 || log_mask > 255)
    {
        goto error;
    }
    opts->log_mask = log_mask;
    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
error:
    return GlobusFTP2GridError(
        "The log mask must be an integer between 0 and 255",
        GLOBUS_FTP2GRID_ERROR_PARM);
}

static
globus_result_t
gwtftp_l_opts_help(
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
gwtftp_l_opts_logfile(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_gwtftp_cmd_opts_t *      opts;

    opts = (globus_i_gwtftp_cmd_opts_t *) arg;
    *out_parms_used = 1;
    opts->log_file = opt[0];

    return GLOBUS_SUCCESS;
}

static
globus_result_t
gwtftp_l_opts_pwfile(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{   
    globus_i_gwtftp_cmd_opts_t *      opts;
    
    opts = (globus_i_gwtftp_cmd_opts_t *) arg;
    *out_parms_used = 1;
    opts->pw_file = opt[0];

    return GLOBUS_SUCCESS;
}


static
globus_result_t
gwtftp_l_opts_version(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
 /* print the version and exit */
    globus_version_print(
        "globus_gwtftp",
        &local_version,
        stderr,
        GLOBUS_TRUE);
    globus_module_print_activated_versions(stderr, GLOBUS_TRUE);
    *out_parms_used = 0;
    exit(0);
}

globus_options_entry_t                   globus_i_gwtftp_opts_table[] =
{
    {"authorized-hosts", "ah", NULL, NULL,
        "Comma seperated list of authorized IP masks.", 
        1, gwtftp_l_opts_ip_mask},
    {"port", "p", NULL, NULL,
        "Port to listen where incoming clinet connections are accepted.", 
        1, gwtftp_l_opts_port},
    {"pwfile", "pw", NULL, NULL,
        "File where we can find the password hash.", 
        1, gwtftp_l_opts_pwfile},
    {"logfile", "l", NULL, NULL,
        "Set logging output file [default stderr].", 
        1, gwtftp_l_opts_logfile},
    {"logmask", "lm", NULL, NULL,
        "Set logging level.", 
        1, gwtftp_l_opts_logmask},
    {"daemon", "S", NULL, NULL,
        "Run in forking mode.", 
        0, gwtftp_l_opts_daemon},
    {"child", "CH", NULL, NULL,
        "Executable is a child.  Not to be set by the user.", 
        0, gwtftp_l_opts_child},
    {"quiet", "q", NULL, NULL,
        "No noisy output.", 
        0, gwtftp_l_opts_quiet},
    {"help", "h", NULL, NULL,
        "Print the usage message.",
        0, gwtftp_l_opts_help},
    {"version", "v", NULL, NULL,
        "Print version information.",
        0, gwtftp_l_opts_version},
    {NULL, NULL, NULL, NULL, NULL, 0, NULL}
};

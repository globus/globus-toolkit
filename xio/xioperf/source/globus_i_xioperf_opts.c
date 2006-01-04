#include "globus_i_xioperf.h"
#include "globus_options.h"
#include "version.h"

#define GlobusXIOPerfError(error_msg, _type)                                \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            NULL,                                                           \
            NULL,                                                           \
            _type,                                                          \
            __FILE__,                                                       \
            _xioperf_func_name,                                             \
            __LINE__,                                                       \
            "%s",                                                           \
            (error_msg)))

#ifdef __GNUC__
#define GlobusXIOPerfFuncName(func) static const char * _xioperf_func_name __attribute__((__unused__)) = #func
#else
#define GlobusXIOPerfFuncName(func) static const char * _xioperf_func_name = #func
#endif

static
globus_result_t
xioperf_l_kmint(
    char *                              arg,
    int *                               out_i)
{
    int                                 i;
    int                                 sc;
    GlobusXIOPerfFuncName(xioperf_l_kmint);

    sc = sscanf(arg, "%d", &i)
    if(sc != 1)
    {
        return GlobusXIOPerfError(
                "parameter must be an integer",
                GLOBUS_XIO_PERF_ERROR_PARM);
    }
    if(strchr(arg, "K") != NULL)
    {
        *out_i = i;
    }
    else if(strchr(arg, "M") != NULL)
    {
        *out_i = i * 1024;
    }
    else
    {
        return GlobusXIOPerfError(
                "must specify K or M",
                GLOBUS_XIO_PERF_ERROR_PARM);
    }
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_format(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    GlobusXIOPerfFuncName(xioperf_l_opts_format);
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;

    switch(*opt)
    {
        case 'K':
        case 'k':
        case 'M':
        case 'm':
            info->format = *opt;
            break;

        default:
            return GlobusXIOPerfError(
                "format must be one of: kmKM",
                GLOBUS_XIO_PERF_ERROR_PARM);

    }
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xio_perf_l_opts_interval(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    int                                 i;
    int                                 sc;
    GlobusXIOPerfFuncName(xio_perf_l_opts_interval);
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;

    sc = sscanf(opt, "%d", &i)
    if(sc != 1)
    {
        return GlobusXIOPerfError(
                "interval must be an integer",
                GLOBUS_XIO_PERF_ERROR_PARM);
    }

    info->interval = i;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_len(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;
    return xioperf_l_kmint(opt, &info->len);
}

static
globus_result_t
xioperf_l_opts_port(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    int                                 i;
    int                                 sc;
    GlobusXIOPerfFuncName(xioperf_l_opts_port);
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;

    sc = sscanf(opt, "%d", &i)
    if(sc != 1)
    {
        return GlobusXIOPerfError(
                "port must be an integer",
                GLOBUS_XIO_PERF_ERROR_PARM);
    }
    info->port = i;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_window(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;
    return xioperf_l_kmint(opt, &info->window);
}

static
globus_result_t
xioperf_l_opts_bind(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;
    info->bind_addr = strdup(opt);
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_nodelay(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;
    info->nodelay = GLOBUS_TRUE;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_server(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    GlobusXIOPerfFuncName(xioperf_l_opts_server);
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;

    if(info->client != NULL)
    {
        return GlobusXIOPerfError(
                "Cant be a server and a client",
                GLOBUS_XIO_PERF_ERROR_PARM);
    }
    info->server = GLOBUS_TRUE;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_bandwidth(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    GlobusXIOPerfFuncName(xioperf_l_opts_bandwidth);
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;

    return GlobusXIOPerfError(
            "Feature not implemented",
            GLOBUS_XIO_PERF_ERROR_PARM);
}

static
globus_result_t
xioperf_l_opts_client(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    GlobusXIOPerfFuncName(xioperf_l_opts_client);
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;

    if(info->server)
    {
        return GlobusXIOPerfError(
                "Cant be a client and a server",
                GLOBUS_XIO_PERF_ERROR_PARM);
    }
    info->client = strdup(opt);
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_num(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;
    return xioperf_l_kmint(opt, &info->kbytes_to_transfer);
}

static
globus_result_t
xioperf_l_opts_file(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;
    info->file = strdup(opt);
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_parallel(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    int                                 i;
    int                                 sc;
    GlobusXIOPerfFuncName(xioperf_l_opts_parallel);
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;

    sc = sscanf(opt, "%d", &i)
    if(sc != 1)
    {
        return GlobusXIOPerfError(
                "port must be an integer",
                GLOBUS_XIO_PERF_ERROR_PARM);
    }
    info->stream_count = i;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_driver(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_result_t                     result;
    globus_xio_driver_t                 driver;
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;

    result = globus_xio_driver_load(opt, &driver);
    if(result != GLOBUS_SUCESS)
    {
        return result;
    }
    result = globus_xio_stack_push_driver(info->stack, driver);

    return result;
}


static
globus_result_t
xioperf_l_opts_version(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
 /* print the version and exit */
    globus_version_print(
        "xioperf",
        &local_version,
        stderr,
        GLOBUS_TRUE);
    globus_module_print_activated_versions(stderr, GLOBUS_TRUE);
    exit(0);
}

globus_options_entry_t                   globus_i_xioperf_opts_table[] =
{
    {"format", "f", NULL, "[kmKM]",
        "format to report: Kbits, Mbits, KBytes, MBytes",
        1, xioperf_l_opts_format},
    {"interval", "i", NULL, "#",
        "seconds between periodic bandwidth reports", 
        1, xio_perf_l_opts_interval},
    {"len", "l", NULL, "#[KM]",
        "length of buffer to read or write (default 8 KB)", 
        1, xioperf_l_opts_len},
    {"port", "p", NULL, "#",
        "server port to listen on/connect to", 
        1, xioperf_l_opts_port},
    {"window", "w", NULL, "#[KM]",
        "TCP window size (socket buffer size)", 
        1, xioperf_l_opts_window},
    {"bind", "B", NULL, "<host>", "bind to <host>",
        1, xioperf_l_opts_bind},
    {"nodelay", "N", NULL, NULL,
        "set TCP no delay, disabling Nagle's Algorithm", 
        1, xioperf_l_opts_nodelay},
    {"server", "s", NULL, NULL, 
        "run in server mode", 
        1, xioperf_l_opts_server},
    {"bandwidth", "b", NULL, "#[KM]",
        "bandwidth to send at in bits/sec.  (default 1 Mbit/sec)", 
        1, xioperf_l_opts_bandwidth},
    {"client", "c", NULL, "<host>", 
        "run in client mode, connecting to <host>", 
        1, xioperf_l_opts_client},
    {"num", "n", NULL, "#[KM]",
        "number of bytes to transmit (instead of -t)",
        1, xioperf_l_opts_num},
    {"file", "F", NULL, "<path>",
        "filename for input if sender, output file if receiver",
        1, xioperf_l_opts_file},
    {"parallel", "P", NULL, "#",
        "number of parallel streams to use",
        1, xioperf_l_opts_parallel},
    {"driver", "D", NULL, "<driver name>",
        "the name of the driver to put next on the stack",
        1, xioperf_l_opts_driver},
    {"version", "v", NULL, NULL,
        "Print version information.",
        0, xioperf_l_opts_version},
    {NULL, NULL, NULL, NULL, NULL, 0, NULL}
};




#include "globus_i_xioperf.h"
#include "globus_common.h"
#include "globus_options.h"

static
globus_result_t
xioperf_l_kmint(
    char *                              arg,
    globus_off_t *                      out_i)
{
    int                                 i;
    int                                 sc;
    GlobusXIOPerfFuncName(xioperf_l_kmint);

    sc = sscanf(arg, "%d", &i);
    if(sc != 1)
    {
        return GlobusXIOPerfError(
                "parameter must be an integer",
                GLOBUS_XIO_PERF_ERROR_PARM);
    }
    if(strchr(arg, 'K') != NULL)
    {
        *out_i = i * 1024;
    }
    else if(strchr(arg, 'M') != NULL)
    {
        *out_i = i * 1024 * 1024;
    }
    else if(strchr(arg, 'G') != NULL)
    {
        *out_i = i * 1024 * 1024 * 1024;
    }
    else
    {
        *out_i = i;
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
        case 'G':
        case 'g':
        case 'K':
        case 'k':
        case 'M':
        case 'm':
            info->format = toupper(*opt);
            *out_parms_used = 1;
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

    sc = sscanf(opt, "%d", &i);
    if(sc != 1)
    {
        return GlobusXIOPerfError(
                "interval must be an integer",
                GLOBUS_XIO_PERF_ERROR_PARM);
    }
    *out_parms_used = 1;

    info->interval = i;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_quiet(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;
    *out_parms_used = 0;
    info->quiet = GLOBUS_TRUE;

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
    *out_parms_used = 1;
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

    sc = sscanf(opt, "%d", &i);
    if(sc != 1)
    {
        return GlobusXIOPerfError(
                "port must be an integer",
                GLOBUS_XIO_PERF_ERROR_PARM);
    }
    info->port = i;
    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_blocksize(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_result_t                     result;
    globus_i_xioperf_info_t *           info;
    globus_off_t                        bs;

    info = (globus_i_xioperf_info_t *) arg;
    *out_parms_used = 1;
    result = xioperf_l_kmint(opt, &bs);
    info->block_size = (globus_size_t) bs;
    return result;
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
    *out_parms_used = 1;
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
    *out_parms_used = 1;
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
    *out_parms_used = 0;
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
    *out_parms_used = 0;
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

    *out_parms_used = 0;
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

    info->server = GLOBUS_FALSE;
    info->client = strdup(opt);
    *out_parms_used = 1;
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
    *out_parms_used = 1;
    return xioperf_l_kmint(opt, &info->bytes_to_transfer);
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
    *out_parms_used = 1;
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
    globus_i_xioperf_info_t *           info;
    GlobusXIOPerfFuncName(xioperf_l_opts_parallel);

    info = (globus_i_xioperf_info_t *) arg;

    sc = sscanf(opt, "%d", &i);
    if(sc != 1)
    {
        return GlobusXIOPerfError(
                "port must be an integer",
                GLOBUS_XIO_PERF_ERROR_PARM);
    }
    info->stream_count = i;
    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_time(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    int                                 i;
    int                                 sc;
    globus_i_xioperf_info_t *           info;
    GlobusXIOPerfFuncName(xioperf_l_opts_time);

    info = (globus_i_xioperf_info_t *) arg;
    sc = sscanf(opt, "%d", &i);
    if(sc != 1)
    {
        return GlobusXIOPerfError(
                "port must be an integer",
                GLOBUS_XIO_PERF_ERROR_PARM);
    }
    *out_parms_used = 1;
    GlobusTimeReltimeSet(info->time, i, 0);

    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_recv(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;
    info->reader = GLOBUS_TRUE;
    *out_parms_used = 0;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_send(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;
    info->writer = GLOBUS_TRUE;
    *out_parms_used = 0;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_daemon(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;
    info->daemon = GLOBUS_TRUE;
    *out_parms_used = 0;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
xioperf_l_opts_subject_dn(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) arg;

    info->subject = strdup(opt);

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
    if(result != GLOBUS_SUCCESS)
    {
        return result;
    }
    result = globus_xio_stack_push_driver(info->stack, driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    globus_hashtable_insert(&info->driver_table, strdup(opt), driver);
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
error:
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
    *out_parms_used = 0;
    exit(0);
}

globus_options_entry_t                   globus_i_xioperf_opts_table[] =
{
    {"format", "f", NULL, "[kmgKMG]",
        "format to report: Kbits, Mbits, Gbits, KBytes, MBytes, GBytes",
        1, xioperf_l_opts_format},
    {"interval", "i", NULL, "#",
        "seconds between periodic bandwidth reports", 
        1, xio_perf_l_opts_interval},
    {"quiet", "q", NULL, NULL,
        "only output | <time> <read bytes> <read BW> <write bytes> <write BW>", 
        0, xioperf_l_opts_quiet},
    {"len", "l", NULL, "#[KM]",
        "length of buffer to read or write (default 8 KB)", 
        1, xioperf_l_opts_len},
    {"port", "p", NULL, "#",
        "server port to listen on/connect to", 
        1, xioperf_l_opts_port},
    {"block-size", "bs", NULL, "#[GKM]",
        "block size to post at once (also disk block size)", 
        1, xioperf_l_opts_blocksize},
    {"window", "w", NULL, "#[GKM]",
        "TCP window size (socket buffer size)", 
        1, xioperf_l_opts_window},
    {"bind", "B", NULL, "<host>", "bind to <host>",
        1, xioperf_l_opts_bind},
    {"nodelay", "N", NULL, NULL,
        "set TCP no delay, disabling Nagle's Algorithm", 
        0, xioperf_l_opts_nodelay},
    {"server", "s", NULL, NULL, 
        "run in server mode", 
        0, xioperf_l_opts_server},
    {"bandwidth", "b", NULL, "#[GKM]",
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
    {"sender", "S", NULL, NULL,
        "send data",
        0, xioperf_l_opts_send},
    {"receiver", "R", NULL, NULL,
        "recveive data",
        0, xioperf_l_opts_recv},
    {"parallel", "P", NULL, "#",
        "number of parallel streams to use",
        1, xioperf_l_opts_parallel},
    {"time", "t", NULL, "#",
        "time in seconds for which to transmit (default 10 secs)",
        1, xioperf_l_opts_time},
    {"daemon", "d", NULL, NULL,
        "put a server in daemon mode.",
        0, xioperf_l_opts_daemon},
    {"subject", "DN", NULL, "<certificate subject>",
        "the certificate subject if using the gsi driver",
        1, xioperf_l_opts_subject_dn},
    {"driver", "D", NULL, "<driver name>",
        "the name of the driver to put next on the stack",
        1, xioperf_l_opts_driver},
    {"version", "v", NULL, NULL,
        "Print version information.",
        0, xioperf_l_opts_version},
    {NULL, NULL, NULL, NULL, NULL, 0, NULL}
};

#include "globus_i_xio_banner.h"
#include "globus_common.h"
#include "globus_options.h"

static
globus_result_t
xiobanner_l_opts_quiet(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xiobanner_info_t *         info;
    GlobusXIOBannerFuncName(xiobanner_l_opts_quiet);

    info = (globus_i_xiobanner_info_t *) arg;
    *out_parms_used = 0;
    info->quiet = GLOBUS_TRUE;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
xiobanner_l_opts_file(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xiobanner_info_t *         info;
    GlobusXIOBannerFuncName(xiobanner_l_opts_file);

    info = (globus_i_xiobanner_info_t *) arg;
    info->fptr = fopen(opt, "r");
    if(info->fptr != NULL)
    {
        return GlobusXIOBannerError(
                "Coult not open file",
                GLOBUS_XIO_BANNER_ERROR_PARM);
    }
    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xiobanner_l_opts_cs(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xiobanner_info_t *         info;
    GlobusXIOBannerFuncName(xiobanner_l_opts_cs);

    info = (globus_i_xiobanner_info_t *) arg;
    *out_parms_used = 1;
    info->cs = strdup(opt);

    return GLOBUS_SUCCESS;
}

static
globus_bool_t
xio_banner_timeout_cb(
    globus_xio_handle_t                         handle,
    globus_xio_operation_type_t                 type)
{
    return GLOBUS_TRUE;
}


static
globus_result_t
xiobanner_l_opts_timeout(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    int                                 i;
    int                                 sc;
    globus_i_xiobanner_info_t *         info;
    GlobusXIOBannerFuncName(xiobanner_l_opts_timeout);

    info = (globus_i_xiobanner_info_t *) arg;
    sc = sscanf(opt, "%d", &i);
    if(sc != 1)
    {
        return GlobusXIOBannerError(
                "port must be an integer",
                GLOBUS_XIO_BANNER_ERROR_PARM);
    }
    *out_parms_used = 1;
    GlobusTimeReltimeSet(info->time, i, 0);

    globus_xio_attr_cntl(
        info->attr,
        NULL,
        GLOBUS_XIO_ATTR_SET_TIMEOUT_ALL,
        xio_banner_timeout_cb,
        &info->time,
        NULL);
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xiobanner_l_opts_driver(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    char *                              driver_name;
    char *                              driver_opts;
    globus_result_t                     result;
    globus_xio_driver_t                 driver;
    globus_i_xiobanner_info_t *         info;
    GlobusXIOBannerFuncName(xiobanner_l_opts_driver);

    info = (globus_i_xiobanner_info_t *) arg;

    driver_name = strdup(opt);
    driver_opts = strchr(driver_name, ':');
    if(driver_opts != NULL)
    {
        *driver_opts = '\0';
        driver_opts++;
    }

    result = globus_xio_driver_load(driver_name, &driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    result = globus_xio_stack_push_driver(info->stack, driver);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    info->driver_count++;

    globus_xio_attr_cntl(
        info->attr,
        driver,
        GLOBUS_XIO_SET_STRING_OPTIONS,
        driver_opts);

    globus_hashtable_insert(&info->driver_table, driver_name, driver);
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
error:
    free(driver_name);
    return result;
}

static
globus_result_t
xiobanner_l_opts_max(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    int                                 sc;
    int                                 i;
    globus_i_xiobanner_info_t *         info;
    GlobusXIOBannerFuncName(xiobanner_l_opts_max);

    info = (globus_i_xiobanner_info_t *) arg;

    sc = sscanf(opt, "%d", &i);
    if(sc != 1)
    {
        return GlobusXIOBannerError(
                "port must be an integer",
                GLOBUS_XIO_BANNER_ERROR_PARM);
    }
    *out_parms_used = 1;
    info->max_len = i;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
xiobanner_l_opts_del(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_i_xiobanner_info_t *         info;
    GlobusXIOBannerFuncName(xiobanner_l_opts_del);

    info = (globus_i_xiobanner_info_t *) arg;

    info->deliminator = strdup(opt);
    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
xiobanner_l_opts_version(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
 /* print the version and exit */
    globus_version_print(
        "xiobanner",
        &local_version,
        stderr,
        GLOBUS_TRUE);
    globus_module_print_activated_versions(stderr, GLOBUS_TRUE);
    *out_parms_used = 0;
    exit(0);
}

globus_options_entry_t                   globus_i_xiobanner_opts_table[] =
{
    {"timeout", "t", NULL, "<int>",
        "Timeout in seconds for read operation",
        1, xiobanner_l_opts_timeout},
    {"contact", "c", NULL, "<contact string>",
        "Contact string from which to read the banner.",
        1, xiobanner_l_opts_cs},
    {"driver", "D", NULL, "<driver name>",
        "the driver to push on the stack.",
        1, xiobanner_l_opts_driver},
    {"quiet", "q", NULL, NULL,
        "Dont write logging information to stderr.",
        0, xiobanner_l_opts_quiet},
    {"file", "f", NULL, "<file name>",
        "File name to which the banner will be written.  Default is stdout.",
        1, xiobanner_l_opts_file},
    {"deliminator", "d", NULL, "<string>",
        "Processing will continue until the given string is read from "
        "the network.",
        1, xiobanner_l_opts_del},
    {"max", "m", NULL, "<int>",
        "Max number of bytes to read from the banner",
        1, xiobanner_l_opts_max},
    {"version", "v", NULL, NULL,
        "Print version information.",
        0, xiobanner_l_opts_version},
    {NULL, NULL, NULL, NULL, NULL, 0, NULL}
};

#include "globus_i_crft_util.h"
#include "globus_options.h"
#include "version.h"


extern globus_options_entry_t            globus_i_xioperf_opts_table[];

static
globus_result_t
xioperf_l_opts_unknown(
    const char *                        parm,
    void *                              arg)
{
    return globus_error_put(globus_error_construct_error(
        NULL,
        NULL,
        2,
        __FILE__,
        "xioperf_l_opts_unknown",
        __LINE__,
        "Unknown parameter: %s",
        parm));
}

static
globus_i_xioperf_info_t *
xioperf_l_parse_opts(
    int                                 argc,
    char **                             argv)
{
    globus_i_xioperf_info_t *           info;

    info = (globus_i_xioperf_info_t *) globus_calloc(
        1, sizeof(globus_i_xioperf_info_t));
    if(info == NULL)
    {
        goto error;
    }

    info->server = GLOBUS_TRUE;
    info->stream_count = 1;
    info->port = 9999;
    info->len = 8;
    info->format = 'm';
    GlobusTimeAbstimeSet(info->time, 10, 0);
    globus_xio_stack_init(&info->stack, NULL);

    globus_options_init(
        &opt_h, xioperf_l_opts_unknown, info, globus_i_xioperf_opts_table);
    res = globus_options_command_line_process(opt_h, argc, argv);
    if(res != GLOBUS_SUCCESS)
    {
        goto error_result;
    }

    return info;
error_result:
    fprintf(stderr, "%s\n",
        globus_error_print_friendly(globus_error_get(res)));
error:
    return NULL;
}

/*
 *  The first time through cancel it, the second time unregister the trap
 *  so that the thrid time normal ctrl+c stuff happens.
 */
static
void
crft_l_interrupt_cb(
    void *                              user_arg)
{
}

int
main(
    int                                 argc,
    char **                             argv)
{
    globus_i_xioperf_info_t *           info;
    globus_result_t                     res;
 
    globus_module_activate(GLOBUS_XIO_MODULE);

    info = xioperf_l_parse_opts(argc, argv);
    if(info == NULL)
    {
        goto error;
    }

    globus_module_deactivate(GLOBUS_XIO_MODULE);
    return 0;

error:
    globus_module_deactivate(GLOBUS_XIO_MODULE);
    return 1;
}

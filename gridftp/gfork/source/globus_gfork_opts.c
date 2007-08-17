#include "globus_common.h"
#include "globus_options.h"
#include "globus_i_gfork.h"
#include "version.h"

static
globus_list_t *
gfork_l_list_to_list(
    const char *                        in_str,
    globus_list_t *                     old_list);

globus_result_t
globus_i_opts_to_handle(
    gfork_i_options_t *                 opts,
    gfork_i_handle_t *                  handle)
{
    char *                              driver_name;
    char *                              driver_opts;
    globus_xio_attr_t                   attr;
    globus_result_t                     result;
    int                                 i;
    globus_list_t *                     list;
    globus_xio_driver_t                 driver;

    memset(handle, '\0', sizeof(gfork_i_handle_t));

    globus_xio_stack_init(&handle->stack, NULL);
    globus_xio_attr_init(&attr);

    handle->opts = opts;

    if(opts->server != NULL)
    {
        handle->server_argv = (char **) globus_calloc(
            globus_list_size(opts->server_arg_list) + 2, sizeof(char *));
        handle->server_argv[0] = opts->server;

        i = 1;
        for(list = opts->server_arg_list;
            !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            handle->server_argv[i] = (char *) globus_list_first(list);
            i++;
        }
    }
    else
    {
        /* XXX create error object */
        goto error_no_server;
    }
    if(opts->master != NULL)
    {
        handle->master_argv = (char **) globus_calloc(
            globus_list_size(opts->master_arg_list) + 2, sizeof(char *));
        handle->master_argv[0] = opts->master;

        i = 1;
        for(list = opts->master_arg_list;
            !globus_list_empty(list);
            list = globus_list_rest(list))
        {
            handle->master_argv[i] = (char *) globus_list_first(list);
            i++;
        }
    }

    handle->env_argv = (char **) globus_calloc(
        globus_list_size(opts->env_list) + 1, sizeof(char *));
    i = 0;
    for(list = opts->env_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        handle->env_argv[i] = (char *) globus_list_first(list);
        i++;
    }

    if(globus_list_empty(opts->protocol_list))
    {
        globus_list_insert(&opts->protocol_list, "tcp");
    }

    for(list = opts->protocol_list;
        !globus_list_empty(list);
        list = globus_list_rest(list))
    {
        driver_name = (char *) globus_list_first(list);

        driver_opts = strchr(driver_name, ':');
        if(driver_opts != NULL)
        {
            *driver_opts = '\0';
            driver_opts++;
        }
        result = globus_xio_driver_load(driver_name, &driver);
        if(result != GLOBUS_SUCCESS)
        {
            goto error_drivers;
        }

        globus_list_insert(&handle->loaded_drivers, driver);
        if(driver_opts != NULL)
        {
            result = globus_xio_attr_cntl(
                attr,
                driver,
                GLOBUS_XIO_SET_STRING_OPTIONS,
                driver_opts);
            if(result != GLOBUS_SUCCESS)
            {
                goto error_drivers;
            }
        }
        globus_xio_stack_push_driver(handle->stack, driver);

        if(strcmp(driver_name, "tcp") == 0)
        {
            handle->tcp_driver = driver;

            result = globus_xio_attr_cntl(
                attr,
                driver,
                GLOBUS_XIO_TCP_SET_REUSEADDR,
                GLOBUS_TRUE);
            if(result != GLOBUS_SUCCESS)
            {
            }
        }
    }

    if(handle->tcp_driver != NULL)
    {
        if(opts->port != 0)
        {
            globus_xio_attr_cntl(
                attr, handle->tcp_driver, GLOBUS_XIO_TCP_SET_PORT, opts->port);
        }

/*
    int                                 backlog = -1;
        if(opts->instances > 1)
        {
            backlog = opts->instances / 2;
            backlog = 2;
        }
        globus_xio_attr_cntl(
            attr, handle->tcp_driver, GLOBUS_XIO_TCP_SET_BACKLOG, backlog);
*/
    }

    result = globus_xio_server_create(
        &handle->server_xio,
        attr,
        handle->stack);
    if(result != GLOBUS_SUCCESS)
    {
        goto error_server;
    }
    globus_xio_attr_destroy(attr);
    return GLOBUS_SUCCESS;

error_server:
error_drivers:
    if(handle->master_argv)
    {
        globus_free(handle->master_argv);
    }
    globus_free(handle->env_argv);
    globus_free(handle->server_argv);
    globus_list_free(handle->loaded_drivers);
error_no_server:
    globus_xio_attr_destroy(attr);

    return result;
}

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
gfork_l_opts_master_uid(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{   
    int                                 sc;
    int                                 mu;
    gfork_i_options_t *                 gfork_h;

    gfork_h = (gfork_i_options_t *) arg;
    
    sc = sscanf(opt[0], "%d", &mu);
    if(sc != 1)
    {
        goto error_format;
    }

    gfork_h->master_user = mu;
    
    *out_parms_used = 1;
    return GLOBUS_SUCCESS;

error_format:
    *out_parms_used = 0;

    return 0x1;
}


static
globus_result_t
gfork_l_opts_master(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    gfork_i_options_t *                 gfork_h;

    gfork_h = (gfork_i_options_t *) arg;

    gfork_h->master = strdup(opt[0]);

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfork_l_opts_master_args(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_list_t *                     list;
    gfork_i_options_t *                 gfork_h;

    gfork_h = (gfork_i_options_t *) arg;

    list = gfork_l_list_to_list(opt[0], gfork_h->master_arg_list);
    gfork_h->master_arg_list = list;

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

static
globus_list_t *
gfork_l_list_to_list(
    const char *                        in_str,
    globus_list_t *                     old_list)
{
    void *                              tmp_ent;
    globus_list_t *                     out_list;
    globus_list_t *                     list;
    globus_list_t *                     rev_list = NULL;

    list = globus_list_from_string(in_str, ' ', NULL);
    /* gotta reverse this */
    while(!globus_list_empty(list))
    {
        tmp_ent = globus_list_remove(&list, list);
        globus_list_insert(&rev_list, tmp_ent);
    }

    out_list = globus_list_concat(old_list, rev_list);
    globus_list_free(rev_list);
    globus_list_free(old_list);

    return out_list;
}

static
globus_result_t
gfork_l_opts_id(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    gfork_i_options_t *                 gfork_h;

    gfork_h = (gfork_i_options_t *) arg;

    gfork_h->id = strdup(opt[0]);

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfork_l_opts_protocol(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    gfork_i_options_t *                 gfork_h;
    globus_list_t *                     list;

    gfork_h = (gfork_i_options_t *) arg;

    list = gfork_l_list_to_list(opt[0], gfork_h->protocol_list);
    gfork_h->protocol_list = list;

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfork_l_opts_server(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    gfork_i_options_t *                 gfork_h;

    gfork_h = (gfork_i_options_t *) arg;

    gfork_h->server = strdup(opt[0]);
    
    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}


static
globus_result_t
gfork_l_opts_server_args(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_list_t *                     list;
    gfork_i_options_t *                 gfork_h;

    gfork_h = (gfork_i_options_t *) arg;

    list = gfork_l_list_to_list(opt[0], gfork_h->server_arg_list);
    gfork_h->server_arg_list = list;
 
    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
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
    GForkFuncName(gfork_l_opts_port);

    gfork_h = (gfork_i_options_t *) arg;

    sc = sscanf(opt[0], "%d", &port);
    if(sc != 1)
    {
        result = GForkErrorStr("Port must be an integer");
        goto error_format;
    }
    gfork_h->port = port;

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;

error_format:
    *out_parms_used = 0;

    return result;
}

static
globus_result_t
gfork_l_opts_instances(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    gfork_i_options_t *                 gfork_h;
    int                                 instances;
    int                                 sc;
    globus_result_t                     result;
    GForkFuncName(gfork_l_opts_instances);

    gfork_h = (gfork_i_options_t *) arg;

    sc = sscanf(opt[0], "%d", &instances);
    if(sc != 1)
    {
        result = GForkErrorStr("Instance must be an integer");
        goto error_format;
    }
    gfork_h->instances = instances;
    
    *out_parms_used = 1;
    return GLOBUS_SUCCESS;

error_format:
    *out_parms_used = 0;

    return result;
}


static
globus_result_t
gfork_l_opts_nice(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{   
    gfork_i_options_t *                 gfork_h;
    int                                 sc;
    int                                 nice;
    globus_result_t                     result;
    GForkFuncName(gfork_l_opts_nice);
    
    gfork_h = (gfork_i_options_t *) arg;

    sc = sscanf(opt[0], "%d", &nice);
    if(sc != 1)
    {
        result = GForkErrorStr("Nice must be an integer");
        goto error_format;
    }
    gfork_h->nice = nice;

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
error_format:
    *out_parms_used = 0;

    return result;
}   

static
globus_result_t
gfork_l_opts_bind(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    gfork_i_options_t *                 gfork_h;

    gfork_h = (gfork_i_options_t *) arg;

    gfork_h->interface = strdup(opt[0]);

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfork_l_opts_conf_file(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    gfork_i_options_t *                 gfork_h;

    gfork_h = (gfork_i_options_t *) arg;

    gfork_h->conf_file = strdup(opt[0]);

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfork_l_opts_env(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{   
    gfork_i_options_t *                 gfork_h;
    globus_list_t *                     list;

    gfork_h = (gfork_i_options_t *) arg;

    list = gfork_l_list_to_list(opt[0], gfork_h->env_list);
    gfork_h->env_list = list;

    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
gfork_l_opts_log_level(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    gfork_i_options_t *                 gfork_h;
    int                                 level;
    int                                 sc;
    globus_result_t                     result;
    GForkFuncName(gfork_l_opts_log_level);

    gfork_h = (gfork_i_options_t *) arg;

    sc = sscanf(opt[0], "%d", &level);
    if(sc != 1)
    {
        result = GForkErrorStr("Log level must be an integer");
        goto error_format;
    }
    gfork_h->log_level = level;

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;

error_format:
    *out_parms_used = 0;

    return result;
}

static
globus_result_t
gfork_l_opts_log_file(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    gfork_i_options_t *                 gfork_h;
    globus_result_t                     result;
    FILE *                              fptr;
    GForkFuncName(gfork_l_opts_log_file);

    gfork_h = (gfork_i_options_t *) arg;

    if(strcmp(opt[0], "-") == 0)
    {
        gfork_h->log_fptr = stdout;
    }
    else
    {
        fptr = fopen(opt[0], "w");
        if(fptr == NULL)
        {
            result = GForkErrorStr("Could not open log file");
            goto error;
        }
        gfork_h->log_fptr = fptr;
    }

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
error:
    return result;
}

static
globus_result_t
gfork_l_opts_quiet(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{   
    gfork_i_options_t *                 gfork_h;

    gfork_h = (gfork_i_options_t *) arg;

    if(strcasecmp("true", opt[0]) == 0 ||
        strcasecmp("yes", opt[0]) == 0 ||
        strcasecmp("t", opt[0]) == 0 ||
        strcasecmp("y", opt[0]) == 0)
    {
        gfork_h->quiet = GLOBUS_TRUE;
    }
    else
    {
        gfork_h->quiet = GLOBUS_FALSE;
    }

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}

/* 
 *  for xinetd, ignoting type, flags, disable, socket_type, user, group
 */
globus_options_entry_t                   gfork_l_opts_table[] =
{
    {"id", "I", NULL, "<id>",
        "This attribute is used to uniquely identify a service.",
        1, gfork_l_opts_id},
    {"protocol", "S", NULL, "<protocol description>",
        "A list of xio drivers bottom to top",
        1, gfork_l_opts_protocol},
    {"server", "s", NULL, "<server program name>",
        "Determines the program to execute for this service.",
        1, gfork_l_opts_server},
    {"server_args", "sa", NULL, "<arguments to the server>",
        "List of arguments.  Comma seperated (or += if xinetd style)",
        1, gfork_l_opts_server_args},
    {"port", "p", NULL, "<listener port number>",
        "The port number for the TCP listener",
        1, gfork_l_opts_port},
    {"instances", "inst", NULL, "<UNLIMITED | integer>",
        "The number of servers that can be simultaneously active.",
        1, gfork_l_opts_instances},
    {"nice", "n", NULL, "<integer>",
        "Sets the server priority.",
        1, gfork_l_opts_nice},
    {"interface", "b", NULL, "<interface>",
        "Sets the listening interface.",
        1, gfork_l_opts_bind},
    {"bind", "b", NULL, "<interface>",
        "Sets the listening interface.",
        1, gfork_l_opts_bind},
    {"env", "e", NULL, "<string>",
        "Sets the services environment",
        1, gfork_l_opts_env},
    {"master-uid", "M", NULL, "<uid>",
        "The uid under which the master program will be run",
        1, gfork_l_opts_master_uid},
    {"master", "m", NULL, "<master program name>",
        "The name of the master program",
        1, gfork_l_opts_master},
    {"master_args", "m", NULL, "<master program name>",
        "The name of the master program",
        1, gfork_l_opts_master_args},
    {"config_file", "c", NULL, NULL,
        "Print version information.",
        1, gfork_l_opts_conf_file},
    {"version", "v", NULL, NULL,
        "Print version information.",
        0, gfork_l_opts_version},
    {"help", "h", NULL, NULL,
        "print the help message",
        0, gfork_l_opts_help},
    {"log_level", "L", NULL, "<int>",
        "Set the logging level 0 - 9",
        1, gfork_l_opts_log_level},
    {"log_file", "f", NULL, "<path>",
        "Set the log file",
        1, gfork_l_opts_log_file},
    {"quiet", "q", NULL, "<true|false>",
        "Turn off all output",
        1, gfork_l_opts_quiet},
    {NULL, NULL, NULL, NULL, NULL, 0, NULL}
};

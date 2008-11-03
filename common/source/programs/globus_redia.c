#include "globus_common.h"
#include <dlfcn.h>

static char * g_edge_label = "";
static char * g_outfile = "-";
static char * g_txt_file = "-";
static int g_flag = GLOBUS_STATE_DIA_NO_DUPLICATES | GLOBUS_STATE_DIA_NUMBER_LABELS;

static
globus_result_t
redia_l_opts_unknown(
   globus_options_handle_t             opts_handle,
    void *                              unknown_arg,
    int                                 argc,
    char **                             argv)
{
    return globus_error_put(globus_error_construct_error(
        NULL,
        NULL,
        2,
        __FILE__,
        "redia_l_opts_unknown",
        __LINE__,
        "Unknown parameter: %s",
        unknown_arg));
}

static
globus_result_t
redia_l_opts_help(
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
redia_l_opts_edge_name(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    g_flag |= GLOBUS_STATE_DIA_EDGE_EVENT;
    *out_parms_used = 0;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
redia_l_opts_edge_desc(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    g_flag |= GLOBUS_STATE_DIA_EDGE_FUNC;
    *out_parms_used = 0;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
redia_l_opts_edge_label(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    g_edge_label = opt[1];
    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
redia_l_opts_txt_file(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    g_txt_file = opt[1];
    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}

static
globus_result_t
redia_l_opts_outfile(
    globus_options_handle_t             opts_handle,
    char *                              cmd,
    char **                             opt,
    void *                              arg,
    int *                               out_parms_used)
{
    g_outfile = opt[1];
    *out_parms_used = 1;
    return GLOBUS_SUCCESS;
}


globus_options_entry_t                   redia_l_opts_table[] =
{
    {"edge-name", "en", NULL, "",
        "use the library associated edge names",
        0, redia_l_opts_edge_name},
    {"edge-func", "ef", NULL, "",
        "use the function handler as the edge name",
        0, redia_l_opts_edge_desc},
    {"edge-label", "el", NULL, "",
        "additional edge directives",
        0, redia_l_opts_edge_label},
    {"outfile", "o", NULL, "",
        "outfile for dot format",
        1, redia_l_opts_outfile},
    {"txt-outfile", "to", NULL, "",
        "text file output",
        1, redia_l_opts_txt_file},
    {"help", "?", NULL, "",
        "print usage information",
        0, redia_l_opts_help}
};


int
main(int argc, char ** argv)
{
    char *                              lib_name;
    char *                              symbol_name;
    int                                 rc;
    globus_state_extension_handle_t *   ext_data;
    globus_result_t                     result;
    globus_state_handle_t               handle;
    void *                              dlo_h;
    void *                              sym_handle;
    globus_options_handle_t             opt_h;

    globus_options_init(
        &opt_h, redia_l_opts_unknown, NULL);

    globus_options_add_table(opt_h, redia_l_opts_table, NULL);
    result = globus_options_command_line_process(opt_h, argc-2, argv);
    if(result != GLOBUS_SUCCESS)
    {
        exit(1);
    }

    lib_name = argv[argc-2];
    symbol_name = argv[argc-1];

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != 0)
    {
        fprintf(stderr, "Failed to activate common\n");
        exit(1);
    }

    dlo_h = dlopen(lib_name, RTLD_NOW);
    if(dlo_h == NULL)
    {
        fprintf(stderr, "Failed to dlopen %s\n", lib_name);
        exit(1);
    }

    sym_handle = dlsym(dlo_h, symbol_name);
    if(sym_handle == NULL)
    {
        fprintf(stderr, "Failed to dlsym %s\n", symbol_name);
        exit(1);
    }

    ext_data = (globus_state_extension_handle_t *) sym_handle;

    fprintf(stderr, "Found %s, name %s\n", symbol_name, ext_data->name);

    fprintf(stderr, "writing to file %s\n", g_outfile);

    result = globus_states_init(&handle, ext_data->init_handler);
    if(result != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Init handler returned with an error\n");
        exit(1);
    }

    /* call print function */ 
    rc = globus_state_make_graph(
        handle, g_outfile, g_txt_file, g_flag, g_edge_label); 
    if(rc != 0)
    {
        fprintf(stderr, "Failed to make graph in file %s\n", g_outfile);
        exit(1);
    }
    return 0;
}

#ifndef GLOBUS_SRB_OPTIONS_H
#define GLOBUS_SRB_OPTIONS_H 1

#include "globus_common.h"


enum 
{
    GLOBUS_SRB_OPTIONS_HELP = 1,
    GLOBUS_SRB_OPTIONS_NOT_ENOUGH_ARGS,
    GLOBUS_SRB_OPTIONS_INVALID_PARAMETER,
    GLOBUS_SRB_OPTIONS_UNKNOWN
};

typedef
globus_result_t
(*globus_srb_options_callback_t)(
    char *                              cmd,
    char *                              parm,
    void *                              arg,
    int *                               out_parms_used);

typedef
globus_result_t
(*globus_srb_options_unknown_callback_t)(
    const char *                        parm,
    void *                              arg);

typedef struct globus_srb_options_entry_s
{
    char *                              opt_name; /* long and filename */
    char *                              short_opt;
    char *                              env;
    char *                              parms_desc;
    char *                              description;
    int                                 arg_count;
    globus_srb_options_callback_t       func;
} globus_srb_options_entry_t;

typedef struct globus_l_srb_options_handle_s * globus_srb_options_handle_t;

globus_result_t
globus_srb_options_init(
    globus_srb_options_handle_t *       out_handle,
    globus_srb_options_unknown_callback_t   unknown_func,
    void *                              user_arg,
    globus_srb_options_entry_t *        table);

globus_result_t
globus_srb_options_destroy(
    globus_srb_options_handle_t             handle);

globus_result_t
globus_srb_options_command_line_process(
    globus_srb_options_handle_t             handle,
    int                                 argc,
    char **                             argv);

globus_result_t
globus_srb_options_env_process(
    globus_srb_options_handle_t             handle);

globus_result_t
globus_srb_options_file_process(
    globus_srb_options_handle_t             handle,
    char *                              filename);

#endif

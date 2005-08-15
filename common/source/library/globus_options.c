#include "globus_common.h"

typedef struct globus_l_options_handle_s
{
    globus_options_unknown_callback_t    unknown_func;
    void *                              user_arg;
    globus_options_entry_t *             table;
    int                                 table_size;
} globus_l_options_handle_t;

globus_result_t
globus_options_init(
    globus_options_handle_t *            out_handle,
    globus_options_unknown_callback_t    unknown_func,
    void *                              user_arg,
    globus_options_entry_t *             table)
{
    int                                 i;
    globus_l_options_handle_t *          handle;

    handle = (globus_l_options_handle_t *)
        globus_calloc(1, sizeof(globus_l_options_handle_t));
    if(handle == NULL)
    {
    }
    handle->unknown_func = unknown_func;
    handle->user_arg = user_arg;
    handle->table = table;

    for(i = 0; handle->table[i].func != NULL; i++)
    {
    }
    handle->table_size = i;

    *out_handle = handle;

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_options_destroy(
    globus_options_handle_t              handle)
{
    globus_free(handle);

    return GLOBUS_SUCCESS;
}

static
void
globus_options_help(
    globus_options_handle_t                handle)
{
    int                                 i;
    int                                 length;
    int                                 ndx;
    char                                buf[80];

    for(i = 0; i < handle->table_size; i++)
    {
        fprintf(stdout, "-%s | --%s ",
            handle->table[i].short_opt, handle->table[i].opt_name);
        if(handle->table[i].parms_desc != NULL)
        {
            fprintf(stdout, "%s", handle->table[i].parms_desc);
        }
        fprintf(stdout, "\n");
        if(handle->table[i].description != NULL)
        {
            ndx = 0;
            do 
            {
                length = strlen(&handle->table[i].description[ndx]);
                if(length > 70)
                {
                    length = 70;
                }
                snprintf(buf,70,"%s",&handle->table[i].description[ndx]);
                buf[length] = '\0';
                fprintf(stdout, "\t%s\n", buf);
                ndx += length;
            } while(length > 0);
        }
    }
}

globus_result_t
globus_options_command_line_process(
    globus_options_handle_t              handle,
    int                                 argc,
    char **                             argv)
{
    int                                 func_argc;
    globus_result_t                     res;
    int                                 i;
    int                                 j;
    char *                              arg_parm;
    int                                 used;
    char *                              current_arg;
    globus_bool_t                       found;
    GlobusFuncName(globus_options_command_line_process);

    for(i = 1; i < argc; i++)
    {
        current_arg = argv[i];
        found = GLOBUS_FALSE;

        for(j = 0; j < handle->table_size && !found; j++)
        {
            found = GLOBUS_FALSE;
            if(handle->table[j].short_opt != NULL &&
                current_arg[0] == '-' &&
                strcmp(&current_arg[1], handle->table[j].short_opt) == 0)
            {
                found = GLOBUS_TRUE;
            }
            else if(handle->table[j].opt_name != NULL &&
                ((current_arg[0] == '-' && 
                    strcmp(&current_arg[1], handle->table[j].opt_name) == 0) ||
                 (current_arg[0] == '-' && current_arg[1] == '-' &&
                    strcmp(&current_arg[2], handle->table[j].opt_name) == 0)))
            {
                found = GLOBUS_TRUE;
            }

            if(found)
            {
                func_argc = argc - i;
                if(handle->table[j].arg_count == 0)
                {
                    arg_parm = NULL;
                }
                else
                {
                    arg_parm = argv[i+1];
                }

                if(func_argc > handle->table[j].arg_count)
                {
                    res = handle->table[j].func(
                        handle->table[j].opt_name,
                        arg_parm,
                        handle->user_arg,
                        &used);
                    if(used > 1 || used < 0)
                    {
                        res = globus_error_put(globus_error_construct_error(
                            NULL,
                            NULL,
                            GLOBUS_OPTIONS_NOT_ENOUGH_ARGS,
                            __FILE__,
                            _globus_func_name,
                            __LINE__,
                            "Not enough parameters for: %s",
                            current_arg));
                        return res;
                    }
                    if(res != GLOBUS_SUCCESS)
                    {
                        return res;
                    }
                    i += used;
                }
                else
                {
                    return globus_error_put(globus_error_construct_error(
                        NULL,
                        NULL,
                        GLOBUS_OPTIONS_NOT_ENOUGH_ARGS,
                        __FILE__,
                        _globus_func_name,
                        __LINE__,
                        "Not enough parameters for: %s",
                        current_arg));
                }
            }
        }
        if(!found)
        {
            if(strcmp(argv[i],"--help") == 0 ||
                strcmp(argv[i],"-help") == 0 ||
                strcmp(argv[i],"-h") == 0   ||
                strcmp(argv[i],"-?") == 0)
            {
                globus_options_help(handle);
                return globus_error_put(globus_error_construct_error(
                    NULL,
                    NULL,
                    GLOBUS_OPTIONS_HELP,
                    __FILE__,
                    _globus_func_name,
                    __LINE__,
                    "Program usage"));
            }
            /* invalid handler */
            else if(handle->unknown_func != NULL)
            {
                res = handle->unknown_func(argv[i], handle->user_arg);
                if(res != GLOBUS_SUCCESS)
                {
                    return res;
                }
            }
        }
    }

    return GLOBUS_SUCCESS;
}

globus_result_t
globus_options_env_process(
    globus_options_handle_t             handle)
{
    globus_result_t                     res;
    int                                 i;
    char *                              tmp_str;
    int                                 used;

    for(i = 0; i < handle->table_size; i++)
    {
        if(handle->table[i].env != NULL)
        {
            tmp_str = globus_libc_getenv(handle->table[i].env);
            if(tmp_str != NULL)
            {
                if(*tmp_str == '\0')
                {
                    tmp_str = NULL;
                }
                res = handle->table[i].func(
                    handle->table[i].opt_name,
                    tmp_str,
                    handle->user_arg,
                    &used);
                if(res != GLOBUS_SUCCESS)
                {
                    return res;
                }
            }
        }
    }

    return GLOBUS_SUCCESS;
}


globus_result_t
globus_options_file_process(
    globus_options_handle_t              handle,
    char *                              filename)
{
    char *                              opt_arg;
    int                                 used;
    globus_result_t                     res;
    FILE *                              fptr;
    char                                line[1024];
    char                                file_option[1024];
    char                                value[1024];
    int                                 i;
    int                                 rc;
    int                                 line_num;
    int                                 optlen;
    char *                              p;
    GlobusFuncName(globus_options_file_process);

    fptr = fopen(filename, "r");
    if(fptr == NULL)
    {
        return globus_error_put(globus_error_construct_error(
            NULL,
            NULL,
            GLOBUS_OPTIONS_HELP,
            __FILE__,
            _globus_func_name,
            __LINE__,
            "No such file"));
    }

    line_num = 0;
    while(fgets(line, sizeof(line), fptr) != NULL)
    {
        line_num++;
        p = line;
        optlen = 0;
        while(*p && isspace(*p))
        {
            p++;
        }
        if(*p == '\0')
        {
            continue;
        }
        if(*p == '#')
        {
            continue;
        }

        if(*p == '"')
        {
            rc = sscanf(p, "\"%[^\"]\"", file_option);
            optlen = 2;
        }
        else
        {
            rc = sscanf(p, "%s", file_option);
        }
        if(rc != 1)
        {
            goto error_parse;
        }
        optlen += strlen(file_option);
        p = p + optlen;

        optlen = 0;
        while(*p && isspace(*p))
        {
            p++;
        }
        if(*p == '"')
        {
            rc = sscanf(p, "\"%[^\"]\"", value);
            optlen = 2;
        }
        else
        {
            rc = sscanf(p, "%s", value);
        }
        if(rc != 1)
        {
            opt_arg = NULL;
            optlen = 0;
        }
        else
        {
            opt_arg = value;
            optlen += strlen(value);
        }
        p = p + optlen;
        while(*p && isspace(*p))
        {
            p++;
        }
        if(*p && !isspace(*p))
        {
            goto error_parse;
        }

        for(i = 0; i < handle->table_size; i++)
        {
            if(strcmp(file_option, handle->table[i].opt_name) == 0)
            {
                res = handle->table[i].func(
                    handle->table[i].opt_name,
                    opt_arg,
                    handle->user_arg,
                    &used);
                if(res != GLOBUS_SUCCESS)
                {
                    return res;
                }
            }
        }
    }

    fclose(fptr);

    return GLOBUS_SUCCESS;

error_parse:
    fclose(fptr);
    fprintf(stderr, "Problem parsing config file %s: line %d\n",
        filename, line_num);
    return -1;
}

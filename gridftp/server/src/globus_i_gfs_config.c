
#include "globus_i_gridftp_server.h"

typedef enum
{
    GLOBUS_L_GFS_CONFIG_BOOL,
    GLOBUS_L_GFS_CONFIG_INT,
    GLOBUS_L_GFS_CONFIG_STRING
} globus_l_gfs_config_type_t;

typedef struct
{
    char *                              option_name;
    char *                              configfile_option;
    char *                              env_var_option;
    char *                              long_cmdline_option;
    char *                              short_cmdline_option;
    globus_l_gfs_config_type_t          type;
    struct
    {
        int                             int_value;
        char *                          string_value;
    };
} globus_l_gfs_config_option_t;

static const globus_l_gfs_config_option_t option_list[] = 
{ 
 {"max_connections", "max_connections", NULL, "-max-connections", "-mc", GLOBUS_L_GFS_CONFIG_INT, {200, NULL}},
 {"port", "port", "GLOBUS_GRIDFTP_SERVER_PORT", "-port", "-p", GLOBUS_L_GFS_CONFIG_INT, {0, NULL}},
 {"daemon", "daemon", NULL, "-daemon", "-s", GLOBUS_L_GFS_CONFIG_BOOL, {0, NULL}},
 {"detach", "detach", NULL, "-detach", "-S", GLOBUS_L_GFS_CONFIG_BOOL, {0, NULL}},
 {"inetd", "inetd", NULL, "-inetd", "-i", GLOBUS_L_GFS_CONFIG_BOOL, {0, NULL}},
 {"no_security", "no_security", NULL, "-no-security", "-ns", GLOBUS_L_GFS_CONFIG_BOOL, {0, NULL}},
 {"allow_anonymous", "allow_anonymous", NULL, "-allow-anon", "-aa", GLOBUS_L_GFS_CONFIG_BOOL, {0, NULL}},
 {"anonymous_user", "anonymous_user", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, {0, NULL}},
 {"anonymous_group", "anonymous_group", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, {0, NULL}},
 {"data_node", "data_node", NULL, "-data-node", "-dn", GLOBUS_L_GFS_CONFIG_BOOL, {0, NULL}},
 {"terse_banner", "terse_banner", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_BOOL, {0, NULL}},
 {"banner", "banner", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, {0, NULL}},
 {"banner_file", "banner_file", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, {0, NULL}},
 {"login_msg", "login_msg", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, {0, NULL}},
 {"login_msg_file", "login_msg_file", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, {0, NULL}},
 {"connections_disabled", "connections_disabled", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_BOOL, {0, NULL}},
 {"tcp_port_range", "tcp_port_range", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, {0, NULL}},
 {"hostname", "hostname", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, {0, NULL}},
 {"idle_timeout", "idle_timeout", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_INT, {0, NULL}},
 {"globus_location", "globus_location", "GLOBUS_LOCATION", "-G", NULL, GLOBUS_L_GFS_CONFIG_STRING, {0, NULL}},
 {"logfile", "logfile", NULL, "-logfile", "-l", GLOBUS_L_GFS_CONFIG_STRING, {0, NULL}},
 {"remote", "remote", NULL, "-remote", "-r", GLOBUS_L_GFS_CONFIG_STRING, {0, NULL}},
 {"debug_level", "debug_level", NULL, "-debug", "-d", GLOBUS_L_GFS_CONFIG_INT, {1, NULL}},
 {"last_option", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_BOOL, {0, NULL}}
};

static int option_count = sizeof(option_list) / sizeof(globus_l_gfs_config_option_t);

static globus_hashtable_t               option_table;


/* XXX leak when strduping and overwriting string values... never free the old ones */

static
globus_result_t
globus_l_gfs_config_load_config_file(
    char *                              filename)
{
    FILE *                              fptr;
    char                                line[1024];
    char                                file_option[1024];
    char                                value[1024];
    int                                 i;
    int                                 rc;
    globus_l_gfs_config_option_t *      option;
    int                                 line_num;
    int                                 optlen;
    char *                              p;

    fptr = fopen(filename, "r");
    if(fptr == NULL)
    {
        return -1; /* XXX construct real error */
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
            goto error_parse;
        }        
        optlen += strlen(value);
        p = p + optlen;        
        while(*p && isspace(*p))
        {
            p++;
        }
        if(*p && !isspace(*p))
        {
            goto error_parse;
        }

        for(i = 0; i < option_count; i++)
        {
            if(!option_list[i].configfile_option || 
                strcmp(file_option, option_list[i].configfile_option))
            {
                continue;
            }
            
            option = (globus_l_gfs_config_option_t *) globus_hashtable_remove(
                    &option_table, option_list[i].option_name);   
            if(!option)
            {
                option = (globus_l_gfs_config_option_t *)
                    globus_malloc(sizeof(globus_l_gfs_config_option_t));
                memcpy(option, &option_list[i], sizeof(globus_l_gfs_config_option_t));
            }
            switch(option->type)
            {
              case GLOBUS_L_GFS_CONFIG_BOOL:
                option->int_value = (atoi(value) == 0) ? 0 : 1;
                break;
              case GLOBUS_L_GFS_CONFIG_INT:
                option->int_value = atoi(value);
                break;
              case GLOBUS_L_GFS_CONFIG_STRING:
                option->string_value = globus_libc_strdup(value);
                break;
              default:
                break;
            }
            rc = globus_hashtable_insert(&option_table,
                option->option_name,
                (void *) option);
            
            if(rc)
            {
                /* XXX error, log something */
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

static
globus_result_t
globus_l_gfs_config_load_config_env()
{
    char *                              value;
    int                                 rc;
    int                                 i;
    globus_l_gfs_config_option_t *      option;
    

    for(i = 0; i < option_count; i++)
    {
        if (!option_list[i].env_var_option || !*option_list[i].env_var_option)
        {
            continue;
        }

        value = globus_libc_getenv(option_list[i].env_var_option);
        
        if (!value)
        {
            continue;
        }
                            
        option = (globus_l_gfs_config_option_t *) globus_hashtable_remove(
                &option_table, option_list[i].option_name);   
        if(!option)
        {
            option = (globus_l_gfs_config_option_t *)
                globus_malloc(sizeof(globus_l_gfs_config_option_t));
            memcpy(option, &option_list[i], sizeof(globus_l_gfs_config_option_t));
        }
        switch(option->type)
        {
          case GLOBUS_L_GFS_CONFIG_BOOL:
            option->int_value = (atoi(value) == 0) ? 0 : 1;
            break;
          case GLOBUS_L_GFS_CONFIG_INT:
            option->int_value = atoi(value);
            break;
          case GLOBUS_L_GFS_CONFIG_STRING:
            option->string_value = globus_libc_strdup(value);
            break;
          default:
            break;
        }
        rc = globus_hashtable_insert(&option_table,
            option->option_name,
            (void *) option);
        
        if(rc)
        {
            /* XXX error, log something */
        }
    }       

    return GLOBUS_SUCCESS;
}


static
globus_result_t
globus_l_gfs_config_load_commandline(
    int                                 argc,
    char **                             argv)
{
    int                                 arg_num;
    char *                              argp;
    int                                 i;
    int                                 rc;
    globus_l_gfs_config_option_t *      option;
    
    for(arg_num = 0; arg_num < argc; ++arg_num)
    {
        argp = argv[arg_num];
 
        for(i = 0; i < option_count; i++)
        {
            if((!option_list[i].short_cmdline_option || 
                strcmp(argp, option_list[i].short_cmdline_option)) && 
                (!option_list[i].long_cmdline_option || 
                strcmp(argp, option_list[i].long_cmdline_option)) )
            {
                continue;
            }
                        
            option = (globus_l_gfs_config_option_t *) globus_hashtable_remove(
                    &option_table, option_list[i].option_name);   
            if(!option)
            {
                option = (globus_l_gfs_config_option_t *)
                    globus_malloc(sizeof(globus_l_gfs_config_option_t));
                memcpy(option, &option_list[i], sizeof(globus_l_gfs_config_option_t));
            }

            switch(option->type)
            {
              case GLOBUS_L_GFS_CONFIG_BOOL:
                option->int_value = 1;
                break;

              case GLOBUS_L_GFS_CONFIG_INT:
                if(++arg_num >= argc)
                {
                    /* XXX error, log something */
                    return -1;
                }
                option->int_value = atoi(argv[arg_num]);
                break;
                
              case GLOBUS_L_GFS_CONFIG_STRING:
                if(++arg_num >= argc)
                {
                    /* XXX error, log something */
                    return -1;
                }
                option->string_value = globus_libc_strdup(argv[arg_num]);
                break;

              default:
                break;
             }

            rc = globus_hashtable_insert(&option_table,
                option->option_name,
                (void *) option);
            
            if(rc)
            {
                /* XXX error, log something */
            }
            
        }
    }
      
    return GLOBUS_SUCCESS;

}


static
globus_result_t
globus_l_gfs_config_load_defaults()
{
    int                                 rc;
    int                                 i;
    globus_l_gfs_config_option_t *      option;
    
    for(i = 0; i < option_count; i++)
    {        
        option = (globus_l_gfs_config_option_t *)
            globus_malloc(sizeof(globus_l_gfs_config_option_t));
        memcpy(option, &option_list[i], sizeof(globus_l_gfs_config_option_t));
        
        rc = globus_hashtable_insert(&option_table, 
            option->option_name, 
            (void *) option);
        
        if(rc)
        {
            /* XXX error, log something */
        }
    }  

    return GLOBUS_SUCCESS; 
}

static
int
globus_l_config_loadfile(
    const char *                        filename,
    char **                             data_out)
{
    FILE *                              file;
    int                                 file_len;
    char *                              out_buf;
     
    file = fopen(filename, "r");
    if(!file)
    {
        goto error;
    }
         
    fseek(file, 0L, SEEK_END);
    file_len = ftell(file);
    fseek(file, 0L, SEEK_SET);	

    out_buf = (char *) malloc((file_len + 1) * sizeof(char));	
    if(!out_buf)
    {
        fclose(file);
        goto error;
    }

    fread(out_buf, sizeof(char), file_len, file);
    fclose(file);
    out_buf[file_len] = '\0';

    *data_out = out_buf;
         
    return 0;

error:
    return 1;
}

static
globus_result_t
globus_l_gfs_config_misc()
{
    int                                 rc;
    int                                 i;
    globus_l_gfs_config_option_t *      option;    
    globus_bool_t                       bool_value;
    char *                              value;
    char *                              data;
    
    if(globus_i_gfs_config_bool("detach") && 
        !globus_i_gfs_config_bool("daemon"))
    {
        option = (globus_l_gfs_config_option_t *) globus_hashtable_remove(
                &option_table, "daemon");   
        if(!option)
        {
            option = (globus_l_gfs_config_option_t *)
                globus_malloc(sizeof(globus_l_gfs_config_option_t));
            for(i = 0; 
                i < option_count && 
                    strcmp("daemon", option_list[i].option_name); 
                i++);
            if(i == option_count)
            {
            }    
            memcpy(option, &option_list[i], sizeof(globus_l_gfs_config_option_t));
        }
        
        option->int_value = GLOBUS_TRUE;   
        rc = globus_hashtable_insert(&option_table,
            "daemon",
            (void *) option);
        
        if(rc)
        {
        }          
    } 
    if((bool_value = globus_i_gfs_config_bool("terse_banner")) == GLOBUS_TRUE)
    {
        option = (globus_l_gfs_config_option_t *) globus_hashtable_remove(
                &option_table, "banner");   
        if(!option)
        {
            option = (globus_l_gfs_config_option_t *)
                globus_malloc(sizeof(globus_l_gfs_config_option_t));
            for(i = 0; 
                i < option_count && 
                    strcmp("banner", option_list[i].option_name); 
                i++);
            if(i == option_count)
            {
            }    
            memcpy(option, &option_list[i], sizeof(globus_l_gfs_config_option_t));
        }
        
        option->string_value = globus_common_create_string("");        
        rc = globus_hashtable_insert(&option_table,
            "banner",
            (void *) option);
        
        if(rc)
        {
        }          
    }
    else if((value = globus_i_gfs_config_string("banner_file")) != GLOBUS_NULL)
    {
        rc = globus_l_config_loadfile(value, &data);
        if(!rc)
        {
            option = (globus_l_gfs_config_option_t *) globus_hashtable_remove(
                    &option_table, "banner");   
            if(!option)
            {
                option = (globus_l_gfs_config_option_t *)
                    globus_malloc(sizeof(globus_l_gfs_config_option_t));
                for(i = 0; 
                    i < option_count && 
                        strcmp("banner", option_list[i].option_name); 
                    i++);
                if(i == option_count)
                {
                }    
                memcpy(option, &option_list[i], sizeof(globus_l_gfs_config_option_t));
            }
            
            option->string_value = data;        
            rc = globus_hashtable_insert(&option_table,
                "banner",
                (void *) option);
            
            if(rc)
            {
            }
        }          
        globus_free(value);
    }

    if((value = globus_i_gfs_config_string("login_msg_file")) != GLOBUS_NULL)
    {
        rc = globus_l_config_loadfile(value, &data);
        if(!rc)
        {
            option = (globus_l_gfs_config_option_t *) globus_hashtable_remove(
                    &option_table, "login_msg");   
            if(!option)
            {
                option = (globus_l_gfs_config_option_t *)
                    globus_malloc(sizeof(globus_l_gfs_config_option_t));
                for(i = 0; 
                    i < option_count && 
                        strcmp("banner", option_list[i].option_name); 
                    i++);
                if(i == option_count)
                {
                }    
                memcpy(option, &option_list[i], sizeof(globus_l_gfs_config_option_t));
            }
            
            option->string_value = data;        
            rc = globus_hashtable_insert(&option_table,
                "login_msg",
                (void *) option);
            
            if(rc)
            {
            }
        }
        globus_free(value);          
    }

    if((value = globus_i_gfs_config_string("tcp_port_range")) != GLOBUS_NULL)
    {
        rc = globus_libc_setenv("GLOBUS_TCP_PORT_RANGE", value, 1);
        if(rc)
        {
        }
        globus_free(value);
    }

    if((value = globus_i_gfs_config_string("hostname")) != GLOBUS_NULL)
    {
        rc = globus_libc_setenv("GLOBUS_HOSTNAME", value, 1);
        if(rc)
        {
        }
        globus_free(value);
    }
    
    return GLOBUS_SUCCESS;
}
    

/**
 * load configuration.  read from defaults, file, env, and command line 
 * arguments. each overriding the other.
 * this function will log error messages and exit the server if any
 * errors occur.
 * XXX need to allow config errors to log to syslog, etc depending on how its
 * running.
 */
void
globus_i_gfs_config_init(
    int                                 argc,
    char **                             argv)
{
    char *                              local_config_file;
    char *                              global_config_file;
    int                                 arg_num;
    char *                              argp;
    
    globus_hashtable_init(
        &option_table,
        256,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    global_config_file = "/etc/grid-security/gridftp.conf";
    local_config_file = NULL;

    for(arg_num = 0; arg_num < argc; ++arg_num)
    {
        argp = argv[arg_num];
        if(*argp == '-' && *++argp == 'c' && argv[arg_num + 1])
        {
            local_config_file = globus_libc_strdup(argv[arg_num + 1]);
            arg_num = argc;
        }
    }
    if(local_config_file == NULL)
    {
        local_config_file = globus_common_create_string(
        "%s/etc/gridftp.conf", globus_libc_getenv("GLOBUS_LOCATION"));
    }
    
    globus_l_gfs_config_load_defaults();
    globus_l_gfs_config_load_config_file(global_config_file);
    globus_l_gfs_config_load_config_file(local_config_file);
    globus_l_gfs_config_load_config_env();
    globus_l_gfs_config_load_commandline(argc, argv);
    globus_l_gfs_config_misc();
    
    globus_free(local_config_file);
        
}

/* returns false if option doesnt exist */
globus_bool_t
globus_i_gfs_config_bool(
    const char *                        option_name)
{
    globus_l_gfs_config_option_t *      option;    
    
    option = (globus_l_gfs_config_option_t *) 
        globus_hashtable_lookup(&option_table, (void *) option_name);
    
    if(option)
    {
        return option->int_value;
    }
    
    return GLOBUS_FALSE;
}


/* returns INT_MAX if option doesnt exist */
int
globus_i_gfs_config_int(
    const char *                        option_name)
{
    globus_l_gfs_config_option_t *      option;
    int                                 value = INT_MAX;    
    
    option = (globus_l_gfs_config_option_t *) 
        globus_hashtable_lookup(&option_table, (void *) option_name);
        
    if(option)
    {        
        value = option->int_value;
    }

    return value;
}

char *
globus_i_gfs_config_string(
    const char *                        option_name)
{
    globus_l_gfs_config_option_t *      option;
    char *                              value = GLOBUS_NULL;    
    
    option = (globus_l_gfs_config_option_t *) 
        globus_hashtable_lookup(&option_table, (void *) option_name);
        
    if(option && option->string_value)
    {        
        value = globus_libc_strdup(option->string_value);
    }

    return value;
}


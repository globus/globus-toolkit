
#include "globus_i_gridftp_server.h"
#include "version.h"

typedef enum
{
    GLOBUS_L_GFS_CONFIG_BOOL,
    GLOBUS_L_GFS_CONFIG_INT,
    GLOBUS_L_GFS_CONFIG_STRING,
    GLOBUS_L_GFS_CONFIG_LIST,
    GLOBUS_L_GFS_CONFIG_VOID
} globus_l_gfs_config_type_t;

typedef struct
{
    char *                              option_name;
    char *                              configfile_option;
    char *                              env_var_option;
    char *                              long_cmdline_option;
    char *                              short_cmdline_option;
    globus_l_gfs_config_type_t          type;
    int                                 int_value;
    void *                              value;
} globus_l_gfs_config_option_t;

static const globus_l_gfs_config_option_t option_list[] = 
{ 
 {"pw_file", "pw_file", NULL, "--password-file", "-pf", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"max_connections", "max_connections", NULL, "-max-connections", "-mc", GLOBUS_L_GFS_CONFIG_INT, 0},
 {"port", "port", "GLOBUS_GRIDFTP_SERVER_PORT", "-port", "-p", GLOBUS_L_GFS_CONFIG_INT, 0},
 {"daemon", "daemon", NULL, "-daemon", "-s", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE},
 {"node_authorizes", NULL, NULL, "--node-authorizes", NULL, GLOBUS_L_GFS_CONFIG_INT, -1},
 {"detach", "detach", NULL, "-detach", "-S", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE},
 {"inetd", "inetd", NULL, "-inetd", "-i", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE},
 {"no_security", "no_security", NULL, "-no-security", "-ns", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE},
 {"allow_anonymous", "allow_anonymous", NULL, "-allow-anon", "-aa", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE},
 {"anonymous_user", "anonymous_user", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"anonymous_group", "anonymous_group", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"striped_mode", "striped_mode", NULL, "-striped-mode", NULL, GLOBUS_L_GFS_CONFIG_INT, 1},
 {"data_node", "data_node", NULL, "-data-node", "-dn", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE},
 {"ipc_gsi", "ipc_gsi", NULL, "-ipc-gsi", "-IG", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE},
 {"ipc_idle_timeout", "ipc_idle_timeout", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_INT, 0},
 {"ipc_connect_timeout", "ipc_connect_timeout", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_INT, 30},
 {"terse_banner", "terse_banner", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE},
 {"cas","cas",NULL, "-cas", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE},
 {"sync", "sync",NULL, "-sync", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE},
 {"banner", "banner", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"banner_file", "banner_file", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"login_msg", "login_msg", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"login_msg_file", "login_msg_file", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"connections_disabled", "connections_disabled", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE},
 {"tcp_port_range", "tcp_port_range", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"hostname", "hostname", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"idle_timeout", "idle_timeout", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_INT, 0},
 {"globus_location", "globus_location", "GLOBUS_LOCATION", "-G", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"logfile", "logfile", NULL, "-logfile", "-l", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"log_public", "log_public", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE},
 {"remote", "remote", NULL, "-remote", "-r", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"debug_level", "debug_level", NULL, "-debug", "-d", GLOBUS_L_GFS_CONFIG_INT, 1},
 {"blocksize", "blocksize", NULL, "-blocksize", "-bs", GLOBUS_L_GFS_CONFIG_INT, (256 * 1024)},
 {"stripe_blocksize", "stripe_blocksize", NULL, "-stripe-blocksize", "-sbs", GLOBUS_L_GFS_CONFIG_INT, 10},
 {"community", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_LIST, 0, NULL},
 {"dsi", "storage_type", NULL, "-dsi", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, "file"},
 {"version", NULL, NULL, "-version", "-v", GLOBUS_L_GFS_CONFIG_BOOL, 0},
 {"versions", NULL, NULL, "-versions", "-V", GLOBUS_L_GFS_CONFIG_BOOL, 0},
 {"exec", "exec", NULL, "-exec", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"exec_name", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL},
 {"argv", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_VOID, 0, NULL},
 {"argc", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_INT, 0}
};

static int option_count = sizeof(option_list) / sizeof(globus_l_gfs_config_option_t);

static globus_hashtable_t               option_table;


/* XXX leak when strduping and overwriting string values... never free the old ones */

static
int
globus_l_gfs_config_set(
    char *                              option_name,
    int                                 int_value,
    void *                              value)
{
    globus_l_gfs_config_option_t *      option;
    int                                 i;
    int                                 rc; 

    option = (globus_l_gfs_config_option_t *) globus_hashtable_remove(
            &option_table, option_name);   
    if(!option)
    {
        option = (globus_l_gfs_config_option_t *)
            globus_calloc(1, sizeof(globus_l_gfs_config_option_t));
        for(i = 0; 
            i < option_count && 
                strcmp(option_name, option_list[i].option_name); 
            i++);
        if(i == option_count)
        {
            goto error;
        }    
        memcpy(option, &option_list[i], sizeof(globus_l_gfs_config_option_t));
    }
    switch(option->type)
    {
      case GLOBUS_L_GFS_CONFIG_BOOL:
      case GLOBUS_L_GFS_CONFIG_INT:
        option->int_value = int_value;
        break;
      case GLOBUS_L_GFS_CONFIG_STRING:
      case GLOBUS_L_GFS_CONFIG_LIST:
      case GLOBUS_L_GFS_CONFIG_VOID:
        option->value = value;
        break;
      default:
        option->value = value;
        break;
    }
    rc = globus_hashtable_insert(&option_table,
        option_name,
        option);
    
    if(rc)
    {
        goto error;
    }

    return 0;

error:
    globus_free(option);
    return 1;             
}

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
                option->value = globus_libc_strdup(value);
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
            option->value = globus_libc_strdup(value);
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
                memcpy(
                    option,
                    &option_list[i],
                    sizeof(globus_l_gfs_config_option_t));
            }

            switch(option->type)
            {
              case GLOBUS_L_GFS_CONFIG_BOOL:
                option->int_value = GLOBUS_TRUE;
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
                option->value = globus_libc_strdup(argv[arg_num]);
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
    globus_bool_t                       bool_value;
    char *                              value;
    char *                              data;
    
    if(globus_i_gfs_config_bool("detach") && 
        !globus_i_gfs_config_bool("daemon"))
    {
        globus_l_gfs_config_set("daemon", GLOBUS_TRUE, NULL);
    } 
    
    if((value = globus_i_gfs_config_string("hostname")) != GLOBUS_NULL)
    {
        rc = globus_libc_setenv("GLOBUS_HOSTNAME", value, 1);
        if(rc)
        {
        }
    }
    
    if((bool_value = globus_i_gfs_config_bool("terse_banner")) == GLOBUS_TRUE)
    {
        globus_l_gfs_config_set("banner", 0, globus_libc_strdup(""));                
    }
    else if((value = globus_i_gfs_config_string("banner_file")) != GLOBUS_NULL)
    {
        rc = globus_l_config_loadfile(value, &data);
        globus_l_gfs_config_set("banner", 0, data);                
    }
    else
    {
        char *                          hostname;

        hostname = globus_malloc(1024);
        globus_libc_gethostname(hostname, 1024);
        data = globus_common_create_string(
            "GridFTP Server %s %d.%d (%s, %d-%d) ready."
            GLOBUS_GRIDFTP_SERVER_RELEASE_TYPE,
            hostname,
            local_version.major,
            local_version.minor,
            build_flavor,
            local_version.timestamp,
            local_version.branch_id);
        globus_l_gfs_config_set("banner", 0, data);
        globus_free(hostname);
    }

    if((value = globus_i_gfs_config_string("login_msg_file")) != GLOBUS_NULL)
    {
        rc = globus_l_config_loadfile(value, &data);
        globus_l_gfs_config_set("login_msg", 0, data);                
    }
    
    if((value = globus_i_gfs_config_string("tcp_port_range")) != GLOBUS_NULL)
    {
        rc = globus_libc_setenv("GLOBUS_TCP_PORT_RANGE", value, 1);
        if(rc)
        {
        }
    }

    value = globus_i_gfs_config_string("remote");
    {
        globus_i_gfs_community_t *      community;
        globus_list_t *                 community_list = NULL;
        char *                          p;
        int                             i;
        community = (globus_i_gfs_community_t *)
            globus_malloc(sizeof(globus_i_gfs_community_t)); 
        if(!value)
        {
            value = "";
        }
        else
        {
            globus_l_gfs_config_set("dsi", 0, globus_libc_strdup("remote"));                
        }            
        community->cs_count = 1;
        
        p = strchr(value, ',');
        while(p != NULL)
        {   
            p++;
            community->cs_count++;
            p = strchr(p, ',');
        }
        
        community->name = globus_libc_strdup("default");
        community->root = globus_libc_strdup("/");
        community->cs = (char **) globus_malloc(
            sizeof(char *) * community->cs_count);
        
        for(i = 0; i < community->cs_count; i++)
        {
            p = strchr(value, ',');
            if(p != NULL)
            {
                *p = '\0';
                community->cs[i] = (char *) globus_libc_strdup(value);
                value = p + 1;
            }
            else
            {
                community->cs[i] = (char *) globus_libc_strdup(value);
            }
        }
        globus_list_insert(&community_list, community);  
        
        globus_l_gfs_config_set("community", 0, community_list);                
    }
    
    /* if node_authorizes is -1 it means it has not yet been touched */
    if(globus_i_gfs_config_int("node_authorizes") == -1)
    {
        if(globus_i_gfs_config_bool("data_node"))
        {
            globus_l_gfs_config_set("node_authorizes", 0, NULL);
        }
        else
        {
            globus_l_gfs_config_set("node_authorizes", 1, NULL);
        }
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
    char *                              exec_name;
    char *                              local_config_file;
    char *                              global_config_file;
    int                                 arg_num;
    char *                              argp;
    
    globus_hashtable_init(
        &option_table,
        256,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    /* set defaul exe name */
    exec_name = globus_common_create_string(
        "%s/sbin/globus-gridftp-server",
        globus_module_getenv("GLOBUS_LOCATION"));
    global_config_file = "/etc/grid-security/gridftp.conf";
    local_config_file = NULL;

    for(arg_num = 0; arg_num < argc; arg_num++)
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
    
    globus_l_gfs_config_set("exec_name", 0, exec_name);
    globus_l_gfs_config_set("argv", 0, argv);
    globus_l_gfs_config_set("argc", argc, NULL);

    globus_free(local_config_file);     
}


int
globus_i_gfs_config_int(
    const char *                        option_name)
{
    globus_l_gfs_config_option_t *      option;
    int                                 value = 0;    
    
    option = (globus_l_gfs_config_option_t *) 
        globus_hashtable_lookup(&option_table, (void *) option_name);
        
    if(option)
    {        
        value = option->int_value;
    }

    return value;
}


void *
globus_i_gfs_config_get(
    const char *                        option_name)
{
    globus_l_gfs_config_option_t *      option;
    void *                              value = NULL;    
    
    option = (globus_l_gfs_config_option_t *) 
        globus_hashtable_lookup(&option_table, (void *) option_name);
        
    if(option && option->value)
    {        
        value = option->value;
    }

    return value;
}

globus_bool_t
globus_i_gfs_config_is_anonymous(
    const char *                        userid)
{
    if(strcmp(userid, "ftp") == 0)
    {
        return GLOBUS_TRUE;
    }
    if(strcmp(userid, "anonymous") == 0)
    {
        return GLOBUS_TRUE;
    }
    if(strcmp(userid, ":globus-mapping:") == 0)
    {
        return GLOBUS_TRUE;
    }
    return GLOBUS_FALSE;
}


const char *
globus_i_gfs_config_get_module_name(
    const char *                        client_supplied_name)
{
    return client_supplied_name;
}


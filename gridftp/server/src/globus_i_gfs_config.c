
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
    char *                              usage;
} globus_l_gfs_config_option_t;

static const globus_l_gfs_config_option_t option_list[] = 
{ 
 {"usage", NULL, NULL, "-help", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Show this."},
/* logging */
 {"log_module", "log_module", NULL, "-log-module", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "globus_logging module that will be loaded. Default is stdio."},
 {"log_single", "log_single", NULL, "-logfile", "-l", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Path of a single file to log all activity to."},
 {"log_unique", "log_unique", NULL, "-logdir", "-L", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Partial path to which 'gridftp.<pid>.log' will be appended to make the log filename."},
 {"log_filemode", "log_filemode", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "File access permissions of log files."},
 {"debug_level", "debug_level", NULL, "-debug", "-d", GLOBUS_L_GFS_CONFIG_INT, 1, NULL,
    "Log level. 1 only logs errors, 16 logs everything."},
/* auth/security related */
 {"allow_anonymous", "allow_anonymous", NULL, "-allow-anon", "-aa", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Allow cleartext anonymous access. If server is running as root anonymous_user must also be set."},
 {"anonymous_user", "anonymous_user", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "User to setuid to for an anonymous connection. Only applies when running as root."},
 {"anonymous_group", "anonymous_group", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Group to setgid to for an anonymous connection. Default is the default group of anonymous_user."},
 {"pw_file", "pw_file", NULL, "--password-file", "-pf", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Enable cleartext access and authenticate users against this /etc/passwd style file."},
 {"no_security", "no_security", NULL, "-no-security", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "No security whatsoever. Don't use this."},
 {"cas", "cas", NULL, "-cas", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Enable CAS authorization."},
 {"node_authorizes", NULL, NULL, "--node-authorizes", NULL, GLOBUS_L_GFS_CONFIG_INT, -1, NULL,
    "This node will authenticate users. Default is yes for frontend only."},
 {"ipc_gsi", "ipc_gsi", NULL, "-ipc-gsi", "-IG", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Encrypt ipc channel."},
 {"max_connections", "max_connections", NULL, "-max-connections", "-mc", GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Max connections to allow while running as a daemon process."},
 {"connections_disabled", "connections_disabled", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Disable all new connections."},
/* execution modes */
 {"nofork", "nofork", NULL, "-nofork", "-nf", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Server will not fork. All connections will work in a single process and will not setuid."},
 {"daemon", "daemon", NULL, "-daemon", "-s", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Run as a daemon.  All connections will fork off a new process and setuid if allowed."},
 {"detach", "detach", NULL, "-detach", "-S", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Run as a background daemon detached from any controlling terminals."},
 {"inetd", "inetd", NULL, "-inetd", "-i", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Run under an inetd service."},
 {"chdir_to", "chdir_to",NULL, "-chdir-to", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Directory to chdir to after starting.  Default is /."},
 {"no_chdir", "no_chdir",NULL, "-no-chdir", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Do not move out of the current directory.  This is default only for non-forked mode."},
 {"exec", "exec", NULL, "-exec", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "For staticly compiled or non-GL standard binary locations, force the full path of server to exec when forking."},
/* network/interface options */
 {"control_interface", "control_interface", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Hostname or IP address of the interface to listen for control connections on. Default is all."},
 {"data_interface", "data_interface", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Hostname or IP address of the interface to use for data connections. Default is the current control interface."},
 {"port", "port", "GLOBUS_GRIDFTP_SERVER_PORT", "-port", "-p", GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Port to listen for control connections on.  If not speficied a random port will be chosen."},
 {"ipc_port", "ipc_port", NULL, "-ipc-port", NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Port to listen for data node registrations."},
 {"tcp_port_range", "tcp_port_range", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Port range to use for PASV data connections.  Sets GLOBUS_TCP_PORT_RANGE."},
 {"hostname", "hostname", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Sets GLOBUS_HOSTNAME.  Effectively forces control_hostname and data_hostname."},
/* timeouts */
 {"ipc_idle_timeout", "ipc_idle_timeout", NULL, "--ipc-idle-timeout", NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Idle time in seconds before an unused ipc connection will close."},
 {"ipc_connect_timeout", "ipc_connect_timeout", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_INT, 30, NULL,
    "Time in seconds before cancelling an attempted ipc connection."},
 {"idle_timeout", "idle_timeout", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Time in seconds to allow a user to remain connected to the control channel without activity."},
/* user messages */
 {"terse_banner", "terse_banner", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Display the absolute minimum 220 message to unauthenticated users."},
 {"banner", "banner", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Message to display before authentication."},
 {"banner_file", "banner_file", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "File to read banner message from."},
 {"login_msg", "login_msg", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Message to display after authentication."},
 {"login_msg_file", "login_msg_file", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "File to read login message from."},
/* dsi */
 {"data_node", "data_node", NULL, "-data-node", "-dn", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "This server is a backend data node."},
 {"dsi", "storage_type", NULL, "-dsi", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, "file",
    "Data Storage Interface module to load. Defaults to file unless remote is specified, which loads remote."},
 {"allowed_modules", "allowed_modules", NULL, "-allowed-modules", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Comma seperated list of ERET/ESTO modules to allow. i.e. <module1>,<alias2>:<module2>,<module3> (module2 will be loaded when a client asks for alias2)."}, 
/* striped options */
 {"remote", "remote", NULL, "-remote", "-r", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Comma seperated list of backend contact strings."},
 {"striped_mode", "striped_mode", NULL, "-striped-mode", NULL, GLOBUS_L_GFS_CONFIG_INT, 1, NULL,
    "Default is a 1-1 stripe configuration. Mode 2 would be ALL-ALL."},
 {"stripe_blocksize", "stripe_blocksize", NULL, "-stripe-blocksize", "-sbs", GLOBUS_L_GFS_CONFIG_INT, 10, NULL,
    "Multiple of blocksize used to divide files over each stripe."},
/* disk options */
 {"blocksize", "blocksize", NULL, "-blocksize", "-bs", GLOBUS_L_GFS_CONFIG_INT, (256 * 1024), NULL,
    "Size of data blocks to read from disk before posting to the network."},
 {"sync", "sync", NULL, "-sync", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Flush disk writes before sending restart markers. May impact performance."},
/* other */
 {"globus_location", "globus_location", "GLOBUS_LOCATION", "-G", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "GLOBUS_LOCATION."},
 {"version", NULL, NULL, "-version", "-v", GLOBUS_L_GFS_CONFIG_BOOL, 0, NULL,
    "Show version information for the server."},
 {"versions", NULL, NULL, "-versions", "-V", GLOBUS_L_GFS_CONFIG_BOOL, 0, NULL,
    "Show version information for all loaded globus libraries."},
/* internal use */
 {"community", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_LIST, 0, NULL,
    NULL /* used to store list of known backends and associated info */},
 {"module_list", "module_list", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_LIST, 0, NULL,
    NULL /* used to store list of allowed modules */},
 {"exec_name", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    NULL /* full path of server used when fork/execing */},
 {"argv", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_VOID, 0, NULL,
    NULL /* original argv */},
 {"argc", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    NULL /* original argc */}
};

static int option_count = sizeof(option_list) / sizeof(globus_l_gfs_config_option_t);

static globus_hashtable_t               option_table;

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
                option->int_value = strtol(value, NULL, 0);
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
            option->int_value = strtol(value, NULL, 0);
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
                option->int_value = strtol(argv[arg_num], NULL, 0);
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

void
globus_i_gfs_config_display_usage()
{
    int                                 i;
    globus_l_gfs_config_option_t *      o;
        
    for(i = 0; i < option_count; i++)
    {        
        o = (globus_l_gfs_config_option_t *) &option_list[i];
        if(o->usage == NULL)
        {
            continue;
        }
        
        printf("%-14s    %s\n%-14s    %sCommand line or ENV args:", 
            o->option_name, o->usage, "",
            o->type == GLOBUS_L_GFS_CONFIG_BOOL ? "(FLAG)  " : "");
        if(o->short_cmdline_option)
        {
            printf(" %s,", o->short_cmdline_option);
        }
        if(o->long_cmdline_option)
        {
            printf(" %s,", o->long_cmdline_option);
        }
        if(o->env_var_option)
        {
            printf(" $%s", o->env_var_option);
        }
        printf("\n");
    }

    return; 
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
    if(globus_i_gfs_config_bool("nofork"))
    {
        globus_l_gfs_config_set("daemon", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("no_chdir", GLOBUS_TRUE, NULL);
    }
    if(globus_i_gfs_config_bool("inetd"))
    {
        globus_l_gfs_config_set("daemon", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("detach", GLOBUS_FALSE, NULL);
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

    if((value = globus_i_gfs_config_string("allowed_modules")) != NULL)
    {
        globus_list_t *                 module_list = NULL;
        char *                          module;
        char *                          p;
        
        p = strchr(value, ',');
        while(p != NULL)
        {   
            p++;
            module = globus_libc_strdup(p);            
            globus_list_insert(&module_list, module); 
            p = strchr(p, ',');
        }
        
        globus_l_gfs_config_set("module_list", 0, module_list);                
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
    const char *                        client_alias)
{
    globus_list_t *                     module_list;
    globus_list_t *                     list;
    const char *                        module;
    char *                              alias;
    globus_bool_t                       found = GLOBUS_FALSE;
    int                                 size;

    module_list = (globus_list_t *) globus_i_gfs_config_get("module_list");  
    for(list = module_list;
        !globus_list_empty(list) && !found;
        list = globus_list_rest(list))
    {
        /* parse out module name from <module> or <alias>:<module> */
        alias = (char *) globus_list_first(list);
        module = strchr(alias, ':');
        if(module != NULL)
        {
            size = module - alias;
            module++;
        }
        else
        {
            size = strlen(alias);
            module = alias;
        }
        if(strncasecmp(alias, client_alias, size) == 0)
        {
            found = GLOBUS_TRUE;
        }
    } 
    if(found)
    {
        return module;
    }
    else
    {
        return NULL;
    }
}


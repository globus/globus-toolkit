
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
{NULL, "Informational Options", NULL, NULL, NULL, 0, 0, NULL, NULL},
 {"help", "help", NULL, "help", "h", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Show usage information and exit."},
 {"version", "version", NULL, "version", "v", GLOBUS_L_GFS_CONFIG_BOOL, 0, NULL,
    "Show version information for the server and exit."},
 {"versions", "versions", NULL, "versions", "V", GLOBUS_L_GFS_CONFIG_BOOL, 0, NULL,
    "Show version information for all loaded globus libraries and exit."},
{NULL, "Modes of Operation", NULL, NULL, NULL, 0, 0, NULL, NULL},
 {"single", "single", NULL, "single", "1", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL, "run 1 instance then end"},
 {"inetd", "inetd", NULL, "inetd", "i", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Run under an inetd service."},
 {"daemon", "daemon", NULL, "daemon", "s", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Run as a daemon.  All connections will fork off a new process and setuid if allowed."},
 {"detach", "detach", NULL, "detach", "S", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Run as a background daemon detached from any controlling terminals."},
 {"exec", "exec", NULL, "exec", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "For staticly compiled or non-GLOBUS_LOCATION standard binary locations, specify the full "
    "path of the server binary here.  Only needed when run in daemon mode."},
 {"chdir", "chdir", NULL, "chdir", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Change directory when the server starts. This will change directory to the dir specified "
    "by the chdir_to option."},
 {"chdir_to", "chdir_to", NULL, "chdir-to", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Directory to chdir to after starting.  Will use / if not set."},
 {"fork", "fork", NULL, "fork", "f", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Server will fork for each new connection.  Disabling this option is only recommended"
    "when debugging."},
{NULL, "Authentication, Authorization, and Security Options", NULL, NULL, NULL, 0, 0, NULL, NULL},
 {"auth_level", "auth_level", NULL, "auth-level", NULL, GLOBUS_L_GFS_CONFIG_INT, -1, NULL,
    "0 = Disables all authorization checks. 1 = Authorize identity only.  "
    "2 = Authorize all file/resource accesses.  "
    "If not set uses level 2 for front ends and level 1 for data nodes."},
 {"allow_from", "allow_from", NULL, "allow-from", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Only allow connections from these source ip addresses.  Specify a comma "
    "seperated list of ip address fragments.  A match is any ip address that "
    "starts with the specified fragment.  Example: '192.168.1.' will match and"
    "allow a connection from 192.168.1.45.  Note that if this option is used "
    "any address not specifically allowed will be denied."},
 {"deny_from", "deny_from", NULL, "deny-from", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Deny connections from these source ip addresses. Specify a comma "
    "seperated list of ip address fragments.  A match is any ip address that "
    "starts with the specified fragment.  Example: '192.168.2.' will match and"
    "deny a connection from 192.168.2.45."},
 {"cas", "cas", NULL, "cas", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Enable CAS authorization."},
 {"secure_ipc", "secure_ipc", NULL, "secure-ipc", "si", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Use GSI security on ipc channel."},
 {"ipc_auth_mode", "ipc_auth_mode", NULL, "ipc-auth-mode", "ia", GLOBUS_L_GFS_CONFIG_STRING, 0, "host",
    "Set GSI authorization mode for the ipc connection.  Options are: none, host, self or subject:<subject>"},
 {"allow_anonymous", "allow_anonymous", NULL, "allow-anonymous", "aa", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Allow cleartext anonymous access. If server is running as root anonymous_user "
    "must also be set.  Disables ipc security."},
 {"anonymous_names_allowed", "anonymous_names_allowed", NULL, "anonymous-names-allowed", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Comma seperated list of names to treat as anonymous users when "
    "allowing anonymous access.  If not set, the default names of 'anonymous' "
    "and 'ftp' will be allowed.  Use '*' to allow any username."},
 {"anonymous_user", "anonymous_user", NULL, "anonymous-user", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "User to setuid to for an anonymous connection. Only applies when running as root."},
 {"anonymous_group", "anonymous_group", NULL, "anonymous-group", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Group to setgid to for an anonymous connection. If unset, the default group "
    "of anonymous_user will be used."},
 {"pw_file", "pw_file", NULL, "password-file", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Enable cleartext access and authenticate users against this /etc/passwd formatted file."},
 {"connections_max", "connections_max", NULL, "connections-max", NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Maximum concurrent connections allowed.  Only applies when running in daemon "
    "mode.  Unlimited if not set."},
 {"connections_disabled", "connections_disabled", NULL, "connections-disabled", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Disable all new connections.  Does not affect ongoing connections.  This would have be set "
    "in the configuration file and then the server issued a SIGHUP in order to reload that config."},
{NULL, "Logging Options", NULL, NULL, NULL, 0, 0, NULL, NULL},
 {"log_level", "log_level", NULL, "log-level", "d", GLOBUS_L_GFS_CONFIG_STRING, 0, "ERROR",
    "Log level. A comma seperated list of levels from: 'ERROR, WARN, INFO, DUMP, ALL'. "
    "Example: error,warn,info. You may also specify a numeric level of 1-255."},
 {"log_module", "log_module", NULL, "log-module", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "globus_logging module that will be loaded. If not set, logfile options apply."},
 {"log_single", "log_single", NULL, "logfile", "l", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Path of a single file to log all activity to.  If neither this option or log_unique is set, "
    "logs will be written to stderr unless the execution mode is detached or inetd, "
    "in which case logging will be disabled."},
 {"log_unique", "log_unique", NULL, "logdir", "L", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Partial path to which 'gridftp.(pid).log' will be appended to construct the log filename. "
    "Example: -L /var/log/gridftp/ will create a seperate log ( /var/log/gridftp/gridftp.xxxx.log ) "
    "for each process (which is normally each new client session).  If neither this option or "
    "log_single is set, logs will be written to stderr unless the execution mode is detached or inetd, "
    "in which case logging will be disabled."},
 {"log_transfer", "log_transfer", NULL, "log-transfer", "Z", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Log netlogger style info for each transfer into this file."},
 {"log_filemode", "log_filemode", NULL, "log-filemode", NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "File access permissions of log files. Should be an octal number such as "
    "0644 (the leading 0 is required)."},
 {"disable_usage_stats", "disable_usage_stats", "GLOBUS_USAGE_OPTOUT", "disable-usage-stats", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Allow usage statistics to be transmitted to a Globus database or other specified target."},
 {"usage_stats_target", "usage_stats_target", NULL, "usage-stats-target", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Comma seperated list of contact strings for usage statistics listeners."},
{NULL, "Single and Striped Remote Data Node Options", NULL, NULL, NULL, 0, 0, NULL, NULL},
 {"remote_nodes", "remote_nodes", NULL, "remote-nodes", "r", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Comma seperated list of remote node contact strings."},
 {"data_node", "data_node", NULL, "data-node", "dn", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "This server is a backend data node."},
 {"stripe_blocksize", "stripe_blocksize", NULL, "stripe-blocksize", "sbs", GLOBUS_L_GFS_CONFIG_INT, (1024 * 1024), NULL,
    "Size in bytes of sequential data that each stripe will transfer."},
 {"stripe_layout", "stripe_layout", NULL, "stripe-layout", "sl", GLOBUS_L_GFS_CONFIG_INT, GLOBUS_GFS_LAYOUT_BLOCKED, NULL,
    "Stripe layout. 1 = Partitioned, 2 = Blocked."},
 {"stripe_blocksize_locked", "stripe_blocksize_locked", NULL, "stripe-blocksize-locked", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Do not allow client to override stripe blocksize with the OPTS RETR command"},
 {"stripe_layout_locked", "stripe_layout_locked", NULL, "stripe-layout-locked", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Do not allow client to override stripe layout with the OPTS RETR command"},
 {"stripe_mode", "stripe_mode", NULL, "stripe-mode", NULL, GLOBUS_L_GFS_CONFIG_INT, 1, NULL,
    NULL /* "Mode 1 is a 1-1 stripe configuration. Mode 2 is ALL-ALL."  */},
{NULL, "Disk Options", NULL, NULL, NULL, 0, 0, NULL, NULL},
 {"blocksize", "blocksize", NULL, "blocksize", "bs", GLOBUS_L_GFS_CONFIG_INT, (256 * 1024), NULL,
    "Size in bytes of data blocks to read from disk before posting to the network."},
 {"sync_writes", "sync_writes", NULL, "sync-writes", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Flush disk writes before sending a restart marker.  This attempts to ensure that "
    "the range specified in the restart marker has actually been committed to disk. "
    "This option will probably impact performance, and may result in different behavior "
    "on different storage systems. See the manpage for sync() for more information."},
{NULL, "Network Options", NULL, NULL, NULL, 0, 0, NULL, NULL},
 {"port", "port", NULL, "port", "p", GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Port on which a frontend will listend for client control channel connections, "
    "or on which a data node will listen for connections from a frontend.  If not set "
    "a random port will be chosen and printed via the logging mechanism."},
 {"control_interface", "control_interface", NULL, "control-interface", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Hostname or IP address of the interface to listen for control connections "
    "on. If not set will listen on all interfaces."},
 {"data_interface", "data_interface", NULL, "data-interface", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Hostname or IP address of the interface to use for data connections. If not "
    "set will use the current control interface."},
 {"ipc_interface", "ipc_interface", NULL, "ipc-interface", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Hostname or IP address of the interface to use for ipc connections. If not "
    "set will listen on all interfaces."},
 {"hostname", "hostname", NULL, "hostname", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Effectively sets the above control_interface, data_interface and ipc_interface options."},
 {"ipc_port", "ipc_port", NULL, "ipc-port", NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Port on which the frontend will listen for data node connections."},
{NULL, "Timeouts", NULL, NULL, NULL, 0, 0, NULL, NULL},
 {"control_preauth_timeout", "control_preauth_timeout", NULL, "control-preauth-timeout", NULL, GLOBUS_L_GFS_CONFIG_INT, 120, NULL,
    "Time in seconds to allow a client to remain connected to the control "
    "channel without activity before authenticating."},
 {"control_idle_timeout", "control_idle_timeout", NULL, "control-idle-timeout", NULL, GLOBUS_L_GFS_CONFIG_INT, 600, NULL,
    "Time in seconds to allow a client to remain connected to the control "
    "channel without activity."},
 {"ipc_idle_timeout", "ipc_idle_timeout", NULL, "ipc-idle-timeout", NULL, GLOBUS_L_GFS_CONFIG_INT, 600, NULL,
    "Idle time in seconds before an unused ipc connection will close."},
 {"ipc_connect_timeout", "ipc_connect_timeout", NULL, "ipc-connect-timeout", NULL, GLOBUS_L_GFS_CONFIG_INT, 60, NULL,
    "Time in seconds before cancelling an attempted ipc connection."},
{NULL, "User Messages", NULL, NULL, NULL, 0, 0, NULL, NULL},
 {"banner", "banner", NULL, "banner", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Message to display to the client before authentication."},
 {"banner_file", "banner_file", NULL, "banner-file", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "File to read banner message from."},
 {"banner_terse", "banner_terse", NULL, "banner-terse", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "When this is set, the minimum allowed banner message will be displayed "
    "to unauthenticated clients."},
 {"login_msg", "login_msg", NULL, "login-msg", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Message to display to the client after authentication."},
 {"login_msg_file", "login_msg_file", NULL, "login-msg-file", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "File to read login message from."},
 {"use_home_dirs", "use_home_dirs", NULL, "use-home-dirs", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Set the virtual current directory to the authenticated users home dir."},
{NULL, "Module Options", NULL, NULL, NULL, 0, 0, NULL, NULL},
 {"load_dsi_module", "load_dsi_module", NULL, "dsi", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, "file",
    "Data Storage Interface module to load. file and remote modules are defined by the server. "
    "Defaults to file unless the 'remote' option is specified, in which case the remote "
    "DSI is loaded."},
 {"allowed_modules", "allowed_modules", NULL, "allowed-modules", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Comma seperated list of ERET/ESTO modules to allow, and optionally specify an alias for. "
    "Example: module1,alias2:module2,module3 (module2 will be loaded when a client asks for alias2)."}, 
{NULL, "Other", NULL, NULL, NULL, 0, 0, NULL, NULL},
 {"configfile", "configfile", NULL, "c", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
     "Path to configuration file that should be loaded.  Otherwise will attempt "
     "to load $GLOBUS_LOCATION/etc/gridftp.conf and /etc/grid-security/gridftp.conf."},
 {"debug", "debug", NULL, "debug", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Sets options that make server easier to debug. Not recommended for production servers."}, 
/* internal use */
 {"globus_location", "globus_location", "GLOBUS_LOCATION", "G", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    NULL} /* "GLOBUS_LOCATION." */,
 {"tcp_port_range", "tcp_port_range", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    NULL} /*"Port range to use for PASV data connections.  Sets GLOBUS_TCP_PORT_RANGE."}*/,
 {"bad_signal_exit", "bad_signal_exit", NULL, "exit", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    NULL}, /* exit cleanly on bad signals (no core dump) */
 {"test_acl", NULL, NULL, NULL, "testacl", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    NULL /* load and pass arguments to the test acl module. the string
        may include BLOCK, which will cause a failure in the callback,
        and any or all of ALL, init, or read, write, etc action to fail on */},
 {"html", NULL, NULL, "html", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    NULL /* generate usage suitable for web docs */},
 {"fqdn", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    NULL /* hostname found by gethostname() */},
 {"loaded_config", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
     NULL /* placeholder so configfile check doesn't fail */},
 {"version_string", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
     NULL /* version string */},
 {"community", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_LIST, 0, NULL,
    NULL /* used to store list of known backends and associated info */},
 {"module_list", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_LIST, 0, NULL,
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
    GlobusGFSName(globus_l_gfs_config_set);
    GlobusGFSDebugEnter();

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

    GlobusGFSDebugExit();
    return 0;

error:
    globus_free(option);
    GlobusGFSDebugExitWithError();
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
    globus_off_t                        tmp_off;
    GlobusGFSName(globus_l_gfs_config_load_config_file);
    GlobusGFSDebugEnter();

    fptr = fopen(filename, "r");
    if(fptr == NULL)
    {
        GlobusGFSDebugExitWithError();
        return -2; /* XXX construct real error */
    }
    globus_l_gfs_config_set("loaded_config", 0, globus_libc_strdup(filename));  
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
            if(option_list[i].option_name == NULL)
            {
                continue;
            }
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
                rc = globus_args_bytestr_to_num(value, &tmp_off);
                if(rc != 0)
                {
                    fprintf(stderr, "Invalid value for %s\n", 
                        option_list[i].option_name);
                    goto error_parse;
                }                  
                option->int_value = (int) tmp_off;
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
    
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

error_parse:
    fclose(fptr);
    fprintf(stderr, "Problem parsing config file %s: line %d\n", 
        filename, line_num);
    GlobusGFSDebugExitWithError();
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
    globus_off_t                        tmp_off;
    GlobusGFSName(globus_l_gfs_config_load_config_env);
    GlobusGFSDebugEnter();
    

    for(i = 0; i < option_count; i++)
    {
        if(option_list[i].option_name == NULL)
        {
            continue;
        }
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
            rc = globus_args_bytestr_to_num(value, &tmp_off);
            if(rc != 0)
            {
                fprintf(stderr, "Invalid value for %s\n", 
                    option_list[i].option_name);
                return -1;
            }                  
            option->int_value = (int) tmp_off;
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

    GlobusGFSDebugExit();
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
    int                                 len;
    globus_l_gfs_config_option_t *      option;
    globus_bool_t                       found;
    globus_bool_t                       negate;
    globus_off_t                        tmp_off;
    GlobusGFSName(globus_l_gfs_config_load_commandline);
    GlobusGFSDebugEnter();
    
    for(arg_num = 1; arg_num < argc; ++arg_num)
    {
        found = GLOBUS_FALSE;
        negate = GLOBUS_FALSE;
        
        argp = argv[arg_num];
        len = strlen(argp);
        
        if(len && *argp == '-')
        {
            argp++;
            len--;
        }
        if(len && *argp == '-')
        {
            argp++;
            len--;
        }
        if((len - 2) && strncasecmp(argp, "no-", 3) == 0)
        {
            argp += 3;
            len -= 3;
            negate = GLOBUS_TRUE;
        }
        else if(len && tolower(*argp) == 'n')
        {
            argp ++;
            len --;
            negate = GLOBUS_TRUE;
        }
        
        for(i = 0; i < option_count && !found && len; i++)
        {
            if(option_list[i].option_name == NULL)
            {
                continue;
            }
            if((!option_list[i].short_cmdline_option || 
                strcmp(argp, option_list[i].short_cmdline_option)) && 
                (!option_list[i].long_cmdline_option || 
                strcmp(argp, option_list[i].long_cmdline_option)) )
            {
                continue;
            }
            
            found = GLOBUS_TRUE;
                       
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
                option->int_value = !negate;
                break;

              case GLOBUS_L_GFS_CONFIG_INT:
                if(++arg_num >= argc)
                {
                    fprintf(stderr, "Option %s is missing a value\n", argp);
                    return -1;
                }
                rc = globus_args_bytestr_to_num(argv[arg_num], &tmp_off);
                if(rc != 0)
                {
                    fprintf(stderr, "Invalid value for %s\n", argp);
                    return -1;
                }                  
                option->int_value = (int) tmp_off;
                break;
                
              case GLOBUS_L_GFS_CONFIG_STRING:
                if(++arg_num >= argc)
                {
                    fprintf(stderr, "Option %s is missing a value\n", argp);
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
        
        if(!found)
        {
            fprintf(stderr, "Unknown option on command line: %s%s\n",
                negate ? "no-" : "", argp);
            return -1;
        }
    }
      
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

}


static
globus_result_t
globus_l_gfs_config_load_defaults()
{
    int                                 rc;
    int                                 i;
    globus_l_gfs_config_option_t *      option;
    GlobusGFSName(globus_l_gfs_config_load_defaults);
    GlobusGFSDebugEnter();
    
    for(i = 0; i < option_count; i++)
    {        
        if(option_list[i].option_name == NULL)
        {
            continue;
        }
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

    GlobusGFSDebugExit();
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
    GlobusGFSName(globus_l_config_loadfile);
    GlobusGFSDebugEnter();
     
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
         
    GlobusGFSDebugExit();
    return 0;

error:
    GlobusGFSDebugExitWithError();
    return 1;
}

static
void
globus_l_gfs_config_display_html_usage()
{
    int                                 i;
    globus_l_gfs_config_option_t *      o;
    GlobusGFSName(globus_l_gfs_config_display_html_usage);
    GlobusGFSDebugEnter();
    
    printf("<!-- generated by globus-gridftp-server -help -html -->\n");
    printf("<p>\n"
        "The table below lists config file options, associated command line " 
        "options (if available) and descriptions. Note that any boolean "
        "option can be negated on the command line by preceding the specified " 
        "option with '-no-' or '-n'.  example: -no-cas or -nf.\n"
        "</p>\n");

    printf("<ul>\n");
    for(i = 0; i < option_count; i++)
    {        
        o = (globus_l_gfs_config_option_t *) &option_list[i];
        if(o->option_name == NULL)
        {
            printf("  <li><a href=\"#gftpclass%d\">%s</a></li>\n",
                i, o->configfile_option);
        }
    }
    printf("</ul>\n");

    printf("\n");

    printf("<table border=\"1\" cellpadding=\"5\">\n");
    for(i = 0; i < option_count; i++)
    {        
        char *                          shortflag;
        char *                          longflag;
        char *                          value;
        char *                          defval;
        
        o = (globus_l_gfs_config_option_t *) &option_list[i];
        if(o->option_name == NULL)
        {
            printf(
                "  <tr>\n"
                "    <th colspan=\"2\" valign=\"top\"><a name=\"gftpclass%d\"></a>%s</th>\n"
                "  </tr>\n",
                i,
                o->configfile_option);
            continue;
        }
        if(o->usage == NULL)
        {
            continue;
        }

        switch(o->type)
        {
          case GLOBUS_L_GFS_CONFIG_BOOL:
            shortflag = "-";
            longflag = "-";
            value = " &lt;0|1&gt;"; 
            defval = o->int_value ? "TRUE" : "FALSE";
            break;
          case GLOBUS_L_GFS_CONFIG_INT:
            shortflag = "-";
            longflag = "-";
            value = " &lt;number&gt;"; 
            defval = o->int_value > 0 ? 
                globus_common_create_string("%d", o->int_value) : "not set";
            break;
          case GLOBUS_L_GFS_CONFIG_STRING:
            shortflag = "-";
            longflag = "-";
            value = " &lt;string&gt;"; 
            defval = o->value ? o->value : "not set";
            break;
          default:
            shortflag = "";
            longflag = "";
            value = ""; 
            defval = o->value ? o->value : "not set";
            break;
        }
        printf(
            "  <tr>\n"
            "    <td valign=\"top\"><pre><p>%s%s</p><p>%s%s%s%s%s</p></pre></td>\n"
            "    <td valign=\"top\"><p>%s</p><p>Default value: %s</p></td>\n"
            "  </tr>\n", 
            o->configfile_option, 
            value,
            o->short_cmdline_option ? shortflag : "", 
            o->short_cmdline_option ? o->short_cmdline_option : "", 
            o->short_cmdline_option ? " " : "", 
            o->long_cmdline_option ? longflag : "",
            o->long_cmdline_option ? o->long_cmdline_option : "",
            o->usage,
            defval);
    }
    printf("</table>\n");
    printf("<!-- end generated block -->\n");

    GlobusGFSDebugExit();
}

void
globus_i_gfs_config_display_usage()
{
    int                                 i;
    globus_l_gfs_config_option_t *      o;
    GlobusGFSName(globus_i_gfs_config_display_usage);
    GlobusGFSDebugEnter();
    
    if(globus_i_gfs_config_bool("html"))
    {
        globus_l_gfs_config_display_html_usage();
    }
    else
    {        
            
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
                printf(" -%s,", o->short_cmdline_option);
            }
            if(o->long_cmdline_option)
            {
                printf(" -%s,", o->long_cmdline_option);
            }
            if(o->env_var_option)
            {
                printf(" $%s", o->env_var_option);
            }
            printf("\n");
        }
        printf("\nAny FLAG can be negated by prepending '-no-' or '-n' to the "
            "command line option or setting a value of 0 in the config file.\n\n");
        printf("Check http://www-unix.globus.org/toolkit/docs/development/4.0-drafts/data/gridftp/ "
            "for more in-depth documentation.\n\n");
    }

    GlobusGFSDebugExit();
}

static
globus_result_t
globus_l_gfs_config_misc()
{
    int                                 rc;
    globus_bool_t                       bool_value;
    char *                              value;
    char *                              data;
    GlobusGFSName(globus_l_gfs_config_misc);
    GlobusGFSDebugEnter();
    
    if(globus_i_gfs_config_bool("detach") && 
        !globus_i_gfs_config_bool("daemon"))
    {
        globus_l_gfs_config_set("daemon", GLOBUS_TRUE, NULL);
    } 
    if(!globus_i_gfs_config_bool("fork"))
    {
        globus_l_gfs_config_set("daemon", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("chdir", GLOBUS_FALSE, NULL);
    }
    if(globus_i_gfs_config_bool("inetd"))
    {
        globus_l_gfs_config_set("single", GLOBUS_TRUE, NULL);
        globus_l_gfs_config_set("daemon", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("detach", GLOBUS_FALSE, NULL);
    }

    if(globus_i_gfs_config_bool("debug"))
    {
        globus_l_gfs_config_set("daemon", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("detach", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("fork", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("bad_signal_exit", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("chdir", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("allow_anonymous", GLOBUS_TRUE, NULL);
        globus_l_gfs_config_set("secure_ipc", GLOBUS_FALSE, NULL);
    }

    if(globus_i_gfs_config_bool("allow_anonymous"))
    {
        globus_l_gfs_config_set("secure_ipc", GLOBUS_FALSE, NULL);
    }

        
    if((bool_value = globus_i_gfs_config_bool("banner_terse")) == GLOBUS_TRUE)
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
        globus_l_gfs_config_set("fqdn", 0, globus_libc_strdup(hostname));
        globus_free(hostname);
    }

    data = globus_common_create_string(
            "%d.%d (%s, %d-%d)",
            local_version.major,
            local_version.minor,
            build_flavor,
            local_version.timestamp,
            local_version.branch_id);
    globus_l_gfs_config_set("version_string", 0, data);
            

    if((value = globus_i_gfs_config_string("hostname")) != GLOBUS_NULL)
    {
        globus_libc_setenv("GLOBUS_HOSTNAME", value, 1);
        globus_l_gfs_config_set("fqdn", 0, globus_libc_strdup(value));
        globus_l_gfs_config_set("control_interface", 0, globus_libc_strdup(value));
        globus_l_gfs_config_set("data_interface", 0, globus_libc_strdup(value));
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

    value = globus_i_gfs_config_string("remote_nodes");
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
            globus_l_gfs_config_set("load_dsi_module", 0, globus_libc_strdup("remote"));                
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
    
    value = globus_libc_strdup(globus_i_gfs_config_string("allowed_modules"));
    if(value != NULL)
    {
        globus_list_t *                 module_list = NULL;
        char *                          module;
        char *                          ptr;
        
            module = value;
            while((ptr = strchr(module, ',')) != NULL)
            {
                *ptr = '\0';
                globus_list_insert(&module_list, globus_libc_strdup(module)); 
                module = ptr + 1;
            }
            if(ptr == NULL)
            {
                globus_list_insert(&module_list, globus_libc_strdup(module)); 
            }               
        
        globus_l_gfs_config_set("module_list", 0, module_list);   
        globus_free(value);             
    }
    
    /* if auth_level is -1 it means it has not yet been touched */
    if(globus_i_gfs_config_int("auth_level") == -1)
    {
        if(globus_i_gfs_config_bool("data_node"))
        {
            globus_l_gfs_config_set("auth_level", 1, NULL);
        }
        else
        {
            globus_l_gfs_config_set("auth_level", 2, NULL);
        }
    }

    /* make sure root running process that does not fork can only run
        once */
    if(!globus_i_gfs_config_bool("daemon") && getuid() == 0)
    {
        globus_l_gfs_config_set("connections_max", 1, NULL);
        globus_l_gfs_config_set("single", 1, NULL);
    }
    
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;
}
    

/**
 * load configuration.  read from defaults, file, env, and command line 
 * arguments. each overriding the other.
 * this function will log error messages and exit the server if any
 * errors occur.
 * XXX need to allow config errors to log to syslog, stderr, etc
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
    int                                 rc;
    GlobusGFSName(globus_i_gfs_config_init);
    GlobusGFSDebugEnter();
    
    globus_hashtable_init(
        &option_table,
        256,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    /* set default exe name */
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
    rc = globus_l_gfs_config_load_config_file(local_config_file);
    if(rc == -2)
    {
        rc = globus_l_gfs_config_load_config_file(global_config_file);
    }
    if(rc == -1)
    {
        goto error;
    }
    globus_l_gfs_config_load_config_env();
    rc = globus_l_gfs_config_load_commandline(argc, argv);
    if(rc == -1)
    {
        goto error;
    }
    globus_l_gfs_config_misc();
    
    globus_l_gfs_config_set("exec_name", 0, exec_name);
    globus_l_gfs_config_set("argv", 0, argv);
    globus_l_gfs_config_set("argc", argc, NULL);

    globus_free(local_config_file);     

    GlobusGFSDebugExit();
    return;

error:
    exit(2);     
}


int
globus_i_gfs_config_int(
    const char *                        option_name)
{
    globus_l_gfs_config_option_t *      option;
    int                                 value = 0;    
    GlobusGFSName(globus_i_gfs_config_int);
    GlobusGFSDebugEnter();
    
    option = (globus_l_gfs_config_option_t *) 
        globus_hashtable_lookup(&option_table, (void *) option_name);
        
    if(option)
    {        
        value = option->int_value;
    }

    GlobusGFSDebugExit();
    return value;
}


void *
globus_i_gfs_config_get(
    const char *                        option_name)
{
    globus_l_gfs_config_option_t *      option;
    void *                              value = NULL;    
    GlobusGFSName(globus_i_gfs_config_get);
    GlobusGFSDebugEnter();
    
    option = (globus_l_gfs_config_option_t *) 
        globus_hashtable_lookup(&option_table, (void *) option_name);
        
    if(option && option->value)
    {        
        value = option->value;
    }

    GlobusGFSDebugExit();
    return value;
}

globus_bool_t
globus_i_gfs_config_is_anonymous(
    const char *                        userid)
{
    globus_bool_t                       valid = GLOBUS_FALSE;
    char *                              anonymous_names;
    GlobusGFSName(globus_i_gfs_config_is_anonymous);
    GlobusGFSDebugEnter();

    anonymous_names = globus_i_gfs_config_string("anonymous_names_allowed");
    if(anonymous_names)
    {
        if(*anonymous_names == '*' || strstr(anonymous_names, userid))
        {
            valid = GLOBUS_TRUE;
        }
    }
    else
    {
        if(strcmp(userid, "ftp") == 0 ||
            strcmp(userid, "anonymous") == 0 ||
            strcmp(userid, ":globus-mapping:") == 0)
        {
            valid = GLOBUS_TRUE;
        }
    }
    
    GlobusGFSDebugExit();
    return valid;
}

globus_bool_t
globus_i_gfs_config_allow_addr(
    const char *                        remote_addr)
{
    char *                              allow_list;
    char *                              deny_list;
    globus_bool_t                       allowed = GLOBUS_FALSE;
    char *                              addr;
    char *                              ptr;
    GlobusGFSName(globus_i_gfs_config_allow_addr);
    GlobusGFSDebugEnter();
    
    allow_list = globus_libc_strdup(globus_i_gfs_config_string("allow_from"));
    deny_list = globus_libc_strdup(globus_i_gfs_config_string("deny_from"));

    if(allow_list == NULL)
    {
        allowed = GLOBUS_TRUE;
    }
    else
    {
        addr = allow_list;
        while((ptr = strchr(addr, ',')) != NULL && !allowed)
        {
            *ptr = '\0';
            if(strncmp(addr, remote_addr, strlen(addr)) == 0)
            {
                allowed = GLOBUS_TRUE;
            }
            addr = ptr + 1;
        }
        if(ptr == NULL && !allowed)
        {
           if(strncmp(addr, remote_addr, strlen(addr)) == 0)
            {
                allowed = GLOBUS_TRUE;
            }
        }
        globus_free(allow_list);
    }
    if(allowed && deny_list != NULL)
    {
        addr = deny_list;
        while((ptr = strchr(addr, ',')) != NULL && allowed)
        {
            *ptr = '\0';
            if(strncmp(addr, remote_addr, strlen(addr)) == 0)
            {
                allowed = GLOBUS_FALSE;
            }
            addr = ptr + 1;
        }
        if(ptr == NULL && allowed)
        {
           if(strncmp(addr, remote_addr, strlen(addr)) == 0)
            {
                allowed = GLOBUS_FALSE;
            }
        }
        globus_free(deny_list);
    }

    GlobusGFSDebugExit();
    return allowed;
}


const char *
globus_i_gfs_config_get_module_name(
    const char *                        client_alias)
{
    globus_list_t *                     module_list;
    globus_list_t *                     list;
    const char *                        module;
    const char *                        out_module = NULL;
    char *                              alias;
    globus_bool_t                       found = GLOBUS_FALSE;
    int                                 size;
    GlobusGFSName(globus_i_gfs_config_get_module_name);
    GlobusGFSDebugEnter();

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
        out_module = module;
    }

    GlobusGFSDebugExit();
    return out_module;
}


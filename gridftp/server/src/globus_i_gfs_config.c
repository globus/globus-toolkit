
#include "globus_i_gridftp_server.h"

#define GLOBUS_I_GFS_MAX_OPTS 1024


/* value verification? */

/* option_name, default val, configfile, env, cmdline long, cmdline short, bool? */
static char*                            option_list[][7] = 
{
    {"port",                "0",    "port",                 "GLOBUS_GRIDFTP_SERVER_PORT",        "-port",               "-p", "0"},
    {"data_port_range",     "0",    "data_port_range",      "GLOBUS_TCP_PORT_RANGE",             "-data-port-range",    "-dpr", "0"},
    {"max_connections",     "200",  "max_connections",      "",                                  "-max-connections",    "-mc", "0"},
    {"fork",                "0",    "fork",                 "",                                  "-fork",               "-f", "1"},
    {"data_node",           "0",    "data_node",            "",                                  "-data-node",          "-d", "1"}
};

static int option_count = sizeof(option_list) / sizeof(char *) / 7;

static globus_hashtable_t               option_table;



static
globus_result_t
globus_l_gfs_config_load_config_file(
    char *                              filename)
{
    FILE *                              fptr;
    char                                line[1024];
    char                                option[1024];
    char                                value[1024];
    globus_bool_t                       option_saved;
    int                                 i;
    int                                 rc;
    
    fptr = fopen(filename, "r");
    if(fptr == NULL)
    {
        return -1; /* XXX construct real error */
    }

    while(fgets(line, sizeof(line), fptr) != NULL)
    {
        option_saved = GLOBUS_FALSE;
            
        rc = sscanf(line, "%s%s", option, value);

        if(rc != 2)
        {
            /* XXX log message, invalid line in config */
            continue;
        }

        for(i = 0; i < option_count; i++)
        {
            if(strcmp(option, option_list[i][2]))
            {
                continue;
            }
            
            globus_hashtable_remove(&option_table, option_list[i][0]);                        
            rc = globus_hashtable_insert(&option_table,
                option_list[i][0],
                globus_libc_strdup(value));
            
            if(rc)
            {
                /* XXX error, log something */
            }
            
            option_saved = GLOBUS_TRUE;        
        }
        
        /* XXX possibly use the option even if it isn't in option table */
        if(!option_saved)
        {
            globus_hashtable_remove(&option_table, option);                        
            rc = globus_hashtable_insert(&option_table,
                option,
                globus_libc_strdup(value));
            
            if(rc)
            {
                /* XXX error, log something */
            }
        }     
    }

    fclose(fptr);
    
    return GLOBUS_SUCCESS;
}

static
globus_result_t
globus_l_gfs_config_load_config_env()
{
    char *                              value;
    int                                 rc;
    int                                 i;
    

    for(i = 0; i < option_count; i++)
    {
        if (!*option_list[i][3])
        {
            continue;
        }

        value = globus_libc_getenv(option_list[i][3]);
        
        if (!value)
        {
            continue;
        }
            
        globus_hashtable_remove(&option_table, option_list[i][0]);                        
        rc = globus_hashtable_insert(&option_table,
            option_list[i][0],
            globus_libc_strdup(value));
        
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
    char *                              value;
    int                                 rc;
    
    for(arg_num = 0; arg_num < argc; ++arg_num)
    {
        argp = argv[arg_num];
 
        for(i = 0; i < option_count; i++)
        {
            if(strcmp(argp, option_list[i][4]) && 
                strcmp(argp, option_list[i][5]))
            {
                continue;
            }
            
            if(!strcmp(option_list[i][6], "1"))
            {
                value = "1";
            }
            else
            {
                if(++arg_num >= argc)
                {
                    /* XXX error, log something */
                    return -1;
                }
                value = argv[arg_num];
            }
            
            globus_hashtable_remove(&option_table, option_list[i][0]);                        
            rc = globus_hashtable_insert(&option_table,
                option_list[i][0],
                globus_libc_strdup(value));
            
            if(rc)
            {
                /* XXX error, log something */
            }
            
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
    char *                              local_config_file;
    char *                              global_config_file;
    
    globus_hashtable_init(&option_table,
        GLOBUS_I_GFS_MAX_OPTS,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    /* XXX read config filename from commandline */
    global_config_file = "/etc/gridftp.conf";
    local_config_file = "gridftp.conf";
            
    globus_l_gfs_config_load_defaults();
    globus_l_gfs_config_load_config_file(global_config_file);
    globus_l_gfs_config_load_config_file(local_config_file);
    globus_l_gfs_config_load_config_env();
    globus_l_gfs_config_load_commandline(argc, argv);
        
}

/* returns false if option doesnt exist */
globus_bool_t
globus_i_gfs_config_bool(
    const char *                        option)
{
    char *                              value;
    
    value = (char *) globus_hashtable_lookup(&option_table, option);
    
    if(value && !strcmp(value, "1"))
    {
        return GLOBUS_TRUE;
    }
    
    return GLOBUS_FALSE;
}


/* returns INT_MAX if option doesnt exist */
int
globus_i_gfs_config_int(
    const char *                        option)
{
    char *                              value;
    int                                 int_value = INT_MAX;
    
    value = (char *) globus_hashtable_lookup(&option_table, option);
    
    if(value)
    {
        int_value = atoi(value);
    }
    
    return int_value;
}




static
globus_result_t
globus_l_gfs_config_load_defaults()
{
    int                                 rc;
    int                                 i;
    
    for(i = 0; i < option_count; i++)
    {        
        rc = globus_hashtable_insert(&option_table, 
            option_list[i][0], 
            option_list[i][1]);
        
        if(rc)
        {
            /* XXX error, log something */
        }
    }  

    return GLOBUS_SUCCESS; 
}



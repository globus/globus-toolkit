
#include "globus_i_gridftp_server.h"

#define GLOBUS_I_GFS_MAX_OPTS 1024


/* value verification? */
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
    union
    {
        int                             int_value;
        char *                          string_value;
    };
} globus_l_gfs_config_option_t;

static const globus_l_gfs_config_option_t option_list[] = 
{ 
 {"max_connections", "max_connections", "", "-max-connections", "-mc", GLOBUS_L_GFS_CONFIG_INT, {200}},
 {"port", "port", "GLOBUS_GRIDFTP_SERVER_PORT", "-port", "-p", GLOBUS_L_GFS_CONFIG_INT, {0}},
 {"fork", "fork", "", "-fork", "-f", GLOBUS_L_GFS_CONFIG_BOOL, {0}},
 {"inetd", "inetd", "", "-inetd", "-i", GLOBUS_L_GFS_CONFIG_BOOL, {0}},
 {"no_gssapi", "no_gssapi", "", "-no-gssapi", "-ng", GLOBUS_L_GFS_CONFIG_BOOL, {0}},
 {"allow_clear", "allow_clear", "", "-allow-clear", "-ac", GLOBUS_L_GFS_CONFIG_BOOL, {0}},
 {"data_node", "data_node", "", "-data-node", "-d", GLOBUS_L_GFS_CONFIG_BOOL, {0}}
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
    globus_bool_t                       option_saved;
    int                                 i;
    int                                 rc;
    globus_l_gfs_config_option_t *      option;

    fptr = fopen(filename, "r");
    if(fptr == NULL)
    {
        return -1; /* XXX construct real error */
    }

    while(fgets(line, sizeof(line), fptr) != NULL)
    {
        option_saved = GLOBUS_FALSE;
            
        rc = sscanf(line, "%s%s", file_option, value);

        if(rc != 2)
        {
            /* XXX log message, invalid line in config */
            continue;
        }

        for(i = 0; i < option_count; i++)
        {
            if(strcmp(file_option, option_list[i].configfile_option))
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
            
            option_saved = GLOBUS_TRUE;        
        }
        
        /* XXX possibly use the option even if it isn't in option table */
        if(!option_saved && 0)
        {
            globus_hashtable_remove(&option_table, option);                        
            rc = globus_hashtable_insert(&option_table,
                option,
                (void *) atoi(value));
            
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
    globus_l_gfs_config_option_t *      option;
    

    for(i = 0; i < option_count; i++)
    {
        if (!*option_list[i].env_var_option)
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
    int                                 value;
    int                                 rc;
    globus_l_gfs_config_option_t *      option;
    
    for(arg_num = 0; arg_num < argc; ++arg_num)
    {
        argp = argv[arg_num];
 
        for(i = 0; i < option_count; i++)
        {
            if(strcmp(argp, option_list[i].short_cmdline_option) && 
                strcmp(argp, option_list[i].long_cmdline_option))
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






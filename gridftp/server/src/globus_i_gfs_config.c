
#include "globus_i_gridftp_server.h"

#define GLOBUS_I_GFS_MAX_OPTS 1024

static globus_hashtable_t               option_table;

/* val verification, bool flags? 
*/

/* option_name, default val, configfile, env, cmdline long, cmdline short */

static char[][] option_list = {
    {"port",                "0",    "port",                 "GLOBUS_GRIDFTP_SERVER_PORT",        "-port",               "-p"},
    {"data_port_range",     "0",    "data_port_range",      "GLOBUS_TCP_PORT_RANGE",             "-data-port-range",    "-dpr"},
    {"max_connections",     "200",  "max_connections",      "",                                  "-max-connections",    "-mc"},
    {"fork",                "0",    "fork",                 "",                                  "-fork",               "-f"},
    {"data_node",           "0",    "data_node",            "",                                  "-data-node",          "-d"}
};
    

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
    char *                              local_config;
    
    globus_hashtable_init(&option_table,
        GLOBUS_I_GFS_MAX_OPTS,
        globus_hashtable_voidp_hash,
        globus_hashtable_voidp_keyeq);
        
    globus_i_gfs_config_load_defaults();
    globus_i_gfs_config_load_config_file(local_config);
    globus_i_gfs_config_load_config_env();
    globus_i_gfs_config_load_commandline(argc, argv);
        
}


/* returns false if option doesnt exist */
globus_bool_t
globus_i_gfs_config_bool(
    const char *                        option)
{
    
    return GLOBUS_FALSE;
}

/* returns INT_MAX if option doesnt exist */
int
globus_i_gfs_config_int(
    const char *                        option)
{
    return 0;
}


static
globus_result_t
globus_l_gfs_config_load_config_file(
    char *                              filename)
{
/*
    open file;
    add each line to hashtable;
    close;
*/
}

static
globus_result_t
globus_l_gfs_config_load_config_env()
{
/*
    for each env var in array, load it
*/
}

static
globus_result_t
globus_l_gfs_config_load_commandline(
    int                                 argc,
    char **                             argv)
{
/*
    for each arg add option
*/
}

static
globus_result_t
globus_l_gfs_config_load_defaults()
{
/*
    load all defaults into table
*/
}



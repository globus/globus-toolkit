
#include "globus_i_gridftp_server.h"

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

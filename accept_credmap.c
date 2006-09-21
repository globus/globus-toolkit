#include "myproxy_common.h"


static int
consult_mapfile ( char * mapfile, char * userdn, char * username ) {

    int retval = 0;  /* Assume success */
    char * oldenv = NULL;

    myproxy_debug("consult_mapfile(%s,%s,%s)",mapfile,userdn,username);

    /* Save the current GRIDMAP environment variable so we can set it 
     * to accepted_credentials_mapfile for a globus_gss_assist call */
    oldenv = (char*)getenv("GRIDMAP");
    setenv("GRIDMAP", mapfile, 1);

    /* Note: globus_gss_assist_userok returns 0 upon success */
    if (globus_gss_assist_userok(userdn, username) != 0) {
        retval = 1;  
        verror_put_string("PUT/STORE: No mapping found for "
                          "'%s' and '%s' in '%s'",
                          userdn,username,mapfile);
    }

    /* Now, restore the previous GRIDMAP environment variable */
    setenv("GRIDMAP", oldenv, 1);

    return retval; 
}


static int
consult_mapapp ( char * mapapp, char * userdn, char * username) {

    int retval = 0;   /* Assume success */
    pid_t childpid;
    int fds[3];
    int exit_status;

    myproxy_debug("consult_mapapp(%s,%s,%s)",mapapp,userdn,username);

    if ((childpid = myproxy_popen(fds,mapapp,userdn,username,NULL)) < 0) {
        return -1; /* myproxy_popen will set verror */
    }

    close(fds[0]);

    /* Wait for child (mapapp) to exit */
    if (waitpid(childpid,&exit_status,0) == -1) {
        verror_put_string("wait() failed for consult_mapapp child");
        verror_put_errno(errno);
        return -1;
    }

    if (exit_status != 0) {  /* mapapp returned fail; no valid mapping */

        FILE *fp = NULL;
        char buf[100];

        retval = 1;     /* return failure */
        verror_put_string("consult_mapapp call-out returned failure");

        /* Check stdout for any error output */
        fp = fdopen(fds[1],"r");
        if (fp) {
            while (fgets(buf,100,fp) != NULL) {
                verror_put_string(buf);
            }
            fclose(fp);
        } else {
            close(fds[1]);
        }

        /* Check stderr for any error output */
        fp = fdopen(fds[2],"r");
        if (fp) {
            while (fgets(buf,100,fp) != NULL) {
                verror_put_string(buf);
            }
            fclose(fp);
        } else {
            close(fds[2]);
        }

    } else {  /* mapapp returned success; close remaining file handles */

        close(fds[1]);
        close(fds[2]);

    }

    return retval;
}


int accept_credmap( char * userdn, char * username,
                    myproxy_server_context_t * server_context ) {

    int retval = 0;      /* Assume success */

    myproxy_debug("accept_credmap()");

    /* Check to see if the accepted_credentials_mapapp value has been 
     * specified in the config file.  Also do a sanity check and verify
     * that the mapapp is still executable. */
    if (server_context->accepted_credentials_mapapp != NULL) {
        if (access(server_context->accepted_credentials_mapapp, X_OK) < 0) {
            verror_put_string("accepted_credentials_mapapp %s not executable",
                              server_context->accepted_credentials_mapapp);
            verror_put_errno(errno);
            retval = -1;
        }
        
        if (consult_mapapp(server_context->accepted_credentials_mapapp,
                           userdn,username)) {
            verror_put_string("Accepted credentials failure for DN/Username "
                              "via call-out");
            retval = 1;
        }

    /* If the mapapp was not specified (or not executable), check to see if
     * the accepted_credentials_mapfile value has been specified in the
     * config file.  Also do a sanity check and verify that the mapfile is
     * still readable. */
    } else if (server_context->accepted_credentials_mapfile != NULL) {
        if (access(server_context->accepted_credentials_mapfile, R_OK) < 0) {
            verror_put_string("accepted_credentials_mapfile %s not readable",
                              server_context->accepted_credentials_mapfile);
            verror_put_errno(errno);
            retval = -1;
        }            

        if (consult_mapfile(server_context->accepted_credentials_mapfile,
                           userdn,username)) {
            verror_put_string("Accepted credentials failure for DN/Username "
                              "via grid-mapfile");
            retval = 1;
        }

    }

    return retval;
}


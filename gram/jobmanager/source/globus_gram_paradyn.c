/******************************************************************************
                             Include header files
******************************************************************************/
#include <stdio.h>
#include <malloc.h>
#include <sys/param.h>
#include <sys/time.h>
#include <string.h> /* for strdup() */
#include <memory.h>
#include <fcntl.h>
#include "globus_nexus.h"
#include "globus_gram_client.h"
#include "globus_i_gram_jm.h"

/******************************************************************************
                               Type definitions
******************************************************************************/

/******************************************************************************
                          Module specific prototypes
******************************************************************************/

extern char * grami_jm_libexecdir;

/******************************************************************************
                       Define variables for external use
******************************************************************************/

/******************************************************************************
                       Define module specific variables
******************************************************************************/

/******************************************************************************
Function:       grami_paradyn_is paradyn_job()
Description:    Checks to see if the job should use paradyn
Parameters:     filled out params structure
Returns:        1 if a paradyn job, 0 if not
******************************************************************************/
int
grami_is_paradyn_job(gram_request_param_t * params)
{

    if (strlen(params->paradyn) > 0)
    {
        return 1;
    }

    return 0;

} /* grami_paradyn_is_paradyn_job() */

/******************************************************************************
Function:       grami_paradyn_rewrite_params()
Description:    Modifies the params structure to run paradynd
                which then in turn starts up the application
Parameters:     Filled out params structure
Returns:        1 if it successfully 
******************************************************************************/
int
grami_paradyn_rewrite_params(gram_request_param_t * params)
{
    char tmp_string[GLOBUS_GRAM_CLIENT_PARAM_SIZE*4];
    char paradyn_port[GLOBUS_GRAM_CLIENT_PARAM_SIZE];
    char paradyn_host[GLOBUS_GRAM_CLIENT_PARAM_SIZE];
    char paradynd_type[GLOBUS_GRAM_CLIENT_PARAM_SIZE];
    char paradynd_location[GLOBUS_GRAM_CLIENT_PARAM_SIZE*2];

    /*
     *  Initialize our strings
     */

    strcpy(paradyn_port,"");
    strcpy(paradyn_host,"");
    strcpy(paradynd_type,"");
    strcpy(paradynd_location,"");

    sscanf(params->paradyn,"%s %s %s %s",paradyn_host,paradyn_port,paradynd_type,paradynd_location);

    /*
     *  If we haven't received all our necessary parameters, die
     */

    if (strlen(paradyn_port)  == 0 ||
        strlen(paradyn_host)  == 0 ||
        strlen(paradynd_type) == 0)
    {
        return 0;
    }

    /*
     *  Set the argument parameter
     *
     *  We have a hack here to put a ./ in front of the executable because
     *  of a problem with paradynd.
     */


    if (params->pgm[0] != '/')
    {
       sprintf(tmp_string,"-p%s -m%s -l2 -z%s -runme ./%s %s"
                         ,paradyn_port
                         ,paradyn_host
                         ,paradynd_type
                         ,params->pgm
                         ,params->pgm_args);
    }
    else
    {
       sprintf(tmp_string,"-p%s -m%s -l2 -z%s -runme %s %s"
                         ,paradyn_port
                         ,paradyn_host
                         ,paradynd_type
                         ,params->pgm
                         ,params->pgm_args);
    }

    strncpy(params->pgm_args,tmp_string,GLOBUS_GRAM_CLIENT_PARAM_SIZE);

    /*
     * Change program name to paradynd
     */

    if (strlen(paradynd_location) == 0)
    {
        strcpy(params->pgm,"file://");
        strcat(params->pgm,grami_jm_libexecdir);
        strcat(params->pgm,"/paradynd");
    }
    else
    {
        strcpy(params->pgm,paradynd_location);
    }

    return 1;

} /* grami_paradyn_rewrite_params() */


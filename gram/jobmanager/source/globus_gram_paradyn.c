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
#include "globus_gram_job_manager.h"
#include "globus_gram_client.h"

/******************************************************************************
                               Type definitions
******************************************************************************/

/******************************************************************************
                          Module specific prototypes
******************************************************************************/

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
grami_is_paradyn_job(globus_gram_jobmanager_request_t * params)
{

    if (params->paradyn)
    {
        return 1;
    }

    return 0;

} /* grami_is_paradyn_job() */

/******************************************************************************
Function:       grami_paradyn_rewrite_params()
Description:    Modifies the params structure to run paradynd
                which then in turn starts up the application
Parameters:     Filled out params structure
Returns:        1 if it successfully 
******************************************************************************/
int
grami_paradyn_rewrite_params(globus_gram_jobmanager_request_t * params)
{
    char tmp_string[GLOBUS_GRAM_CLIENT_PARAM_SIZE*4];
    char paradyn_port[GLOBUS_GRAM_CLIENT_PARAM_SIZE];
    char paradyn_host[GLOBUS_GRAM_CLIENT_PARAM_SIZE];
    char paradynd_type[GLOBUS_GRAM_CLIENT_PARAM_SIZE];
    char paradynd_location[GLOBUS_GRAM_CLIENT_PARAM_SIZE*2];
    int i;
    char ** new_args;

    /*
     *  Initialize our strings
     */

    strcpy(paradyn_port,"");
    strcpy(paradyn_host,"");
    strcpy(paradynd_type,"");
    strcpy(paradynd_location,"");

    sscanf(params->paradyn,"%s %s %s %s",
           paradyn_host,
           paradyn_port,
           paradynd_type,
           paradynd_location);

    /*
     *  If we haven't received all our necessary parameters, die
     */

    if (strlen(paradyn_port)  == 0 ||
        strlen(paradyn_host)  == 0 ||
        strlen(paradynd_type) == 0)
    {
        return 0;
    }

    for (i = 0; (params->arguments)[i]; i++)
        ;

    /* make new args big enough to handle all the paradyn ones plus the old
     * ones.
     */
    new_args = (char **)globus_malloc(sizeof(char *) * (i + 7));

    (new_args)[0] = (char *) malloc (sizeof(char *) * strlen(paradyn_port) +3);
    strcpy((new_args)[0], "-p");
    strcat((new_args)[0], paradyn_port);

    (new_args)[1] = (char *) malloc (sizeof(char *) * strlen(paradyn_host) +3);
    strcpy((new_args)[1], "-m");
    strcat((new_args)[1], paradyn_host);

    (new_args)[2] = (char *) malloc (sizeof(char *) * 3);
    strcpy((new_args)[2], "-l2");

    (new_args)[3] = (char *) malloc (sizeof(char *) * strlen(paradynd_type) +3);
    strcpy((new_args)[3], "-l");
    strcat((new_args)[3], paradynd_type);

    (new_args)[4] = (char *) malloc (sizeof(char *) * 7);
    strcpy((new_args)[4], "-runme");

    /*
     *  We have a hack here to put a ./ in front of the executable because
     *  of a problem with paradynd.
     */

    if (params->executable[0] != '/')
    {
        (new_args)[5]=(char *) malloc (sizeof(char *) * 
                       strlen(params->executable) +3);
        strcpy((new_args)[5], "./");
        strcat((new_args)[5], params->executable);

    }
    else
    {
        (new_args)[5]=(char *) malloc (sizeof(char *) *
                       strlen(params->executable) +1);
        strcpy((new_args)[5], params->executable);
    }

    /* Tack on the user defined arguments to the list
     */
    for (i = 0; (params->arguments)[i]; i++)
    {
        (new_args)[i+6] = (char *) malloc (sizeof(char *) * 
                                     strlen((params->arguments)[i]) +1);
        strcpy((new_args)[i+6], (params->arguments)[i]);
    }

    (new_args)[i+6] = NULL;

    params->arguments = new_args;

    /*
     * Change program name to paradynd
     */

    if (strlen(paradynd_location) == 0)
    {
        params->executable = (char *) globus_malloc (sizeof(char *) * 
                              strlen(params->jobmanager_libexecdir) + 17);
        strcpy(params->executable,"file://");
        strcat(params->executable,params->jobmanager_libexecdir);
        strcat(params->executable,"/paradynd");
    }
    else
    {
        params->executable = (char *) globus_malloc (sizeof(char *) * 
                                              strlen(paradynd_location) + 1);
        strcpy(params->executable,paradynd_location);
    }

    return 1;

} /* grami_paradyn_rewrite_params() */


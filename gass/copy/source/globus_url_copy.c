/******************************************************************************
globus_url_copy.c 

Description:

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_common.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#include "globus_gass_file.h"

#if 1
const char * oneline_usage
    = "globus-url-copy [-help] [-usage] [-version] [-binary] sourceURL destURL";
#else
const char * oneline_usage
    = "globus-url-copy [-help] [-usage] [-version] [-binary|-ascii] sourceURL destURL";
#endif

const char * long_usage
    =   "\nglobus-url-copy [options] sourceURL destURL\n"
        "OPTIONS\n"
        "\t -help             : Print this message \n" 
        "\t -usage            : Print a short usage description message\n"
        "\t -version          : Print the version of this program\n"
        "\t -ascii            : NOT available yet; convert the file to/from\n"
        "\t                     netASCII format to/from local file format\n"
        "\t -binary           : Do not apply any conversion to the files\n"
        "\t                     -binary is used by default\n\n";

#define binary_id   1
#define ascii_id    2

static char *  ascii_aliases[]    = { "-ascii", GLOBUS_NULL };
static char *  binary_aliases[]   = { "-binary", GLOBUS_NULL };

static globus_args_option_descriptor_t option_list[]
    = { {ascii_id,  ascii_aliases,  0, GLOBUS_NULL, GLOBUS_NULL} ,
	{binary_id, binary_aliases, 0, GLOBUS_NULL, GLOBUS_NULL} };


#define NB_OPTIONS (sizeof(option_list)/sizeof(globus_args_option_descriptor_t))

static char *got_option[NB_OPTIONS] =
{GLOBUS_NULL,
 GLOBUS_NULL
};

int
main(int argc, char **argv)
{
    globus_args_option_instance_t *  option;
    globus_list_t *                  options_found;
    globus_list_t *                  list;
    char *                           error_msg;
    int                              n_options;
    int                              err;
    char *                           sourceURL;
    char *                           destURL;
    globus_url_t		     test_url;

    int                              fd_source =-1;
    int                              fd_dest   =-1;
    int                              nb_read;
    int                              nb_to_write;
    int                              nb_written;
    int                              rc=0;

    char                             buffer[512];

    n_options = NB_OPTIONS;

    error_msg = GLOBUS_NULL;
    err = globus_args_scan( &argc,
			    &argv,
			    n_options,
			    option_list,
			    oneline_usage,
			    long_usage,
			    &options_found,
			    GLOBUS_NULL    );

    if (err >= 0)
    {
        /*
	 * printf("option list : \n");
	 */
	for (list = options_found;
	     !globus_list_empty(list);
	     list = globus_list_rest(list))
	{
	    option = globus_list_first(list);
	    
            /* mark that we got this option */
	    got_option[(option->id_number)-1]=
		*(option_list[(option->id_number)-1]).names; 
	}

	globus_args_option_instance_list_free( &options_found );
    }

    /* check for incompatible options */
    if (got_option[0]!= GLOBUS_NULL && got_option[1]!= GLOBUS_NULL)
    {
	fprintf(stderr,"Options -ascii and -binary are exclusive\n");
	fprintf(stderr,"%s\n",oneline_usage);
	exit(-1);
    }
    /* check for default */
    if (got_option[ascii_id-1]== GLOBUS_NULL &&
	got_option[binary_id-1]== GLOBUS_NULL)
    {
	/* set this defaults option as set, as if we had got it */
	got_option[binary_id-1]=*((option_list[binary_id-1]).names);
    }
    if (got_option[ascii_id-1]!= GLOBUS_NULL)
    {
	fprintf(stderr,"Sorry, ascii mode not yet supported\n");
	fprintf(stderr,"%s\n",oneline_usage);
	exit(-1);
    }
    

    /* check for extra arguments (not options) */
    if (argc!=3)
    {
	fprintf(stderr,"%s\n",oneline_usage);
	exit(-1);
    }

    sourceURL=argv[1];
    destURL=argv[2];

    /* if sourceURl and destURL are identical, well lets not care about it,
       they might be GASS servers actually doing some action the user really
       want to happen
       This is commented out:
    if (!strcmp(sourceURL,destURL))
    {
	if (strcmp(sourceURL, "-"))
	{
	
	    fprintf(stderr,"sourceURl and destURL are identical\n"); 
	    exit(GLOBUS_SUCCESS);
	}
    }
    */

    /* Verify that the source and destination are valid URLs */
    if (strcmp(sourceURL,"-"))
    {
	rc = globus_url_parse(sourceURL, &test_url);
	if(rc != GLOBUS_SUCCESS)
	{
	    fprintf(stderr, "can not parse sourceURL \"%s\"\n", sourceURL);
	    exit(GLOBUS_SUCCESS);
	}
	globus_url_destroy(&test_url);
    }

    if (strcmp(destURL,"-"))
    {
	rc = globus_url_parse(destURL, &test_url);
	if(rc != GLOBUS_SUCCESS)
	{
	    fprintf(stderr, "can not parse destURL \"%s\"\n", destURL);
	    exit(GLOBUS_SUCCESS);
	}
	globus_url_destroy(&test_url);
    }
    /* end of argument parsing */

    /* To find out if I need to do some netASCII to Unix or
       Unix to netASCII conversion, I need to know what is the kind of each
       URL. I will convert netASCII to Unix
     */
    
    /* open the source and dest url */
   
    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_GASS_FILE_MODULE);

    
    if (strcmp(sourceURL, "-"))
    {
	fd_source = globus_gass_open(sourceURL, O_RDONLY, 0);
	if(fd_source < 0)
	{
	    globus_libc_fprintf(
		stderr,
		"%s: Error opening sourceURL %s: error code: %d\n",
		argv[0],
		sourceURL,
		errno);
	    rc=-2;
	    goto end;
	}
    }
    else
    {
	fd_source = 0;
    }

    if (strcmp(destURL, "-"))
    {
	fd_dest = globus_gass_open(destURL, O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU|S_IRWXG|S_IRWXO);
	if(fd_dest < 0)
	{
	    globus_libc_fprintf(
		stderr,
		"%s: Error opening destURL %s: error code: %d\n",
		argv[0],
		destURL,
		errno);
	    rc=-3;
	    goto end;
	}
    }
    else
    {
	fd_dest = 0;
    }


    while (GLOBUS_TRUE)
    {
 
	while ( (nb_read = globus_libc_read(fd_source, buffer,sizeof(buffer)))
		== -1 )
	{
	    if (errno != EINTR && errno !=EAGAIN)
	    {
		globus_libc_fprintf(
		    stderr,
		    "Error reading from sourceURL %s: error code: %d\n",
		    sourceURL,
		    errno);
		rc=-4;
		goto end;
	    }
	}
	
	if (nb_read ==0)
	{
	    break;
	}
	
	/* ascii conversion...*/

	/* now write the data out */
	nb_to_write=nb_read;
	while ( (nb_written=globus_libc_write(fd_dest, buffer,nb_to_write))
		!= nb_to_write )
	{
	    if (nb_written==-1 && errno != EINTR && errno !=EAGAIN)
	    {
		globus_libc_fprintf(
		    stderr,
		    "Error writing to destURL %s: error code: %d\n",
		    sourceURL,
		    errno);
		rc=-5;
		goto end;
	    }
	    if (nb_written!=-1)
	    {		
		nb_to_write-=nb_written;
	    }
	}
	
    }
    
    
end:
    if(fd_source >= 0)
    {
	globus_libc_close(fd_source);
    }
    if(fd_dest >= 0)
    {
	globus_libc_close(fd_dest);
    }
    globus_module_deactivate(GLOBUS_GASS_FILE_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return rc;
    
}





/*
 * myproxy_acpp.c
 *
 * Change passphrase tool
 *
 */

#include "myproxy_creds.h"
#include "myproxy.h"
#include "myproxy_server.h"
#include "myproxy_log.h"
#include "ssl_utils.h"
#include "gnu_getopt.h"
#include "verror.h"
#include "myproxy_read_pass.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define BINARY_NAME "myproxy-acpp"

static char usage[] = \
"\n"\
" Syntax:  "  BINARY_NAME "[-usage|-help] [-version]\n"\
"\n"\
"    Options\n"\
"    -h | --help                	Displays usage\n"\
"    -u | --usage                             \n"\
"						\n"\
"    -l | --username <username>		Username of the delegated proxy\n"\
"    -k | --credname <name>		Credential name\n"\
"    -v | --verbose             	Display debugging messages\n"\
"    -V | --version             	Displays version\n"\
"    -s | --storage <directory> 	Specifies the credential storage directory\n"
"                                            \n"\
"\n";

struct option long_options[] =
{
    {"help",             no_argument, NULL, 'h'},
    {"usage",            no_argument, NULL, 'u'},
    {"username",   required_argument, NULL, 'l'},
    {"credname",   required_argument, NULL, 'k'},
    {"storage",	   required_argument, NULL, 's'},
    {"verbose",          no_argument, NULL, 'v'},
    {"version",          no_argument, NULL, 'V'},
    {0, 0, 0, 0}
};

static char short_options[] = "hus:vVl:k:";

static char version[] =
BINARY_NAME "version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

/* Function declarations */
void init_arguments(int argc, char *argv[], struct myproxy_creds *pcreds);

int
main(int argc, char *argv[]) 
{
    struct myproxy_creds cred;
 
   /* Initialize arguments*/
    init_arguments(argc, argv, &cred);

    cred.passphrase = (char *) malloc (MAX_PASS_LEN+1);
    if (myproxy_read_verified_passphrase(cred.passphrase,
                                         MAX_PASS_LEN) == -1) {

         fprintf(stderr, "%s\n",
                 verror_get_string());

	 goto cleanup;
    }

    myproxy_debug("Changing passphrase for username \"%s\"", cred.username);

    if (myproxy_admin_change_passphrase(&cred,cred.passphrase) < 0) {
        myproxy_log_verror();
        fprintf (stderr, "Unable to change passphrase !! %s\n", verror_get_string());
    } else {
        fprintf (stdout, "Password Changed !! \n");
    }

    cleanup:;
    return 0;
}

void 
init_arguments(int argc, 
		       char *argv[], struct myproxy_creds *pcreds)
{
    extern char *gnu_optarg;
    int arg;

    pcreds->username = NULL;  	/* username is required */
    pcreds->credname = NULL;   /* credential name is optional */

    while((arg = gnu_getopt_long(argc, argv, short_options, 
                             long_options, NULL)) != EOF) 
    {
        switch(arg) 
        {  
        case 's': /* set the credential storage directory */
        { char *s;
          s=(char *) malloc(strlen(gnu_optarg) + 1);
          strcpy(s,gnu_optarg);
          myproxy_set_storage_dir(s);
          break;
         }
        case 'u': 	/* print help and exit */
            fprintf(stderr, usage);
            exit(1);
       	    break;
	case 'l':	/* username */
	    pcreds->username = strdup (gnu_optarg);
	    break;
	case 'k':	/* credential name */
	    pcreds->credname = strdup (gnu_optarg);
	    break;
	case 'h': 	/* print help and exit */
            fprintf(stderr, usage);
            exit(1);
            break;
	case 'v':	/* verbose */
	    myproxy_debug_set_level(1);
	    break;
        case 'V':       /* print version and exit */
            fprintf(stderr, version);
            exit(1);
            break;
        default:        /* print usage and exit */ 
            fprintf(stderr, usage);
	    exit(1);
            break;	
        }
    }

    if (pcreds->username == NULL)  /* username is required */
    {
	fprintf (stderr, "Please specify username\n");
	exit(1);
    }

    return;
}

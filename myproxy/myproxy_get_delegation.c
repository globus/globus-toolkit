/*
 * myproxy-get-delegation
 *
 * Webserver program to retrieve a delegated credential from a myproxy-server
 */

#include "myproxy.h"
#include "gnu_getopt.h"
#include "version.h"
#include "verror.h"
#include "myproxy_read_pass.h"
#include "myproxy_delegation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h> 
#include <assert.h>
#include <errno.h>
#include <unistd.h>

static char usage[] = \
"\n"
"Syntax: myproxy-get-delegation [-t hours] [-l username] ...\n"
"        myproxy-get-delegation [-usage|-help] [-v|--version]\n"
"\n"
"   Options\n"
"       -h | --help                       Displays usage\n"
"       -u | --usage                                    \n"
"                                                      \n"
"       -v | --version                    Displays version\n"
"       -l | --username        <username> Username for the delegated proxy\n"
"       -t | --portal_lifetime <hours>    Lifetime of delegated proxy on\n" 
"                                         the portal (default 2 hours)\n"
"       -o | --out             <path>     Location of delegated proxy\n"
"       -s | --pshost          <hostname> Hostname of the myproxy-server\n"
"       -p | --psport          <port #>   Port of the myproxy-server\n"
"       -a | --authorization   <path>     Use special credential for authorization\n"
"                                         (instead of common pass phrase)\n"
"\n";

struct option long_options[] =
{
    {"help",                   no_argument, NULL, 'h'},
    {"pshost",           required_argument, NULL, 's'},
    {"psport",           required_argument, NULL, 'p'},
    {"portal_lifetime",  required_argument, NULL, 't'},
    {"out",              required_argument, NULL, 'o'},
    {"usage",                  no_argument, NULL, 'u'},
    {"username",         required_argument, NULL, 'l'},
    {"version",                no_argument, NULL, 'v'},
    {"authorization",    required_argument, NULL, 'r'},
    {0, 0, 0, 0}
};

static char short_options[] = "hus:p:l:t:o:va:";

static char version[] =
"myproxy-get-delegation version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

void 
init_arguments(int argc, char *argv[], 
	       myproxy_socket_attrs_t *attrs,
	       myproxy_request_t *request); 

int  read_passphrase(char *passphrase, const int passlen, 
                     const int min, const int max);

/*
 * Use setvbuf() instead of setlinebuf() since cygwin doesn't support
 * setlinebuf().
 */
#define my_setlinebuf(stream)	setvbuf((stream), (char *) NULL, _IOLBF, 0)

/* location of delegated proxy */
char *outputfile = NULL;
char *creds_to_authorization = NULL;

int
main(int argc, char *argv[]) 
{    
    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;
    char proxyfile[MAXPATHLEN];

    my_setlinebuf(stdout);
    my_setlinebuf(stderr);

    socket_attrs = malloc(sizeof(*socket_attrs));
    memset(socket_attrs, 0, sizeof(*socket_attrs));

    client_request = malloc(sizeof(*client_request));
    memset(client_request, 0, sizeof(*client_request));

    server_response = malloc(sizeof(*server_response));
    memset(server_response, 0, sizeof(*server_response));

    /* Setup defaults */
    myproxy_set_delegation_defaults(socket_attrs,client_request);

    /* Initialize client arguments and create client request object */
    init_arguments(argc, argv, socket_attrs, client_request);

    if (creds_to_authorization == NULL) {
       /* Allow user to provide a passphrase */
       if (myproxy_read_passphrase(client_request->passphrase,
				   sizeof(client_request->passphrase)) == -1)
       {
	   fprintf(stderr, "Error reading passphrase\n");
	   exit(1);
       }
    }

    if (client_request->username == NULL && creds_to_authorization) 
       if (ssl_get_base_subject_file(creds_to_authorization,
		                     &client_request->username)) {
	  fprintf(stderr, "Cannot get subject name from your certificate %s\n",
		  creds_to_authorization);
	  exit(1);
       }
    if (client_request->username == NULL) {
       fprintf(stderr, usage);
       fprintf(stderr, "Please specify a username!\n");
       exit(1);
    }

    if (outputfile == NULL) {
       snprintf(proxyfile, sizeof(proxyfile), "%s/XXXXXX", P_tmpdir);
       if (mkstemp(proxyfile) == -1) {
          fprintf(stderr, "Cannot create filename to store the proxy (%s)\n",
		  strerror(errno));
          exit(1);
       }
       outputfile = strdup(proxyfile);
    }

    if (myproxy_get_delegation(socket_attrs, client_request, 
	    creds_to_authorization, server_response, outputfile)==0) {
        printf("A proxy has been received for user %s in %s\n",
           client_request->username, outputfile);
    }
    free(outputfile);
    verror_clear();

    /* free memory allocated */
    myproxy_destroy(socket_attrs, client_request, server_response);
    exit(0);
}

void 
init_arguments(int argc, 
	       char *argv[], 
	       myproxy_socket_attrs_t *attrs,
	       myproxy_request_t *request) 
{   
    extern char *gnu_optarg;
    int arg;

    while((arg = gnu_getopt_long(argc, argv, short_options, 
				 long_options, NULL)) != EOF) 
    {
        switch(arg) 
        {
	case 't':       /* Specify portal lifetime in seconds */
	  request->portal_lifetime = 60*60*atoi(gnu_optarg);
	  break;
        case 's': 	/* pshost name */
	    attrs->pshost = strdup(gnu_optarg);
            break;
        case 'p': 	/* psport */
            attrs->psport = atoi(gnu_optarg);
            break;
	case 'h': 	/* print help and exit */
            fprintf(stderr, usage);
            exit(1);
            break;
        case 'u': 	/* print help and exit */
            fprintf(stderr, usage);
            exit(1);
            break;
        case 'l':	/* username */
            request->username = strdup(gnu_optarg);
            break;
	case 'o':	/* output file */
	    outputfile = strdup(gnu_optarg);
            break;    
	case 'a':       /* special authorization */
	    creds_to_authorization = strdup(gnu_optarg);
	    break; 
        case 'v':       /* print version and exit */
            fprintf(stderr, version);
            exit(1);
            break;
        default:        /* print usage and exit */ 
	    fprintf(stderr, usage);
	    exit(1);
	    break;	
        }
    }

    /* Check to see if myproxy-server specified */
    if (attrs->pshost == NULL) {
	fprintf(stderr, "Unspecified myproxy-server! Either set the MYPROXY_SERVER environment variable or explicitly set the myproxy-server via the -s flag\n");
	exit(1);
    }

#if 0
    /* Check to see if username specified */
    if (request->username == NULL) {
	fprintf(stderr, usage);
	fprintf(stderr, "Please specify a username!\n");
	exit(1);
    }
#endif

    return;
}

/* read_passphrase()
 * 
 * Reads a passphrase from stdin. The passphrase must be allocated and
 * be less than min and greater than max characters
 */
int
read_passphrase(char *passphrase, const int passlen, const int min, const int max) 
{
    int i;
    char pass[1024];
    int done = 0;
 
    assert(passphrase != NULL);
    assert(passlen < 1024);

    /* Get user's passphrase */    
    do {
        printf("Enter password to retrieve proxy on myproxy-server:\n");
        
        if (!(fgets(pass, 1024, stdin))) {
            fprintf(stderr,"Failed to read password from stdin\n");   
            return -1;
        }	
        i = strlen(pass) - 1;
        if ((i < min) || (i > max)) {
            fprintf(stderr, "Password must be between %d and %d characters\n", min, max);
        } else {
            done = 1;
        }
    } while (!done);
    
    if (pass[i] == '\n') {
        pass[i] = '\0';
    }
    strncpy(passphrase, pass, passlen);
    return 0;
}

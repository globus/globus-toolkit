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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
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
    {0, 0, 0, 0}
};

static char short_options[] = "hus:p:l:t:o:v";

static char version[] =
"myproxy-get-delegation version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

void 
init_arguments(int argc, char *argv[], 
	       myproxy_socket_attrs_t *attrs,
	       myproxy_request_t *request); 

int  read_passphrase(char *passphrase, const int passlen, 
                     const int min, const int max);

void receive_response(myproxy_socket_attrs_t *attrs, 
		      myproxy_response_t *response);

static int copy_file(const char *source,
		     const char *dest,
		     const mode_t mode);

/*
 * Use setvbuf() instead of setlinebuf() since cygwin doesn't support
 * setlinebuf().
 */
#define my_setlinebuf(stream)	setvbuf((stream), (char *) NULL, _IOLBF, 0)

/* location of delegated proxy */
char *outputfile = NULL;

int
main(int argc, char *argv[]) 
{    
    int noerr = 1;
    char *pshost;
    char request_buffer[1024];
    int  requestlen;
    char delegfile[128];

    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;

    my_setlinebuf(stdout);
    my_setlinebuf(stderr);
    
    socket_attrs = malloc(sizeof(*socket_attrs));
    memset(socket_attrs, 0, sizeof(*socket_attrs));

    client_request = malloc(sizeof(*client_request));
    memset(client_request, 0, sizeof(*client_request));

    server_response = malloc(sizeof(*server_response));
    memset(server_response, 0, sizeof(*server_response));

    /* Setup defaults */
    client_request->version = strdup(MYPROXY_VERSION);
    client_request->command_type = MYPROXY_GET_PROXY;

    pshost = getenv("MYPROXY_SERVER");
    if (pshost != NULL) {
	socket_attrs->pshost = strdup(pshost);
    }

    client_request->portal_lifetime = 60*60*MYPROXY_DEFAULT_PORTAL_HOURS;
 
    socket_attrs->psport = MYPROXY_SERVER_PORT;

    /* Initialize client arguments and create client request object */
    init_arguments(argc, argv, socket_attrs, client_request);

    /* Allow user to provide a passphrase */
    if (myproxy_read_passphrase(client_request->passphrase,
				sizeof(client_request->passphrase)) == -1)
    {
        fprintf(stderr, "Error reading passphrase\n");
        exit(1);
    }
    
    /* Set up client socket attributes */
    if (myproxy_init_client(socket_attrs) < 0) {
        fprintf(stderr, "Error: %s\n", verror_get_string());
        exit(1);
    }
    
     /* Authenticate client to server */
    if (myproxy_authenticate_init(socket_attrs, NULL) < 0) {
        fprintf(stderr, "Error: %s: %s\n", 
		socket_attrs->pshost, verror_get_string());
        exit(1);
    }

    /* Serialize client request object */
    requestlen = myproxy_serialize_request(client_request, 
                                           request_buffer, sizeof(request_buffer));
    if (requestlen < 0) {
        fprintf(stderr, "Error in myproxy_serialize_request():\n");
        exit(1);
    }

    /* Send request to the myproxy-server */
    if (myproxy_send(socket_attrs, request_buffer, requestlen) < 0) {
        fprintf(stderr, "Error in myproxy_send_request(): %s\n", 
		verror_get_string());
        exit(1);
    }

    /* Continue unless the response is not OK */
    receive_response(socket_attrs, server_response);

    /* Accept delegated credentials from client */
    if (myproxy_accept_delegation(socket_attrs, delegfile, sizeof(delegfile)) < 0) {
        fprintf(stderr, "Error in myproxy_accept_delegation(): %s\n", 
		verror_get_string());
	exit(1);
    }      

    /* Continue unless the response is not OK */
    receive_response(socket_attrs, server_response);

    /* move delegfile to outputfile if specified */
    if (outputfile != NULL) {
        if (copy_file(delegfile, outputfile, 0600) < 0) {
		fprintf(stderr, "Error creating file: %s\n",
		outputfile);
		noerr=0;
	}
	unlink(delegfile);
	strcpy(delegfile, outputfile);
	free(outputfile);
    }
    
    if (noerr) {
    	printf("A proxy has been received for user %s in %s\n", client_request->username, delegfile);
    }

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

    /* Check to see if username specified */
    if (request->username == NULL) {
	fprintf(stderr, usage);
	fprintf(stderr, "Please specify a username!\n");
	exit(1);
    }

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

void
receive_response(myproxy_socket_attrs_t *attrs, myproxy_response_t *response) {
    int responselen;
    char response_buffer[1024];

    /* Receive a response from the server */
    responselen = myproxy_recv(attrs, response_buffer, sizeof(response_buffer));
    if (responselen < 0) {
        fprintf(stderr, "Error in myproxy_recv_response():\n");
        exit(1);
    }

    /* Make a response object from the response buffer */
    if (myproxy_deserialize_response(response, response_buffer, responselen) < 0) {
      fprintf(stderr, "Error in myproxy_deserialize_response():\n");
      exit(1);
    }

    /* Check version */
    if (strcmp(response->version, MYPROXY_VERSION) != 0) {
      fprintf(stderr, "Error: Received invalid version number from server\n");
      exit(1);
    } 

    /* Check response */
    switch(response->response_type) {
        case MYPROXY_ERROR_RESPONSE:
            fprintf(stderr, "%s\n", response->error_string);
	    exit(1);
            break;
        case MYPROXY_OK_RESPONSE:
            break;
        default:
            fprintf(stderr, "Error: Received unknown response type\n");
	    exit(1);
            break;
    }
    return;
}

/*
 * copy_file()
 *
 * Copy source to destination, creating destination if necessary
 * Set permissions on destination to given mode.
 *
 * Returns 0 on success, -1 on error. 
 */
static int
copy_file(const char *source,
	  const char *dest,
	  const mode_t mode)
{
    int src_fd = -1;
    int dst_fd = -1;
    int src_flags = O_RDONLY;
    int dst_flags = O_WRONLY | O_CREAT;
    char buffer[2048];
    int bytes_read;
    int return_code = -1;
    
    assert(source != NULL);
    assert(dest != NULL);
    
    src_fd = open(source, src_flags);
    
    if (src_fd == -1)
    {
	verror_put_errno(errno);
	verror_put_string("opening %s for reading", source);
	goto error;
    }
     
    dst_fd = open(dest, dst_flags, mode);
    
    if (dst_fd == -1)
    {
	verror_put_errno(errno);
	verror_put_string("opening %s for writing", dest);
	goto error;
    }
    
    do 
    {
	bytes_read = read(src_fd, buffer, sizeof(buffer));
	
	if (bytes_read == -1)
	{
	    verror_put_errno(errno);
	    verror_put_string("reading %s", source);
	    goto error;
	}

	if (bytes_read != 0)
	{
	    if (write(dst_fd, buffer, bytes_read) == -1)
	    {
		verror_put_errno(errno);
		verror_put_string("writing %s", dest);
		goto error;
	    }
	}
    }
    while (bytes_read > 0);
    
    /* Success */
    return_code = 0;
	
  error:
    if (src_fd != -1)
    {
	close(src_fd);
    }
    
    if (dst_fd != -1)
    {
	close(dst_fd);

	if (return_code == -1)
	{
	    unlink(dest);
	}
    }
    
    return return_code;
}

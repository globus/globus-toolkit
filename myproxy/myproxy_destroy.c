/*
 * myproxy-destroy
 *
 * Client program to delete a credential on a myproxy-server
 */

#include "myproxy.h"
#include "myproxy_server.h"
#include "gnu_getopt.h"
#include "version.h"
#include "verror.h"
#include "myproxy_read_pass.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Location of default proxy */
#define MYPROXY_DEFAULT_PROXY  "/tmp/myproxy-proxy"

static char usage[] = \
"\n"\
"Syntax: myproxy-destroy [-l username] ...\n"\
"        myproxy-destroy [-usage|-help] [-v|-version]\n"\
"\n"\
"    Options\n"\
"    -h | --help                Displays usage\n"\
"    -u | --usage                             \n"\
"                                            \n"\
"    -v | --version             Displays version\n"\
"    -l | --username <username> Username for the delegated proxy\n"\
"    -s | --pshost   <hostname> Hostname of the myproxy-server\n"\
"    -p | --psport   #          Port of the myproxy-server\n"\
"\n";

struct option long_options[] =
{
    {"help",             no_argument, NULL, 'h'},
    {"pshost",     required_argument, NULL, 's'},
    {"psport",     required_argument, NULL, 'p'},
    {"usage",            no_argument, NULL, 'u'},
    {"username",   required_argument, NULL, 'l'},
    {"version",          no_argument, NULL, 'v'},
    {0, 0, 0, 0}
};

static char short_options[] = "hus:p:l:v";

static char version[] =
"myproxy-destroy version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";


/* Function declarations */
void init_arguments(int argc, char *argv[], 
                    myproxy_socket_attrs_t *attrs, myproxy_request_t *request);
int  read_passphrase(char *passphrase, const int passlen,
                     const int min, const int max);
int grid_proxy_init(int hours, const char *proxyfile);
int grid_proxy_destroy(const char *proxyfile);

int
main(int argc, char *argv[]) 
{    
    char *username, *pshost; 
    char request_buffer[1024], response_buffer[1024];
    int requestlen, responselen;
    char proxyfile[64];
    int return_status = 1;

    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;
    
    socket_attrs = malloc(sizeof(*socket_attrs));
    memset(socket_attrs, 0, sizeof(*socket_attrs));

    client_request = malloc(sizeof(*client_request));
    memset(client_request, 0, sizeof(*client_request));

    server_response = malloc(sizeof(*server_response));
    memset(server_response, 0, sizeof(*server_response));

    /* setup defaults */
    client_request->version = malloc(strlen(MYPROXY_VERSION) + 1);
    strcpy(client_request->version, MYPROXY_VERSION);
    client_request->command_type = MYPROXY_DESTROY_PROXY;

#if 0
    username = getenv("LOGNAME");
    client_request->username = strdup(username);
#endif
    
    pshost = getenv("MYPROXY_SERVER");
    if (pshost != NULL) {
        socket_attrs->pshost = strdup(pshost);
    }

    client_request->portal_lifetime = 0;
    
    socket_attrs->psport = MYPROXY_SERVER_PORT;

    /* Initialize client arguments and create client request object */
    init_arguments(argc, argv, socket_attrs, client_request);

    /* Create a proxy by running [grid-proxy-init] */
    /* A proxy is created here because the myproxy_authenticate_init() function 
       is not able to use user's long-term key if encrypted. The new proxy is 
       created even if a valid proxy is available. This breaks the single 
       sign-on principle but helps to avoid other problems with checking whether
       current proxy is valid. (Which is the right way to do that??)
    */
    sprintf(proxyfile, "%s.%u", MYPROXY_DEFAULT_PROXY, (unsigned)getpid());

    /* Run grid-proxy-init to create a proxy valid for one hour*/
    if (grid_proxy_init(1, proxyfile) != 0) { 
       fprintf(stderr, "Program grid_proxy_init failed\n");
       exit(1);
    }

    /*
     * We don't need to send the real pass phrase to the server as it
     * will just use our identity to authenticate and autorize us.
     * But we need to send over a dummy pass phrase at least
     * MIN_PASS_PHASE_LEN (currently 6) characters long.
     */
    strncpy(client_request->passphrase, "DUMMY-PASSPHRASE",
	    sizeof(client_request->passphrase));
    
    /* Set up client socket attributes */
    if (myproxy_init_client(socket_attrs) < 0) {
        fprintf(stderr, "error in myproxy_init_client(): %s\n",
		verror_get_string());
        goto end;
    }

    /* As we neither send the real passphrase nor another sensitive data we 
       can disable encryption entirely */
    GSI_SOCKET_set_encryption(socket_attrs->gsi_socket, 0);

    /* If the user didn't provide us with required username, we will try to use
       subject name from user's default certificate. */
    if (client_request->username == NULL &&
	ssl_get_base_subject_file(NULL, &client_request->username)) {
        fprintf(stderr, "Cannot get subject name from your certificate\n");
	goto end;
    }

    /* Authenticate client to server */
    if (myproxy_authenticate_init(socket_attrs, proxyfile) < 0) {
        fprintf(stderr, "error in myproxy_authenticate_init(): %s\n",
		verror_get_string());
        goto end;
    }

    /* Serialize client request object */
    requestlen = myproxy_serialize_request(client_request, 
                                           request_buffer, sizeof(request_buffer));
    
    if (requestlen < 0) {
        fprintf(stderr, "error in myproxy_serialize_request()\n");
        goto end;
    }

    /* Send request to the myproxy-server */
    if (myproxy_send(socket_attrs, request_buffer, requestlen) < 0) {
        fprintf(stderr, "error in myproxy_send_request(): %s,\n",
		verror_get_string());
        goto end;
    }

    /* Receive a response from the server */
    responselen = myproxy_recv(socket_attrs, 
                               response_buffer, sizeof(response_buffer));
    if (responselen < 0) {
        fprintf(stderr, "error in myproxy_recv_response(): %s\n",
		verror_get_string());
        goto end;
    }

    /* Make a response object from the response buffer */
    if (myproxy_deserialize_response(server_response, response_buffer, responselen) < 0) {
        fprintf(stderr, "error in myproxy_deserialize_response()\n");
        goto end;
    }

    /* Check version */
    if (strcmp(server_response->version, MYPROXY_VERSION) != 0) {
        fprintf(stderr, "Invalid version number received from server\n");
    } 

    /* Check response */
    switch(server_response->response_type) {
    case MYPROXY_ERROR_RESPONSE:
        fprintf(stderr, "Received ERROR_RESPONSE: %s\n", server_response->error_string);
        break;
    case MYPROXY_OK_RESPONSE:
        printf("proxy was succesfully destroyed for user %s.\n", client_request->username); 
        break;
    default:
        fprintf(stderr, "Invalid response type received.\n");
        break;
    }
    
    return_status = 0;
end:
    /* free memory allocated */
    myproxy_destroy(socket_attrs, client_request, server_response);

    /* Delete proxy file */
     if (grid_proxy_destroy(proxyfile) != 0) {
	fprintf(stderr, "Program grid_proxy_destroy failed\n");
	return_status = 1;
     }

    exit(return_status);
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
        case 's': 	/* pshost name */
	    attrs->pshost = strdup(gnu_optarg);
            break;
        case 'p': 	/* psport */
            attrs->psport = atoi(gnu_optarg);
            break;
        case 'u': 	/* print help and exit */
            fprintf(stderr, usage);
            exit(1);
            break;
	case 'h': 	/* print help and exit */
            fprintf(stderr, usage);
            exit(1);
            break;
        case 'l':	/* username */
	    request->username = strdup(gnu_optarg);
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
	fprintf(stderr, usage);
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
        printf("Enter password used to delete  proxy on  myproxy-server:\n");
        
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

/* grid_proxy_init()
 *
 * Uses the system() call to run grid-proxy-init to create a user proxy
 *
 * returns grid-proxy-init status 0 if OK, -1 on error
 */
int
grid_proxy_init(int hours, const char *proxyfile) {

    int rc;
    char command[128];
  
    assert(proxyfile != NULL);
    
    sprintf(command, "grid-proxy-init -hours %d -out %s", hours, proxyfile);
    rc = system(command);

    return rc;
}

/* grid_proxy_destroy()
 *
 * Uses the system() call to run grid-proxy-destroy to create a user proxy
 *
 * returns grid-proxy-destroy status 0 if OK, -1 on error
 */
int
grid_proxy_destroy(const char *proxyfile) {
  
    int rc;
    char command[128];

    assert(proxyfile != NULL);

    sprintf(command, "grid-proxy-destroy %s", proxyfile);
    rc = system(command);

    return rc;
}

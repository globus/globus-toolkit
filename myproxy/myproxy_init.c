/*
 * myproxy-init
 *
 * Client program to delegate a credential to a my-proxy-server
 */

//#include "gsi-packet.h"
//#include "myproxy-delegation.h"
//#include "myproxy-auth.h"
//#include "myproxy-gss-context.h"

#include "version.h"
/*#include "myproxy.h"*/
#include "gsi_socket.h"
#include "gnu_getopt.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <stdlib.h>



/*
static char usage_short[] = "\
Usage: %s [-help] [-s server] [-p port] [-t lifetime] [-l username] ...\n\
Try `%s --help' for more information.\n"; 
*/

#define MAX_PASS 10
#define MIN_PASS 5

#define MYPROXYSERVER_PORT 6667

static char * bad_lifetime_usage = "\nIncorrect credential lifetime specified\n";

static char * usage = \
"\n"\
"Syntax: myproxy-init [-t hh:mm:ss] [-l username] ...\n"\
"        myproxy-init [--usage|--help] [-v|--version]\n"\
"\n"\
"    Options\n"\
"    --help | --usage            Displays usage\n"\
"    -v | -version             Displays version\n"\
"    -l | -username <username> Specifies the username for the delegated proxy\n"\
"    -t | -lifetime hh:mm:ss   Specifies the lifetime of the delegated proxy\n"\
"    -s | -pshost   <hostname> Specifies the hostname of the myproxy-server\n"\
"    -p | -psport   #          Specifies the port of the myproxy-server\n"\
"\n";

struct option long_options[] =
{
  {"help",             no_argument, NULL, 'u'},
  {"pshost",   	 required_argument, NULL, 's'},
  {"psport",     required_argument, NULL, 'p'},
  {"lifetime",   required_argument, NULL, 't'},
  {"usage",            no_argument, NULL, 'u'},
  {"username",   required_argument, NULL, 'l'},
  {"version",          no_argument, NULL, 'v'},
  {0, 0, 0, 0}
};

static char short_options[] = "us:p:t:l:v";

static char version[] =
"myproxy-init version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

typedef struct
{
    int hours;
    int minutes;
    int seconds;
} delegation_lifetime_t;

typedef struct 
{
    delegation_lifetime_t deleg_lifetime;
    char *username;
    char passphrase[MAX_PASS+1];
    char *pshost;	
    int psport;
    GSI_SOCKET *gsi_socket;
    /* MESSAGE *client_message;*/
} myproxy_client_attrs_t;


main(int argc, char *argv[])
{

    int socket_fd;
    myproxy_client_attrs_t *proxy_attrs;

    proxy_attrs = malloc(sizeof(*proxy_attrs));

    if ( myproxy_init_arguments(argc, argv, proxy_attrs) < 0 ) {
	fprintf(stderr, usage);
	exit(1);
    }

    if ( myproxy_read_passphrase(proxy_attrs->passphrase) < 0 ) {
	perror("error in myproxy_read_passphrase()");
	exit(1);
    }
    
    socket_fd = myproxy_init_client(proxy_attrs);
    if (socket_fd < 0 ) {
	perror("error in myproxy_init_client()");
	exit(1);
    }

    if ( myproxy_send_message(proxy_attrs) < 0 ) {
	perror("error in myproxy_init_client()");
	exit(1);
    }
    
    close(socket_fd);

    exit(0);
}

int 
myproxy_init_arguments(int argc, char *argv[], myproxy_client_attrs_t *attrs)
{ 
    extern char *gnu_optarg;
    extern int gnu_optind;

    int arg;
    int arg_error = 0;

    char *timestr = NULL;
    attrs->username = NULL;
    attrs->psport = MYPROXYSERVER_PORT;
    attrs->pshost = NULL;
    attrs->deleg_lifetime = (delegation_lifetime_t) {72, 0, 0};

    while((arg = gnu_getopt_long(argc, argv, short_options, 
			     long_options, NULL)) != EOF) 
    {
	switch(arg) {
	    
	case 't': 	/* Specify lifetime */
	    timestr = malloc(strlen(gnu_optarg) + 1);
	    strcpy(timestr, gnu_optarg);
	    if ( get_cred_lifetime(&(attrs->deleg_lifetime), timestr) ) {
		arg_error = -1;
		fprintf(stderr, bad_lifetime_usage);
	    }	
	    break;      
	case 's': 	/* pshost name */
	    attrs->pshost = malloc(strlen(gnu_optarg) + 1);
	    strcpy(attrs->pshost, gnu_optarg); 
	    break;
	case 'p': 	/* psport */
	    attrs->psport = atoi(gnu_optarg);
	    break;
	case 'u': 	/* print help and exit */
	    fprintf(stderr, usage);
	    exit(1);
	    break;
	case 'l':	/* username */
	    attrs->username = malloc(strlen(gnu_optarg) + 1);
	    strcpy(attrs->username, gnu_optarg); 
	    break;
	case 'v': /* print version and exit */
	    fprintf(stderr, version);
	    exit(1);
	    break;
        default: /* ignore unknown */ 
	    arg_error = -1;
	    break;	
        }
    }

    /* Make sure username and myproxy-server host is specified */
    if ( (attrs->username == NULL) || (attrs->pshost == NULL) )
	arg_error = -1;

    return arg_error;
}

int
myproxy_read_passphrase(char *passphrase) 
{
    int i;
    char pass[MAX_PASS];
    int done = 0;
    
    do {
	printf("Enter pass phrase:\n");
	if (!(fgets(pass, sizeof(pass), stdin))) {
	    fprintf(stderr,"Failed to read pass-phrase from stdin\n");                      	return -1;
	}	
	i = strlen(pass)-1;
	if ((i < MIN_PASS) || (i > MAX_PASS)) { 
	    printf("Pass-phrase must be between 5 and 10 characters\n");
	} else {
	    done = 1;
	}
    } while ( !done );

    if (pass[i-1] == '\n') {
	pass[i-1] = '\0';
    }
    strncpy(passphrase, pass, MAX_PASS);
    return 0;
}
    
/*
 * Returns -1 if failure or socket fd on success
 */
int 
myproxy_init_client(myproxy_client_attrs_t *attrs)
{
    int sock;
    char error_string[1024]; 
    struct sockaddr_in sin;
    struct hostent *host_info;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock == -1)
    {
        perror("socket");
        return -1;
    } 

    host_info = gethostbyname(attrs->pshost); 

    if (host_info == NULL)
    {
        fprintf(stderr, "Unknown host \"%s\"\n", attrs->pshost);
        return -1;
    } 

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    memcpy(&(sin.sin_addr), host_info->h_addr, sizeof(sin.sin_addr));
    sin.sin_port = htons(attrs->psport);

    if (connect(sock, (struct sockaddr *) &sin, sizeof(sin)) < 0)
    {
        perror("connect");
        return -1;
    }

    attrs->gsi_socket = GSI_SOCKET_new(sock);
    
    if (attrs->gsi_socket == NULL)
    {
	perror("GSI_SOCKET_new()");
	return -1;
    }

    if (GSI_SOCKET_authentication_init(attrs->gsi_socket) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error authenticating: %s\n", error_string);
	return -1;
    }
    return sock;
}

/** The following protocol is used **
     
    VERSION=0.1
    COMMAND=PUT_PROXY
    USERNAME=<username>
    PASSPHRASE=<pass phrase>
    LIFETIME=<lifetime>
  
*/
int 
myproxy_send_message(myproxy_client_attrs_t *attrs) {

/*
    myproxy_transfer *message;
    message = myproxy_transfer_new();
*/
    int len;
    int tot_seconds;
    char error_string[1024]; 
    char request[1024];
    char response[1024];
    char versionstr[128];
    char commstr[128];
    char userstr[128];
    char passstr[128];
    char lifestr[128];
    
    char * version_str = "VERSION=";
    char * command_str = "COMMAND=";
    char * user_str = "USERNAME=";
    char * pass_str = "PASSPHRASE=";
    char * life_str = "LIFETIME=";


    tot_seconds = attrs->deleg_lifetime.seconds + 
	          60*(attrs->deleg_lifetime.minutes + 
		      60*attrs->deleg_lifetime.hours);
    snprintf(versionstr, sizeof(versionstr), "%s%s", version_str, version);
    snprintf(commstr, sizeof(commstr), "%s%s", command_str, "PUT_PROXY");
    snprintf(userstr, sizeof(userstr), "%s%s", user_str, attrs->username);
    snprintf(passstr, sizeof(passstr), "%s%s", pass_str, attrs->passphrase);
    snprintf(lifestr, sizeof(lifestr), "%s%d", life_str, tot_seconds);
 
    len = snprintf(request, sizeof(request), "%s\n%s\n%s\n%s\n", 
		   versionstr, 
		   commstr, 
		   passstr, 
		   lifestr) + 1; /* NUL */

    /* MESSAGE *client_message = MESSAGE_new();*/
    

    if (GSI_SOCKET_write_buffer(attrs->gsi_socket, request, len) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error writing: %s\n", error_string);
	return -1;
    }

   if (GSI_SOCKET_read_buffer(attrs->gsi_socket, response,
			       sizeof(response)) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
				    sizeof(error_string));
	fprintf(stderr, "Error reading: %s\n", error_string);
	return -1;
    }

    printf("Server message: %s\n", response);

    GSI_SOCKET_destroy(attrs->gsi_socket);
    
    return 0;
    
}


/** Returns 0 if timestr is valid */
int 
get_cred_lifetime(delegation_lifetime_t *proxy_lifetime, char *timestr)
{  
    int arg_error = 0;
    char *ptr = timestr;
    char *hours, *minutes, *seconds;

    /* Check hours */
    if ( (ptr = strtok(timestr, ":") ) != NULL) {
	proxy_lifetime->hours = atoi( ptr );
    } else {
 	arg_error = 1;
    }
    
    /* Check minutes */
    if ( (ptr = strtok(NULL, ":") ) != NULL) {
	proxy_lifetime->minutes = atoi( ptr );
	
	if (proxy_lifetime->minutes > 60) 
	    arg_error = 1;
    }  else {
 	arg_error = 1;
    }

    /* Check seconds */
    if ( (ptr = strtok(NULL, ":") ) != NULL) {
	proxy_lifetime->seconds = atoi( ptr );
	
	if (proxy_lifetime->seconds > 60) 
	    arg_error = 1;
    }  else {
 	arg_error = 1;
    }

    return arg_error;
}


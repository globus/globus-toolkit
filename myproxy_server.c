/*
 * myproxy-server
 *
 * program to store user's delegated credentials for use in a portal
 */

#include "myproxy.h"
#include "myproxy_server.h"
#include "myproxy_creds.h"
#include "gnu_getopt.h"
#include "version.h"
#include "verror.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h> 
#include <errno.h>
#include <assert.h>

static char usage[] = \
"\n"\
"Syntax: myproxy-server [-p port#] [-c config-file] ...\n"\
"        myproxy-server [--usage|--help] [-v|--version]\n"\
"\n"\
"    Options\n"\
"    --help | --usage        Displays usage\n"\
"    -v | -version           Displays version\n"\
"    -c | -config            Specifies configuration file to use\n"\
"    -p | -port   #          Specifies the port to run on\n"\
"\n";

struct option long_options[] =
{
  {"help",             no_argument, NULL, 'u'},
  {"port",       required_argument, NULL, 'p'},
  {"config",           no_argument, NULL, 'c'},       
  {"usage",            no_argument, NULL, 'u'},
  {"version",          no_argument, NULL, 'v'},
  {0, 0, 0, 0}
};

static char short_options[] = "uc:p:v";

static char version[] =
"myproxy-server version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

/* Function declarations */
int init_arguments(int argc, 
                   char *argv[], 
                   myproxy_socket_attrs_t *server_attrs, 
                   myproxy_server_context_t *server_context);

int handle_client(myproxy_socket_attrs_t *server_attrs, 
                  myproxy_server_context_t *server_context);

int get_proxy(myproxy_creds_t *creds, myproxy_response_t *response);

int put_proxy(myproxy_creds_t *creds, myproxy_response_t *response);

int info_proxy(myproxy_creds_t *creds, myproxy_response_t *response);

int destroy_proxy(myproxy_creds_t *creds, myproxy_response_t *response);


/* Signal handling */
typedef void Sigfunc(int);  

Sigfunc *my_signal(int signo, Sigfunc *func);
void sig_exit(int signo);
void sig_chld(int signo); 


int
main(int argc, char *argv[]) 
{    
    int   listenfd;
    pid_t childpid;  

    myproxy_socket_attrs_t         *socket_attrs;
    myproxy_server_context_t       *server_context;
  
    socket_attrs    = malloc(sizeof(*socket_attrs));
    server_context  = malloc(sizeof(*server_context));

    if (init_arguments(argc, argv, socket_attrs, server_context) < 0) {
        fprintf(stderr, usage);
        exit(1);
    }

    /* Read my configuration */
    if (myproxy_server_config_read(server_context) == -1)
    {
	fprintf(stderr, "%s\n", verror_get_string());
	exit(1);
    }
    
    /* Set up server socket attributes */
    listenfd = myproxy_init_server(socket_attrs, MYPROXYSERVER_PORT);
    if (listenfd < 0) {
        fprintf(stderr, "error in myproxy_init_server()\n");
        exit(1);
    }

    /* Set up signal handling to deal with zombie processes left over  */
    my_signal(SIGCHLD, sig_chld);
    
    /* If process is killed or Ctrl-C */
    my_signal(SIGTERM, sig_exit); 
    my_signal(SIGINT,  sig_exit); 

    /* Set up concurrent server */
    while (1) {
        socket_attrs->socket_fd = accept(listenfd, NULL, NULL);
        if (socket_attrs->socket_fd < 0) {
          if (errno == EINTR) {
            continue; 
          } else {
            perror("Error in accept\n");
            exit(1);
          }
        }
        childpid = fork();
        
        if (childpid < 0) {              /* check for error */
            perror("Error in fork\n");
            exit(1);
        } else if (childpid == 0) {      /* child process */
          close(listenfd);
          if (handle_client(socket_attrs, server_context) < 0) {
             fprintf(stderr, "error in handle_client()\n");
             exit(1);
          } 
          exit(0);
        }
        close(socket_attrs->socket_fd);  /* parent closes connected socket */
    }
    exit(0);
}

int
handle_client(myproxy_socket_attrs_t *attrs, myproxy_server_context_t *context) 
{
    int   rc, is_err;
    char  error_string[1024];
    char  client_name[1024];
    char  client_buffer[1024], server_buffer[1024];
    int   requestlen, responselen;
    char  delegfile[64];

    myproxy_creds_t *client_creds;          
    myproxy_request_t *client_request;
    myproxy_response_t *server_response;

    client_creds    = malloc(sizeof(*client_creds));
    client_request  = malloc(sizeof(*client_request));
    server_response = malloc(sizeof(*server_response));

    /* Set version in response message */
    server_response->version = malloc(strlen(MYPROXY_VERSION) + 1);
    strcpy(server_response->version, MYPROXY_VERSION);   

    /* Create a new gsi socket */
    attrs->gsi_socket = GSI_SOCKET_new(attrs->socket_fd);
    if (attrs->gsi_socket == NULL) {
        perror("GSI_SOCKET_new()\n");
        return -1;
    }

    /* Authenticate server to client and get DN of client */
    if (myproxy_authenticate_accept(attrs, client_name, sizeof(client_name)) < 0) {
        fprintf(stderr, "error in myproxy_authenticate_accept()\n");
        exit(1);
    }

    /* Accept delegated credentials from client */
    if (myproxy_accept_delegation(attrs, delegfile, sizeof(delegfile)) < 0) {
        fprintf(stderr, "error in myproxy_accept_delegation()\n");
        exit(1);
    }
    
    /* Receive client request */
    requestlen = myproxy_recv(attrs, client_buffer, sizeof(client_buffer));
    if (requestlen < 0) {
        fprintf(stderr, "error in myproxy_recv_response()\n");
        exit(1);
    }

    /* Deserialize client request */
    if (myproxy_deserialize_request(client_buffer, requestlen, 
                                    client_request) < 0) {
        fprintf(stderr, "error in myproxy_deserialize_request()\n");
        exit(1);
    }

    /* Check client version */
    if (strcmp(client_request->version, MYPROXY_VERSION) != 0) {
        strcat(error_string, "Invalid version number received.\n");
        is_err = 1;
    }

    /* Fill in credential structure = owner, user, passphrase, proxy location */
    client_creds->owner_name = malloc(strlen(client_name) + 1);
    strcpy(client_creds->owner_name, client_name);
    client_creds->user_name = malloc(strlen(client_request->username) + 1);
    strcpy(client_creds->user_name, client_request->username);
    client_creds->pass_phrase = malloc(strlen(client_request->passphrase) + 1);
    strcpy(client_creds->pass_phrase, client_request->passphrase);
    client_creds->location = malloc(strlen(delegfile) + 1);
    strcpy(client_creds->location, delegfile);
    
    /* Handle client request */
    switch (client_request->command_type) {
    case MYPROXY_GET_PROXY:
        /* add lifetime (s) = client_request->hours * 60 minutes/hour * 60 minutes/sec */
        client_creds->lifetime = 60*60*client_request->hours; 
        rc = get_proxy(client_creds, server_response);
        if (rc < 0) 
          is_err = 1;
        break;
    case MYPROXY_PUT_PROXY:
        /* add lifetime (s) = client_request->hours * 60 minutes/hour * 60 minutes/sec */
        client_creds->lifetime = 60*60*client_request->hours; 
        rc = put_proxy(client_creds, server_response);
        if (rc < 0)
          is_err = 1;
        break;
    case MYPROXY_INFO_PROXY:
        rc = info_proxy(client_creds, server_response);
        if (rc < 0)
          is_err = 1;
        break;
    case MYPROXY_DESTROY_PROXY:
        rc = destroy_proxy(client_creds, server_response);
        if (rc < 0)
          is_err = 1;
        break;
    default:
        strcat(error_string, "Invalid client request command.\n");
        is_err = 1;
        break;
    }
    
    /* Set version */
    server_response->version = malloc(strlen(MYPROXY_VERSION) + 1);
    sprintf(server_response->version, "%s", MYPROXY_VERSION);

    responselen = myproxy_serialize_response(server_response, 
                                         server_buffer, sizeof(server_buffer));
    
    if (responselen < 0) {
	    fprintf(stderr, "error in myproxy_serialize_response()\n");
        return -1;
    }

    if (myproxy_send(attrs, server_buffer, responselen) < 0) {
	    fprintf(stderr, "error in myproxy_send()\n");
        return -1;
    } 
  
    myproxy_destroy(attrs, client_request, server_response);

    if (context->config_file != NULL) {
      free(context->config_file);
      context->config_file = NULL;
    }

    free(context);

    return 0;
}

int 
init_arguments(int argc, char *argv[], 
               myproxy_socket_attrs_t *attrs, 
               myproxy_server_context_t *context) 
{   
    extern char *gnu_optarg;
    extern int gnu_optind;

    int arg;
    int arg_error = 0;

    while((arg = getopt_long(argc, argv, short_options, 
			     long_options, NULL)) != EOF) 
    {
	switch(arg) 
	{
	case 'p': 	/* port */
	    attrs->psport = atoi(gnu_optarg);
	    break;
	case 'u': 	/* print help and exit */
	    fprintf(stderr, usage);
	    exit(1);
	    break;
	case 'c':
        context->config_file =  malloc(strlen(gnu_optarg) + 1);
        strcpy(context->config_file, gnu_optarg);   
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

    return arg_error;
}

int get_proxy(myproxy_creds_t *creds, myproxy_response_t *response) {
    if (myproxy_creds_retrieve(creds->user_name, creds) < 0) {
        response->response_type =  MYPROXY_ERROR_RESPONSE; 
        strcat(response->error_string, "Unable to retrieve credentials\n"); 
    }
    response->response_type = MYPROXY_OK_RESPONSE;
    return 0;
}

int put_proxy(myproxy_creds_t *creds, myproxy_response_t *response) {
    if (myproxy_creds_store(creds) < 0) {
        response->response_type =  MYPROXY_ERROR_RESPONSE; 
        strcat(response->error_string, "Unable to store credentials\n"); 
    }
    response->response_type = MYPROXY_OK_RESPONSE;
    return 0;
}

int info_proxy(myproxy_creds_t *creds, myproxy_response_t *response) {
    response->response_type = MYPROXY_OK_RESPONSE;
    return 0;
}

int destroy_proxy(myproxy_creds_t *creds, myproxy_response_t *response) {
  myproxy_creds_delete(creds->user_name);  
    response->response_type = MYPROXY_OK_RESPONSE;
    return 0;
}

/*
 * my_signal
 *
 * installs a signal handler, and returns the old handler.
 * This emulates the semi-standard signal() function in a
 * standard way using the Posix sigaction function.
 *
 * from Stevens, 1998, section 5.8
 */
Sigfunc *my_signal(int signo, Sigfunc *func)
{
    struct sigaction new_action, old_action;

    assert(func != NULL);

    new_action.sa_handler = func;
    sigemptyset( &new_action.sa_mask );
    new_action.sa_flags = 0;

    if (signo == SIGALRM) {
#ifdef SA_INTERRUPT
        new_action.sa_flags |= SA_INTERRUPT;  /* SunOS 4.x */
#endif
    }
    else { 
#ifdef SA_RESTART
        new_action.sa_flags |= SA_RESTART;    /* SVR4, 4.4BSD */
#endif
    }

    if (sigaction(signo, &new_action, &old_action) < 0) {
        return SIG_ERR;
    }
    else {
        return old_action.sa_handler;
    }
} 

void
sig_chld(int signo) {
    pid_t pid;
    int   stat;

    while ( (pid = waitpid(-1, &stat, WNOHANG)) > 0)
      printf("child %d terminated\n", pid);
    return;
} 

void sig_exit(int signo) {
    fprintf(stderr, "Server killed\n");
    exit(0);
}

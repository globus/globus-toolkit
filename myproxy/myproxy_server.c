/*
 * myproxy-server
 *
 * program to store user's delegated credentials for use in a portal
 */

#include "myproxy.h"
#include "myproxy_server.h"
#include "myproxy_creds.h"
#include "myproxy_log.h"
#include "gnu_getopt.h"
#include "version.h"
#include "verror.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h> 
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h> 
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h> 
#include <errno.h>
#include <assert.h>
#include <string.h>

static char usage[] = \
"\n"\
"Syntax: myproxy-server [-d|--debug] [-p|--port #] [-c config-file] ...\n"\
"        myproxy-server [-h|--help] [-v|--version]\n"\
"\n"\
"    Options\n"\
"    -h | --help                Displays usage\n"\
"    -v | --version             Displays version\n"\
"    -d | --debug               Turns on debugging\n"\
"    -c | --config              Specifies configuration file to use\n"\
"    -p | --port <portnumber>   Specifies the port to run on\n"\
"\n";

struct option long_options[] =
{
    {"debug",            no_argument, NULL, 'd'},
    {"help",             no_argument, NULL, 'h'},
    {"port",       required_argument, NULL, 'p'},
    {"config",     required_argument, NULL, 'c'},       
    {"usage",            no_argument, NULL, 'u'},
    {"version",          no_argument, NULL, 'v'},
    {0, 0, 0, 0}
};

static char short_options[] = "dhc:p:vu";

static char version[] =
"myproxy-server version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

/* Signal handling */
typedef void Sigfunc(int);  

Sigfunc *my_signal(int signo, Sigfunc *func);
void sig_exit(int signo);
void sig_chld(int signo);
void sig_ign(int signo);

/* Function declarations */
int init_arguments(int argc, 
                   char *argv[], 
                   myproxy_socket_attrs_t *server_attrs, 
                   myproxy_server_context_t *server_context);

int myproxy_init_server(myproxy_socket_attrs_t *server_attrs, int port_number);

int handle_client(myproxy_socket_attrs_t *server_attrs, 
                  myproxy_server_context_t *server_context);

void respond_with_error_and_die(myproxy_socket_attrs_t *attrs,
				const char *error);

void send_response(myproxy_socket_attrs_t *server_attrs, 
		   myproxy_response_t *response, 
		   char *client_name);

void get_proxy(myproxy_socket_attrs_t *server_attrs, 
	      myproxy_creds_t *creds, 
	      myproxy_response_t *response);

void put_proxy(myproxy_socket_attrs_t *server_attrs, 
	      myproxy_creds_t *creds, 
	      myproxy_response_t *response);

void info_proxy(myproxy_creds_t *creds, myproxy_response_t *response);

void destroy_proxy(myproxy_creds_t *creds, myproxy_response_t *response);

static void failure(const char *failure_message); 

static void my_failure(const char *failure_message);

static char *timestamp(void);

static int become_daemon(myproxy_server_context_t *server_context);

static int debug = 0;

static int numclients = 0;

int
main(int argc, char *argv[]) 
{    
    int   fd, listenfd;
    pid_t childpid;  

    myproxy_socket_attrs_t         *socket_attrs;
    myproxy_server_context_t       *server_context;
  
    socket_attrs    = malloc(sizeof(*socket_attrs));
    memset(socket_attrs, 0, sizeof(*socket_attrs));

    server_context  = malloc(sizeof(*server_context));
    memset(server_context, 0, sizeof(*server_context));

    /* Set context defaults */
    server_context->run_as_daemon = 1;
    server_context->config_file = MYPROXY_SERVER_DIR "/myproxy-server.config";
    
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

    if (server_context->run_as_daemon)
    {
	if (become_daemon(server_context) < 0) {
	    fprintf(stderr, "Error starting daemon\n");
	    exit(1);
	}
    }

    /* Initialize Logging */
    if (debug) {
	myproxy_debug_set_level(1);
        myproxy_log_use_stream(stderr);
    }
    else
    {
	myproxy_log_use_syslog(LOG_DAEMON, server_context->my_name);
    }

    /*
     * Logging initialized: For here on use myproxy_log functions
     * instead of fprintf() and ilk.
     */

    myproxy_log("starting at %s", timestamp());

    /* Set up signal handling to deal with zombie processes left over  */
    my_signal(SIGCHLD, sig_chld);
    
    /* If process is killed or Ctrl-C */
    my_signal(SIGTERM, sig_exit); 
    my_signal(SIGINT,  sig_exit); 

    /* Set up server socket attributes */
    listenfd = myproxy_init_server(socket_attrs, MYPROXYSERVER_PORT);

    /* Set up concurrent server */
    while (1) {
	struct sockaddr_in client_addr;
	int client_addr_len = sizeof(client_addr);
	
        socket_attrs->socket_fd = accept(listenfd,
					 (struct sockaddr *) &client_addr,
					 &client_addr_len);

        if (socket_attrs->socket_fd < 0) {
            if (errno == EINTR) {
                continue; 
            } else {
                myproxy_log_perror("Error in accept()");
            }
        }

	myproxy_log("Connection from %s", inet_ntoa(client_addr.sin_addr));
	
	if (!debug)
	{
	    childpid = fork();
        
	    if (childpid < 0) {              /* check for error */
		myproxy_log_perror("Error in fork");
		close(socket_attrs->socket_fd);
	    }
	    else if (childpid != 0)
	    {
		/* Parent */

		/* parent closes connected socket */
		close(socket_attrs->socket_fd);

		continue;	/* while(1) */
	    }

	    /* child process */
	    fd = open("/dev/tty",O_RDWR);
	    if (fd >= 0) {
		ioctl(fd, TIOCNOTTY, 0);
		close(fd);
	    }
	    fclose(stdin);
	    close(0);
	    close(listenfd);
	}
	numclients++;
	myproxy_log("Client has connected, total clients=%d", numclients);
	if (handle_client(socket_attrs, server_context) < 0) {
	    my_failure("error in handle_client()");
	} 
	_exit(0);
    }
    exit(0);
}

int
handle_client(myproxy_socket_attrs_t *attrs, myproxy_server_context_t *context) 
{
    char  error_string[1024];
    char  client_name[1024];
    char  client_buffer[1024], server_buffer[1024];
    int   requestlen, responselen;
    int   authorization_ok = 0;
    int   rc;
    
    myproxy_creds_t *client_creds;          
    myproxy_request_t *client_request;
    myproxy_response_t *server_response;

    client_creds    = malloc(sizeof(*client_creds));
    memset(client_creds, 0, sizeof(*client_creds));

    client_request  = malloc(sizeof(*client_request));
    memset(client_request, 0, sizeof(*client_request));

    server_response = malloc(sizeof(*server_response));
    memset(server_response, 0, sizeof(*server_response));
    /* Set response OK unless error... */
    server_response->response_type =  MYPROXY_OK_RESPONSE;
 
    /* Create a new gsi socket */
    attrs->gsi_socket = GSI_SOCKET_new(attrs->socket_fd);
    if (attrs->gsi_socket == NULL) {
        myproxy_log_perror("GSI_SOCKET_new()");
        return -1;
    }

    if (GSI_SOCKET_set_encryption(attrs->gsi_socket, 1) == GSI_SOCKET_ERROR)
    {
	GSI_SOCKET_get_error_string(attrs->gsi_socket, error_string,
                                   sizeof(error_string));
	myproxy_log("Error enabling encryption: %s\n", error_string);
	return -1;
    }

    /* Authenticate server to client and get DN of client */
    if (myproxy_authenticate_accept(attrs, client_name, sizeof(client_name)) < 0) {
	/* Client_name may not be set on error so don't use it. */
	respond_with_error_and_die(attrs, "authentication failed");
    }

    /* Log client name */
    myproxy_log("Authenticated client %s", client_name); 
    
    /* Receive client request */
    requestlen = myproxy_recv(attrs, client_buffer, sizeof(client_buffer));
    if (requestlen < 0) {
	respond_with_error_and_die(attrs, "Error in myproxy_recv_response()");
    }

    /* Log client request */
    myproxy_log("Received client %s buffer %s", client_name, client_buffer); 
   
    /* Deserialize client request */
    if (myproxy_deserialize_request(client_buffer, requestlen, 
                                    client_request) < 0) {
        respond_with_error_and_die(attrs,
				   "error in myproxy_deserialize_request()");
    }

    /* Check client version */
    if (strcmp(client_request->version, MYPROXY_VERSION) != 0) {
	myproxy_log("client %s Invalid version number (%s) received",
		    client_name, client_request->version);
        respond_with_error_and_die(attrs,
				   "Invalid version number received.\n");
    }

    /* Fill in credential structure = owner, user, passphrase, proxy location */
    client_creds->owner_name = malloc(strlen(client_name) + 1);
    strcpy(client_creds->owner_name, client_name);
    client_creds->user_name = malloc(strlen(client_request->username) + 1);
    strcpy(client_creds->user_name, client_request->username);
    client_creds->pass_phrase = malloc(strlen(client_request->passphrase) + 1);
    strcpy(client_creds->pass_phrase, client_request->passphrase);

    /* Check authorization for request */
    switch (client_request->command_type)	
    {	
      case MYPROXY_GET_PROXY:
	/* Only servers are allowed to retrieve proxies */
	authorization_ok = myproxy_server_check_service(context,
							client_name);
	break;
	
      case MYPROXY_PUT_PROXY:
      case MYPROXY_INFO_PROXY:
      case MYPROXY_DESTROY_PROXY:
	/* Either a service or a client can do these operations */
	authorization_ok = myproxy_server_check_client(context, client_name);
	
	if (authorization_ok != 1)
	{
	    authorization_ok = myproxy_server_check_service(context,
							    client_name);
	}
	break;
    }

    if (authorization_ok == -1)
    {
	myproxy_log_verror();
	respond_with_error_and_die(attrs, "Error checking authorization");
    }
    
    if (authorization_ok != 1)
    {
	respond_with_error_and_die(attrs, "Authorization failed");
    }

    /* Handle client request */
    switch (client_request->command_type) {
    case MYPROXY_GET_PROXY:
	/* return server response */
	send_response(attrs, server_response, client_name);

        /* add lifetime (s) = client_request->hours * 60 minutes/hour * 60 minutes/sec */
        client_creds->lifetime = 60*60*client_request->hours; 
        get_proxy(attrs, client_creds, server_response);
        break;
    case MYPROXY_PUT_PROXY:
	/* return server response */
	send_response(attrs, server_response, client_name);

        /* add lifetime (s) = client_request->hours * 60 minutes/hour * 60 minutes/sec */
        client_creds->lifetime = 60*60*client_request->hours; 
        put_proxy(attrs, client_creds, server_response);
        break;
    case MYPROXY_INFO_PROXY:
        info_proxy(client_creds, server_response);
        break;
    case MYPROXY_DESTROY_PROXY:
        destroy_proxy(client_creds, server_response);
        break;
    default:
        strcat(server_response->error_string, "Invalid client request command.\n");
        break;
    }
    
    /* return server response */
    send_response(attrs, server_response, client_name);
  
    myproxy_destroy(attrs, client_request, server_response);

    /* Log request */
    numclients--;
    myproxy_log("Client %s disconnected total clients=%d", client_name, numclients);
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

    char *last_directory_seperator;
    char directory_seperator = '/';
    
    /* Get my name, removing any preceding path */
    last_directory_seperator = strrchr(argv[0], directory_seperator);
    
    if (last_directory_seperator == NULL)
    {
	context->my_name = strdup(argv[0]);
    }
    else
    {
	context->my_name = strdup(last_directory_seperator + 1);
    }
    
    while((arg = gnu_getopt_long(argc, argv, short_options, 
			     long_options, NULL)) != EOF) 
    {
        switch(arg) 
        {
        case 'p': 	/* port */
            attrs->psport = atoi(gnu_optarg);
            break;
        case 'h': 	/* print help and exit */
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
	case 'u': /* print version and exit */
            fprintf(stderr, usage);
            exit(1);
            break;
        case 'd':
            debug = 1;
	    context->run_as_daemon = 0;
            break;
        default: /* ignore unknown */ 
            arg_error = -1;
            break;	
        }
    }

    return arg_error;
}

/*
 * myproxy_init_server()
 *
 * Create a generic server socket ready on the given port ready to accept.
 *
 * returns the listener fd on success 
 */
int 
myproxy_init_server(myproxy_socket_attrs_t *attrs, int port_number) 
{
    int on = 1;
    int listen_sock;
    struct sockaddr_in sin;

    /* Could do something smarter to get FQDN */
    attrs->pshost = malloc(strlen("localhost")+1);
    strcpy(attrs->pshost, "localhost");
    attrs->psport = port_number;
    
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);

    if (listen_sock == -1) {
        failure("Error in socket()");
    } 

    /* Allow reuse of socket */
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(attrs->psport);

    if (bind(listen_sock, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
	    failure("Error in bind()");
    }
    if (listen(listen_sock, 5) < 0) {
	    failure("Error in listen()");
    }
    return listen_sock;
}

void
respond_with_error_and_die(myproxy_socket_attrs_t *attrs,
			   const char *error)
{
    myproxy_response_t		response;
    int				responselen;
    char			response_buffer[2048];
    

    response.version = strdup(MYPROXY_VERSION);
    response.response_type = MYPROXY_ERROR_RESPONSE;
    snprintf(response.error_string, sizeof(response.error_string),
	     "%s", error);
    
    responselen = myproxy_serialize_response(&response,
					     response_buffer,
					     sizeof(response_buffer));
    
    if (responselen < 0) {
        my_failure("error in myproxy_serialize_response()");
    }

    if (myproxy_send(attrs, response_buffer, responselen) < 0) {
        my_failure("error in myproxy_send()\n");
    } 

    myproxy_log("ERROR: %s. Exiting", error);
    
    exit(1);
}

void send_response(myproxy_socket_attrs_t *attrs, myproxy_response_t *response, char *client_name) {
    char server_buffer[1024];
    int responselen;
    assert(response != NULL);

    /* set version */
    response->version = malloc(strlen(MYPROXY_VERSION) + 1);
    sprintf(response->version, "%s", MYPROXY_VERSION);

    responselen = myproxy_serialize_response(response, server_buffer, sizeof(server_buffer));
    
    if (responselen < 0) {
        my_failure("error in myproxy_serialize_response()");
    }

    /* Log request */
    myproxy_log("Send client %s server response %s", client_name, server_buffer);
 
    if (myproxy_send(attrs, server_buffer, responselen) < 0) {
        my_failure("error in myproxy_send()\n");
    } 

    return;
}

void get_proxy(myproxy_socket_attrs_t *attrs, 
	       myproxy_creds_t *creds, 
	       myproxy_response_t *response) 
{
    myproxy_debug("Retrieving credentials for username \"%s\"",
		  creds->user_name);
    
    /* Retrieve credentials */
    if (myproxy_creds_retrieve(creds) < 0) {
        response->response_type =  MYPROXY_ERROR_RESPONSE; 
        strcat(response->error_string, "Unable to retrieve credentials.\n");
	return;
    }
 
    myproxy_debug("  Owner is \"%s\"", creds->owner_name);
    myproxy_debug("  Location is %s", creds->location);
    myproxy_debug("  Lifetime is %d seconds", creds->lifetime);
    
    /* Delegate credentials to client */
    if (myproxy_init_delegation(attrs, creds->location, creds->lifetime) < 0) {
        response->response_type =  MYPROXY_ERROR_RESPONSE; 
	strcat(response->error_string, "Unable to delegate credentials.\n");
	myproxy_log("Unable to delegate credentials for %s", creds->owner_name);
    } else {
        myproxy_log("Delegating credentials for %s", creds->owner_name);
	response->response_type = MYPROXY_OK_RESPONSE;
    }
  
}

void put_proxy(myproxy_socket_attrs_t *attrs, 
	      myproxy_creds_t *creds, 
	      myproxy_response_t *response) 
{
    char delegfile[64];

    myproxy_debug("Storing credentials for username \"%s\"", creds->user_name);
    myproxy_debug("  Owner is \"%s\"", creds->owner_name);
    myproxy_debug("  Delegation lifetime is %d seconds", creds->lifetime);
    
    /* Accept delegated credentials from client */
    if (myproxy_accept_delegation(attrs, delegfile, sizeof(delegfile)) < 0) {
	myproxy_log("error in myproxy_accept_delegation()");
        exit(1);
    }
    myproxy_debug("  Accepted delegation: %s", delegfile);
 
    creds->location = malloc(strlen(delegfile) + 1);
    strcpy(creds->location, delegfile);

    if (myproxy_creds_store(creds) < 0) {
	myproxy_log_verror();
        response->response_type =  MYPROXY_ERROR_RESPONSE; 
        strcat(response->error_string, "Unable to store credentials.\n"); 
    } else {
	response->response_type = MYPROXY_OK_RESPONSE;
    }

    /* Clean up temporary delegation */
    if (unlink(delegfile) != 0)
    {
	myproxy_log_perror("Removal of temporary credentials file %s failed",
			   delegfile);
    }
}

void info_proxy(myproxy_creds_t *creds, myproxy_response_t *response) {
    response->response_type = MYPROXY_OK_RESPONSE;
}

void destroy_proxy(myproxy_creds_t *creds, myproxy_response_t *response) {
    myproxy_creds_delete(creds);  
    response->response_type = MYPROXY_OK_RESPONSE;
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
        myproxy_debug("child %d terminated", pid);
    return;
} 

void sig_exit(int signo) {
    myproxy_log("Server killed by signal %d", signo);
    exit(0);
}


static void
failure(const char *failure_message) {
    myproxy_log_perror("Failure: %s", failure_message);
    exit(1);
} 

static void
my_failure(const char *failure_message) {
    myproxy_log("Failure: %s", failure_message);       
    exit(1);
} 

static char *
timestamp(void)
{
    time_t clock;
    struct tm *tmp;

    time(&clock);
    tmp = (struct tm *)localtime(&clock);
    return (char *)asctime(tmp);
}

static int
become_daemon(myproxy_server_context_t *context)
{
    pid_t childpid;
    int fd, fdlimit;
    
    /* Steps taken from UNIX Programming FAQ */
    
    /* 1. Fork off a child so the new process is not a process group leader */
    childpid = fork();
    switch (childpid) {
    case 0:         /* child */
      break;
    case -1:        /* error */
      perror("Error in fork()");
      return -1;
    default:        /* exit the original process */
      _exit(0);
    }

    /* 2. Set session id to become a process group and session group leader */
    if (setsid() < 0) { 
        perror("Error in setsid()"); 
	return -1;
    } 

    /* 3. Fork again so the parent, (the session group leader), can exit.
          This means that we, as a non-session group leader, can never 
          regain a controlling terminal. 
    */
    signal(SIGHUP, SIG_IGN);
    childpid = fork();
    switch (childpid) {
    case 0:             /* child */
	break;
    case -1:            /* error */
	perror("Error in fork()");
	return -1;
    default:            /* exit the original process */
	_exit(0);
    }
	
   
    
    /* 4. `chdir("/")' to ensure that our process doesn't keep any directory in use */
    chdir("/");

    /* 5. `umask(0)' so that we have complete control over the permissions of 
          anything we write
    */
    umask(0);

    /* 6. Close all file descriptors */
    fdlimit = sysconf(_SC_OPEN_MAX);
    while (fd < fdlimit)
      close(fd++);

    /* 7.Establish new open descriptors for stdin, stdout and stderr */    
    (void)open("/dev/null", O_RDWR);
    dup(0); 
    dup(0);
    fd = open("/dev/tty", O_RDWR);
    if (fd >= 0) {
      ioctl(fd, TIOCNOTTY, 0);
      (void)close(fd);
    } 
    return 0;
}

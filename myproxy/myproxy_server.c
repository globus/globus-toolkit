/*
 * myproxy-server
 *
 * program to store user's delegated credentials for later retrieval
 */

#include "myproxy_common.h"	/* all needed headers included here */

#ifndef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#endif

/* temporary define for forking */
#define NOFORK

static char usage[] = \
"\n"\
"Syntax: myproxy-server [-d|-debug] [-p|-port #] "\
"[-c config-file] [-s storage-dir] ...\n"\
"        myproxy-server [-h|-help] [-version]\n"\
"\n"\
"   Options\n"\
"       -h | --help                     Displays usage\n"\
"       -u | --usage                             \n"\
"                                               \n"\
"       -v | --verbose              Display debugging messages\n"\
"       -V | --version              Displays version\n"\
"       -d | --debug                Run in debug mode (don't fork)\n"\
"       -c | --config               Specifies configuration file to use\n"\
"       -p | --port    <portnumber> Specifies the port to run on\n"\
"       -s | --storage <directory>  Specifies the credential storage directory\n"\
"\n";

struct option long_options[] =
{
    {"debug",            no_argument, NULL, 'd'},
    {"help",             no_argument, NULL, 'h'},
    {"port",       required_argument, NULL, 'p'},
    {"config",     required_argument, NULL, 'c'},       
    {"storage",    required_argument, NULL, 's'},       
    {"usage",            no_argument, NULL, 'u'},
    {"verbose",          no_argument, NULL, 'v'},
    {"version",          no_argument, NULL, 'V'},
    {0, 0, 0, 0}
};

static char short_options[] = "dhc:p:s:vVuD:";

static char version[] =
"myproxy-server version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

#ifdef PKCS11
/* pkcs11 engine */
ENGINE *e;
#endif

/* Signal handling */
typedef void Sigfunc(int);  

Sigfunc *my_signal(int signo, Sigfunc *func);
void sig_exit(int signo);
void sig_chld(int signo);
void sig_ign(int signo);

int myproxy_creds_info(struct myproxy_creds *creds,
		       myproxy_response_t *response);

/* Function declarations */
int init_arguments(int argc, 
                   char *argv[], 
                   myproxy_socket_attrs_t *server_attrs, 
                   myproxy_server_context_t *server_context);

int myproxy_init_server(myproxy_socket_attrs_t *server_attrs);

int handle_client(myproxy_socket_attrs_t *server_attrs, 
                  myproxy_server_context_t *server_context);

void respond_with_error(myproxy_socket_attrs_t *attrs,
				const char *error);

void send_response(myproxy_socket_attrs_t *server_attrs, 
		   myproxy_response_t *response, 
		   char *client_name);

void get_proxy(myproxy_socket_attrs_t *server_attrs, 
	       myproxy_creds_t *creds,
	       myproxy_request_t *request,
	       myproxy_response_t *response);

void put_proxy(myproxy_socket_attrs_t *server_attrs, 
	      myproxy_creds_t *creds, 
	      myproxy_response_t *response);

void info_proxy(myproxy_creds_t *creds, myproxy_response_t *response);

void destroy_proxy(myproxy_creds_t *creds, myproxy_response_t *response);

void change_passwd(myproxy_creds_t *creds, char *new_passphrase,
		   myproxy_response_t *response);

static void failure(const char *failure_message); 

static void my_failure(const char *failure_message);

static char *timestamp(void);

static int become_daemon(myproxy_server_context_t *server_context);

static int myproxy_authorize_accept(myproxy_server_context_t *context,
                                    myproxy_socket_attrs_t *attrs,
				    myproxy_request_t *client_request,
				    char *client_name);

static int get_client_authdata(myproxy_socket_attrs_t *attrs,
                               myproxy_request_t *client_request,
			       char *client_name,
			       authorization_data_t *auth_data);

static int debug = 0;

int
main(int argc, char *argv[]) 
{    
    int   listenfd;
    pid_t childpid;
    struct sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);


    
    myproxy_socket_attrs_t         *socket_attrs;
    myproxy_server_context_t       *server_context;
  
    socket_attrs    = malloc(sizeof(*socket_attrs));
    memset(socket_attrs, 0, sizeof(*socket_attrs));

    server_context  = malloc(sizeof(*server_context));
    memset(server_context, 0, sizeof(*server_context));

    /* Set context defaults */
    server_context->run_as_daemon = 1;

    if (init_arguments(argc, argv, socket_attrs, server_context) < 0) {
        fprintf(stderr, usage);
        exit(1);
    }

    /* Read my configuration */
    if (myproxy_server_config_read(server_context) == -1) {
	fprintf(stderr, "%s %s\n", verror_get_string(), verror_strerror());
	exit(1);
    }

#ifdef PKCS11
    /* initialize pkcs11 engine */

    ENGINE_load_pkcs11();
    e = ENGINE_by_id("pkcs11");
    if(!e) {
       /* the engine isn't available */
       fprintf(stderr,"I am sorry, it appears the PKCS11 device is not available \n");
       ERR_print_errors_fp(stderr);
       exit(1);
    }
    if(!ENGINE_init(e)) {
       ENGINE_free(e);
       fprintf (stderr,"I am sorry, I was unable to initialize the PKCS11 device. \n");
       fprintf (stderr,"This may be due to an incorrect PIN or a problem with the device itself.\n");
       ERR_print_errors_fp(stderr);
       exit(1);
    }

    /* register engine for all RSA operations */
    ENGINE_register_RSA(e);
#endif


    /* 
     * Test to see if we're run out of inetd 
     * If so, then stdin will be connected to a socket,
     * so getpeername() will succeed.
     */
    if (getpeername(fileno(stdin), (struct sockaddr *) &client_addr, &client_addr_len) < 0) {
       server_context->run_as_daemon = 1;
#ifndef NOFORK
       if (!debug) {
	  if (become_daemon(server_context) < 0) {
	     fprintf(stderr, "Error starting daemon\n");
	     exit(1);
	  }
       }
#endif
    } else { 
       server_context->run_as_daemon = 0;
       close(1);
       (void) open("/dev/null",O_WRONLY);
    }


    /* Initialize Logging */
    if (debug) {
	myproxy_debug_set_level(1);
        myproxy_log_use_stream(stderr);
    } else {
#ifndef NOFORK
 	myproxy_log_use_syslog(LOG_DAEMON, server_context->my_name);
#else
        myproxy_log_use_stream(stderr);
#endif 
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
    
    /* Make sure all's well with the storage directory. */
    if (myproxy_check_storage_dir() == -1) {
	myproxy_log_verror();
	myproxy_log("Exiting.  Please fix errors with storage directory and restart.");
	exit(1);
    }

    if (!server_context->run_as_daemon) {
       myproxy_log("Connection from %s", inet_ntoa(client_addr.sin_addr));
       socket_attrs->socket_fd = fileno(stdin);
       if (handle_client(socket_attrs, server_context) < 0) {
	  my_failure("error in handle_client()");
       } 
    } else {    
       /* Run as a daemon */
       listenfd = myproxy_init_server(socket_attrs);
       /* Set up concurrent server */
       while (1) {
	  socket_attrs->socket_fd = accept(listenfd,
					   (struct sockaddr *) &client_addr,
					   &client_addr_len);
	  myproxy_log("Connection from %s", inet_ntoa(client_addr.sin_addr));
	  if (socket_attrs->socket_fd < 0) {
	     if (errno == EINTR) {
		continue; 
	     } else {
		myproxy_log_perror("Error in accept()");
	     }
	  }
#ifndef NOFORK /* no forks when an open cryptoki session is here */
	  if (!debug) {
	     childpid = fork();
	     
	     if (childpid < 0) {              /* check for error */
		myproxy_log_perror("Error in fork");
		close(socket_attrs->socket_fd);
	     } else if (childpid != 0) {
		/* Parent */
		/* parent closes connected socket */
		close(socket_attrs->socket_fd);	     
		continue;	/* while(1) */
	     }
	     
	     /* child process */
	     close(0);
	     close(1);
	     if (!debug) {
		close(2);
	     }
	     close(listenfd);
	  }
#endif
	  if (handle_client(socket_attrs, server_context) < 0) {
	     my_failure("error in handle_client()");
	  } 
          /* close the socket */
          close(socket_attrs->socket_fd);

#ifndef NOFORK
	  _exit(0);
#endif
          

       }
    }

#ifdef PKCS11

     /* pkcs11 engine cleanup*/
    if(e != NULL) ENGINE_finish(e);
    if(e != NULL) ENGINE_free(e);
    ENGINE_cleanup();

#endif

    return 0;
}   

int
handle_client(myproxy_socket_attrs_t *attrs,
	      myproxy_server_context_t *context) 
{
    char  client_name[1024];
    char  *client_buffer = NULL;
    int   requestlen;
    time_t now;

    myproxy_creds_t *client_creds;
    myproxy_request_t *client_request;
    myproxy_response_t *server_response;

    client_creds    = malloc(sizeof(*client_creds));
    memset(client_creds, 0, sizeof(*client_creds));

    client_request  = malloc(sizeof(*client_request));
    memset(client_request, 0, sizeof(*client_request));

    server_response = malloc(sizeof(*server_response));
    memset(server_response, 0, sizeof(*server_response));

    now = time(0);

    /* Create a new gsi socket */
    attrs->gsi_socket = GSI_SOCKET_new(attrs->socket_fd);
    if (attrs->gsi_socket == NULL) {
        myproxy_log_perror("GSI_SOCKET_new()");
        return -1;
    }


    /* Authenticate server to client and get DN of client */
    if (myproxy_authenticate_accept(attrs, client_name,
				    sizeof(client_name)) < 0) {
	/* Client_name may not be set on error so don't use it. */
	myproxy_log_verror();
	respond_with_error(attrs, "authentication failed");
        return 0;
    }

    /* Log client name */
    myproxy_log("Authenticated client %s", client_name); 
    
    /* Receive client request */
    requestlen = myproxy_recv_ex(attrs, &client_buffer);
    if (requestlen <= 0) {
        myproxy_log_verror();
	respond_with_error(attrs, "Error in myproxy_recv_ex()");
        return 0;
    }
   
    /* Deserialize client request */
    if (myproxy_deserialize_request(client_buffer, requestlen, 
                                    client_request) < 0) {
	myproxy_log_verror();
        respond_with_error(attrs, "error parsing request");
        return 0;
    }
    free(client_buffer);
    client_buffer = NULL;


    /* Check client version */
    if (strcmp(client_request->version, MYPROXY_VERSION) != 0) {
	myproxy_log("client %s Invalid version number (%s) received",
		    client_name, client_request->version);
        respond_with_error(attrs,
				   "Invalid version number received.\n");
        return 0;
    }

    /* Check client username and pass phrase */
    if ((client_request->username == NULL) ||
	(strlen(client_request->username) == 0)) 
    {
	myproxy_log("client %s Invalid username (%s) received",
		    client_name,
		    (client_request->username == NULL ? "<NULL>" :
		     client_request->username));
	respond_with_error(attrs,
				   "Invalid username received.\n");
        return 0;
    }

    /* All authorization policies are enforced in this function. */
    if (myproxy_authorize_accept(context, attrs, 
	                         client_request, client_name) < 0) {
       myproxy_log("authorization failed");
       respond_with_error(attrs, verror_get_string());
       return 0;
    }
    
    /* Fill in client_creds with info from the request that describes
       the credentials the request applies to. */
    client_creds->owner_name     = strdup(client_name);
    client_creds->username       = strdup(client_request->username);
    client_creds->passphrase     = strdup(client_request->passphrase);
    client_creds->lifetime 	 = client_request->proxy_lifetime;
    if (client_request->retrievers != NULL)
	client_creds->retrievers = strdup(client_request->retrievers);
    if (client_request->renewers != NULL)
	client_creds->renewers   = strdup(client_request->renewers);
    if (client_request->credname != NULL)
	client_creds->credname   = strdup (client_request->credname);
    if (client_request->creddesc != NULL)
	client_creds->creddesc   = strdup (client_request->creddesc);

    /* Set response OK unless error... */
    server_response->response_type =  MYPROXY_OK_RESPONSE;
      
    /* Handle client request */
    switch (client_request->command_type) {
    case MYPROXY_GET_PROXY: 
        myproxy_log("Received GET request from %s", client_name);

	/* Retrieve the credentials from the repository */
	if (myproxy_creds_retrieve(client_creds) < 0) {
	    respond_with_error(attrs, verror_get_string());
            return 0;
	}

	myproxy_debug("  Owner: %s", client_creds->username);
	myproxy_debug("  Username: %s", client_creds->username);
	myproxy_debug("  Location: %s", client_creds->location);
	myproxy_debug("  Requested lifetime: %d seconds",
		      client_request->proxy_lifetime);
	myproxy_debug("  Max. delegation lifetime: %d seconds",
		      client_creds->lifetime);

	/* Are credentials expired? */
	if (client_creds->start_time > now) {
	    myproxy_debug("  warning: credentials not yet valid! "
			  "(problem with local clock?)");
	} else if (client_creds->end_time < now) {
	    respond_with_error(attrs,
        	       "requested credentials have expired");
            return 0;
	}

	/* Are credentials locked? */
	if (client_creds->lockmsg) {
	    char *error, *msg="credential locked\n";
	    error = malloc(strlen(msg)+strlen(client_creds->lockmsg)+1);
	    strcpy(error, msg);
	    strcat(error, client_creds->lockmsg);
	    respond_with_error(attrs, error);
            return 0;
	}
	
	/* Send initial OK response */
	send_response(attrs, server_response, client_name);
	
	/* Delegate the credential and set final server_response */
        get_proxy(attrs, client_creds, client_request, server_response);
        break;


    case MYPROXY_PUT_PROXY:
        myproxy_log("Received PUT request from %s", client_name);
	myproxy_debug("  Username: %s", client_creds->username);
	myproxy_debug("  Max. delegation lifetime: %d seconds",
		      client_creds->lifetime);
	if (client_creds->retrievers != NULL)
	    myproxy_debug("  Retriever policy: %s", client_creds->retrievers);
	if (client_creds->renewers != NULL)
    	    myproxy_debug("  Renewer policy: %s", client_creds->renewers); 

	if (myproxy_check_passphrase_policy(client_request->passphrase,
					    context->passphrase_policy_pgm,
					    client_request->username,
					    client_request->credname,
					    client_request->retrievers,
					    client_request->renewers,
					    client_name) < 0) {
	    respond_with_error(attrs, verror_get_string());
            return 0;
	}

	/* Send initial OK response */
	send_response(attrs, server_response, client_name);

	/* Store the credentials in the repository and
	   set final server_response */
        put_proxy(attrs, client_creds, server_response);
        break;

    case MYPROXY_INFO_PROXY:
        myproxy_log("Received client %s command: INFO", client_name);
	myproxy_debug("  Username is \"%s\"", client_request->username);
        info_proxy(client_creds, server_response);
        break;
    case MYPROXY_DESTROY_PROXY:
        myproxy_log("Received client %s command: DESTROY", client_name);
	myproxy_debug("  Username is \"%s\"", client_request->username);
        destroy_proxy(client_creds, server_response);
        break;

    case MYPROXY_CHANGE_CRED_PASSPHRASE:
	/* change credential passphrase*/
	myproxy_log("Received client %s command: CHANGE_PASS", client_name);
	myproxy_debug("  Username is \"%s\"", client_request->username);

	if (myproxy_check_passphrase_policy(client_request->new_passphrase,
					    context->passphrase_policy_pgm,
					    client_request->username,
					    client_request->credname,
					    client_request->retrievers,
					    client_request->renewers,
					    client_name) < 0) {
	    respond_with_error(attrs, verror_get_string());
	    return 0;
        }

	change_passwd(client_creds, client_request->new_passphrase,
		      server_response);

    default:
        server_response->error_string = strdup("Unknown command.\n");
        break;
    }
    
    /* return server response */
    send_response(attrs, server_response, client_name);

    /* Log request */
    myproxy_log("Client %s disconnected", client_name);
   
    /* free stuff up */
    if (client_creds != NULL) {
	myproxy_creds_free_contents(client_creds);
	free(client_creds);
    }
    
    
    myproxy_free(NULL, client_request, server_response);
    GSI_SOCKET_destroy(attrs->gsi_socket);


    return 0;
}

int 
init_arguments(int argc, char *argv[], 
               myproxy_socket_attrs_t *attrs, 
               myproxy_server_context_t *context) 
{   
    extern char *gnu_optarg;

    int arg;
    int arg_error = 0;

    char *last_directory_seperator;
    char directory_seperator = '/';
    
    /* Could do something smarter to get FQDN */
    attrs->pshost = strdup("localhost");
    
    attrs->psport = MYPROXY_SERVER_PORT;

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
	case 'v':
	    myproxy_debug_set_level(1);
	    break;
        case 'V': /* print version and exit */
            fprintf(stderr, version);
            exit(1);
            break;
        case 's': /* set the credential storage directory */
            { char *s;
            s=(char *) malloc(strlen(gnu_optarg) + 1);
            strcpy(s,gnu_optarg);
            myproxy_set_storage_dir(s);
            break;
            }
	case 'u': /* print version and exit */
            fprintf(stderr, usage);
            exit(1);
            break;
        case 'd':
            debug = 1;
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
myproxy_init_server(myproxy_socket_attrs_t *attrs) 
{
    int on = 1;
    int listen_sock;
    struct sockaddr_in sin;
    struct linger lin = {0,0};
    GSI_SOCKET *tmp_gsi_sock;

    if ((tmp_gsi_sock = GSI_SOCKET_new(0)) == NULL) {
	failure("malloc() failed in GSI_SOCKET_new()");
    }
    if (GSI_SOCKET_check_creds(tmp_gsi_sock) == GSI_SOCKET_ERROR) {
	char error_string[1024];
	GSI_SOCKET_get_error_string(tmp_gsi_sock, error_string,
				    sizeof(error_string));
	myproxy_log("Problem with server credentials.\n%s\n",
		    error_string);
	exit(1);
    }
    GSI_SOCKET_destroy(tmp_gsi_sock);
    
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);

    if (listen_sock == -1) {
        failure("Error in socket()");
    } 

    /* Allow reuse of socket */
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));
    setsockopt(listen_sock, SOL_SOCKET, SO_LINGER, (char *) &lin, sizeof(lin));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(attrs->psport);

    if (bind(listen_sock, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
	if (errno == EADDRINUSE) {
	    myproxy_log("Port %d already in use, probably by another "
			"myproxy-server instance.\nUse the -p option to run "
			"multiple myproxy-server instances on different "
			"ports.", attrs->psport);
	}
	failure("Error in bind()");
    }
    if (listen(listen_sock, 5) < 0) {
	    failure("Error in listen()");
    }
    return listen_sock;
}

void
respond_with_error(myproxy_socket_attrs_t *attrs,
			   const char *error)
{
    myproxy_response_t		response = {0}; /* initialize with 0s */
    int				responselen;
    char			response_buffer[2048];
    

    memset (&response, 0, sizeof (response));
    response.version = strdup(MYPROXY_VERSION);
    response.response_type = MYPROXY_ERROR_RESPONSE;
    response.authorization_data = NULL;
    response.error_string = strdup(error);
    
    responselen = myproxy_serialize_response(&response,
					     response_buffer,
					     sizeof(response_buffer));
    
    if (responselen < 0) {
        my_failure("error in myproxy_serialize_response()");
    }

    if (myproxy_send(attrs, response_buffer, responselen) < 0) {
        my_failure("error in myproxy_send()\n");
    } 

    myproxy_log("Error - closing connection: %s", error);
    
}

void send_response(myproxy_socket_attrs_t *attrs, myproxy_response_t *response,
		   char *client_name)
{
    char server_buffer[10240];
    int responselen;
    assert(response != NULL);

    /* set version */
    response->version = malloc(strlen(MYPROXY_VERSION) + 1);
    sprintf(response->version, "%s", MYPROXY_VERSION);

    responselen = myproxy_serialize_response(response, server_buffer, sizeof(server_buffer));
    
    if (responselen < 0) {
        my_failure("error in myproxy_serialize_response()");
    }

    /* Log response */
    if (response->response_type == MYPROXY_OK_RESPONSE) {
      myproxy_debug("Sending OK response to client %s", client_name);
    } else if (response->response_type == MYPROXY_ERROR_RESPONSE) {
      myproxy_debug("Sending ERROR response \"%s\" to client %s",
		    response->error_string, client_name);
    }

    if (myproxy_send(attrs, server_buffer, responselen) < 0) {
	myproxy_log_verror();
        my_failure("error in myproxy_send()\n");
    } 
    free(response->version);
    response->version = NULL;

    return;
}

/**********************************************************************
 *
 * Routines to handle client requests to the server.
 *
 */

/* Delegate requested credentials to the client */
void get_proxy(myproxy_socket_attrs_t *attrs, 
	       myproxy_creds_t *creds,
	       myproxy_request_t *request,
	       myproxy_response_t *response) 
{
    int min_lifetime;
  
    min_lifetime = MIN(creds->lifetime, request->proxy_lifetime);

    if (myproxy_init_delegation(attrs, creds->location, min_lifetime,
				request->passphrase) < 0) {
        myproxy_log_verror();
	response->response_type =  MYPROXY_ERROR_RESPONSE; 
	response->error_string = strdup("Unable to delegate credentials.\n");
    } else {
        myproxy_log("Delegating credentials for %s lifetime=%d",
		    creds->owner_name, min_lifetime);
	response->response_type = MYPROXY_OK_RESPONSE;
    } 
}

/* Accept delegated credentials from client */
void put_proxy(myproxy_socket_attrs_t *attrs, 
	       myproxy_creds_t *creds, 
	       myproxy_response_t *response) 
{
    char delegfile[64];

    if (myproxy_accept_delegation(attrs, delegfile, sizeof(delegfile),
				  creds->passphrase) < 0) {
	myproxy_log_verror();
        response->response_type =  MYPROXY_ERROR_RESPONSE; 
        response->error_string = strdup("Failed to accept credentials.\n"); 
	return;
    }

    myproxy_debug("  Accepted delegation: %s", delegfile);
 
    creds->location = strdup(delegfile);

    if (myproxy_creds_store(creds) < 0) {
	myproxy_log_verror();
        response->response_type = MYPROXY_ERROR_RESPONSE; 
        response->error_string = strdup("Unable to store credentials.\n"); 
    } else {
	response->response_type = MYPROXY_OK_RESPONSE;
    }

    /* Clean up temporary delegation */
    if (ssl_proxy_file_destroy(delegfile) != SSL_SUCCESS) {
	myproxy_log_perror("Removal of temporary credentials file %s failed",
			   delegfile);
    }
}

void info_proxy(myproxy_creds_t *creds, myproxy_response_t *response) {
    if (myproxy_creds_retrieve_all(creds) < 0) {
       myproxy_log_verror();
       response->response_type =  MYPROXY_ERROR_RESPONSE;
       response->error_string = strdup(verror_get_string());
    } else { 
       response->response_type = MYPROXY_OK_RESPONSE;
       response->info_creds = creds;
    }
}

void destroy_proxy(myproxy_creds_t *creds, myproxy_response_t *response) {
    
    myproxy_debug("Deleting credentials for username \"%s\"", creds->username);
    myproxy_debug("  Owner is \"%s\"", creds->owner_name);
    myproxy_debug("  Delegation lifetime is %d seconds", creds->lifetime);
    
    if (myproxy_creds_delete(creds) < 0) { 
	myproxy_log_verror();
        response->response_type =  MYPROXY_ERROR_RESPONSE; 
	response->error_string = strdup(verror_get_string());
    } else {
	response->response_type = MYPROXY_OK_RESPONSE;
    }
 
}

void change_passwd(myproxy_creds_t *creds, char *new_passphrase,
		   myproxy_response_t *response) {
    
    myproxy_debug("Changing pass phrase for username \"%s\"", creds->username);
    myproxy_debug("  Owner is \"%s\"", creds->owner_name);
    
    if (myproxy_creds_change_passphrase(creds, new_passphrase) < 0) { 
	myproxy_log_verror();
        response->response_type =  MYPROXY_ERROR_RESPONSE; 
        response->error_string = strdup("Unable to change pass phrase.\n"); 
    } else {
	response->response_type = MYPROXY_OK_RESPONSE;
    }
 
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
    int fd = 0;
    int fdlimit;

   
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
#ifdef TIOCNOTTY
    fd = open("/dev/tty", O_RDWR);
    if (fd >= 0) {
      ioctl(fd, TIOCNOTTY, 0);
      (void)close(fd);
    } 
#endif /* TIOCNOTTY */

    return 0;
}

/* Check authorization for all incoming requests.  The authorization
 * rules are as follows.
 * GET with passphrase (credential retrieval):
 *   Client DN must match server-wide allowed_retrievers policy.
 *   Client DN must match credential-specific allowed_retrievers policy.
 *   Passphrase in request must match passphrase for credentials.
 * GET with certificate (credential renewal):
 *   Client DN must match server-wide allowed_renewers policy.
 *   Client DN must match credential-specific allowed_renewers policy.
 *   DN in second X.509 authentication must match owner of credentials.
 * PUT and DESTROY:
 *   Client DN must match accepted_credentials.
 *   If credentials already exist for the username, the client must own them.
 * INFO:
 *   Client DN must match accepted_credentials.
 *   Ownership checking done in info_proxy().
 * CHANGE_CRED_PASSPHRASE:
 *   Client DN must match accepted_credentials.
 *   Client DN must match credential owner.
 *   Passphrase in request must match passphrase for credentials.
 */
static int
myproxy_authorize_accept(myproxy_server_context_t *context,
                         myproxy_socket_attrs_t *attrs,
			 myproxy_request_t *client_request,
			 char *client_name)
{
   int   credentials_exist = 0;
   int   client_owns_credentials = 0;
   int   authorization_ok = -1;
   int   return_status = -1;
   authorization_data_t auth_data;
   myproxy_creds_t creds;

   memset(&creds, 0, sizeof(creds));
   memset(&auth_data, 0, sizeof(auth_data));
   
   switch (client_request->command_type) {
   case MYPROXY_GET_PROXY:
       /* Gather all authorization information for the GET request from
	  the client.  May include additional network exchanges. */
       if (get_client_authdata(attrs, client_request, client_name,
			       &auth_data) < 0) {
	   verror_put_string("Unable to get client authorization data");
	   goto end;
       }

       /* get information about credential */
       creds.username = strdup(client_request->username);
       if (client_request->credname) {
	   creds.credname = strdup(client_request->credname);
       }
       if (myproxy_creds_retrieve(&creds) < 0) {
	   verror_put_string("Unable to retrieve credential information");
	   goto end;
       }

       switch (auth_data.method) {
       case AUTHORIZETYPE_PASSWD: /* retrieval */
	   /* check server-wide policy */
	   authorization_ok =
	       myproxy_server_check_policy_list((const char **)context->authorized_retriever_dns, client_name);
	   if (authorization_ok != 1) {
	       verror_put_string("\"%s\" not authorized by server's authorized_retriever policy", client_name);
	       goto end;
	   }
	   /* check per-credential policy */
	   if (creds.retrievers) {
	       authorization_ok =
		   myproxy_server_check_policy(creds.retrievers, client_name);
	       if (authorization_ok != 1) {
		   verror_put_string("\"%s\" not authorized by credential's retriever policy", client_name);
		   goto end;
	       }
	   } else if (context->default_retriever_dns) {
	       authorization_ok =
		   myproxy_server_check_policy_list((const char **)context->default_retriever_dns, client_name);
	       if (authorization_ok != 1) {
		   verror_put_string("\"%s\" not authorized by server's default retriever policy", client_name);
		   goto end;
	       }
	   }
	   /* Does passphrase match? */
	   authorization_ok =
	       authorization_check(&auth_data, &creds, client_name);
	   if (authorization_ok != 1) {
	       verror_put_string("invalid pass phrase");
	       goto end;
	   }
	   break;

       case AUTHORIZETYPE_CERT:	/* renewal */
	   /* check server-wide policy */
	   authorization_ok =
	       myproxy_server_check_policy_list((const char **)context->authorized_renewer_dns, client_name);
	   if (authorization_ok != 1) goto end;
	   /* check per-credential policy */
	   if (creds.renewers) {
	       authorization_ok =
		   myproxy_server_check_policy(creds.renewers, client_name);
	       if (authorization_ok != 1) {
		   verror_put_string("\"%s\" not authorized by credential's renewer policy", client_name);
		   goto end;
	       }
	   } else if (context->default_renewer_dns) {
	       authorization_ok =
		   myproxy_server_check_policy_list((const char **)context->default_renewer_dns, client_name);
	       if (authorization_ok != 1) {
		   verror_put_string("\"%s\" not authorized by server's default renewer policy");
		   goto end;
	       }
	   }
	   /* Does cert DN match cred owner? */
	   authorization_ok =
	       authorization_check(&auth_data, &creds, client_name);
	   if (authorization_ok != 1) {
	       verror_put_string("invalid credential for renewal");
	       goto end;
	   }
	   /* Sanity check: Renewal credentials should not have a passphrase.
	      We store a crypt'ed empty passphrase instead.  (yuk!) */
	   if (creds.passphrase && creds.passphrase[0]) {
	       char *tmp;
	       tmp = (char *)des_crypt("", &creds.owner_name[strlen(creds.owner_name)-3]);
	       if (strcmp(tmp, creds.passphrase)) {
		   verror_put_string("credential configured for retrieval, not renewal");
		   goto end;
	       }
	   }
	   break;

       default:
	   verror_put_string("unknown authorization method");
	   goto end;
	   break;
       }
       break;

   case MYPROXY_PUT_PROXY:
   case MYPROXY_DESTROY_PROXY:
       /* Is this client authorized to store credentials here? */
       authorization_ok =
	   myproxy_server_check_policy_list((const char **)context->accepted_credential_dns, client_name);
       if (authorization_ok != 1) {
	   verror_put_string("\"%s\" not authorized to store credentials on this server", client_name);
	   goto end;
       }

       credentials_exist = myproxy_creds_exist(client_request->username, client_request->credname);
       if (credentials_exist == -1) {
	   myproxy_log_verror();
	   verror_put_string("Error checking credential existence");
	   goto end;
       }

       if (credentials_exist == 1) {
	   client_owns_credentials = myproxy_creds_is_owner(client_request->username, client_request->credname, client_name);
	   if (client_owns_credentials == -1) {
	       verror_put_string("Error checking credential ownership");
	       goto end;
	   }

	   if (!client_owns_credentials) {
	       if (client_request->command_type == MYPROXY_PUT_PROXY) {
		   myproxy_log("Username and credential name in use by another client.");
		   verror_put_string("Username and credential name in use by someone else.");
	       } else {
		   myproxy_log("Failed credential owner check.");
		   verror_put_string("Credentials owned by someone else.");
	       }
	       goto end;
	   }
       }
       break;

   case MYPROXY_INFO_PROXY:
       /* Is this client authorized to store credentials here? */
       authorization_ok =
	   myproxy_server_check_policy_list((const char **)context->accepted_credential_dns, client_name);
       if (authorization_ok != 1) {
	   verror_put_string("\"%s\" not authorized to query credentials on this server", client_name);
	   goto end;
       }

       /* Further authorization checking done inside the processing
	  of the INFO request, since there may be multiple credentials
          stored under this username. */

       break;

   case MYPROXY_CHANGE_CRED_PASSPHRASE:
       /* Is this client authorized to store credentials here? */
       authorization_ok =
	   myproxy_server_check_policy_list((const char **)context->accepted_credential_dns, client_name);
       if (authorization_ok != 1) {
	   verror_put_string("\"%s\" not authorized to store credentials on this server", client_name);
	   goto end;
       }

       credentials_exist = myproxy_creds_exist(client_request->username, client_request->credname);
       if (credentials_exist == 0) {
	   verror_put_string("credential does not exist");
	   goto end;
       } else if (credentials_exist == -1) {
	   verror_put_string("error checking credential existence");
	   goto end;
       }

       client_owns_credentials = myproxy_creds_is_owner(client_request->username, client_request->credname, client_name);
       if (client_owns_credentials == 0) {
	   verror_put_string("'%s' does not own the credentials",
			     client_name);
	   goto end;
       } else if (client_owns_credentials == -1) {
	   verror_put_string("Error checking credential ownership");
	   goto end;
       }

       /* Initialize authorization data with current passphrase. */
       if (get_client_authdata(attrs, client_request, client_name,
                               &auth_data) < 0) {
           verror_put_string("Unable to get client authorization data");
           goto end;
       }

       /* get information about credential */
       creds.username = strdup(client_request->username);
       if (client_request->credname) {
	   creds.credname = strdup(client_request->credname);
       }
       if (myproxy_creds_retrieve(&creds) < 0) {
	   verror_put_string("Unable to retrieve credential information");
	   goto end;
       }

       /* Does passphrase match? */
       if (auth_data.method != AUTHORIZETYPE_PASSWD) {
	   verror_put_string("current passphrase required when changing passphrase");
	   goto end;
       } else {
	   authorization_ok = authorization_check(&auth_data, &creds, client_name);
	   if (authorization_ok != 1) {
	       verror_put_string("invalid pass phrase");
	       goto end;
	   }
       }
       break;
   }

   if (authorization_ok == -1) {
      verror_put_string("Error checking authorization");
      goto end;
   }

   if (authorization_ok != 1) {
      verror_put_string("Authorization failed");
      goto end;
   }

   return_status = 0;

end:
   if (creds.passphrase)
      memset(creds.passphrase, 0, strlen(creds.passphrase));
   myproxy_creds_free_contents(&creds);
   if (auth_data.server_data)
      free(auth_data.server_data);
   if (auth_data.client_data)
      free(auth_data.client_data);

   return return_status;
}

static int
get_client_authdata(myproxy_socket_attrs_t *attrs,
                    myproxy_request_t *client_request,
		    char *client_name,
		    authorization_data_t *auth_data)
{
   myproxy_response_t server_response;
   char  *client_buffer = NULL;
   int   client_length;
   int   return_status = -1;
   authorization_data_t *client_auth_data = NULL;
   author_method_t client_auth_method;

   assert(auth_data != NULL);
   
   memset(&server_response, 0, sizeof(server_response));

   if (client_request->passphrase && strlen(client_request->passphrase) > 0) {
      auth_data->server_data = NULL;
      auth_data->client_data = strdup(client_request->passphrase);
      auth_data->client_data_len = strlen(client_request->passphrase) + 1;
      auth_data->method = AUTHORIZETYPE_PASSWD;
      return 0;
   }

   authorization_init_server(&server_response.authorization_data);
   server_response.response_type = MYPROXY_AUTHORIZATION_RESPONSE;
   send_response(attrs, &server_response, client_name);

   /* Wait for client's response. Its first four bytes are supposed to
      contain a specification of the method that the client chose to
      authorization. */
   client_length = myproxy_recv_ex(attrs, &client_buffer);
   if (client_length <= 0)
      goto end;

   client_auth_method = (*client_buffer);
   /* fill in the client's response and return pointer to filled data */
   client_auth_data = authorization_store_response(
	                  client_buffer + sizeof(client_auth_method),
			  client_length - sizeof(client_auth_method),
			  client_auth_method,
			  server_response.authorization_data);
   if (client_auth_data == NULL) 
      goto end;

   auth_data->server_data = strdup(client_auth_data->server_data);
   auth_data->client_data = malloc(client_auth_data->client_data_len);
   if (auth_data->client_data == NULL) {
      verror_put_string("malloc() failed");
      verror_put_errno(errno);
      goto end;
   }
   memcpy(auth_data->client_data, client_auth_data->client_data, 
	  client_auth_data->client_data_len);
   auth_data->client_data_len = client_auth_data->client_data_len;
   auth_data->method = client_auth_data->method;

   return_status = 0;

end:
   authorization_data_free(server_response.authorization_data);
   if (client_buffer) free(client_buffer);

   return return_status;
}

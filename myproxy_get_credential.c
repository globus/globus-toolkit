/*
 * myproxy-get-credential
 *
 * Webserver program to retrieve a end-entity credential from a myproxy-server
 */

#include "myproxy_common.h"	/* all needed headers included here */

static char usage[] = \
"\n"
"Syntax: myproxy-retrieve [-l username] ...\n"
"        myproxy-retrieve [-usage|-help] [-version]\n"
"\n"
"   Options\n"
"       -h | --help                       Displays usage\n"
"       -u | --usage                                    \n"
"                                                      \n"
"       -v | --verbose                    Display debugging messages\n"
"       -V | --version                    Displays version\n"
"       -l | --username        <username> Username for the delegated proxy\n"
"       -s | --pshost          <hostname> Hostname of the myproxy-server\n"
"       -p | --psport          <port #>   Port of the myproxy-server\n"
"       -a | --authorization   <path>     Use credential for authorization\n"
"                                         (instead of passphrase)\n"
"       -d | --dn_as_username             Use subject of the authorization\n"
"                                         credential (or default credential\n"
"                                         if -a not used) as the default\n"
"                                         username instead of $LOGNAME\n"
"       -k | --credname        <name>     Specify credential name\n"
"       -c | --certfile        <filename> Certificate file name\n"
"       -y | --keyfile         <filename> Key file name\n"
"       -S | --stdin_pass                 Read passphrase from stdin\n"
"       -n | --no_passphrase              Don't prompt for passphrase\n"
"\n";

struct option long_options[] =
{
    {"help",                   no_argument, NULL, 'h'},
    {"pshost",           required_argument, NULL, 's'},
    {"psport",           required_argument, NULL, 'p'},
    {"proxy_lifetime",   required_argument, NULL, 't'},
    {"out",              required_argument, NULL, 'o'},
    {"usage",                  no_argument, NULL, 'u'},
    {"username",         required_argument, NULL, 'l'},
    {"verbose",                no_argument, NULL, 'v'},
    {"version",                no_argument, NULL, 'V'},
    {"authorization",    required_argument, NULL, 'r'},
    {"dn_as_username",         no_argument, NULL, 'd'},
    {"credname",	 required_argument, NULL, 'k'},
    {"stdin_pass",             no_argument, NULL, 'S'},
    {"no_passphrase",          no_argument, NULL, 'n'},
    {"certfile",         required_argument, NULL, 'c'},
    {"keyfile",          required_argument, NULL, 'y'},
    {0, 0, 0, 0}
};

static char short_options[] = "hus:p:l:t:o:c:y:vVa:dk:Sn";

static char version[] =
"myproxy-retrieve version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

void 
init_arguments(int argc, char *argv[], 
	       myproxy_socket_attrs_t *attrs,
	       myproxy_request_t *request);
 
int
store_credential( char *delegfile,
                  char *certfile,
                  char *keyfile );

int
file2buf(const char   filename[],
         char       **buf);

int
buffer2file( char *buffer,
             int   size,
             int   fd );

int
write_cert( const char *path,
            const char *buffer );

int
write_key( const char *path,
            const char *buffer );

/*
 * Use setvbuf() instead of setlinebuf() since cygwin doesn't support
 * setlinebuf().
 */
#define my_setlinebuf(stream)	setvbuf((stream), (char *) NULL, _IOLBF, 0)

/* location of delegated proxy */
static char *outputfile             = NULL;
static char *certfile               = NULL;     /* certificate file name */
static char *keyfile                = NULL;     /* key file name */
static int   dn_as_username         = 0;
static int   read_passwd_from_stdin = 0;
static int   use_empty_passwd       = 0;

int
main(int argc, char *argv[]) 
{    
    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;
    char                   *pshost;
    char                    delegfile[128];
    char                    request_buffer[2048];
    int                     requestlen;

    myproxy_log_use_stream (stderr);

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
    client_request->command_type = MYPROXY_RETRIEVE_CERT;

    pshost = getenv("MYPROXY_SERVER");
    if (pshost != NULL) {
        socket_attrs->pshost = strdup(pshost);
    }

    client_request->proxy_lifetime = 60*60*MYPROXY_DEFAULT_DELEG_HOURS;

    if (getenv("MYPROXY_SERVER_PORT")) {
        socket_attrs->psport = atoi(getenv("MYPROXY_SERVER_PORT"));
    } else {
        socket_attrs->psport = MYPROXY_SERVER_PORT;
    }

    GLOBUS_GSI_SYSCONFIG_GET_USER_CERT_FILENAME( &certfile,
                                                 &keyfile ); 

    /* Initialize client arguments and create client request object */
    init_arguments(argc, argv, socket_attrs, client_request);

    /* Connect to server. */
    if (myproxy_init_client(socket_attrs) < 0) {
        fprintf(stderr, "Error: %s\n", verror_get_string());
        return(1);
    }
    
    if (!outputfile) {
	GLOBUS_GSI_SYSCONFIG_GET_PROXY_FILENAME(&outputfile,
						GLOBUS_PROXY_FILE_OUTPUT);
    }

    if (!use_empty_passwd) {
       /* Allow user to provide a passphrase */
	int rval;
	if (read_passwd_from_stdin) {
	    rval = myproxy_read_passphrase_stdin(
			   client_request->passphrase,
			   sizeof(client_request->passphrase),
			   NULL);
	} else {
	    rval = myproxy_read_passphrase(client_request->passphrase,
					   sizeof(client_request->passphrase),
					   NULL);
	}
	if (rval == -1) {
	    fprintf(stderr, "Error reading passphrase\n");
	    return 1;
	}
    }

    if (client_request->username == NULL) { /* set default username */
	if (dn_as_username) {
	    if (client_request->authzcreds) {
		if (ssl_get_base_subject_file(client_request->authzcreds,
					      &client_request->username)) {
		    fprintf(stderr, "Cannot get subject name from %s\n",
			    client_request->authzcreds);
		    return 1;
		}
	    } else {
		if (ssl_get_base_subject_file(NULL,
					      &client_request->username)) {
		    fprintf(stderr,
			    "Cannot get subject name from your certificate\n");
		    return 1;
		}
	    }
	} else {
	    char *username = NULL;
	    if (!(username = getenv("LOGNAME"))) {
		fprintf(stderr, "Please specify a username.\n");
		return 1;
	    }
	    client_request->username = strdup(username);
	}
    }

    /* Attempt anonymous-mode credential retrieval if we don't have a
       credential. */
    GSI_SOCKET_allow_anonymous(socket_attrs->gsi_socket, 1);

     /* Authenticate client to server */
    if (myproxy_authenticate_init(socket_attrs, NULL) < 0) {
        fprintf(stderr, "Error: %s: %s\n",
                socket_attrs->pshost, verror_get_string());
        return(1);
    }

    /* Serialize client request object */
    requestlen = myproxy_serialize_request(client_request, request_buffer,
                                           sizeof(request_buffer));
    if (requestlen < 0) {
        fprintf(stderr, "Error in myproxy_serialize_request():\n");
        return(1);
    }

    /* Send request to the myproxy-server */
    if (myproxy_send(socket_attrs, request_buffer, requestlen) < 0) {
        fprintf(stderr, "Error in myproxy_send_request(): %s\n",
                verror_get_string());
        return(1);
    }

    /* Continue unless the response is not OK */
    if (myproxy_recv_response_ex(socket_attrs, server_response,
                                 client_request) != 0) {
        fprintf(stderr, "%s\n", verror_get_string());
        return(1);
    }

    /* Accept delegated credentials from server */
    if (myproxy_accept_credentials(socket_attrs, delegfile, sizeof(delegfile),
                                  NULL) < 0) {
        fprintf(stderr, "Error in (myproxy_accept_credentials(): %s\n",
                verror_get_string());
        return(1);
    }

    /* Let the server know the client is done. */
    client_request->command_type = MYPROXY_CONTINUE;

    /* Serialize client request MYPROXY_CONTINUE */
    requestlen = myproxy_serialize_request(client_request, request_buffer,
                                           sizeof(request_buffer));
    if (requestlen < 0) {
        fprintf(stderr, "Error in myproxy_serialize_request():\n");
        return(1);
    }

    /* Send request to the myproxy-server */
    if (myproxy_send(socket_attrs, request_buffer, requestlen) < 0) {
        fprintf(stderr, 
                "Error in sending: MYPROXY_CONTINUE: %s\n",
                verror_get_string());
        return(1);
    }

    if( store_credential( delegfile, certfile, keyfile ) < 0 )
    {
       fprintf( stderr, "Problem storing to: %s and %s\n", certfile, keyfile );
       return(1);
    }

    /* move delegfile to outputfile if specified */
    if (outputfile != NULL) {
        ssl_proxy_file_destroy(delegfile);
    }

    printf("Credentials for %s have been stored in %s and %s\n",
           client_request->username, certfile, keyfile);
    free(outputfile);
    verror_clear();

    /* free memory allocated */
    myproxy_free(socket_attrs, client_request, server_response);
    return 0;
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
	case 't':       /* Specify proxy lifetime in seconds */
	  request->proxy_lifetime = 60*60*atoi(gnu_optarg);
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
	case 'a':       /* special authorization */
	    request->authzcreds = strdup(gnu_optarg);
	    use_empty_passwd = 1;
	    break;
	case 'n':       /* no passphrase */
	    use_empty_passwd = 1;
	    break;
	case 'v':
	    myproxy_debug_set_level(1);
	    break;
        case 'V':       /* print version and exit */
            fprintf(stderr, version);
            exit(1);
            break;
	case 'd':       /* use the certificate subject (DN) as the default
		           username instead of LOGNAME */
	    dn_as_username = 1;
	    break;
	case 'k':       /* credential name */
	    request->credname = strdup (gnu_optarg);
	    break;
	case 'S':
	    read_passwd_from_stdin = 1;
	    break;
        case 'c':       /* credential file name */
            certfile = strdup(gnu_optarg);
            break;
        case 'y':       /* key file name */
            keyfile = strdup(gnu_optarg);
            break;
        default:        /* print usage and exit */ 
	    fprintf(stderr, usage);
	    exit(1);
	    break;	
        }
    }

    /* Check to see if myproxy-server specified */
    if (attrs->pshost == NULL) {
	fprintf(stderr, "Unspecified myproxy-server.  Set the MYPROXY_SERVER environment variable to\nthe hostname of the myproxy-server or run with '-s server-hostname'.\n");
	exit(1);
    }

    return;
}

int
store_credential( char *delegfile, 
                  char *certfile, 
                  char *keyfile )
{
    char               *input_buffer       = NULL;
    int                 retval              = -1;


    if (file2buf(delegfile, &input_buffer) < 0)
    {
      fprintf(stderr, "open(%s) failed: %s\n", delegfile, strerror(errno));
      goto error;
    }

    if (write_cert(certfile, input_buffer) < 0)
    {
      fprintf(stderr, "open(%s) failed: %s\n", certfile, strerror(errno));
      goto error;
    }

    if (write_key(keyfile, input_buffer) < 0)
    {
      fprintf(stderr, "open(%s) failed: %s\n", keyfile, strerror(errno));
      goto error;
    }

    retval = 0;
error:
    return(retval);
}

int
file2buf(const char   filename[],
         char       **buf)
{
    int fd, size, rval;
    char *b;

    if ((fd = open(filename, O_RDONLY)) < 0) {
        perror("open");
        return -1;
    }

    if ((size = (int) lseek(fd, 0, SEEK_END)) < 0) {
        perror("lseek");
        return -1;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("lseek");
        return -1;
    }

    *buf = b = (char *) malloc(size + 1);
    if (b == NULL) {
        perror("malloc");
        return -1;
    }

    while (size) {
        if ((rval = read(fd, b, size)) < 0) {
            perror("read");
            return -1;
        }

        size -= rval;
        b += rval;
    }
    *b = '\0';

    return 0;
}

int
write_cert( const char *path, 
            const char *buffer )
{
    int          fd;
    static char  BEGINCERT[] = "-----BEGIN CERTIFICATE-----";
    static char  ENDCERT[]   = "-----END CERTIFICATE-----";
    char        *certstart,
                *certend;
    int          retval      = -1;
    int          size;


    /* Open the output file. */
    if ((fd = open(path, O_CREAT | O_EXCL | O_WRONLY,
                 S_IRUSR | S_IWUSR)) < 0)
    {
      fprintf(stderr, "open(%s) failed: %s\n", path, strerror(errno));
      goto error;
    }

    if ((certstart = strstr(buffer, BEGINCERT)) == NULL)
    {
      fprintf(stderr, "CRED doesn't contain '%s'.\n",  BEGINCERT);
      goto error;
    }

    if ((certend = strstr(certstart, ENDCERT)) == NULL)
    {
      fprintf(stderr, "CRED doesn't contain '%s'.\n", ENDCERT);
      goto error;
    }
    certend += strlen(ENDCERT);
    size = certend-certstart;

    if( buffer2file( certstart, size, fd ) != 0 )
    {
      fprintf(stderr, "Could not write cert to: '%s'.\n", path);
      goto error;
    }

    certstart += size;

    while ((certstart = strstr(certstart, BEGINCERT)) != NULL) {

        if ((certend = strstr(certstart, ENDCERT)) == NULL) {
            fprintf(stderr, "Can't find matching '%s' in %s.\n", ENDCERT,
                    certfile);
            goto error;
        }
        certend += strlen(ENDCERT);
        size = certend-certstart;

        buffer2file( certstart, size, fd );
        certstart += size;
    }

    retval = 0;

error:
    if( fd )
    {
      close( fd );
    }

    return( retval );
}

int
write_key( const char *path, 
           const char *buffer )
{
    int          fd;
    static char  BEGINKEY[] = "-----BEGIN RSA PRIVATE KEY-----";
    static char  ENDKEY[]   = "-----END RSA PRIVATE KEY-----";
    char        *keystart,
                *keyend;
    int          retval     = -1;
    int          size;


    /* Open the output file. */
    if ((fd = open(path, O_CREAT | O_EXCL | O_WRONLY,
                 S_IRUSR | S_IWUSR)) < 0)
    {
      fprintf(stderr, "open(%s) failed: %s\n", path, strerror(errno));
      goto error;
    }

//     Write the key.
    if ((keystart = strstr(buffer, BEGINKEY)) == NULL)
    {
      fprintf(stderr, "CREDKEY doesn't contain '%s'.\n", BEGINKEY);
      goto error;
    }

    if ((keyend = strstr(keystart, ENDKEY)) == NULL)
    {
      fprintf(stderr, "CREDKEY doesn't contain '%s'.\n", ENDKEY);
      goto error;
    }
    keyend += strlen(ENDKEY);
    size = keyend-keystart;

    if( buffer2file( keystart, size, fd ) != 0 )
    {
      fprintf(stderr, "Could not write key to: '%s'.\n", path);
      goto error;
    }

    retval = 0;

error:
    if( fd )
    {
      close( fd );
    }

    return( retval );
}

int
buffer2file( char *buffer,
             int   size,
             int   fd )
{
    int   rval;
    char *certstart;

    certstart = buffer;

    while (size)
    {
      if ((rval = write(fd, certstart, size)) < 0)
      {
          perror("write");
          return( -1 );
      }
      size -= rval;
      certstart += rval;
    }

    if (write(fd, "\n", 1) < 0)
    {
      perror("write");
      return(-1);
    }

    return( 0 );
}

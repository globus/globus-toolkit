/*
 * myproxy-init
 *
 * Client program to delegate a credential to a myproxy-server
 */

#include "myproxy.h"
#include "myproxy_log.h"
#include "gnu_getopt.h"
#include "version.h"
#include "verror.h"
#include "myproxy_read_pass.h"
#include "ssl_utils.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

/* Location of default proxy */
#define MYPROXY_DEFAULT_PROXY  "/tmp/myproxy-proxy"

static char usage[] = \
"\n"\
"Syntax: myproxy-init [-c #hours] [-t #hours] [-l username] [-r retrievers] [-w renewers] ...\n"\
"        myproxy-init [-usage|-help] [-version]\n"\
"\n"\
"   Options\n"\
"       -h | --help                       Displays usage\n"
"       -u | --usage                                    \n"
"                                                      \n"
"       -v | --verbose                    Display debugging messages\n"
"       -V | --version                    Displays version\n"
"       -l | --username        <username> Username for the delegated proxy\n"
"       -c | --cred_lifetime   <hours>    Lifetime of delegated proxy on\n" 
"                                         server (default 1 week)\n"
"       -t | --proxy_lifetime  <hours>    Lifetime of proxies delegated by\n" 
"                                         server (default 2 hours)\n"
"       -s | --pshost          <hostname> Hostname of the myproxy-server\n"
"                                         Can also set MYPROXY_SERVER env. var.\n"
"       -a | --allow_anonymous_retrievers Allow credentials to be retrieved\n"
"                                         with just username/passphrase\n"
"       -A | --allow_anonymous_renewers   Allow credentials to be renewed by\n"
"                                         any client (not recommended)\n"
"       -r | --retrievable_by  <dn>       Allow specified entity to retrieve\n"
"                                         credential\n"
"       -R | --renewable_by    <dn>       Allow specified entity to renew\n"
"                                         credential\n"
"       -x | --regex_dn_match             Set regular expression matching mode\n"
"                                         for following policy options\n"
"       -X | --match_cn_only              Set CN matching mode (default)\n"
"                                         for following policy options\n"
"       -p | --psport          <port #>   Port of the myproxy-server\n"
"       -n | --no_passphrase              Disable passphrase authentication\n"
"       -d | --dn_as_username             Use the proxy certificate subject\n"
"                                         (DN) as the default username,\n"
"                                         instead of the LOGNAME env. var.\n"
"	-k | --credname <name>		  Specifies credential name\n"
"	-K | --creddesc <description>	  Specifies credential description\n"
"	-f | --force			  Force Credential Overwrite\n"
"\n";

struct option long_options[] =
{
  {"help",                  no_argument, NULL, 'h'},
  {"pshost",   	      required_argument, NULL, 's'},
  {"psport",          required_argument, NULL, 'p'},
  {"cred_lifetime",   required_argument, NULL, 'c'},
  {"proxy_lifetime",  required_argument, NULL, 't'},
  {"usage",                 no_argument, NULL, 'u'},
  {"username",        required_argument, NULL, 'l'},
  {"verbose",               no_argument, NULL, 'v'},
  {"version",               no_argument, NULL, 'V'},
  {"no_passphrase",         no_argument, NULL, 'n'},
  {"dn_as_username",        no_argument, NULL, 'd'},
  {"allow_anonymous_retrievers", no_argument, NULL, 'a'},
  {"allow_anonymous_renewers", no_argument, NULL, 'A'},
  {"retrievable_by",  required_argument, NULL, 'r'},
  {"renewable_by",    required_argument, NULL, 'R'},
  {"regex_dn_match",        no_argument, NULL, 'x'},
  {"match_cn_only", 	    no_argument, NULL, 'X'},
  {"credname",	      required_argument, NULL, 'k'},
  {"creddesc",	      required_argument, NULL, 'K'},
  {"force",	      	    no_argument, NULL, 'f'},
  {0, 0, 0, 0}
};

static char short_options[] = "uhD:s:p:t:c:l:vVndr:R:xXaAk:K:f";  //colon following an option indicates option takes an argument

static char version[] =
"myproxy-init version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

static int use_empty_passwd = 0;
static int dn_as_username = 0;

/* Function declarations */
int init_arguments(int argc, char *argv[], 
		    myproxy_socket_attrs_t *attrs, myproxy_request_t *request, int *cred_lifetime);

int grid_proxy_init(int hours, const char *proxyfile);

int grid_proxy_destroy(const char *proxyfile);

#define		SECONDS_PER_HOUR			(60 * 60)

int
main(int argc, char *argv[]) 
{    
    int cred_lifetime, hours;
    float days;
    char *pshost; 
    char proxyfile[64];
    char request_buffer[1024]; 
    int requestlen;
    int cleanup_user_proxy = 0;

    myproxy_socket_attrs_t *socket_attrs;
    myproxy_request_t      *client_request;
    myproxy_response_t     *server_response;

    myproxy_log_use_stream (stderr);

    socket_attrs = malloc(sizeof(*socket_attrs));
    memset(socket_attrs, 0, sizeof(*socket_attrs));

    client_request = malloc(sizeof(*client_request));
    memset(client_request, 0, sizeof(*client_request));

    server_response = malloc(sizeof(*server_response));
    memset(server_response, 0, sizeof(*server_response));

    /* setup defaults */
    client_request->version = malloc(strlen(MYPROXY_VERSION) + 1);
    strcpy(client_request->version, MYPROXY_VERSION);
    client_request->command_type = MYPROXY_PUT_PROXY;

    pshost = getenv("MYPROXY_SERVER");
    if (pshost != NULL) {
      socket_attrs->pshost = strdup(pshost);
    }

    /* client_request stores the lifetime of proxies delegated by the server */
    client_request->proxy_lifetime = SECONDS_PER_HOUR * MYPROXY_DEFAULT_DELEG_HOURS;

    /* the lifetime of the proxy */
    cred_lifetime                   = SECONDS_PER_HOUR * MYPROXY_DEFAULT_HOURS;
 
    socket_attrs->psport = MYPROXY_SERVER_PORT;

    /* Initialize client arguments and create client request object */
    if (init_arguments(argc, argv, socket_attrs, client_request,
		       &cred_lifetime) != 0) {
      goto cleanup;
    }
    
    /* Create a proxy by running [grid-proxy-init] */
    sprintf(proxyfile, "%s.%u", MYPROXY_DEFAULT_PROXY, (unsigned) getuid());

    /* Run grid-proxy-init to create a proxy */
    if (grid_proxy_init(cred_lifetime, proxyfile) != 0) {
        fprintf(stderr, "Program grid_proxy_init failed\n");
        goto cleanup;
    }

    /* Be sure to delete the user proxy on abnormal exit */
    cleanup_user_proxy = 1;
    
    if (client_request->username == NULL) { /* set default username */
	if (dn_as_username) {
	    if (ssl_get_base_subject_file(proxyfile,
					  &client_request->username)) {
		fprintf(stderr,
			"Cannot get subject name from your certificate\n");
		goto cleanup;
	    }
	} else {
	    char *username = NULL;
	    if (!(username = getenv("LOGNAME"))) {
		fprintf(stderr, "Please specify a username.\n");
		goto cleanup;
	    }
	    client_request->username = strdup(username);
	}
    }

    /* Allow user to provide a passphrase */
    if (!use_empty_passwd) {
	if (myproxy_read_verified_passphrase(client_request->passphrase,
					     sizeof(client_request->passphrase)) == -1) {
	    fprintf(stderr, "%s\n",
		    verror_get_string());
	    goto cleanup;
	}
    }
    
    /* Set up client socket attributes */
    if (myproxy_init_client(socket_attrs) < 0) {
        fprintf(stderr, "%s\n", 
		verror_get_string());
        goto cleanup;
    }

    /* Authenticate client to server */
    if (myproxy_authenticate_init(socket_attrs, proxyfile) < 0) {
        fprintf(stderr, "%s\n", 
		verror_get_string());
        goto cleanup;
    }

    /* Serialize client request object */
    requestlen = myproxy_serialize_request(client_request, 
                                           request_buffer, sizeof(request_buffer));
    if (requestlen < 0) {
        fprintf(stderr, "%s\n",verror_get_string());
	goto cleanup;
    }

    /* Send request to the myproxy-server */

    if (myproxy_send(socket_attrs, request_buffer, requestlen) < 0) {
        fprintf(stderr, "%s\n", 
		verror_get_string());
	goto cleanup;
    }

    /* Continue unless the response is not OK */
    if (myproxy_recv_response(socket_attrs, server_response) != 0) {
        fprintf(stderr, "%s\n", 
		verror_get_string());
        goto cleanup;
    }
    
    /* Delegate credentials to server using the default lifetime of the cert. */
    if (myproxy_init_delegation(socket_attrs, proxyfile, cred_lifetime,
				NULL /* no passphrase */) < 0) {
	fprintf(stderr, "%s\n", 
		verror_get_string());
	goto cleanup;
    }

    /* Delete proxy file */
    if (grid_proxy_destroy(proxyfile) != 0) {
        fprintf(stderr, "Failed to remove temporary proxy credential.\n");
	goto cleanup;
    }
    cleanup_user_proxy = 0;
    
    /* Get final response from server */
    if (myproxy_recv_response(socket_attrs, server_response) != 0) {
        fprintf(stderr, "%s\n", 
		verror_get_string());
        goto cleanup;
    }

    hours = (int)(cred_lifetime/SECONDS_PER_HOUR);
    days = (float)(hours/24.0);
    printf("A proxy valid for %d hours (%.1f days) for user %s now exists on %s.\n", 
	   hours, days, client_request->username, socket_attrs->pshost); 
    
    /* free memory allocated */
    myproxy_free(socket_attrs, client_request, server_response);

    return 0;

 cleanup:
    if (cleanup_user_proxy) {
        grid_proxy_destroy(proxyfile);
    }
    return 1;
}

int
init_arguments(int argc, 
	       char *argv[], 
	       myproxy_socket_attrs_t *attrs,
	       myproxy_request_t *request,
	       int *cred_lifetime) 
{   
    extern char *gnu_optarg;
    int expr_type = MATCH_CN_ONLY;  //default

    int arg;

    request->force_credential_overwrite = 0;
    while((arg = gnu_getopt_long(argc, argv, short_options, 
				 long_options, NULL)) != EOF) 
    {
	switch(arg) 
	{
	case 'h':       /* print help and exit */
	    fprintf(stderr, usage);
	    return -1;
	    break;
	case 'c': 	/* Specify cred lifetime in hours */
	    *cred_lifetime  = SECONDS_PER_HOUR * atoi(gnu_optarg);
	    break;    
	case 't': 	/* Specify proxy lifetime in hours */
	    request->proxy_lifetime = SECONDS_PER_HOUR * atoi(gnu_optarg);
	    break;        
	case 's': 	/* pshost name */
	    attrs->pshost = strdup(gnu_optarg);
	    break;
	case 'p': 	/* psport */
	    attrs->psport = atoi(gnu_optarg);
	    break;
	case 'u': 	/* print help and exit */
	    fprintf(stderr, usage);
	    return -1;
	    break;
	case 'l':	/* username */
	    request->username = strdup(gnu_optarg);
	    break;
	case 'v':
	    myproxy_debug_set_level(1);
	    break;
	case 'V': /* print version and exit */
	    fprintf(stderr, version);
	    return -1;
	    break;
	case 'n':   /* use an empty passwd == require certificate based
		       authorization while getting the creds */
	    use_empty_passwd = 1;
	    break;
	case 'd':   /* use the certificate subject (DN) as the default
		       username instead of LOGNAME */
	    dn_as_username = 1;
	    break;
	case 'r':   /* retrievers list */
	    if (expr_type == REGULAR_EXP)  //copy as is
	      request->retrievers = strdup (gnu_optarg);
	    else   //prepend a "*/CN=" string
	    {
		request->retrievers = (char *) malloc (strlen (gnu_optarg) + 5);
		strcpy (request->retrievers, "*/CN=");
		myproxy_debug("authorized retriever %s",
			      request->retrievers);
		request->retrievers = strcat (request->retrievers,gnu_optarg);
	    }
	    break;
	case 'R':   /* renewers list */
	    if (expr_type == REGULAR_EXP)  //copy as is
	      request->renewers = strdup (gnu_optarg);
	    else   //prepend a "*/CN=" string
	    {
		request->renewers = (char *) malloc (strlen (gnu_optarg) + 6);
		strcpy (request->renewers, "*/CN=");
		myproxy_debug("authorized renewer %s",
			      request->renewers);
		request->renewers = strcat (request->renewers,gnu_optarg);
	    }
	    break;
	case 'x':   /*set expression type to regex*/
	    expr_type = REGULAR_EXP;
	    myproxy_debug("expr-type = regex");
	    break;
	case 'X':   /*set expression type to common name*/
	    expr_type = MATCH_CN_ONLY;
	    myproxy_debug("expr-type = CN");
	    break;
	case 'a':  /*allow anonymous retrievers*/
	    request->retrievers = strdup ("*");
	    myproxy_debug("anonymous retrievers allowed");
	    break;
	case 'A':  /*allow anonymous renewers*/
	    request->renewers = strdup ("*");
	    myproxy_debug("anonymous renewers allowed");
	    break;
	case 'k':  /*credential name*/
	    request->credname = strdup (gnu_optarg);
	    /* XXX: Need input validation here. */
	    break;
	case 'K':  /*credential description*/
	    request->creddesc = strdup (gnu_optarg);
	    break;
	case 'f':  /*force credential overwrite*/
	    request->force_credential_overwrite = 1;
	    break;

        default:  
	    fprintf(stderr, usage);
	    return -1;
	    break;	
        }
    }
    /* Check to see if myproxy-server specified */
    if (attrs->pshost == NULL) {
	fprintf(stderr, usage);
	fprintf(stderr, "Unspecified myproxy-server! Either set the MYPROXY_SERVER environment variable or explicitly set the myproxy-server via the -s flag\n");
	return -1;
    }

    return 0;
}


/* grid_proxy_init()
 *
 * Uses the system() call to run grid-proxy-init to create a user proxy
 *
 * returns grid-proxy-init status 0 if OK, -1 on error
 */
int
grid_proxy_init(int seconds, const char *proxyfile) {

    int rc;
    char command[128];
    int hours;
      
    assert(proxyfile != NULL);

    hours = seconds / SECONDS_PER_HOUR;
    
    sprintf(command, "grid-proxy-init -hours %d -out %s", hours, proxyfile);
    rc = system(command);

    return rc;
}

/* grid_proxy_destroy()
 *
 * Fill the proxy file with zeros and unlink.
 *
 * returns 0 if OK, -1 on error
 */
int
grid_proxy_destroy(const char *proxyfile)
{
    FILE *fp;
    long offset, i;
    char zero = '\0';
    
    assert(proxyfile != NULL);

    fp = fopen(proxyfile, "r+");
    if (!fp) {
	perror("fopen");
	return -1;
    }
    if (fseek(fp, 0L, SEEK_END) < 0) {
	perror("fseek");
	fclose(fp);
	return -1;
    }
    offset = ftell(fp);
    if (offset < 0) {
	perror("ftell");
	fclose(fp);
	return -1;
    }
    if (fseek(fp, 0L, SEEK_SET) < 0) {
	perror("fseek");
	fclose(fp);
	return -1;
    }
    for (i=0; i < offset; i++) {
	if (fwrite(&zero, 1, 1, fp) != 1) {
	    perror("fwrite");
	    fclose(fp);
	    return -1;
	}
    }
    fclose(fp);
    if (unlink(proxyfile) < 0) {
	perror("unlink");
	return -1;
    }

    return 0;
}


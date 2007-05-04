/*
 * myproxy_arq.c
 *
 * Admin repository query tool
 *
 */

#include "myproxy_common.h"	/* all needed headers included here */

#define BINARY_NAME "myproxy-admin-query"
#define SECONDS_PER_HOUR 3600

static char usage[] = 
"\n"
"Admin Repository Query Tool\n"
"\n"
" Syntax:  "  BINARY_NAME " [-usage|-help] [-version] ...\n"
"\n"
"    Options\n"
"    -h | --help                     Displays usage\n"
"    -u | --usage                                  \n"
"                                                  \n"
"    -c | --config                   Specifies configuration file to use\n"\
"    -s | --storage      <directory> Specifies the credential storage directory\n"
"    -l | --username     <name>      Query by username\n"
"    -k | --credname     <name>      Query by credential name\n"
"    -e | --expiring_in  <hours>     Query for creds expiring in less than \n"
"                                    specified <hours>\n"
"    -t | --time_left    <hours>     Query for creds with lifetime greater \n"
"                                    than specified <hours>\n"
"    -i | --invalid                  Query for invalid credentials\n"
"    -r | --remove                   Remove credentials matching query\n"
"    -L | --lock         'msg'       Lock access to credential(s).\n"
"                                    Specified msg will be returned instead.\n"
"    -U | --unlock                   Unlock previously locked credential(s).\n"
"    -v | --verbose                  Display debugging messages\n"
"    -V | --version                  Displays version\n"
"\n";

struct option long_options[] =
{
    {"help",              no_argument, NULL, 'h'},
    {"usage",             no_argument, NULL, 'u'},
    {"username",    required_argument, NULL, 'l'},
    {"credname",    required_argument, NULL, 'k'},
    {"config",      required_argument, NULL, 'c'},
    {"expiring_in", required_argument, NULL, 'e'},
    {"time_left",   required_argument, NULL, 't'},
    {"storage",	    required_argument, NULL, 's'},
    {"lock",        required_argument, NULL, 'L'},
    {"unlock",            no_argument, NULL, 'U'},
    {"verbose",           no_argument, NULL, 'v'},
    {"version",           no_argument, NULL, 'V'},
    {"remove",            no_argument, NULL, 'r'},
    {"invalid",           no_argument, NULL, 'i'},
    {0, 0, 0, 0}
};

static char short_options[] = "hul:c:k:e:t:s:vVriL:U";

static char version[] =
BINARY_NAME "version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

/* Function declarations */
void init_arguments(int argc, char *argv[]);

void do_remove_creds(myproxy_creds_t *creds);
void do_lock_creds(myproxy_creds_t *creds);
void do_unlock_creds(myproxy_creds_t *creds);

struct myproxy_creds cred = {0};
int remove_creds = 0;
char *lock_msg = NULL;
char *config_file = NULL;
int unlock_creds = 0;
int invalid_creds = 0;
int verbose = 0;

int
main(int argc, char *argv[]) 
{
    int numcreds;
    myproxy_server_context_t server_context = { 0 };
    struct myproxy_creds *credp = NULL;

    /* check library version */
    if (myproxy_check_version()) {
	fprintf(stderr, "MyProxy library version mismatch.\n"
		"Expecting %s.  Found %s.\n",
		MYPROXY_VERSION_DATE, myproxy_version(0,0,0));
	exit(1);
    }

    /* Initialize arguments*/
    init_arguments(argc, argv);

    if (verbose) myproxy_log_use_stream (stderr);

    /* Read server config file for OCSP options, etc. */
    server_context.config_file = config_file;
    myproxy_server_config_read(&server_context);

    numcreds = myproxy_admin_retrieve_all(&cred);
    if (numcreds < 0) {
        myproxy_log_verror();
        fprintf (stderr, "Failed to read credentials.\n%s\n",
		 verror_get_string());
	exit(1);
    }

    if (numcreds && invalid_creds) {
        int i;
        struct myproxy_creds **credlist;
        credlist = malloc(sizeof(struct myproxy_creds *)*(numcreds+1));
        numcreds = 0;
        for (credp = &cred; credp; credp = credp->next) {
            verror_clear();
            if (myproxy_creds_verify(credp) < 0) {
                fprintf(stderr, "%s: %s",
                        credp->location, verror_get_string());
                credlist[numcreds++] = credp;
            }
        }
        for (i = 0; i < numcreds; i++) {
            credlist[i]->next = credlist[i+1];
        }
        credp = credlist[0];
    } else {
        credp = &cred;
    }
    verror_clear();

    if (numcreds == 0) {
	printf("No credentials found.\n");
    } else if (remove_creds) {
	do_remove_creds (credp);
    } else if (lock_msg) {
	do_lock_creds (credp);
    } else if (unlock_creds) {
	do_unlock_creds (credp);
    } else {
	if (myproxy_print_cred_info(credp, stdout) < 0) {
	    verror_print_error(stderr);
	    exit(1);
	}
    }

    return 0;
}

void 
init_arguments(int argc, 
		       char *argv[])
{
    extern char *optarg;
    int arg;

    while((arg = getopt_long(argc, argv, short_options, 
                             long_options, NULL)) != EOF) {
        switch(arg) {  
	case 'h': 	/* print help and exit */
        case 'u': 	/* print help and exit */
            printf(usage);
            exit(0);
       	    break;
        case 's': /* set the credential storage directory */
	    myproxy_set_storage_dir(optarg);
	    break;
        case 'l':	/* username */
	    cred.username = strdup(optarg);
	    break;
        case 'k':	/* credname */
	    cred.credname = strdup(optarg);
	    break;
    case 'c':
        config_file = strdup(optarg);
	case 'e':	/* expiring in <hours> */
	    cred.end_time = (SECONDS_PER_HOUR * atoi(optarg)) + time(0);
	    break;
	case 'i':
        invalid_creds = 1;
        break;
	case 't':	/* time left */
	    cred.start_time = (SECONDS_PER_HOUR * atoi(optarg)) + time(0);
	    break;
	case 'r':	/* remove */
	    remove_creds = 1;
	    break;
	case 'L':	/* lock */
	    lock_msg = strdup(optarg);
	    break;
	case 'U':	/* unlock */
	    unlock_creds = 1;
	    break;
	case 'v':	/* verbose */
	    myproxy_debug_set_level(1);
        verbose = 1;
	    break;
        case 'V':       /* print version and exit */
            printf(version);
            exit(0);
            break;
        default:        /* print usage and exit */ 
            fprintf(stderr, usage);
	    exit(1);
            break;	
        }
    }

    if (optind != argc) {
	fprintf(stderr, "%s: invalid option -- %s\n", argv[0],
		argv[optind]);
	fprintf(stderr, usage);
	exit(1);
    }

    return;
}

void
do_remove_creds(myproxy_creds_t *creds)
{
    if (!creds) return;

    for (; creds; creds = creds->next) {
	if (myproxy_creds_delete(creds) == 0) {
	    printf("Credential for user %s (name: %s) removed.\n",
		   creds->username,
		   creds->credname ? creds->credname : "default");
	} else {
	    fprintf(stderr, "Failed to remove credential for user %s "
		    "(name: %s).\n%s\n", creds->username,
		    creds->credname ? creds->credname : "default",
		    verror_get_string());
	}
    }
}

void
do_lock_creds(myproxy_creds_t *creds)
{
    if (!creds) return;

    for (; creds; creds = creds->next) {
	if (myproxy_creds_lock(creds, lock_msg) == 0) {
	    printf("Credential for user %s (name: %s) locked.\n",
		   creds->username,
		   creds->credname ? creds->credname : "default");
	} else {
	    fprintf(stderr, "Failed to lock credential for user %s "
		    "(name: %s).\n%s\n", creds->username,
		    creds->credname ? creds->credname : "default",
		    verror_get_string());
	}
    }
}

void
do_unlock_creds(myproxy_creds_t *creds)
{
    if (!creds) return;

    for (; creds; creds = creds->next) {
	if (myproxy_creds_unlock(creds) == 0) {
	    printf("Credential for user %s (name: %s) unlocked.\n",
		   creds->username,
		   creds->credname ? creds->credname : "default");
	} else {
	    fprintf(stderr, "Failed to unlock credential for user %s "
		    "(name: %s).\n%s\n", creds->username,
		    creds->credname ? creds->credname : "default",
		    verror_get_string());
	}
    }
}

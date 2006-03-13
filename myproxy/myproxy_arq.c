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
"    -s | --storage      <directory> Specifies the credential storage directory\n"
"    -l | --username     <name>      Query by username\n"
"    -k | --credname     <name>      Query by credential name\n"
"    -e | --expiring_in  <hours>     Query for creds expiring in less than \n"
"                                    specified <hours>\n"
"    -t | --time_left    <hours>     Query for creds with lifetime greater \n"
"                                    than specified <hours>\n"
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
    {"expiring_in", required_argument, NULL, 'e'},
    {"time_left",   required_argument, NULL, 't'},
    {"storage",	    required_argument, NULL, 's'},
    {"lock",        required_argument, NULL, 'L'},
    {"unlock",            no_argument, NULL, 'U'},
    {"verbose",           no_argument, NULL, 'v'},
    {"version",           no_argument, NULL, 'V'},
    {"remove",            no_argument, NULL, 'r'},
    {0, 0, 0, 0}
};

static char short_options[] = "hul:k:e:t:s:vVrL:U";

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
int unlock_creds = 0;

int
main(int argc, char *argv[]) 
{
    int numcreds;

    /* check library version */
    if (myproxy_check_version()) {
	fprintf(stderr, "MyProxy library version mismatch.\n"
		"Expecting %s.  Found %s.\n",
		MYPROXY_VERSION_DATE, myproxy_version(0,0,0));
	exit(1);
    }

    myproxy_log_use_stream (stderr);

    /* Initialize arguments*/
    init_arguments(argc, argv);

    numcreds = myproxy_admin_retrieve_all(&cred);
    if (numcreds < 0) {
        myproxy_log_verror();
        fprintf (stderr, "Failed to read credentials.\n%s\n",
		 verror_get_string());
	exit(1);
    } else if (numcreds == 0) {
	printf("No credentials found.\n");
    } else if (remove_creds) {
	do_remove_creds (&cred);
    } else if (lock_msg) {
	do_lock_creds (&cred);
    } else if (unlock_creds) {
	do_unlock_creds (&cred);
    } else {
	if (myproxy_print_cred_info(&cred, stdout) < 0) {
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
            fprintf(stderr, usage);
            exit(1);
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
	case 'e':	/* expiring in <hours> */
	    cred.end_time = (SECONDS_PER_HOUR * atoi(optarg)) + time(0);
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
	    break;
        case 'V':       /* print version and exit */
            fprintf(stderr, version);
            exit(1);
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

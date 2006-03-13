/*
 * myproxy-admin-change-pass
 *
 * Change credential passphrase directly on MyProxy server.
 */

#include "myproxy_common.h"	/* all needed headers included here */

static char usage[] = \
"\n"
"Syntax: myproxy-admin-change-pass [-l username] [-k credname] ... \n"
"        myproxy-admin-change-pass [-usage|-help] [-version]\n"
"\n"
"   Options\n"
"       -h | --help                       Displays usage\n"
"       -u | --usage                                    \n"
"                                                      \n"
"       -v | --verbose                    Display debugging messages\n"
"       -V | --version                    Displays version\n"
"       -s | --storage        <directory> Specifies the credential storage directory\n"
"       -l | --username       <username>  Username for the target proxy\n"
"       -k | --credname       <name>      Specify credential name\n"
"       -S | --stdin_pass                 Read pass phrase from stdin\n"
"\n";

struct option long_options[] =
{
    {"help",                   no_argument, NULL, 'h'},
    {"usage",                  no_argument, NULL, 'u'},
    {"storage",         required_argument, NULL, 's'},
    {"username",         required_argument, NULL, 'l'},
    {"verbose",                no_argument, NULL, 'v'},
    {"version",                no_argument, NULL, 'V'},
    {"credname",	 required_argument, NULL, 'k'},
    {"stdin_pass",             no_argument, NULL, 'S'},
    {0, 0, 0, 0}
};

static char short_options[] = "hus:l:vVk:S";

static char version[] =
"myproxy-admin-change-pass version " MYPROXY_VERSION " ("
MYPROXY_VERSION_DATE ") "  "\n";

void init_arguments(int argc, char *argv[]);

struct myproxy_creds cred = {0};
static int read_passwd_from_stdin = 0;

int
main(int argc, char *argv[]) 
{
    char passphrase[MAX_PASS_LEN+1], new_passphrase[MAX_PASS_LEN+1], *np=NULL;
    int rval = 0;

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

    if (cred.username == NULL) { /* set default username */
	if (!(cred.username = getenv("LOGNAME"))) {
	    fprintf(stderr, "Please specify a username.\n");
	    return 1;
	}
    }

    /*Accept credential passphrase*/
    if (read_passwd_from_stdin) {
	rval = myproxy_read_passphrase_stdin(passphrase, sizeof(passphrase),
		 "Enter (current) MyProxy pass phrase:");
    } else if (myproxy_creds_encrypted(&cred)) {
	rval = myproxy_read_passphrase(passphrase, sizeof(passphrase),
		 "Enter (current) MyProxy pass phrase:");
    }
    if (rval == -1) {
	verror_print_error(stderr);
	return 1;
    }
    if (passphrase)
	cred.passphrase = passphrase;

    /* Accept new passphrase */
    if (read_passwd_from_stdin) {
	rval = myproxy_read_passphrase_stdin(new_passphrase,
		 sizeof(new_passphrase),
		 "Enter new MyProxy pass phrase:");
    } else {
	rval = myproxy_read_verified_passphrase(new_passphrase,
		 sizeof(new_passphrase),
		 "Enter new MyProxy pass phrase:");
    }
    if (rval == -1) {
	verror_print_error(stderr);
	return 1;
    }
    if (new_passphrase[0])
	np = new_passphrase;

    if (myproxy_creds_change_passphrase(&cred, np) < 0) {
	verror_print_error(stderr);
	exit(1);
    }

    printf("Pass phrase changed.\n");

    return 0;
}

void 
init_arguments(int argc, char *argv[])
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
	case 'v':	/* verbose */
	    myproxy_debug_set_level(1);
	    break;
        case 'V':       /* print version and exit */
            fprintf(stderr, version);
            exit(1);
            break;
	case 'S':
	    read_passwd_from_stdin = 1;
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

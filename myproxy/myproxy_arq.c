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
    {"verbose",           no_argument, NULL, 'v'},
    {"version",           no_argument, NULL, 'V'},
    {"remove",            no_argument, NULL, 'r'},
    {0, 0, 0, 0}
};

static char short_options[] = "hul:k:e:t:s:vVr";

static char version[] =
BINARY_NAME "version " MYPROXY_VERSION " (" MYPROXY_VERSION_DATE ") "  "\n";

/* Function declarations */
void init_arguments(int argc, char *argv[]);

void print_cred_info(myproxy_creds_t *creds);
void do_remove_creds(myproxy_creds_t *creds);

struct myproxy_creds cred = {0};
int remove_creds = 0;

int
main(int argc, char *argv[]) 
{
   /* Initialize arguments*/
    init_arguments(argc, argv);

    if (myproxy_admin_retrieve_all(&cred) < 0) {
        myproxy_log_verror();
        fprintf (stderr, "Failed to read credentials.\n%s\n",
		 verror_get_string());
    } else if (remove_creds) {
	do_remove_creds (&cred);
    } else {
	print_cred_info (&cred);
    }

    return 0;
}

void 
init_arguments(int argc, 
		       char *argv[])
{
    extern char *gnu_optarg;
    int arg;

    while((arg = gnu_getopt_long(argc, argv, short_options, 
                             long_options, NULL)) != EOF) {
        switch(arg) {  
	case 'h': 	/* print help and exit */
        case 'u': 	/* print help and exit */
            fprintf(stderr, usage);
            exit(1);
       	    break;
        case 's': /* set the credential storage directory */
	    myproxy_set_storage_dir(gnu_optarg);
	    break;
        case 'l':	/* username */
	    cred.username = strdup(gnu_optarg);
	    break;
        case 'k':	/* credname */
	    cred.credname = strdup(gnu_optarg);
	    break;
	case 'e':	/* expiring in <hours> */
	    cred.end_time = (SECONDS_PER_HOUR * atoi(gnu_optarg)) + time(0);
	    break;
	case 't':	/* time left */
	    cred.start_time = (SECONDS_PER_HOUR * atoi(gnu_optarg)) + time(0);
	    break;
	case 'r':	/* remove */
	    remove_creds = 1;
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

    return;
}

void
print_cred_info(myproxy_creds_t *creds)
{
    int first_time = 1;
    if (!creds) return;

    if (creds->owner_name == NULL && creds->next == NULL)
    {
	printf ("No credentials present.\n");
	return;
    }

    for (; creds; creds = creds->next) {
        time_t time_diff, now;
        float days;

    	printf("owner: %s\n", creds->owner_name);
    	printf("username: %s\n", creds->username);

        if (creds->credname) {
            printf("  name: %s\n", creds->credname);
	}
        if (creds->creddesc) {
            printf("  description: %s\n", creds->creddesc);
        }
        if (creds->retrievers) {
            printf("  retrieval policy: %s\n", creds->retrievers);
        }
        if (creds->renewers) {
            printf("  renewal policy: %s\n", creds->renewers);
        }
        now = time(0);
        if (creds->end_time > now) {
            time_diff = creds->end_time - now;
            days = time_diff / 86400.0;
        } else {
            time_diff = 0;
            days = 0.0;
        }
        printf("  timeleft: %ld:%02ld:%02ld",
               (long)(time_diff / 3600),
               (long)(time_diff % 3600) / 60,
               (long)time_diff % 60 );
        if (days > 1.0) {
            printf("  (%.1f days)\n", days);
        } else {
            printf("\n");
        }
        first_time = 0;
    }
}

void
do_remove_creds(myproxy_creds_t *creds)
{
    if (!creds) return;

    if (creds->owner_name == NULL && creds->next == NULL)
    {
	printf("No credentials present.\n");
	return;
    }

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

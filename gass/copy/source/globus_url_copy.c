/******************************************************************************
globus_url_copy.c

Description:

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_common.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>

#include "globus_gass_copy.h"
#include "globus_ftp_client_debug_plugin.h"
/*
 *  use globus_io for netlogger stuff
 */
#include "globus_io.h"
#include "version.h"  /* provides local_version */

/******************************************************************************
                               Type definitions
******************************************************************************/
typedef struct
{
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;
    globus_object_t *                   err;
    globus_bool_t                       use_err;
    volatile globus_bool_t              done;
} my_monitor_t;


/*****************************************************************************
                          Module specific prototypes
*****************************************************************************/

static globus_callback_handle_t          globus_l_callback_handle;

static void
globus_l_url_copy_monitor_callback(void * callback_arg,
                                    globus_gass_copy_handle_t * handle,
                                    globus_object_t * result);

static void
globus_l_url_copy_cancel_callback(void * callback_arg,
                                    globus_gass_copy_handle_t * handle,
                                    globus_object_t * result);

/**** Support for SIGINT handling ****/
static RETSIGTYPE
globus_l_globus_url_copy_sigint_handler(int dummy);

#if defined(BUILD_LITE)
static
void
globus_l_globus_url_copy_signal_wakeup(
    void *                              user_args);

#define globus_l_globus_url_copy_remove_cancel_poll() \
    globus_callback_unregister(globus_l_callback_handle, GLOBUS_NULL, GLOBUS_NULL, GLOBUS_NULL)
#else
#define globus_l_globus_url_copy_remove_cancel_poll()
#endif

#ifndef TARGET_ARCH_WIN32
static int
globus_l_globus_url_copy_signal(int signum, RETSIGTYPE (*func)(int));
#endif

static
void
globus_l_gass_copy_performance_cb(
    void *                                          user_arg,
    globus_gass_copy_handle_t *                     handle,
    globus_off_t                                    total_bytes,
    float                                           instantaneous_throughput,
    float                                           avg_throughput);

/*****************************************************************************
                          Module specific variables
*****************************************************************************/

#define GLOBUS_URL_COPY_ARG_ASCII       1
#define GLOBUS_URL_COPY_ARG_BINARY      2
#define GLOBUS_URL_COPY_ARG_VERBOSE     4

const char * oneline_usage
    = "globus-url-copy [-help | -usage] [-version[s]] [-vb] [-dbg] [-b | -a]\n"
      "                        [-s <subject>] [-ds <subject>] [-ss <subject>]\n"
      "                        [-tcp-bs <size>] [-bs <size>] [-p <parallelism>]\n"
      "                        [-notpt] [-nodcau]\n"
      "                        sourceURL destURL";

const char * long_usage =
"\nglobus-url-copy [options] sourceURL destURL\n"
"OPTIONS\n"
"\t -help | -usage\n"
"\t      Print help\n"
"\t -version\n"
"\t      Print the version of this program\n"
"\t -versions\n"
"\t      Print the versions of all modules that this program uses\n"
"\t -a | -ascii\n"
"\t      convert the file to/from netASCII format to/from local file format\n"
"\t -vb | -verbose \n"
"\t      during the transfer, display the number of bytes transferred\n"
"\t      and the transfer rate per second\n"
"\t -dbg |-debugftp \n"
"\t      Debug ftp connections.  Prints control channel communication\n"
"\t      to stderr\n"
"\t -b | -binary\n"
"\t      Do not apply any conversion to the files. *default*\n"
"\t -s  <subject> | -subject <subject>\n"
"\t      Use this subject to match with both the source and dest servers\n"
"\t -ss <subject> | -source-subject <subject>\n"
"\t      Use this subject to match with the source server\n"
"\t -ds <subject> | -dest-subject <subject>\n"
"\t      Use this subject to match with the destionation server\n"
"\t -tcp-bs <size> | -tcp-buffer-size <size>\n"
"\t      specify the size (in bytes) of the buffer to be used by the\n"
"\t      underlying ftp data channels\n"
"\t -bs <block size> | -block-size <block size>\n"
"\t      specify the size (in bytes) of the buffer to be used by the\n"
"\t      underlying transfer methods\n"
"\t -p <parallelism> | -parallel <parallelism>\n"
"\t      specify the number of streams to be used in the ftp transfer\n"
"\t -notpt | -no-third-party-transfers\n"
"\t      turn third-party transfers off (on by default)\n"
"\t -nodcau | -no-data-channel-authentication\n"
"\t      turn off data channel authentication for ftp transfers\n"
"\n";

/***********

this feature has not yet been implemented.

"\t Note: entering a dash \"-\" in the above arguments where <subject> is\n"
"\t       required will result in the subject being obtained from the users\n"
"\t       credentials\n"
"\n";
***********/

#define globus_url_copy_l_args_error(a) \
{ \
    globus_libc_fprintf(stderr, \
                        "\nERROR: " \
                        a \
                        "\n\nSyntax: %s\n" \
                        "\nUse -help to display full usage\n", \
                        oneline_usage); \
    globus_module_deactivate_all(); \
    exit(1); \
}

#define globus_url_copy_l_args_error_fmt(fmt,arg) \
{ \
    globus_libc_fprintf(stderr, \
                        "\nERROR: " \
                        fmt \
                        "\n\nSyntax: %s\n" \
                        "\nUse -help to display full usage\n", \
                        arg, oneline_usage); \
    globus_module_deactivate_all(); \
    exit(1); \
}

int
test_integer( char *   value,
              void *   ignored,
              char **  errmsg )
{
    int  res = (atoi(value) <= 0);
    if (res)
        *errmsg = strdup("argument is not a positive integer");
    return res;
}

enum { arg_a = 1, arg_b, arg_s, arg_p, arg_vb, arg_debugftp, arg_ss, arg_ds, arg_tcp_bs,
       arg_bs, arg_notpt, arg_nodcau, arg_num = arg_nodcau };

#define listname(x) x##_aliases
#define namedef(id,alias1,alias2) \
static char * listname(id)[] = { alias1, alias2, GLOBUS_NULL }

#define defname(x) x##_definition
#define flagdef(id,alias1,alias2) \
namedef(id,alias1,alias2); \
static globus_args_option_descriptor_t defname(id) = { id, listname(id), 0, \
						GLOBUS_NULL, GLOBUS_NULL }
#define funcname(x) x##_predicate_test
#define paramsname(x) x##_predicate_params
#define oneargdef(id,alias1,alias2,testfunc,testparams) \
namedef(id,alias1,alias2); \
static globus_args_valid_predicate_t funcname(id)[] = { testfunc }; \
static void* paramsname(id)[] = { (void *) testparams }; \
globus_args_option_descriptor_t defname(id) = \
    { (int) id, (char **) listname(id), 1, funcname(id), (void **) paramsname(id) }

flagdef(arg_a, "-a", "-ascii");
flagdef(arg_b, "-b", "-binary");
flagdef(arg_vb, "-vb", "-verbose");
flagdef(arg_debugftp, "-dbg", "-debugftp");
flagdef(arg_notpt, "-notpt", "-no-third-party-transfers");
flagdef(arg_nodcau, "-nodcau", "-no-data-channel-authentication");

oneargdef(arg_bs, "-bs", "-block-size", test_integer, GLOBUS_NULL);
oneargdef(arg_tcp_bs, "-tcp-bs", "-tcp-buffer-size", test_integer, GLOBUS_NULL);
oneargdef(arg_p, "-p", "-parallel", test_integer, GLOBUS_NULL);
oneargdef(arg_s, "-s", "-subject", GLOBUS_NULL, GLOBUS_NULL);
oneargdef(arg_ss, "-ss", "-source-subject", GLOBUS_NULL, GLOBUS_NULL);
oneargdef(arg_ds, "-ds", "-dest-subject", GLOBUS_NULL, GLOBUS_NULL);


static globus_args_option_descriptor_t args_options[arg_num];

#define setupopt(id) args_options[id-1] = defname(id)

#define globus_url_copy_i_args_init() \
    setupopt(arg_a); setupopt(arg_b); setupopt(arg_s); setupopt(arg_vb); \
    setupopt(arg_debugftp); setupopt(arg_ss); setupopt(arg_ds); setupopt(arg_tcp_bs); \
    setupopt(arg_bs); setupopt(arg_p); setupopt(arg_notpt); \
    setupopt(arg_nodcau);

static globus_bool_t globus_l_globus_url_copy_ctrlc = GLOBUS_FALSE;
static globus_bool_t globus_l_globus_url_copy_ctrlc_handled = GLOBUS_FALSE;
static globus_bool_t verbose_flag = GLOBUS_FALSE;

/*
#define GLOBUS_BUILD_WITH_NETLOGGER 1
*/
/******************************************************************************
Function: main()
Description:
Parameters:
Returns:
******************************************************************************/
int
main(int argc, char **argv)
{
    char *                             program           = GLOBUS_NULL;
    globus_bool_t                      ret_val           = GLOBUS_FALSE;
    globus_bool_t                      no_more_options   = GLOBUS_FALSE;
    globus_bool_t                      usage_error       = GLOBUS_FALSE;
    globus_bool_t                      ignore_ctrlc      = GLOBUS_FALSE;
    globus_bool_t                      source_is_stdin   = GLOBUS_FALSE;
    globus_bool_t                      dest_is_stdin     = GLOBUS_FALSE;
    globus_list_t *                    options_found     = GLOBUS_NULL;
    globus_list_t *                    list              = GLOBUS_NULL;
    globus_args_option_instance_t *    instance          = GLOBUS_NULL;
    unsigned long                      options           = 0UL;
    globus_io_handle_t *               source_io_handle  = GLOBUS_NULL;
    globus_io_handle_t *               dest_io_handle    = GLOBUS_NULL;
    globus_gass_transfer_requestattr_t * source_gass_attr = GLOBUS_NULL;
    globus_gass_transfer_requestattr_t * dest_gass_attr = GLOBUS_NULL;
    globus_ftp_client_operationattr_t *         source_ftp_attr = GLOBUS_NULL;
    globus_ftp_client_operationattr_t *         dest_ftp_attr = GLOBUS_NULL;
    globus_gass_copy_attr_t            source_gass_copy_attr;
    globus_gass_copy_attr_t            dest_gass_copy_attr;
    globus_gass_copy_url_mode_t        source_url_mode;
    globus_gass_copy_url_mode_t        dest_url_mode;
    int                                err;
    int                                block_size = 0;
    int                                tcp_buffer_size = 0;
    globus_ftp_control_tcpbuffer_t     tcp_buffer;
    int                                num_streams = 0;
    globus_ftp_control_parallelism_t   parallelism;
    globus_ftp_control_dcau_t          dcau;
    globus_bool_t                      no_dcau = GLOBUS_FALSE;
    globus_bool_t                      no_third_party_transfers = GLOBUS_FALSE;
    char *                             subject = GLOBUS_NULL;
    char *                             source_subject = GLOBUS_NULL;
    char *                             dest_subject = GLOBUS_NULL;
    char *                             sourceURL;
    char *                             destURL;
    globus_url_t		       source_url;
    globus_url_t		       dest_url;
    int                                fd_source =-1;
    int                                fd_dest   =-1;
    int                                nb_read;
    int                                nb_to_write;
    int                                nb_written;
    int                                rc=0;
    double                             start_time = 0;
    my_monitor_t                       monitor;
    globus_gass_copy_handle_t          gass_copy_handle;
    char                               buffer[64];
    char                               my_hostname[64];
    globus_result_t                    result;
    globus_netlogger_handle_t          gnl_handle;
    globus_ftp_client_handleattr_t     ftp_handleattr;
    globus_ftp_client_plugin_t         debug_plugin;
    globus_gass_copy_handleattr_t      gass_copy_handleattr;
    globus_io_attr_t                   io_attr;
    globus_bool_t                      ftp_handle_attr_used = GLOBUS_FALSE;
    globus_bool_t                      use_debug = GLOBUS_FALSE;

    err = globus_module_activate(GLOBUS_GASS_COPY_MODULE);
    if ( err != GLOBUS_SUCCESS )
    {
        globus_libc_fprintf(stderr, "Error %d, activating gass copy module\n",
            err);
        return 1;
    }
    err = globus_module_activate(GLOBUS_FTP_CLIENT_DEBUG_PLUGIN_MODULE);
    if ( err != GLOBUS_SUCCESS )
    {
        globus_libc_fprintf(stderr, "Error %d, activating ftp debug plugin module\n",
            err);
        return 1;
    }
    
    if (strrchr(argv[0],'/'))
        program = strrchr(argv[0],'/') + 1;
    else
        program = argv[0];

    globus_url_copy_i_args_init();

    if ( 0 > globus_args_scan( &argc,
                               &argv,
                               arg_num,
                               args_options,
			       "globus-url-copy",
			       &local_version,
                               oneline_usage,
                               long_usage,
                               &options_found,
                               GLOBUS_NULL   ) )  /* error on argument line */
    {
        globus_module_deactivate_all();
        exit(1);
    }

    /* globus_libc_fprintf(stdout, "after args scan\n"); */

    /* there must be 2 additional unflagged arguments:
     *     the source and destination URL's
     */
    if (argc > 3)
       globus_url_copy_l_args_error("too many url strings specified");
    if (argc < 3)
       globus_url_copy_l_args_error("source and dest url strings are required");

    sourceURL=globus_libc_strdup(argv[1]);
    destURL=globus_libc_strdup(argv[2]);

    for (list = options_found;
         !globus_list_empty(list);
         list = globus_list_rest(list))
    {
        instance = globus_list_first(list);

        switch(instance->id_number)
        {
        case arg_a:
            options |= GLOBUS_URL_COPY_ARG_ASCII;
            break;
        case arg_b:
            options |= GLOBUS_URL_COPY_ARG_BINARY;
            break;
        case arg_vb:
            verbose_flag = GLOBUS_TRUE;
            break;
        case arg_bs:
            block_size = atoi(instance->values[0]);
            break;
        case arg_tcp_bs:
            tcp_buffer_size = atoi(instance->values[0]);
            break;
        case arg_s:
            subject = globus_libc_strdup(instance->values[0]);
            break;
        case arg_ss:
            source_subject = globus_libc_strdup(instance->values[0]);
            break;
        case arg_ds:
            dest_subject = globus_libc_strdup(instance->values[0]);
            break;
	case arg_p:
	    num_streams = atoi(instance->values[0]);
	    break;
	case arg_notpt:
	    no_third_party_transfers = GLOBUS_TRUE;
	    break;
	case arg_nodcau:
	    no_dcau = GLOBUS_TRUE;
	    break;
	case arg_debugftp:
	    use_debug = GLOBUS_TRUE;
	    break;
        default:
            globus_url_copy_l_args_error_fmt("parse panic, arg id = %d",
                                       instance->id_number );
            break;
        }
    }
    
    globus_args_option_instance_list_free( &options_found );
    
    if ( (options & GLOBUS_URL_COPY_ARG_ASCII) &&
         (options & GLOBUS_URL_COPY_ARG_BINARY) )
    {
        globus_url_copy_l_args_error("option -ascii and -binary are exclusive");
    }

    /* All below transfer methods must be activated in case an attr structure
     * needs to be created.
     */
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);
    monitor.done = GLOBUS_FALSE;
    monitor.use_err = GLOBUS_FALSE;



    /*
     *  added for netlogger
     */
    globus_gass_copy_handleattr_init(&gass_copy_handleattr);
    globus_gass_copy_attr_init(&source_gass_copy_attr);
    globus_gass_copy_attr_init(&dest_gass_copy_attr);

    if(use_debug)
    {
        if(!ftp_handle_attr_used)
        {
            ftp_handle_attr_used = GLOBUS_TRUE;
            
            result = globus_ftp_client_handleattr_init(&ftp_handleattr);
            if(result != GLOBUS_SUCCESS)
            {
                fprintf(stderr, "Error: Unable to init ftp handle attr %s\n",
                    globus_object_printable_to_string(globus_error_get(result)));
    
                return 1;
            }
        }

        result = globus_ftp_client_debug_plugin_init(
            &debug_plugin,
            stderr,
            "debug");
        if(result != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "Error: Unable to init debug plugin %s\n",
                globus_object_printable_to_string(globus_error_get(result)));

            return 1;
        }

        result = globus_ftp_client_handleattr_add_plugin(
            &ftp_handleattr,
            &debug_plugin);
        if(result != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "Error: Unable to register debug plugin %s\n",
                globus_object_printable_to_string(globus_error_get(result)));

            return 1;
        }
    }


#if defined(GLOBUS_BUILD_WITH_NETLOGGER)
    sprintf(buffer, "%d", getpid());
    globus_libc_gethostname(my_hostname, MAXHOSTNAMELEN);

    globus_netlogger_handle_init(
        &gnl_handle,
        my_hostname,
        "globus-url-copy",
        buffer);
    globus_netlogger_set_desc(
        &gnl_handle,
        "DISK");
    
    if(!ftp_handle_attr_used)
    {
        globus_ftp_client_handleattr_init(&ftp_handleattr);
        ftp_handle_attr_used = GLOBUS_TRUE;
    }

    globus_ftp_client_handleattr_set_netlogger(
        &ftp_handleattr,
        &gnl_handle);

    globus_io_fileattr_init(&io_attr);
    globus_io_attr_netlogger_set_handle(&io_attr, &gnl_handle);

    globus_gass_copy_attr_set_io(
        &source_gass_copy_attr,
        &io_attr);
    globus_gass_copy_attr_set_io(
        &dest_gass_copy_attr,
        &io_attr);
    
#endif
    
    if(ftp_handle_attr_used)
    {
        globus_gass_copy_handleattr_set_ftp_attr(
            &gass_copy_handleattr, &ftp_handleattr);
    }
    
    globus_gass_copy_handle_init(&gass_copy_handle, &gass_copy_handleattr);

    if (subject && !source_subject)
        source_subject = subject;

    if (subject && !dest_subject)
        dest_subject = subject;

    if (block_size > 0)
       globus_gass_copy_set_buffer_length(&gass_copy_handle, block_size);

    if(no_third_party_transfers)
      globus_gass_copy_set_no_third_party_transfers(&gass_copy_handle,
						    GLOBUS_TRUE);

    /* Verify that the source and destination are valid URLs */
    if (strcmp(sourceURL,"-"))
    {
		if (globus_url_parse(sourceURL, &source_url)
				!= GLOBUS_SUCCESS)
		{
				globus_url_copy_l_args_error_fmt(
				"can not parse sourceURL \"%s\"\n", sourceURL);
		}
        if (globus_gass_copy_get_url_mode(sourceURL, &source_url_mode)
            != GLOBUS_SUCCESS)
		{
			globus_url_copy_l_args_error_fmt(
			"failed to determine mode for sourceURL \"%s\"\n", sourceURL);
		}

        if (source_url_mode == GLOBUS_GASS_COPY_URL_MODE_FTP)
        {
            source_ftp_attr = globus_libc_malloc
                              (sizeof(globus_ftp_client_operationattr_t));
            globus_ftp_client_operationattr_init(source_ftp_attr);

            if (tcp_buffer_size > 0)
            {
                tcp_buffer.mode = GLOBUS_FTP_CONTROL_TCPBUFFER_FIXED;
                tcp_buffer.fixed.size = tcp_buffer_size;
                globus_ftp_client_operationattr_set_tcp_buffer(source_ftp_attr,
							       &tcp_buffer);
            }

			if (num_streams >= 1)
			{
				globus_ftp_client_operationattr_set_mode(
					source_ftp_attr,
					GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK);
				parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
				parallelism.fixed.size = num_streams;
				globus_ftp_client_operationattr_set_parallelism(
					source_ftp_attr,
					&parallelism);
			}

			if (source_subject  ||
				source_url.user ||
				source_url.password)
			{
				globus_ftp_client_operationattr_set_authorization(
					source_ftp_attr,
					GSS_C_NO_CREDENTIAL,
					source_url.user,
					source_url.password,
					NULL,
					source_subject);
	        }

			if (no_dcau)
			{
					dcau.mode = GLOBUS_FTP_CONTROL_DCAU_NONE;
					globus_ftp_client_operationattr_set_dcau(source_ftp_attr,
								&dcau);
			}

	        globus_gass_copy_attr_set_ftp(&source_gass_copy_attr,
                                          source_ftp_attr);
        }
        else if (source_url_mode == GLOBUS_GASS_COPY_URL_MODE_GASS)
        {
            source_gass_attr = globus_libc_malloc
                              (sizeof(globus_gass_transfer_requestattr_t));
            globus_gass_transfer_requestattr_init(source_gass_attr,
                                                  source_url.scheme);

            if (options & GLOBUS_URL_COPY_ARG_ASCII)
            {
                 globus_gass_transfer_requestattr_set_file_mode(
                      source_gass_attr,
                      GLOBUS_GASS_TRANSFER_FILE_MODE_TEXT);
            }
            else
            {
                 globus_gass_transfer_requestattr_set_file_mode(
                      source_gass_attr,
                      GLOBUS_GASS_TRANSFER_FILE_MODE_BINARY);
            }

            if (source_subject)
            {
                globus_gass_transfer_secure_requestattr_set_authorization(
                    source_gass_attr,
                    GLOBUS_GASS_TRANSFER_AUTHORIZE_SUBJECT,
                    source_subject);
            }

            globus_gass_copy_attr_set_gass(&source_gass_copy_attr,
                                           source_gass_attr);
        }
    }
    else
#ifndef TARGET_ARCH_WIN32
    {
        source_io_handle =(globus_io_handle_t *)
            globus_libc_malloc(sizeof(globus_io_handle_t));

        /* convert stdin to be a globus_io_handle */
        globus_io_file_posix_convert(fileno(stdin),
                                     GLOBUS_NULL,
                                     source_io_handle);
    }
#else
    {
        fprintf(stderr, "Error: On Windows, the source URL cannot be stdin\n" );
        globus_module_deactivate_all();
        exit(1);
    }
#endif

    if (strcmp(destURL,"-"))
    {
	if (globus_url_parse(destURL, &dest_url) != GLOBUS_SUCCESS)
	{
            globus_url_copy_l_args_error_fmt(
	        "can not parse destURL \"%s\"\n", destURL);
	}
        if (globus_gass_copy_get_url_mode(destURL, &dest_url_mode)
            != GLOBUS_SUCCESS)
	{
            globus_url_copy_l_args_error_fmt(
	        "failed to determine mode for destURL \"%s\"\n", destURL);
	}

        if (dest_url_mode == GLOBUS_GASS_COPY_URL_MODE_FTP)
        {
            dest_ftp_attr = globus_libc_malloc
                              (sizeof(globus_ftp_client_operationattr_t));
            globus_ftp_client_operationattr_init(dest_ftp_attr);

            if (tcp_buffer_size > 0)
            {
                tcp_buffer.mode = GLOBUS_FTP_CONTROL_TCPBUFFER_FIXED;
                tcp_buffer.fixed.size = tcp_buffer_size;
                globus_ftp_client_operationattr_set_tcp_buffer(dest_ftp_attr,
							       &tcp_buffer);
            }

	    if (num_streams >= 1)
	    {
		globus_ftp_client_operationattr_set_mode(
		    dest_ftp_attr,
		    GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK);
		parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
		parallelism.fixed.size = num_streams;
		globus_ftp_client_operationattr_set_parallelism(dest_ftp_attr,
								&parallelism);
	    }

            if (dest_subject  ||
                dest_url.user ||
                dest_url.password)
            {
                globus_ftp_client_operationattr_set_authorization(
		    dest_ftp_attr,
		    GSS_C_NO_CREDENTIAL,
		    dest_url.user,
		    dest_url.password,
		    dest_url.user,
		    dest_subject);
            }

	    if (no_dcau)
	    {
                dcau.mode = GLOBUS_FTP_CONTROL_DCAU_NONE;
		globus_ftp_client_operationattr_set_dcau(dest_ftp_attr,
							  &dcau);
	    }
	    
            globus_gass_copy_attr_set_ftp(&dest_gass_copy_attr,
                                          dest_ftp_attr);
        }
        else if (dest_url_mode == GLOBUS_GASS_COPY_URL_MODE_GASS)
        {
            dest_gass_attr = globus_libc_malloc
                              (sizeof(globus_gass_transfer_requestattr_t));
            globus_gass_transfer_requestattr_init(dest_gass_attr,
                                                  dest_url.scheme);

            if (options & GLOBUS_URL_COPY_ARG_ASCII)
            {
                 globus_gass_transfer_requestattr_set_file_mode(
                      dest_gass_attr,
                      GLOBUS_GASS_TRANSFER_FILE_MODE_TEXT);
            }
            else
            {
                 globus_gass_transfer_requestattr_set_file_mode(
                      dest_gass_attr,
                      GLOBUS_GASS_TRANSFER_FILE_MODE_BINARY);
            }

            if (dest_subject)
            {
                globus_gass_transfer_secure_requestattr_set_authorization(
                    dest_gass_attr,
                    GLOBUS_GASS_TRANSFER_AUTHORIZE_SUBJECT,
                    dest_subject);
            }

            globus_gass_copy_attr_set_gass(&dest_gass_copy_attr,
                                           dest_gass_attr);
        }
    }
    else
#ifndef TARGET_ARCH_WIN32
    {
        dest_io_handle =(globus_io_handle_t *)
            globus_libc_malloc(sizeof(globus_io_handle_t));

        /* convert stdin to be a globus_io_handle */
        globus_io_file_posix_convert(fileno(stdout),
                                     GLOBUS_NULL,
                                     dest_io_handle);
    }
#else
    {
        fprintf(stderr, "Error: On Windows, the destination URL cannot be stdout\n" );
        globus_module_deactivate_all();
        exit(1);
    }
#endif

    if (source_io_handle && dest_io_handle)
    {
        globus_url_copy_l_args_error("The sourceURL cannot be stdin and the destURL be stdout");
    }

#ifndef TARGET_ARCH_WIN32
    globus_l_globus_url_copy_signal(SIGINT,
                              globus_l_globus_url_copy_sigint_handler);
#endif

#   if defined(BUILD_LITE)
    {
        globus_reltime_t          delay_time;
        globus_reltime_t          period_time;

        GlobusTimeReltimeSet(delay_time, 0, 0);
        GlobusTimeReltimeSet(period_time, 0, 500000);
        globus_callback_register_periodic(
            &globus_l_callback_handle,
            &delay_time,
            &period_time,
            globus_l_globus_url_copy_signal_wakeup,
            GLOBUS_NULL);
    }
#   endif

    if (verbose_flag)
    {
        result = globus_gass_copy_register_performance_cb(
            &gass_copy_handle,
            globus_l_gass_copy_performance_cb,
            GLOBUS_NULL);

        if (result != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "Error: Unable to register performance handler %s\n",
                    globus_object_printable_to_string(globus_error_get(result)));

            fprintf(stderr, "Continuing without performance info\n");
        }
    }

    if (source_io_handle)
    {
        result = globus_gass_copy_register_handle_to_url(
                     &gass_copy_handle,
                     source_io_handle,
                     destURL,
                     &dest_gass_copy_attr,
                     globus_l_url_copy_monitor_callback,
                     (void *) &monitor);
    }
    else if (dest_io_handle)
    {
        result = globus_gass_copy_register_url_to_handle(
                     &gass_copy_handle,
                     sourceURL,
                     &source_gass_copy_attr,
                     dest_io_handle,
                     globus_l_url_copy_monitor_callback,
                     (void *) &monitor);
    }
    else
    {
        result = globus_gass_copy_register_url_to_url(
                     &gass_copy_handle,
                     sourceURL,
                     &source_gass_copy_attr,
                     destURL,
                     &dest_gass_copy_attr,
                     globus_l_url_copy_monitor_callback,
                     (void *) &monitor);
    }

    if (result != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "error: %s\n",
                globus_object_printable_to_string(globus_error_get(result)));
        globus_mutex_destroy(&monitor.mutex);
        globus_cond_destroy(&monitor.cond);
        exit(1);
    }

    globus_mutex_lock(&monitor.mutex);

    while(!monitor.done)
    {
        globus_cond_wait(&monitor.cond, &monitor.mutex);

        if(globus_l_globus_url_copy_ctrlc &&
          (!globus_l_globus_url_copy_ctrlc_handled))
        {
            printf("Cancelling copy...\n");
            globus_l_globus_url_copy_remove_cancel_poll();
            globus_gass_copy_cancel(&gass_copy_handle,
                                    globus_l_url_copy_cancel_callback,
                                    (void *) &monitor);
            globus_l_globus_url_copy_ctrlc_handled = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(&monitor.mutex);
    
    if (verbose_flag)
    {
        globus_libc_fprintf(stdout, "\n");
    }

    if (monitor.use_err)
    {
        fprintf(stderr, "error: %s\n",
                globus_object_printable_to_string(monitor.err));
        globus_object_free(monitor.err);
	ret_val = GLOBUS_TRUE;
    }

    globus_gass_copy_handle_destroy(&gass_copy_handle);

    if (!source_io_handle)
        globus_url_destroy(&source_url);

    if (!dest_io_handle)
        globus_url_destroy(&dest_url);
    
    globus_module_deactivate_all();

    return ret_val;

} /* main() */

/******************************************************************************
Function: globus_l_url_copy_monitor_callback()
Description:
Parameters:
Returns:
******************************************************************************/
static void
globus_l_url_copy_monitor_callback(void * callback_arg,
    globus_gass_copy_handle_t * handle,
    globus_object_t * error)
{
    my_monitor_t *               monitor;
    globus_bool_t                use_err = GLOBUS_FALSE;
    monitor = (my_monitor_t * )  callback_arg;

    if (error != GLOBUS_SUCCESS)
    {
/*
        fprintf(stderr, " url copy error: %s\n",
                globus_object_printable_to_string(error));
*/
        use_err = GLOBUS_TRUE;
    }

    globus_mutex_lock(&monitor->mutex);
    monitor->done = GLOBUS_TRUE;
    if (use_err)
    {
        monitor->use_err = GLOBUS_TRUE;
        monitor->err = globus_object_copy(error);
    }
    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);

    return;
} /* globus_l_url_copy_monitor_callback() */


/******************************************************************************
Function: globus_l_url_copy_cancel_callback()
Description:
Parameters:
Returns:
******************************************************************************/
static void
globus_l_url_copy_cancel_callback(void * callback_arg,
    globus_gass_copy_handle_t * handle,
    globus_object_t * error)
{
    my_monitor_t *               monitor;
    globus_bool_t                use_err = GLOBUS_FALSE;
    monitor = (my_monitor_t * )  callback_arg;

    if (error != GLOBUS_SUCCESS)
    {
        use_err = GLOBUS_TRUE;
    }

    globus_mutex_lock(&monitor->mutex);
    monitor->done = GLOBUS_TRUE;
    if (use_err)
    {
        monitor->use_err = GLOBUS_TRUE;
        monitor->err = globus_object_copy(error);
    }
    globus_cond_signal(&monitor->cond);
    globus_mutex_unlock(&monitor->mutex);

    return;
} /* globus_l_url_copy_cancel_callback() */


/******************************************************************************
Function: globus_l_globus_url_copy_sigint_handler()
Description:
Parameters:
Returns:
******************************************************************************/
static RETSIGTYPE
globus_l_globus_url_copy_sigint_handler(int dummy)
{
    globus_l_globus_url_copy_ctrlc = GLOBUS_TRUE;

#ifndef TARGET_ARCH_WIN32
    /* don't trap any more signals */
    globus_l_globus_url_copy_signal(SIGINT, SIG_DFL);
#endif

} /* globus_l_globus_url_copy_sigint_handler() */


/******************************************************************************
Function: globus_l_globus_url_copy_signal_wakeup()
Description:
Parameters:
Returns:
******************************************************************************/
static 
void
globus_l_globus_url_copy_signal_wakeup(
    void *                              user_args)
{
    if(globus_l_globus_url_copy_ctrlc)
    {
        globus_callback_signal_poll();
    }
} /* globus_l_globus_url_copy_signal_wakeup() */


/******************************************************************************
Function: globus_l_globus_url_copy_signal()
Description:
Parameters:
Returns:
******************************************************************************/
#ifndef TARGET_ARCH_WIN32
static int
globus_l_globus_url_copy_signal(int signum, RETSIGTYPE (*func)(int))
{
    struct sigaction act;

    memset(&act, '\0', sizeof(struct sigaction));
    sigemptyset(&(act.sa_mask));
    act.sa_handler = func;
    act.sa_flags = 0;

    return sigaction(signum, &act, GLOBUS_NULL);
} /* globus_l_globus_url_copy_signal() */
#endif

/******************************************************************************
Function: globus_l_gass_copy_performance_cb()
Description:
Parameters:
Returns:
******************************************************************************/
static
void
globus_l_gass_copy_performance_cb(
    void *                                          user_arg,
    globus_gass_copy_handle_t *                     handle,
    globus_off_t                                    total_bytes,
    float                                           instantaneous_throughput,
    float                                           avg_throughput)
{
    globus_libc_fprintf(stdout,
        " %12" GLOBUS_OFF_T_FORMAT " bytes %12.2f KB/sec avg %12.2f KB/sec inst\r",
        total_bytes,
        avg_throughput / 1024,
        instantaneous_throughput / 1024);
    fflush(stdout);
}

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
#include "globus_ftp_client_restart_plugin.h"
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

typedef struct 
{
    char *                              src_url;
    char *                              dst_url;
} globus_l_guc_src_dst_pair_t;

typedef struct 
{
    globus_fifo_t                       user_url_list;
    globus_fifo_t                       expanded_url_list;
    char *                              source_subject;
    char *                              dest_subject;
    unsigned long                       options;
    globus_size_t                       block_size;
    globus_size_t                       tcp_buffer_size;
    int                                 num_streams;
    globus_bool_t                       no_3pt;
    globus_bool_t                       no_dcau;
    globus_bool_t                       encrypt_data;
    globus_bool_t                       cancelled;
    globus_bool_t                       recurse;
    int                                 restart_retries;
    int                                 restart_interval;
    int                                 restart_timeout;
    globus_bool_t			striped;

    /* the need for 2 is due to the fact that gass copy is
     * not copying attributes
     */
    globus_ftp_client_operationattr_t   source_ftp_attr;
    globus_ftp_client_operationattr_t   dest_ftp_attr;

    globus_gass_transfer_requestattr_t  source_gass_attr;
    globus_gass_transfer_requestattr_t  dest_gass_attr;
} globus_l_guc_info_t;

/*****************************************************************************
                          Module specific prototypes
*****************************************************************************/

static globus_callback_handle_t          globus_l_callback_handle;

static 
void
globus_l_url_copy_monitor_callback(void * callback_arg,
                                    globus_gass_copy_handle_t * handle,
                                    globus_object_t * result);

static 
void
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

static
int
globus_l_guc_parse_arguments(
    int                                             argc,
    char **                                         argv,
    globus_l_guc_info_t *                           guc_info);

static
globus_result_t
globus_l_guc_expand_urls(
    globus_l_guc_info_t *                        guc_info,
    globus_gass_copy_attr_t *                    gass_copy_attr,   
    globus_gass_copy_handle_t *                  gass_copy_handle);

static
globus_result_t
globus_l_guc_expand_single_url(
    globus_l_guc_src_dst_pair_t *                url_pair,
    globus_l_guc_info_t *                        guc_info,
    globus_gass_copy_attr_t *                    gass_copy_attr,   
    globus_gass_copy_handle_t *                  gass_copy_handle);

static
int
globus_l_guc_transfer_files(
    globus_l_guc_info_t *                        guc_info,
    globus_gass_copy_attr_t *                    source_gass_copy_attr,   
    globus_gass_copy_attr_t *                    dest_gass_copy_attr,   
    globus_gass_copy_handle_t *                  gass_copy_handle);

static
int
globus_l_guc_init_gass_copy_handle(
    globus_gass_copy_handle_t *                     gass_copy_handle,
    globus_l_guc_info_t *                           guc_info);

static
int
globus_l_guc_gass_attr_init(
    globus_gass_copy_attr_t *                       gass_copy_attr,
    globus_gass_transfer_requestattr_t *            gass_attr,
    globus_ftp_client_operationattr_t *             ftp_attr,
    globus_l_guc_info_t *                           guc_info,
    char *                                          url,
    char *                                          subject);

static
globus_io_handle_t *
globus_l_guc_get_io_handle(
    char *                                          url,
    int                                             std_fileno);

static
void
globus_l_guc_info_destroy(
    globus_l_guc_info_t *                           guc_info);
    
static
void
globus_l_guc_destroy_url_list(
    globus_fifo_t *                     url_list);


/*****************************************************************************
                          Module specific variables
*****************************************************************************/

#define GLOBUS_URL_COPY_ARG_ASCII       1
#define GLOBUS_URL_COPY_ARG_BINARY      2
#define GLOBUS_URL_COPY_ARG_VERBOSE     4

const char * oneline_usage =
"globus-url-copy [-help | -usage] [-version[s]] [-vb] [-dbg] [-b | -a]\n"
"                        [-q] [-r] [-rst] [-f <filename>]\n"
"                        [-s <subject>] [-ds <subject>] [-ss <subject>]\n"
"                        [-tcp-bs <size>] [-bs <size>] [-p <parallelism>]\n"
"                        [-notpt] [-nodcau]\n"
"                        <sourceURL> <destURL>";

const char * long_usage =
"\nglobus-url-copy [options] <sourceURL> <destURL>\n"
"globus-url-copy [options] -f <filename>\n\n"

"<sourceURL> may contain wildcard characters * ? and [ ] character ranges.\n"
"If <sourceURL> is a directory, all files within that directory will be copied.\n"
"<destURL> must be a directory if multiple files are being copied.\n"
"Any url specifying a directory must end with a /\n\n"

"OPTIONS\n"
"\t -help | -usage\n"
"\t      Print help\n"
"\t -version\n"
"\t      Print the version of this program\n"
"\t -versions\n"
"\t      Print the versions of all modules that this program uses\n"
"\t -a | -ascii\n"
"\t      Convert the file to/from ASCII format to/from local file format\n"
"\t -b | -binary\n"
"\t      Do not apply any conversion to the files. *default*\n"
"\t -f <filename>\n" 
"\t      Read a list of url pairs from filename.  Each line should contain\n"
"\t      <sourceURL> <destURL>\n"
"\t      Enclose URLs with spaces in double qoutes (\").\n"
"\t      Blank lines and lines beginning with # will be ignored.\n"
"\t -r | -recurse\n" 
"\t      Copy files in subdirectories\n"

"\t -q | -quiet \n"
"\t      Suppress all output for successful operation\n"
"\t -vb | -verbose \n"
"\t      During the transfer, display the number of bytes transferred\n"
"\t      and the transfer rate per second\n"
"\t -dbg | -debugftp \n"
"\t      Debug ftp connections.  Prints control channel communication\n"
"\t      to stderr\n"

"\t -rst | -restart \n"
"\t      Restart failed ftp operations.\n"
"\t -rst-retries <retries>\n"
"\t      The maximum number of times to retry the operation before giving\n"
"\t      up on the transfer.  Use 0 for infinite.  Default is 5.\n"
"\t -rst-interval <seconds>\n"
"\t      The interval in seconds to wait after a failure before retrying\n"
"\t      the transfer.  Use 0 for an exponential backoff.  Default is 0.\n"
"\t -rst-timeout <seconds>\n"
"\t      Maximum time after a failure to keep retrying.  Use 0 for no\n" 
"\t      timeout.  Default is 0.\n"

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
"\t      specify the number of parallel data connections should be used.\n"

"\t -notpt | -no-third-party-transfers\n"
"\t      turn third-party transfers off (on by default)\n"
"\t -nodcau | -no-data-channel-authentication\n"
"\t      turn off data channel authentication for ftp transfers\n"
"\t -dcenc | -data-channel-encryption\n"
"\t      turn on data channel encryption for ftp transfers\n"
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
    int  res = (atoi(value) < 0);
    if (res)
        *errmsg = strdup("argument is not a positive integer");
    return res;
}

enum 
{ 
    arg_a = 1, 
    arg_b, 
    arg_s, 
    arg_p, 
    arg_f, 
    arg_vb,
    arg_q, 
    arg_debugftp, 
    arg_restart,
    arg_rst_retries, 
    arg_rst_interval, 
    arg_rst_timeout, 
    arg_ss, 
    arg_ds, 
    arg_tcp_bs,
    arg_bs, 
    arg_notpt, 
    arg_nodcau,
    arg_encrypt_data,
    arg_recurse,
    arg_striped,
    arg_num = arg_striped
};

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
flagdef(arg_q, "-q", "-quiet");
flagdef(arg_vb, "-vb", "-verbose");
flagdef(arg_debugftp, "-dbg", "-debugftp");
flagdef(arg_restart, "-rst", "-restart");
flagdef(arg_notpt, "-notpt", "-no-third-party-transfers");
flagdef(arg_nodcau, "-nodcau", "-no-data-channel-authentication");
flagdef(arg_encrypt_data, "-dcenc", "-data-channel-encryption");
flagdef(arg_recurse, "-r", "-recurse");
flagdef(arg_striped, "-stripe", "-striped");

oneargdef(arg_f, "-f", "-filename", GLOBUS_NULL, GLOBUS_NULL);
oneargdef(arg_bs, "-bs", "-block-size", test_integer, GLOBUS_NULL);
oneargdef(arg_tcp_bs, "-tcp-bs", "-tcp-buffer-size", test_integer, GLOBUS_NULL);
oneargdef(arg_p, "-p", "-parallel", test_integer, GLOBUS_NULL);
oneargdef(arg_s, "-s", "-subject", GLOBUS_NULL, GLOBUS_NULL);
oneargdef(arg_ss, "-ss", "-source-subject", GLOBUS_NULL, GLOBUS_NULL);
oneargdef(arg_ds, "-ds", "-dest-subject", GLOBUS_NULL, GLOBUS_NULL);
oneargdef(arg_rst_retries, "-rst-retries", "-restart-retries", test_integer, GLOBUS_NULL);
oneargdef(arg_rst_interval, "-rst-interval", "-restart-interval", test_integer, GLOBUS_NULL);
oneargdef(arg_rst_timeout, "-rst-timeout", "-restart-timeout", test_integer, GLOBUS_NULL);


static globus_args_option_descriptor_t args_options[arg_num];

#define setupopt(id) args_options[id-1] = defname(id)

#define globus_url_copy_i_args_init()   \
    setupopt(arg_a);                    \
    setupopt(arg_f);                    \
    setupopt(arg_b);                    \
    setupopt(arg_s);                    \
    setupopt(arg_q);                    \
    setupopt(arg_vb);                   \
    setupopt(arg_debugftp);             \
    setupopt(arg_restart);              \
    setupopt(arg_rst_retries);          \
    setupopt(arg_rst_interval);         \
    setupopt(arg_rst_timeout);          \
    setupopt(arg_ss);                   \
    setupopt(arg_ds);                   \
    setupopt(arg_tcp_bs);               \
    setupopt(arg_bs);                   \
    setupopt(arg_p);                    \
    setupopt(arg_notpt);                \
    setupopt(arg_nodcau);               \
    setupopt(arg_encrypt_data);         \
    setupopt(arg_recurse);		\
    setupopt(arg_striped);

static globus_bool_t globus_l_globus_url_copy_ctrlc = GLOBUS_FALSE;
static globus_bool_t globus_l_globus_url_copy_ctrlc_handled = GLOBUS_FALSE;
static globus_bool_t g_verbose_flag = GLOBUS_FALSE;
static globus_bool_t g_quiet_flag = GLOBUS_FALSE;
static globus_bool_t g_use_debug = GLOBUS_FALSE;
static globus_bool_t g_use_restart = GLOBUS_FALSE;

#if defined(GLOBUS_BUILD_WITH_NETLOGGER)
    globus_netlogger_handle_t                       gnl_handle;
#endif

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
    globus_bool_t                           ret_val = GLOBUS_FALSE;
    globus_gass_copy_attr_t                 source_gass_copy_attr;
    globus_gass_copy_attr_t                 dest_gass_copy_attr;
    int                                     err;
    globus_gass_copy_handle_t               gass_copy_handle;
    globus_result_t                         result;
    globus_l_guc_info_t                     guc_info;

#if defined(GLOBUS_BUILD_WITH_NETLOGGER)
    globus_netlogger_handle_t               gnl_handle;
    globus_io_attr_t                        io_attr;
    char                                    my_hostname[64];
    char                                    buffer[64];
#endif

    err = globus_module_activate(GLOBUS_GASS_COPY_MODULE);
    if ( err != GLOBUS_SUCCESS )
    {
        globus_libc_fprintf(stderr, 
            "Error %d, activating gass copy module\n",
            err);
        return 1;
    }
    err = globus_module_activate(GLOBUS_FTP_CLIENT_DEBUG_PLUGIN_MODULE);
    if ( err != GLOBUS_SUCCESS )
    {
        globus_libc_fprintf(stderr, 
            "Error %d, activating ftp debug plugin module\n",
            err);
        return 1;
    }
    err = globus_module_activate(GLOBUS_FTP_CLIENT_RESTART_PLUGIN_MODULE);
    if ( err != GLOBUS_SUCCESS )
    {
        globus_libc_fprintf(stderr, 
            "Error %d, activating ftp restart plugin module\n",
            err);
        return 1;
    }



    globus_fifo_init(&guc_info.user_url_list);
    globus_fifo_init(&guc_info.expanded_url_list);

    globus_gass_copy_attr_init(&source_gass_copy_attr);
    globus_gass_copy_attr_init(&dest_gass_copy_attr);


#   if defined(GLOBUS_BUILD_WITH_NETLOGGER)
    {
        globus_io_fileattr_init(&io_attr);
        globus_io_attr_netlogger_set_handle(&io_attr, &gnl_handle);

        globus_gass_copy_attr_set_io(
            &source_gass_copy_attr,
            &io_attr);
        globus_gass_copy_attr_set_io(
            &dest_gass_copy_attr,
            &io_attr);
    }
#   endif

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

    /* parse user parms */
    if(globus_l_guc_parse_arguments(
           argc,
           argv,
           &guc_info) != 0)
    {
        return 1;
    }

    /* initialize gass copy handle */
    if(globus_l_guc_init_gass_copy_handle(
           &gass_copy_handle, 
           &guc_info) != 0)
    {
        fprintf(stderr, "Failed to initialize handle.\n");
        return 1;
    }

    /* expand globbed urls */
    result = globus_l_guc_expand_urls(
                 &guc_info,
                 &source_gass_copy_attr,       
                 &gass_copy_handle);
    if(result != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error: unable to expand url: %s\n",
                globus_object_printable_to_string(globus_error_get(result)));
        return 1;
    }
    
    if(globus_fifo_size(&guc_info.expanded_url_list) < 1 )
    {
        fprintf(stderr, "No files matched the source url.\n");
        return 1;
    }


    if((ret_val = globus_l_guc_transfer_files(
                      &guc_info,
                      &source_gass_copy_attr,   
                      &dest_gass_copy_attr,   
                      &gass_copy_handle)) != 0)
    {
        fprintf(stderr, 
            "There was an error with one or more file transfers.\n");
    }

    globus_l_guc_destroy_url_list(&guc_info.user_url_list);
    globus_l_guc_destroy_url_list(&guc_info.expanded_url_list);

    globus_gass_copy_handle_destroy(&gass_copy_handle);

    globus_l_guc_info_destroy(&guc_info);

    globus_module_deactivate_all();

    return ret_val;

} /* main() */



/******************************************************************************
Function: globus_l_url_copy_monitor_callback()
Description:
Parameters:
Returns:
******************************************************************************/
static 
void
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
static 
int
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
        " %12" GLOBUS_OFF_T_FORMAT 
        " bytes %12.2f KB/sec avg %12.2f KB/sec inst\r",
        total_bytes,
        avg_throughput / 1024,
        instantaneous_throughput / 1024);
    fflush(stdout);
}

static 
void
globus_l_guc_info_destroy(
    globus_l_guc_info_t *                    guc_info)
{
/*
    find out how to do this safely

    if(guc_info->source_ftp_attr != GLOBUS_NULL)
        globus_ftp_client_operationattr_destroy(&guc_info->source_ftp_attr);
    if(guc_info->dest_ftp_attr != GLOBUS_NULL)
        globus_ftp_client_operationattr_destroy(&guc_info->dest_ftp_attr);
*/
    if(guc_info->source_subject)
    {
        globus_free(guc_info->source_subject);
    }
    if(guc_info->dest_subject)
    {
        globus_free(guc_info->dest_subject);
    }

    /* destroy the list */
}

static
int
globus_l_guc_parse_file(
    char *                                          file_name, 
    globus_fifo_t *                                 user_url_list)
{
    FILE *                                          fptr;
    char                                            line[1024];
    char                                            src_url[512];
    char                                            dst_url[512];
    globus_l_guc_src_dst_pair_t *                   ent;
    char *                                          p;
    int                                             url_len;
    int                                             line_num = 0;
    int                                             rc;
    globus_bool_t                                   stdin_used = GLOBUS_FALSE;

    fptr = fopen(file_name, "r");
    if(fptr == NULL)
    {
        return -1;
    }

    while(fgets(line, sizeof(line), fptr) != NULL)
    {
        line_num++;
        p = line;
        url_len = 0;
                
        while(*p && isspace(*p))
        {
            p++;
        }
        if(*p == '\0')
        {
            continue;
        }

        if(*p == '#')
        {
            continue;
        }
        
        if(*p == '"')
        {
            rc = sscanf(p, "\"%[^\"]\"", src_url);
            url_len = 2;
        }
        else
        {
            rc = sscanf(p, "%s", src_url);
        } 
        
        if(rc != 1)
        {   
            goto error_parse;
        }
        
        url_len += strlen(src_url);
        p = p + url_len;
       
        url_len = 0;
        while(*p && isspace(*p))
        {
            p++;
        }

        if(*p == '"')
        {
            rc = sscanf(p, "\"%[^\"]\"", dst_url);
            url_len = 2;
        }
        else
        {
            rc = sscanf(p, "%s", dst_url);
        }        

        if(rc != 1)
        {   
            goto error_parse;
        }
        
        url_len += strlen(dst_url);
        p = p + url_len;
        
        while(*p && isspace(*p))
        {
            p++;
        }
        if(*p && !isspace(*p))
        {
            goto error_parse;
        }
        
                
        if(strcmp(src_url, "-") == 0 && strcmp(dst_url, "-") == 0)
        {
            fprintf(stderr, "stdin and stdout cannot be used together.\n");
            goto error_parse;
        }
        if(strcmp(src_url, "-") == 0)
        {
            if(stdin_used)
            {
                fprintf(stderr, "Only 1 stdin can be used.\n");
                goto error_parse;
            }
            stdin_used = GLOBUS_TRUE;
        }

        ent = (globus_l_guc_src_dst_pair_t *)
                globus_malloc(sizeof(globus_l_guc_src_dst_pair_t));
        ent->src_url = globus_libc_strdup(src_url);
        ent->dst_url = globus_libc_strdup(dst_url);
        globus_fifo_enqueue(user_url_list, ent);
    }

    fclose(fptr);

    return 0;
    
error_parse:
    fclose(fptr);
    fprintf(stderr, "Problem parsing url list: line %d\n", line_num);
    return -1;
 
}


static
int
globus_l_guc_transfer_files(
    globus_l_guc_info_t *                        guc_info,
    globus_gass_copy_attr_t *                    source_gass_copy_attr,   
    globus_gass_copy_attr_t *                    dest_gass_copy_attr,   
    globus_gass_copy_handle_t *                  gass_copy_handle)
{
    globus_io_handle_t *                         source_io_handle = GLOBUS_NULL;
    globus_io_handle_t *                         dest_io_handle = GLOBUS_NULL;
    my_monitor_t                                 monitor;
    char *                                       src_url;
    char *                                       dst_url;
    char *                                       src_filename;
    char *                                       dst_filename;
    char *                                       src_url_base = GLOBUS_NULL;
    char *                                       dst_url_base = GLOBUS_NULL;
    int                                          src_url_base_len;
    int                                          dst_url_base_len;
    globus_l_guc_src_dst_pair_t *                url_pair;
    globus_result_t                              result;
    int                                          ret_val = 0;
    globus_bool_t                                new_url;
    globus_bool_t                                dst_is_dir;
        
    
    globus_mutex_init(&monitor.mutex, GLOBUS_NULL);
    globus_cond_init(&monitor.cond, GLOBUS_NULL);

    guc_info->cancelled = GLOBUS_FALSE;

    /* loop through pair queue transferring files */
    while(!globus_fifo_empty(&guc_info->expanded_url_list) &&
          !guc_info->cancelled)
    {        
    
        /* something strange in gass copy forces the need for this */
        globus_ftp_client_operationattr_init(&guc_info->source_ftp_attr);
        globus_ftp_client_operationattr_init(&guc_info->dest_ftp_attr);

        url_pair = (globus_l_guc_src_dst_pair_t *)
                    globus_fifo_dequeue(&guc_info->expanded_url_list);
        src_url = url_pair->src_url;
        dst_url = url_pair->dst_url;
        
        if(dst_url[strlen(dst_url) - 1] == '/')
        {
            dst_is_dir = GLOBUS_TRUE;   
        }
        else
        {
            dst_is_dir = GLOBUS_FALSE;
        }   
            
        /* reset the monitor */
        monitor.done = GLOBUS_FALSE;
        monitor.use_err = GLOBUS_FALSE;

        /* when creating the list the urls are check for validity */
        source_io_handle = globus_l_guc_get_io_handle(src_url, fileno(stdin));
        dest_io_handle = globus_l_guc_get_io_handle(dst_url, fileno(stdout));

        /*
         *  we must setup attrs for every gass url.  if url is not
         *  gass handled the function will just return
         */
        if(source_io_handle == NULL)
        {
            globus_l_guc_gass_attr_init(
                source_gass_copy_attr,
                &guc_info->source_gass_attr,
                &guc_info->source_ftp_attr,
                guc_info,
                src_url,
                guc_info->source_subject);
        } 
        if(dest_io_handle == NULL)
        {
            globus_l_guc_gass_attr_init(
                dest_gass_copy_attr,
                &guc_info->dest_gass_attr,
                &guc_info->dest_ftp_attr,
                guc_info,
                dst_url,
                guc_info->dest_subject);
        }

        if (source_io_handle)
        {
            result = globus_gass_copy_register_handle_to_url(
                         gass_copy_handle,
                         source_io_handle,
                         dst_url,
                         dest_gass_copy_attr,
                         globus_l_url_copy_monitor_callback,
                         (void *) &monitor);
        }
        else if (dest_io_handle)
        {
            result = globus_gass_copy_register_url_to_handle(
                         gass_copy_handle,
                         src_url,
                         source_gass_copy_attr,
                         dest_io_handle,
                         globus_l_url_copy_monitor_callback,
                         (void *) &monitor);
        }
        else
        {
            if (!g_quiet_flag)
            {
                if(dst_is_dir)
                {
                    src_filename = strrchr(src_url, '/');               
                    while(src_filename > src_url && *src_filename == '/')
                    {
                        src_filename--;
                    }
                    while(src_filename > src_url && *src_filename != '/')
                    {
                        src_filename--;
                    }
                    src_filename++;
                    
                    dst_filename = strrchr(dst_url, '/');               
                    while(dst_filename > dst_url && *dst_filename == '/')
                    {
                        dst_filename--;
                    }
                    while(dst_filename > dst_url && *dst_filename != '/')
                    {
                        dst_filename--;
                    }
                    dst_filename++;
                }
                else
                {
                    src_filename = strrchr(src_url, '/') + 1;
                    dst_filename = strrchr(dst_url, '/') + 1;
                }

                
                if(src_url_base == GLOBUS_NULL || 
                    src_filename - src_url != src_url_base_len ||
                    strncmp(src_url, src_url_base, src_filename - src_url))
                {
                    if(src_url_base != GLOBUS_NULL)
                    {
                        globus_free(src_url_base);
                    }
                    src_url_base = globus_libc_strdup(src_url);

                    src_url_base_len = src_filename - src_url;
                    src_url_base[src_url_base_len] = '\0';
                    new_url = GLOBUS_TRUE;
                }
                else
                {
                    new_url = GLOBUS_FALSE;
                }
                
                if(dst_url_base == GLOBUS_NULL || 
                    dst_filename - dst_url != dst_url_base_len ||
                    strncmp(dst_url, dst_url_base, dst_filename - dst_url))
                {
                    if(dst_url_base != GLOBUS_NULL)
                    {
                        globus_free(dst_url_base);
                    }
                    dst_url_base = globus_libc_strdup(dst_url);

                    dst_url_base_len = dst_filename - dst_url;
                    dst_url_base[dst_url_base_len] = '\0';
                    new_url = GLOBUS_TRUE;
                }
                
                if(new_url)
                {
                    globus_libc_fprintf(stdout, "%s  -->  %s\n", 
                        src_url_base, 
                        dst_url_base);
                }
                
                if(!strcmp(src_filename, dst_filename))
                {
                    globus_libc_fprintf(stdout, "  %s\n", src_filename);
                }
                else
                {
                    globus_libc_fprintf(stdout, "  %s  ->  %s\n",
                        src_filename, dst_filename);
                }
            }
            
            if(dst_is_dir)
            {
                result = globus_l_guc_expand_single_url(
                     url_pair,
                     guc_info,
                     source_gass_copy_attr,       
                     gass_copy_handle);
                if(result != GLOBUS_SUCCESS)
                {
                    goto error_mkdir;
                }
                
                result = globus_gass_copy_mkdir(
                    gass_copy_handle,
                    dst_url,
                    dest_gass_copy_attr,
                    globus_l_url_copy_monitor_callback,
                    (void *) &monitor);
                    
                if(result != GLOBUS_SUCCESS)
                {
                    result = GLOBUS_SUCCESS;
                }
     
                monitor.done = GLOBUS_TRUE;
            }
            else
            {
                result = globus_gass_copy_register_url_to_url(
                     gass_copy_handle,
                     src_url,
                     source_gass_copy_attr,
                     dst_url,
                     dest_gass_copy_attr,
                     globus_l_url_copy_monitor_callback,
                     (void *) &monitor);
            }
        }        

        if (result != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "error: %s\n",
                    globus_object_printable_to_string(
                        globus_error_get(result)));
            globus_mutex_destroy(&monitor.mutex);
            globus_cond_destroy(&monitor.cond);
            exit(1);
        }

        globus_mutex_lock(&monitor.mutex);

        while(!monitor.done)
        {
            globus_cond_wait(&monitor.cond, &monitor.mutex);

            if(globus_l_globus_url_copy_ctrlc &&
               !globus_l_globus_url_copy_ctrlc_handled)
            {
                printf("\nCancelling copy...\n");
                guc_info->cancelled = GLOBUS_TRUE;
                globus_l_globus_url_copy_remove_cancel_poll();
                globus_gass_copy_cancel(
                    gass_copy_handle,
                    globus_l_url_copy_cancel_callback,
                    (void *) &monitor);
                globus_l_globus_url_copy_ctrlc_handled = GLOBUS_TRUE;
            }
        }
        globus_mutex_unlock(&monitor.mutex);
    	
	if(g_verbose_flag)
	{
	    printf("\n");
	}
	
        if (monitor.use_err)
        {
            fprintf(stderr, "error: %s\n",
                    globus_object_printable_to_string(monitor.err));
            fprintf(stderr, "failed to transfer %s to %s.\n",
                src_url,
                dst_url);
            globus_object_free(monitor.err);
            ret_val = 1;
        }
	
	
        if(source_io_handle)
        {
            globus_free(source_io_handle);
        }

        if(dest_io_handle)
        {
            globus_free(dest_io_handle);
        }
        globus_ftp_client_operationattr_destroy(&guc_info->source_ftp_attr);
        globus_ftp_client_operationattr_destroy(&guc_info->dest_ftp_attr);
        
        globus_free(url_pair->src_url);
        globus_free(url_pair->dst_url);
        globus_free(url_pair);

    }
    if(src_url_base)
    {
        globus_free(src_url_base);
    }
    if(dst_url_base)
    {
        globus_free(dst_url_base);
    }
    globus_cond_destroy(&monitor.cond);
    globus_mutex_destroy(&monitor.mutex);


    return ret_val;


error_mkdir:
    globus_cond_destroy(&monitor.cond);
    globus_mutex_destroy(&monitor.mutex);


    return ret_val;

}


static
int
globus_l_guc_parse_arguments(
    int                                             argc,
    char **                                         argv,
    globus_l_guc_info_t *                           guc_info)
{
    char *                                          program;
    globus_list_t *                                 options_found = NULL;
    char *                                          subject = NULL;
    char *                                          file_name = NULL;
    globus_args_option_instance_t *                 instance = NULL;
    globus_list_t *                                 list = NULL;
    globus_l_guc_src_dst_pair_t *                   ent;


    guc_info->no_3pt = GLOBUS_FALSE;
    guc_info->no_dcau = GLOBUS_FALSE;
    guc_info->encrypt_data = GLOBUS_FALSE;
    guc_info->recurse = GLOBUS_FALSE;
    guc_info->num_streams = 0;
    guc_info->tcp_buffer_size = 0;
    guc_info->block_size = 0;
    guc_info->options = 0UL;
    guc_info->source_subject = NULL;
    guc_info->dest_subject = NULL;
    guc_info->restart_retries = 5;
    guc_info->restart_interval = 0;
    guc_info->restart_timeout = 0;
    guc_info->striped = GLOBUS_FALSE;

    /* determine the program name */
    
    program = strrchr(argv[0],'/') + 1;
    if (!program)
    {
        program = argv[0];
    }
    
    globus_url_copy_i_args_init();

    if (globus_args_scan(
            &argc,
            &argv,
            arg_num,
            args_options,
            program,
            &local_version,
            oneline_usage,
            long_usage,
            &options_found,
            NULL) < 0)  /* error on argument line */
    {
        return -1;
    }
    
    for (list = options_found;
         !globus_list_empty(list);
         list = globus_list_rest(list))
    {
        instance = globus_list_first(list);

        switch(instance->id_number)
        {
        case arg_a:
            guc_info->options |= GLOBUS_URL_COPY_ARG_ASCII;
            break;
        case arg_b:
            guc_info->options |= GLOBUS_URL_COPY_ARG_BINARY;
            break;
        case arg_q:
            g_quiet_flag = GLOBUS_TRUE;
            break;
        case arg_vb:
            g_verbose_flag = GLOBUS_TRUE;
            break;
        case arg_bs:
            guc_info->block_size = atoi(instance->values[0]);
            break;
        case arg_f:
            file_name = globus_libc_strdup(instance->values[0]);
            break;
        case arg_tcp_bs:
            guc_info->tcp_buffer_size = atoi(instance->values[0]);
            break;
        case arg_s:
            subject = globus_libc_strdup(instance->values[0]);
            break;
        case arg_ss:
            guc_info->source_subject = globus_libc_strdup(instance->values[0]);
            break;
        case arg_ds:
            guc_info->dest_subject = globus_libc_strdup(instance->values[0]);
            break;
        case arg_p:
            guc_info->num_streams = atoi(instance->values[0]);
            break;
        case arg_notpt:
            guc_info->no_3pt = GLOBUS_TRUE;
            break;
        case arg_nodcau:
            guc_info->no_dcau = GLOBUS_TRUE;
            break;
        case arg_encrypt_data:
            guc_info->encrypt_data = GLOBUS_TRUE;
            break;
        case arg_debugftp:
            g_use_debug = GLOBUS_TRUE;
            break;
        case arg_restart:
            g_use_restart = GLOBUS_TRUE;
            break;
        case arg_rst_retries:
            guc_info->restart_retries = atoi(instance->values[0]);
            break;
        case arg_rst_interval:
            guc_info->restart_interval = atoi(instance->values[0]);
            break;
        case arg_rst_timeout:
            guc_info->restart_timeout = atoi(instance->values[0]);
            break;
        case arg_recurse:
            guc_info->recurse = GLOBUS_TRUE;
            break;
	case arg_striped:
	    guc_info->striped = GLOBUS_TRUE;
	    break;
        default:
            globus_url_copy_l_args_error_fmt("parse panic, arg id = %d",
                                       instance->id_number);
            break;
        }
    }

    globus_args_option_instance_list_free(&options_found);
    

    if(file_name != NULL)
    {
        /* get source dest pairs */
        if(argc > 1)
        {
            globus_url_copy_l_args_error(
                "No urls are provided on the command line when using "
                "the -f option.\n");
            globus_free(file_name);
            return -1;
        }

        if(globus_l_guc_parse_file(file_name, &guc_info->user_url_list) != 0)
        {
            globus_free(file_name);
            return -1;
        }

        globus_free(file_name);
    }
    else
    {
        /* there must be 2 additional unflagged arguments:
         *     the source and destination URL's 
         */    
        if (argc > 3)
        {
            globus_url_copy_l_args_error("too many url strings specified");
            return -1;
        }
        if (argc < 3)
        {
            globus_url_copy_l_args_error(
                "source and dest url strings are required");
            return -1;
        }

        if(strcmp(argv[1], "-") == 0 && strcmp(argv[2], "-") == 0)
        {
            globus_url_copy_l_args_error(
                "Cannot have stdin as source and stdout as destination.\n");
            return -1;
        }
        else
        {
        
            ent = (globus_l_guc_src_dst_pair_t *)
                    globus_malloc(sizeof(globus_l_guc_src_dst_pair_t));
            ent->src_url = globus_libc_strdup(argv[1]);
            ent->dst_url = globus_libc_strdup(argv[2]);
            
            globus_fifo_enqueue(&guc_info->user_url_list, ent);
        }
        
    }

    if (subject && !guc_info->source_subject)
    {
        guc_info->source_subject = globus_libc_strdup(subject);
    }
    if (subject && !guc_info->dest_subject)
    {
        guc_info->dest_subject = globus_libc_strdup(subject);
    }

    if(subject) globus_free(subject);

    /* check arguemnt validity */
    if((guc_info->options & GLOBUS_URL_COPY_ARG_ASCII) &&
       (guc_info->options & GLOBUS_URL_COPY_ARG_BINARY) )
    {
        globus_url_copy_l_args_error(
            "option -ascii and -binary are exclusive");
        return -1;
    }
    return 0;
}

static
globus_result_t
globus_l_guc_expand_urls(
    globus_l_guc_info_t *                        guc_info,
    globus_gass_copy_attr_t *                    gass_copy_attr,   
    globus_gass_copy_handle_t *                  gass_copy_handle)
{
    char *                                       src_url;
    char *                                       dst_url;
    globus_l_guc_src_dst_pair_t *                user_url_pair;
    globus_result_t                              result;
    globus_io_handle_t *                         source_io_handle;
        
    while(!globus_fifo_empty(&guc_info->user_url_list))
    {
        user_url_pair = (globus_l_guc_src_dst_pair_t *)
                    globus_fifo_dequeue(&guc_info->user_url_list);

        src_url = user_url_pair->src_url;
        dst_url = user_url_pair->dst_url;

        source_io_handle = 
            globus_l_guc_get_io_handle(src_url, fileno(stdin));

        if(source_io_handle != NULL)
        {
            globus_fifo_enqueue(
                &guc_info->expanded_url_list, 
                user_url_pair);

            continue;
        }
        
        globus_ftp_client_operationattr_init(&guc_info->source_ftp_attr);

        globus_l_guc_gass_attr_init(
            gass_copy_attr,
            &guc_info->source_gass_attr,
            &guc_info->source_ftp_attr,
            guc_info,
            src_url,
            guc_info->source_subject);

        result = globus_l_guc_expand_single_url(
            user_url_pair,
            guc_info,
            gass_copy_attr,       
            gass_copy_handle);
                     
        if(result != GLOBUS_SUCCESS)
        {
            goto error_expand;
        }
                                        
        globus_ftp_client_operationattr_destroy(&guc_info->source_ftp_attr);
        
        globus_free(user_url_pair->src_url);
        globus_free(user_url_pair->dst_url);
        globus_free(user_url_pair);
        
    }

    return GLOBUS_SUCCESS;
            
error_expand:
    globus_ftp_client_operationattr_destroy(&guc_info->source_ftp_attr);
    
    globus_free(user_url_pair->src_url);
    globus_free(user_url_pair->dst_url);
    globus_free(user_url_pair);
 
    return result;                
}



static
globus_result_t
globus_l_guc_expand_single_url(
    globus_l_guc_src_dst_pair_t *                url_pair,
    globus_l_guc_info_t *                        guc_info,
    globus_gass_copy_attr_t *                    gass_copy_attr,   
    globus_gass_copy_handle_t *                  gass_copy_handle)
{
    globus_fifo_t                                matched_url_list;
    char *                                       src_url;
    char *                                       dst_url;
    int                                          url_len;
    globus_l_guc_src_dst_pair_t *                expanded_url_pair;
    char *                                       matched_src_url;
    char *                                       matched_file;
    int                                          base_url_len;
    char *                                       matched_dest_url;
    globus_result_t                              result;
    globus_bool_t                                dst_is_file;
        
                
    globus_fifo_init(&matched_url_list);

    src_url = url_pair->src_url;
    dst_url = url_pair->dst_url;
               
    result = globus_gass_copy_glob_expand_url(
                gass_copy_handle,
                src_url,
                gass_copy_attr,
                &matched_url_list);
    
    if(result != GLOBUS_SUCCESS)
    {
        goto error_expand;  
    }
    
    url_len = strlen(dst_url);
    
    if(dst_url[url_len - 1] == '/')
    {
        dst_is_file = GLOBUS_FALSE;
    }
    else
    {
        dst_is_file = GLOBUS_TRUE;
    }
    
    if(dst_is_file && globus_fifo_size(&matched_url_list) > 1)
    {
        goto error_too_many_matches;
    }

    base_url_len = strrchr(src_url, '/') - src_url + 1;
                                 
    while(!globus_fifo_empty(&matched_url_list))
    {
        matched_src_url = (char *) globus_fifo_dequeue(&matched_url_list);
    
        matched_file = matched_src_url + base_url_len;
    
        if(matched_src_url[strlen(matched_src_url) - 1] == '/' && 
            !guc_info->recurse)
        {
            continue;
        }
                    
        if(dst_is_file)
        {
            matched_dest_url = globus_libc_strdup(dst_url);
        }
        else 
        {        
            matched_dest_url = (char *) globus_malloc(
                (url_len + strlen(matched_file) + 1) * sizeof(char));
            
            sprintf(matched_dest_url, "%s%s", dst_url, matched_file);
        }
                                
        expanded_url_pair = (globus_l_guc_src_dst_pair_t *)
                globus_malloc(sizeof(globus_l_guc_src_dst_pair_t));
    
        expanded_url_pair->src_url = matched_src_url;
        expanded_url_pair->dst_url = matched_dest_url;                
        
        globus_fifo_enqueue(
            &guc_info->expanded_url_list, 
            expanded_url_pair);
    }
    
    
    globus_fifo_destroy(&matched_url_list);
    
        


    return GLOBUS_SUCCESS;
error_too_many_matches:
    globus_libc_fprintf(stderr, 
        "Multiple source urls cannot be copied "
        "to the same destination url:\n\t%s\n",
        dst_url);        
            
error_expand:

    globus_fifo_destroy(&matched_url_list);
     
    return result;                
}



static
int
globus_l_guc_init_gass_copy_handle(
    globus_gass_copy_handle_t *                     gass_copy_handle,
    globus_l_guc_info_t *                           guc_info)
{
    globus_ftp_client_handleattr_t                  ftp_handleattr;
    globus_result_t                                 result;
    globus_ftp_client_plugin_t                      debug_plugin;
    globus_ftp_client_plugin_t                      restart_plugin;
    globus_reltime_t                                interval;
    globus_abstime_t                                timeout;
    globus_abstime_t *                              timeout_p = GLOBUS_NULL;
    globus_gass_copy_handleattr_t                   gass_copy_handleattr;

    globus_gass_copy_handleattr_init(&gass_copy_handleattr);

    result = globus_ftp_client_handleattr_init(&ftp_handleattr);
    if(result != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error: Unable to init ftp handle attr %s\n",
            globus_object_printable_to_string(globus_error_get(result)));

        return -1;
    }

    globus_ftp_client_handleattr_set_cache_all(&ftp_handleattr, GLOBUS_TRUE);

    if(g_use_debug)
    {
        result = globus_ftp_client_debug_plugin_init(
            &debug_plugin,
            stderr,
            "debug");
        if(result != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "Error: Unable to init debug plugin %s\n",
                globus_object_printable_to_string(globus_error_get(result)));

            return -1;
        }

        result = globus_ftp_client_handleattr_add_plugin(
            &ftp_handleattr,
            &debug_plugin);
        if(result != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "Error: Unable to register debug plugin %s\n",
                globus_object_printable_to_string(globus_error_get(result)));

            return -1;
        }
    }

    if(g_use_restart)
    {
        GlobusTimeReltimeSet(interval, guc_info->restart_interval, 0);
        
        if(guc_info->restart_timeout)
        {
            GlobusTimeAbstimeSet(timeout, guc_info->restart_timeout, 0);
            timeout_p = &timeout;
        }
            
        result = globus_ftp_client_restart_plugin_init(
            &restart_plugin,
            guc_info->restart_retries, /* retry times 0=forever */
            &interval, /* time between tries 0=exponential backoff */
            timeout_p); /* absolute timeout NULL=inifinte */
        if(result != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "Error: Unable to init debug plugin %s\n",
                globus_object_printable_to_string(globus_error_get(result)));

            return -1;
        }

        result = globus_ftp_client_handleattr_add_plugin(
            &ftp_handleattr,
            &restart_plugin);
        if(result != GLOBUS_SUCCESS)
        {
            fprintf(stderr, "Error: Unable to register restart plugin %s\n",
                globus_object_printable_to_string(globus_error_get(result)));

            return -1;
        }
    }

#   if defined(GLOBUS_BUILD_WITH_NETLOGGER)
    {
        char                                        my_hostname[64];
        char                                        buffer[64];

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

        globus_ftp_client_handleattr_set_netlogger(
            &ftp_handleattr,
            &gnl_handle);
    }
#   endif

    globus_gass_copy_handleattr_set_ftp_attr(
        &gass_copy_handleattr, &ftp_handleattr);

    globus_gass_copy_handle_init(gass_copy_handle, &gass_copy_handleattr);

    if(guc_info->block_size > 0)
    {
        globus_gass_copy_set_buffer_length(gass_copy_handle, 
            guc_info->block_size);
    }
    if(guc_info->no_3pt)
    {
        globus_gass_copy_set_no_third_party_transfers(gass_copy_handle,
                            GLOBUS_TRUE);
    }

    if (g_verbose_flag)
    {
        result = globus_gass_copy_register_performance_cb(
            gass_copy_handle,
            globus_l_gass_copy_performance_cb,
            GLOBUS_NULL);

        if (result != GLOBUS_SUCCESS)
        {
            fprintf(stderr, 
                "Error: Unable to register performance handler %s\n",
                globus_object_printable_to_string(globus_error_get(result)));

            fprintf(stderr, "Continuing without performance info\n");
        }
    }

#   ifndef TARGET_ARCH_WIN32
    {
        globus_l_globus_url_copy_signal(SIGINT,
                              globus_l_globus_url_copy_sigint_handler);
    }
#   endif

    return 0;
}



/*
 *  since i can't seem to find away to get a list of schemes that
 *  gass supports this will need to be called for each url
 */

static
int
globus_l_guc_gass_attr_init(
    globus_gass_copy_attr_t *                       gass_copy_attr,
    globus_gass_transfer_requestattr_t *            gass_t_attr,
    globus_ftp_client_operationattr_t *             ftp_attr,
    globus_l_guc_info_t *                           guc_info,
    char *                                          url,
    char *                                          subject)
{
    globus_url_t                                    url_info;
    globus_gass_copy_url_mode_t                     url_mode;
    globus_ftp_control_tcpbuffer_t                  tcp_buffer;
    globus_ftp_control_parallelism_t                parallelism;
    globus_ftp_control_dcau_t                       dcau;
    
    globus_url_parse(url, &url_info);
    globus_gass_copy_get_url_mode(url, &url_mode);
    /*
     *  setup the ftp attr
     */
    if (url_mode == GLOBUS_GASS_COPY_URL_MODE_FTP)
    {
        if (guc_info->tcp_buffer_size > 0)
        {
            tcp_buffer.mode = GLOBUS_FTP_CONTROL_TCPBUFFER_FIXED;
            tcp_buffer.fixed.size = guc_info->tcp_buffer_size;
            globus_ftp_client_operationattr_set_tcp_buffer(
                ftp_attr,
                &tcp_buffer);
        }

        if (guc_info->num_streams >= 1)
        {
            globus_ftp_client_operationattr_set_mode(
                ftp_attr,
                GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK);

            parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
            parallelism.fixed.size = guc_info->num_streams;
            globus_ftp_client_operationattr_set_parallelism(
                ftp_attr,
                &parallelism);        	
	}

	if (guc_info->striped)
	{
		globus_ftp_client_operationattr_set_mode(
                	ftp_attr,
                	GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK);

		globus_ftp_client_operationattr_set_striped(ftp_attr, GLOBUS_TRUE);
	}

        if (subject  ||
            url_info.user ||
            url_info.password)
        {
            globus_ftp_client_operationattr_set_authorization(
                ftp_attr,
                GSS_C_NO_CREDENTIAL,
                url_info.user,
                url_info.password,
                NULL,
                subject);
        }

        if (guc_info->no_dcau)
        {
            dcau.mode = GLOBUS_FTP_CONTROL_DCAU_NONE;
            globus_ftp_client_operationattr_set_dcau(
                ftp_attr,
                &dcau);
        }
        
        if (guc_info->encrypt_data)
        {
            globus_ftp_client_operationattr_set_data_protection(
                ftp_attr,
                GLOBUS_FTP_CONTROL_PROTECTION_PRIVATE);
        }

        globus_gass_copy_attr_set_ftp(gass_copy_attr,
                                      ftp_attr);
                                      
        
    }
    /*
     *  setup the gass copy attr
     */
    else if (url_mode == GLOBUS_GASS_COPY_URL_MODE_GASS)
    {
        globus_gass_transfer_requestattr_init(gass_t_attr, url_info.scheme);

        if (guc_info->options & GLOBUS_URL_COPY_ARG_ASCII)
        {
             globus_gass_transfer_requestattr_set_file_mode(
                  gass_t_attr,
                  GLOBUS_GASS_TRANSFER_FILE_MODE_TEXT);
        }
        else if(guc_info->options & GLOBUS_URL_COPY_ARG_BINARY)
        {
             globus_gass_transfer_requestattr_set_file_mode(
                gass_t_attr,
                GLOBUS_GASS_TRANSFER_FILE_MODE_BINARY);
        }

        if (subject)
        {
            globus_gass_transfer_secure_requestattr_set_authorization(
                gass_t_attr,
                GLOBUS_GASS_TRANSFER_AUTHORIZE_SUBJECT,
                subject);
        }

        globus_gass_copy_attr_set_gass(gass_copy_attr, gass_t_attr);
    }

    return 0;
}



static
globus_io_handle_t *
globus_l_guc_get_io_handle(
    char *                                          url,
    int                                             std_fileno)
{
    globus_io_handle_t *                            io_handle;

    /*
     *  if not stdio
     */
    if(strcmp(url, "-") != 0)
    {
        return NULL;
    }
#   ifndef TARGET_ARCH_WIN32
    {
        io_handle =(globus_io_handle_t *)
            globus_libc_malloc(sizeof(globus_io_handle_t));

        /* convert stdin to be a globus_io_handle */
        globus_io_file_posix_convert(std_fileno,
                                         GLOBUS_NULL,
                                         io_handle);

        return io_handle;
    }
#   else
    {
        fprintf(stderr, 
            "Error: On Windows, the source URL cannot be stdin\n" );
        globus_module_deactivate_all();

        return NULL;
    }
#   endif
}

static
void
globus_l_guc_destroy_url_list(
    globus_fifo_t *                     url_list)
{
    globus_l_guc_src_dst_pair_t *       url_pair;

    while(!globus_fifo_empty(url_list))
    {
        url_pair = (globus_l_guc_src_dst_pair_t *)
                        globus_fifo_dequeue(url_list);
        globus_free(url_pair->src_url);
        globus_free(url_pair->dst_url);
        globus_free(url_pair);
    }      
    globus_fifo_destroy(url_list);
}   

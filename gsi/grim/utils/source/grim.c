#include "globus_grim_devel.h"
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define GrimFreeNull(a)                                     \
{                                                           \
    int __ctr = 0;                                          \
    while(a[__ctr] != NULL)                                 \
    {                                                       \
        free(a[__ctr]);                                     \
        __ctr++;                                            \
    }                                                       \
    free(a);                                                \
}

#define GRIM_STRING_MAX             512

#define GRIM_ASSERTION_FORMAT_VERSION "1"
#define GRIM_OID                      "1.3.6.1.4.1.3536.1.1.1.7"
#define GRIM_SN                       "GRIMPOLICY"
#define GRIM_LN                       "GRIM Policy Language"

/*
 *  globals:
 *
 *  g_quiet: set by command line option.  elimintates logging when true.
 *
 *  g_logfile: FILE * of place to log data.  opened with privledges.
 *
 *  g_username: the user name running the program (not the privledged user).
 */
static globus_bool_t                        g_quiet = GLOBUS_FALSE;
static FILE *                               g_logfile = NULL;
static char *                               g_username = NULL;

extern char **environ;

/************************************************************************
 *                     function signatures
 ***********************************************************************/
static int
grim_pw_stdin_callback(
    char *                                  buf, 
    int                                     num, 
    int                                     w);

int
grim_verify_proxy(
    char *                                  proxy_out_filename);

int
grim_privedged_code(
    globus_gsi_cred_handle_t *              cred_handle,
    char *                                  ca_cert_dir,
    char *                                  user_cert_filename,
    char *                                  user_key_filename);

int
grim_parse_input(
    int                                     argc,
    char *                                  argv[],
    globus_grim_config_t                    config,
    int *                                   out_valid,
    char **                                 out_proxy_out_filename);

int
grim_write_proxy(
    globus_gsi_cred_handle_t                cred_handle,
    int                                     valid,
    int                                     key_bits,
    char *                                  proxy_out_filename,
    char **                                 dna,
    char **                                 port_types);

/*
 *  like printf for the log messages.
 *
 *  The log file is opened with privledges and this function is called
 *  with privledges at certain times.
 */
int
grim_write_log(
    const char *                            format, 
    ...)
{
    va_list                                 ap;
    int                                     rc;
    char                                    buf[128];

    if(g_quiet)
    {
        return 0;
    }

    sprintf(buf, "grim-proxy-init:%d: %s ::", (int)time(NULL), g_username);
    strcat(buf, format);

#ifdef HAVE_STDARG_H
    va_start(ap, format);
#else
    va_start(ap);
#endif
    rc = globus_libc_vfprintf(g_logfile, buf, ap);

    return rc;
}

#define SHORT_USAGE_FORMAT \
"\nSyntax: %s [-help][-valid H:M][-out <proxyfile>] ...\n"

static char *  LONG_USAGE = \
"\n" \
"    Options\n" \
"    -help, -usage             Displays usage\n" \
"    -version                  Displays version\n" \
"    -q                        Quiet mode, minimal output\n" \
"    -valid H:M                Proxy is valid for H hours and M " \
                               "minutes (default:12:00)\n" \
"    -hours H                  Deprecated support of hours option\n" \
"    -bits  B                  Number of bits in key {512|1024|2048|4096}\n" \
"\n" \
"    -out      <proxyfile>     Non-standard location of new proxy cert\n" \
"\n" ;

/*
 *  PSUEDOCODE:
 *
 *  Initializes globus and global variables.
 *  Parase the input parameters.
 *  Look up all DNs in gridmap file.
 *  Look up port types.
 *  Read in the host cer and proxy
 *  Drop privledges.
 *  Write out proxy.
 */
int 
main(
    int                                     argc,
    char **                                 argv)
{
    int                                     rc;
    int                                     valid;
    globus_result_t                         res;
    /* default proxy to 512 bits */
    int                                     key_bits    = 512;
    /* dont restrict the proxy */
    char *                                  conf_filename;
    char *                                  user_cert_filename;
    char *                                  user_key_filename;
    char *                                  ca_cert_dir;
    char *                                  port_type_filename;
    char *                                  proxy_out_filename = NULL;
    char *                                  log_filename = NULL;
    globus_gsi_cred_handle_t                cred_handle;
    uid_t                                   user_id;
    struct passwd *                         pw_ent;
    char **                                 globus_dns;
    char **                                 port_types;
    int                                     dn_count;
    FILE *                                  port_type_fptr;
    FILE *                                  fptr;
    globus_grim_config_t                    config;
    char **                                 tmp_env;

    tmp_env = environ;
    while(*tmp_env)
    {
        if(strncmp("LD_", *tmp_env, 3) == 0)
        {
            unsetenv(*tmp_env);
        }
        tmp_env++;
    }

    /*
     *  verify that setuid bit is set
     */
    if(getuid() == geteuid())
    {
        /* log to stderr since we do not know the intended log file yet */
        fprintf(stderr, "Not running as a setuid program.  The user may must "
                        "simply use their own proxy.\n");
        return 1;
    }

    /***** BEGIN PRIVLEDGES *****/
    /*
     *  this program is intended to be run with a setuid bit to a 
     *  privledged user, for the purposes of reading in credentials
     *  from which a user proxy is created.
     */

    /* initialize some globals */
    g_logfile = stderr;
    pw_ent = getpwuid(getuid());
    g_username = strdup(pw_ent->pw_name);

    /*
     *  activate stuff
     */
    rc = globus_module_activate(GLOBUS_GRIM_DEVEL_MODULE);
    if(rc != (int)GLOBUS_SUCCESS)
    {
        grim_write_log(
            "\n\nERROR: Couldn't activate module: GLOBUS_GRIM_DEVEL_MODULE.\n"
            "Make sure Globus is installed correctly.\n\n");
        return 1;
    }

    /*
     *  initialize values from conf file
     */
    res = globus_grim_config_init(&config);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log(
            "ERROR: Config init failed: %s.\n",
            globus_object_printable_to_string(globus_error_get(res)));
        return 1;
    }

    /*
     *  open the default location of the conf file.
     *  If it successuflly opens parse out options
     */
    res = globus_grim_get_default_configuration_filename(&conf_filename);
    if(res != GLOBUS_SUCCESS)
    {
        rc = 1;
        goto exit;
    }

    fptr = fopen(conf_filename, "r");
    if(fptr != NULL)
    {
        /*
         *  if this fails we are left with default values
         */
        res = globus_grim_config_load_from_file(config, fptr);
        if(res != GLOBUS_SUCCESS)
        {
            grim_write_log(
                "WARNING: Did not sucessfully parse config file: %s.\n",
                conf_filename);
        }
        fclose(fptr);
    }

    /*
     *  parse command line options
     */
     rc = grim_parse_input(
              argc,
              argv,
              config,
              &valid,
              &proxy_out_filename);
    /* if parse told us not to continue */
    if(rc != 0)
    {
        goto exit;
    }

    /* get values from config structure */
    globus_grim_config_get_ca_cert_dir(config, &ca_cert_dir);
    globus_grim_config_get_cert_filename(config, &user_cert_filename);
    globus_grim_config_get_key_filename(config, &user_key_filename);
    globus_grim_config_get_port_type_filename(config, &port_type_filename);
    globus_grim_config_get_log_filename(config, &log_filename);
    if(log_filename != NULL)
    {
        FILE *                                  tmp_file;

        tmp_file = fopen(log_filename, "r");
        if(tmp_file != NULL)
        {
            g_logfile = tmp_file;
        }
    }

    /*
     *  open port type file will still maintaining privledges
     */
    port_type_fptr = fopen(port_type_filename, "r");
    if(port_type_fptr == NULL)
    {
        grim_write_log("Error failed to open port type file: %s.\n",
            port_type_filename);
        goto exit;
    }

    /*
     *  This may or may not need to be called with privledges.  That 
     *  depends on whether or not gridmap file is world readable.
     */
    res = globus_gss_assist_lookup_all_globusid(
              g_username,
              &globus_dns,
              &dn_count);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log("Error in gridmap lookup.  %s.\n",
            globus_object_printable_to_string(globus_error_get(res)));
        rc = 1;
        goto exit;
    }

    /*
     * do privilaged bits
     */
    rc = grim_privedged_code(
            &cred_handle,
            ca_cert_dir,
            user_cert_filename,
            user_key_filename);
    if(rc != 0)
    {
        goto exit;
    }

    /*
     *  drop privledges
     */
    user_id = getuid();
    seteuid(user_id);
    setegid(getgid());
    /***** END PRIVLEDGES *****/

    /*
     *  at this point we no loner have special privledges
     */
    /*
     * if the file successfully opened look up port types.
     */
    res = globus_grim_devel_port_type_file_parse_uid(
              port_type_fptr,
              &port_types);
    if(res != GLOBUS_SUCCESS)
    {
        goto exit;
    }

    /*
     * if no proxy out file is detected find it
     */
    if(proxy_out_filename == NULL)
    {
        res = GLOBUS_GSI_SYSCONFIG_GET_PROXY_FILENAME(
                  &proxy_out_filename,
                  GLOBUS_PROXY_FILE_OUTPUT);
        if(res != GLOBUS_SUCCESS)
        {
            grim_write_log(
                "\n\nERROR: Couldn't find a valid location "
                "to write the proxy file\n");

            rc = 1;
            goto cred_exit;
        }
    }
    else
    {
        rc = grim_verify_proxy(proxy_out_filename);
        if(rc != 0)
        {
            goto cred_exit;
        }
    }

    /*
     *  write out the proxy
     */
    rc = grim_write_proxy(
            cred_handle,
            valid,
            key_bits,
            proxy_out_filename,
            globus_dns,
            port_types);
    if(rc != 0)
    {
        goto cred_exit;
    }

    /*
     *  clean up memory
     */
    GlobusGssAssistFreeDNArray(globus_dns);
    GrimFreeNull(port_types);

  cred_exit:
    globus_gsi_cred_handle_destroy(cred_handle);

  exit:

    globus_grim_config_destroy(config);
    globus_module_deactivate(GLOBUS_GSI_PROXY_MODULE);
    globus_module_deactivate(GLOBUS_GSI_CALLBACK_MODULE);

    return rc;
}

/*
 *  This function will be called by the gsi code if the key used in 
 *  creating a proxy requires a password.  If a password is required
 *  this function logs that the key may not be used and returns -1, 
 *  which will cause the failure.
 */
static int
grim_pw_stdin_callback(
    char *                              buf, 
    int                                 num, 
    int                                 w)
{
    grim_write_log("Password required for this cert.  Program will fail.\n");
    return -1;
}

/*
 *  parse the input, return indicates whether or not program should 
 *  continue.
 *
 *  RUNS WITH PRIVEDGES
 */
int
grim_parse_input(
    int                                     argc,
    char *                                  argv[],
    globus_grim_config_t                    config,
    int *                                   out_valid,
    char **                                 out_proxy_out_filename)
{
    int                                     max_valid;
    int                                     valid;
    int                                     ctr;
    int                                     key_bits;
    char *                                  gridmap;

    /*
     *  assume these all succed since init succeded
     */
    globus_grim_config_get_default_time(config, &valid);
    globus_grim_config_get_max_time(config, &max_valid);
    globus_grim_config_get_gridmap_filename(config, &gridmap);

    /* 
     * parse the arguments 
     */
    for(ctr = 1; ctr < argc; ctr++)
    {
        if((strcmp(argv[ctr], "-help") == 0) ||
           (strcmp(argv[ctr], "-usage") == 0))
        {
            fprintf(stderr, 
                SHORT_USAGE_FORMAT"%s", "grim-proxy-init", LONG_USAGE);
            return 1;
        }
        else if(strcmp(argv[ctr], "-version") == 0)
        {
            fprintf(stderr, "%s-%s", "0", "1");
            return 1;
        }
        else if(strcmp(argv[ctr], "-out") == 0 && ctr + 1 < argc)
        {
            ctr++;
            *out_proxy_out_filename = argv[ctr];
        }
        else if(strcmp(argv[ctr], "-valid") == 0 && ctr + 1 < argc)
        {
            int                         hours = -1;
            int                         minutes = -1;

            ctr++;
            if(sscanf(argv[ctr], "%d:%d", &hours, &minutes) < 2)
            {
                fprintf(stderr, "ERROR: value must be in the format: H:M\n");
                return 1;
            }
            if(hours < 0)
            {
                fprintf(stderr, 
                    "%s: specified hours must be a nonnegative integer",
                    argv[ctr]);
                return 1;
            }
            if(minutes < 0 || minutes > 60)
            {
                fprintf(stderr, 
                    "%s: specified minutes must be a nonnegative integer",
                    argv[ctr]);
                return 1;
            }
            valid = (hours * 60) + minutes;
        }
        else if(strcmp(argv[ctr], "-hours") == 0 && ctr + 1 < argc)
        {
            int                           hours;

            ctr++;
            hours = atoi(argv[ctr]);
            valid = hours * 60;
        }
        else if(strcmp(argv[ctr], "-bits") == 0 && ctr + 1 < argc)
        {
            ctr++;
            key_bits = atoi(argv[ctr]);
            if((key_bits != 512) && (key_bits != 1024) &&
               (key_bits != 2048) && (key_bits != 4096))
            {
                fprintf(stderr, "value must be one of 512,1024,2048,4096");
                return 1;
            }
            globus_grim_config_set_key_bits(config, key_bits);
        }
        else if(strcmp(argv[ctr], "-q") == 0)
        {
            g_quiet = GLOBUS_TRUE;
        }
        else
        {
            fprintf(stderr, SHORT_USAGE_FORMAT, "grim-proxy-init");
            return 1;
        }
    }
    /* 
     * end parse the arguments 
     */

    /*
     * TODO: pull the cert and key locations out of a config file
     * in the users env. and cert_dir and gridmap.
     *
     * Pull max out of file.
     */

    if(valid > max_valid)
    {
        valid = max_valid;
    }

    /*
     *  This is a bit of a hack.  The gsi code will check this env later
     *  to find the location of the gridmap file.
     */
    setenv("GRIDMAP", gridmap, 1);

    /*
     * set out parameters if the caller is interested.
     */
    if(out_valid)
    {
        *out_valid = valid;
    }

    return 0;
}

/*
 *  verify proxy.
 *
 *  This function is called to verify the existance of a proxy in the
 *  given location.
 */
int
grim_verify_proxy(
    char *                                  proxy_out_filename)
{
    /* verify that the directory path of proxy_out_filename
     * exists and is writeable
     */
    globus_gsi_statcheck_t                  file_status;
    char *                                  proxy_absolute_path = NULL;
    char *                                  temp_filename = NULL;
    char *                                  temp_dir = NULL;
    globus_result_t                         res;

    /* first, make absolute path */
    res = GLOBUS_GSI_SYSCONFIG_MAKE_ABSOLUTE_PATH_FOR_FILENAME(
              proxy_out_filename,
              &proxy_absolute_path);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log(
            "\n\nERROR: Can't create the absolute path "
            "of the proxy filename: %s",
            proxy_out_filename);

        return 1;
    }

    proxy_out_filename = proxy_absolute_path;

    /* then split */
    res = GLOBUS_GSI_SYSCONFIG_SPLIT_DIR_AND_FILENAME(
              proxy_absolute_path,
              &temp_dir,
              &temp_filename);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log(
            "\n\nERROR: Can't split the full path into "
            "directory and filename. The full path is: %s", 
            proxy_absolute_path);
        if(proxy_absolute_path)
        {
            free(proxy_absolute_path);
            proxy_absolute_path = NULL;
        }

        return 1;
    }
                
    res = GLOBUS_GSI_SYSCONFIG_FILE_EXISTS(temp_dir, &file_status);
    if(res != GLOBUS_SUCCESS || file_status != GLOBUS_FILE_DIR)
    {
        if(temp_dir)
        {
            free(temp_dir);
            temp_dir = NULL;
        }
            
        if(temp_filename)
        {
            free(temp_filename);
            temp_filename = NULL;
        }

        grim_write_log(
            "\n\nERROR: %s is not a valid directory for writing the "
            "proxy certificate\n\n",
            temp_dir);
    }

    if(temp_dir)
    {
        free(temp_dir);
        temp_dir = NULL;
    }
        
    if(temp_filename)
    {
        free(temp_filename);
        temp_filename = NULL;
    }

    return 0;
}


/*
 *  read in non-password protected certs
 *
 *  RUNS WITH PRIVEDGES
 */
int
grim_privedged_code(
    globus_gsi_cred_handle_t *                  cred_handle,
    char *                                      ca_cert_dir,
    char *                                      user_cert_filename,
    char *                                      user_key_filename)
{
    globus_result_t                             res;
    globus_gsi_cred_handle_attrs_t              cred_handle_attrs = NULL;

    res = globus_gsi_cred_handle_attrs_init(&cred_handle_attrs);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log(      
                            "ERROR: Couldn't initialize credential "
                            "handle attributes\n");
        return 1;
    }

    res = globus_gsi_cred_handle_attrs_set_ca_cert_dir(
              cred_handle_attrs, 
              ca_cert_dir);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log(
            "\n\nERROR: Couldn't set the trusted CA certificate "
            "directory in the credential handle attributes\n");
        return 1;
    }

    res = globus_gsi_cred_handle_init(cred_handle, cred_handle_attrs);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log("ERROR: Couldn't initialize credential handle\n");
        return 1;
    }

    res = globus_gsi_cred_handle_attrs_destroy(cred_handle_attrs);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log(
            "ERROR: Couldn't destroy credential handle attributes.\n");
        return 1;
    }

    /*
     * the reads are the only real privledged part
     */
    if(strstr(user_cert_filename, ".p12"))
    {
        /* we have a pkcs12 credential */
        res = globus_gsi_cred_read_pkcs12(
                  *cred_handle,
                  user_cert_filename);
        if(res != GLOBUS_SUCCESS)
        {
            grim_write_log(
                "ERROR: Couldn't read in PKCS12 credential "
                "from file: %s\n", user_cert_filename);
            return 1;
        }
    }
    else if(user_cert_filename != user_key_filename)
    {
        res = globus_gsi_cred_read_cert(
                  *cred_handle,
                   user_cert_filename);
        if(res != GLOBUS_SUCCESS)
        {
            grim_write_log(
                "ERROR: Couldn't read user certificate\n"
                "cert file location: %s\n\n", 
                user_cert_filename);
            return 1;
        }

        res = globus_gsi_cred_read_key(
                  *cred_handle,
                  user_key_filename,
                  grim_pw_stdin_callback);
        if(res != GLOBUS_SUCCESS)
        {
            grim_write_log(
                "ERROR: Couldn't read user key: %s.\n",
                user_key_filename);
            return 1;
        }
    }
    else
    {
        grim_write_log(
            "\n\nERROR: The user certificate filename: %s\n"
            "and key filename: %s\nare the same, but they do not point to a "
            "PKCS12 formatted (.p12 extension) certificate\n\n",
            user_cert_filename, user_key_filename);
        return 1;
    }

    return 0;
}

/*
 *  write the proxy
 *
 *  This function writes the proxy out to proxy_out_filename.  It is
 *  not run with provledges.
 */
int
grim_write_proxy(
    globus_gsi_cred_handle_t                    cred_handle,
    int                                         valid,
    int                                         key_bits,
    char *                                      proxy_out_filename,
    char **                                     dna,
    char **                                     port_types)
{
    globus_gsi_proxy_handle_t                   proxy_handle;
    globus_gsi_proxy_handle_attrs_t             proxy_handle_attrs;
    globus_result_t                             res;
    globus_gsi_cred_handle_t                    proxy_cred_handle;
    time_t                                      goodtill;
    time_t                                      lifetime;
    char *                                      issuer;
    globus_grim_assertion_t                     assertion;
    char *                                      assertion_string;
    char *                                      tmp_s2;
    char *                                      tmp_s1;
    X509 *                                      x509_var;
    X509_NAME *                                 x509_name;
    int                                         grim_NID;
    int                                         rc = 0;

    res = globus_gsi_proxy_handle_attrs_init(&proxy_handle_attrs);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log("ERROR: Couldn't initialize the proxy handle attributes.\n");
        return 1;
    }


    /* 
     * set the key bits for the proxy cert in the proxy handle
     * attributes
     */
    res = globus_gsi_proxy_handle_attrs_set_keybits(
              proxy_handle_attrs, 
              key_bits);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log(
                            "ERROR: Couldn't set the key bits for "
                            "the private key of the proxy certificate\n");
        return 1;
    }

    res = globus_gsi_cred_get_issuer_name(
              cred_handle,
              &issuer);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log("ERROR: coulnd not get issuer name.\n");
        return 1;
    }

    res = globus_gsi_cred_get_cert(
              cred_handle,
              &x509_var);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log("ERROR: could not get cert.\n");
        return 1;
    }
    x509_name = X509_get_subject_name(x509_var);
    tmp_s1 = X509_NAME_oneline(x509_name, 0, 0);
    tmp_s2 = malloc(strlen(issuer) + strlen(tmp_s1) + 1);
    sprintf(tmp_s2, "%s%s", issuer, tmp_s1);

    /*
     *  build the serialized assertion string
     */
    res = globus_grim_assertion_init(
              &assertion,
              tmp_s2,
              g_username);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log("ERROR: coulnd not build assertion.\n");
        return 1;
    }
    globus_grim_assertion_set_dn_array(assertion, dna);
    globus_grim_assertion_set_port_types_array(assertion, port_types);

    res = globus_grim_assertion_serialize(
              assertion,
              &assertion_string);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log("ERROR: coulnd not build assertion.\n");
        return 1;
    }

    /*
     *  initialize the handle
     */
    res = globus_gsi_proxy_handle_init(&proxy_handle, proxy_handle_attrs);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log("ERROR: Couldn't initialize the proxy handle\n");
        return 1;
    }

    /* 
     * set the time valid in the proxy handle attributes
     * used to be hours - now the time valid needs to be set in minutes 
     */
    res = globus_gsi_proxy_handle_set_time_valid(
              proxy_handle, 
              valid);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log("ERROR: Couldn't set the validity time "
                       "of the proxy cert to %d minutes.\n", valid);
        return 1;
    }

    globus_grim_devel_get_NID(&grim_NID);


    res = globus_gsi_proxy_handle_set_type(
                proxy_handle, 
                GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_RESTRICTED_PROXY);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log("ERROR could not set the proxy type.\n");
        free(assertion_string);
        return 1;
    }
    res = globus_gsi_proxy_handle_set_policy(
              proxy_handle,
              assertion_string,
              strlen(assertion_string),
              grim_NID);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log("ERROR could not set the assertion.\n");
        free(assertion_string);
        return 1;
    }

    /*
     *  create signed proxy
     */
    res = globus_gsi_proxy_create_signed(
              proxy_handle,
              cred_handle,
              &proxy_cred_handle);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log("ERROR: Couldn't create proxy certificate\n");
        return 1;
    }

    res = globus_gsi_cred_write_proxy(proxy_cred_handle,
                                      proxy_out_filename);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log(
            "ERROR: The proxy credential could not be to %s\n.",
            proxy_out_filename);
        free(assertion);
        return 1;
    }

    free(tmp_s2);
/*
    free(assertion_string);
*/
    res = globus_gsi_cred_get_lifetime(cred_handle, &lifetime);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log(
            "ERROR: Can't get the lifetime of the proxy credential.\n");
        return 1;
    }

    res = globus_gsi_cred_get_goodtill(proxy_cred_handle, &goodtill);
    if(res != GLOBUS_SUCCESS)
    {
        grim_write_log(
            "ERROR: Can't get the expiration date of the proxy credential.\n");
        return 1;
    }

    if(lifetime < 0)
    {
        grim_write_log(
            "\n\nERROR: Your certificate has expired: %s\n\n", 
            asctime(localtime(&goodtill)));
        return 1;
    }
    else if(lifetime < (valid * 60))
    {
        grim_write_log(
            "Warning: cert and proxy will export before time requested.\n");
        return 1;
    }
    grim_write_log(
        "proxy successfully writen to :%s: valid until :%s:\n", 
        proxy_out_filename,
        asctime(localtime(&goodtill)));

    globus_gsi_proxy_handle_destroy(proxy_handle);
    globus_gsi_cred_handle_destroy(proxy_cred_handle);
    globus_grim_assertion_destroy(assertion);

    /*
     * TODO: provide command line options for formating the output
     */
    fprintf(stdout, "%s,%ld\n", proxy_out_filename, goodtill);

    return rc;
}

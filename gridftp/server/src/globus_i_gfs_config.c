/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_i_gridftp_server.h"
#include "version.h"

#define GLOBUS_GFS_HELP_ROWS            20
#define GLOBUS_GFS_HELP_COLS            45
#define GLOBUS_GFS_HELP_WIDTH           80

typedef enum
{
    GLOBUS_L_GFS_CONFIG_BOOL,
    GLOBUS_L_GFS_CONFIG_INT,
    GLOBUS_L_GFS_CONFIG_STRING,
    GLOBUS_L_GFS_CONFIG_LIST,
    GLOBUS_L_GFS_CONFIG_VOID
} globus_l_gfs_config_type_t;

typedef struct
{
    char *                              option_name;
    char *                              configfile_option;
    char *                              env_var_option;
    char *                              long_cmdline_option;
    char *                              short_cmdline_option;
    globus_l_gfs_config_type_t          type;
    int                                 int_value;
    void *                              value;
    char *                              usage;
    char *                              short_usage;
    char *                              expected_val;
    globus_bool_t                       public;
    globus_list_t *                     set_list;
} globus_l_gfs_config_option_t;

static globus_mutex_t                   globus_i_gfs_config_mutex;

static const globus_l_gfs_config_option_t option_list[] = 
{ 
{NULL, "Informational Options", NULL, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL, GLOBUS_FALSE, NULL},
 {"help", "help", NULL, "help", "h", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Show usage information and exit.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"longhelp", "longhelp", NULL, "longhelp", "hh", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Show more usage information and exit.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"version", "version", NULL, "version", "v", GLOBUS_L_GFS_CONFIG_BOOL, 0, NULL,
    "Show version information for the server and exit.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"versions", "versions", NULL, "versions", "V", GLOBUS_L_GFS_CONFIG_BOOL, 0, NULL,
    "Show version information for all loaded globus libraries and exit.", NULL, NULL,GLOBUS_FALSE, NULL},
{NULL, "Modes of Operation", NULL, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL,GLOBUS_FALSE, NULL},
 {"inetd", "inetd", NULL, "inetd", "i", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Run under an inetd service.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"daemon", "daemon", NULL, "daemon", "s", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Run as a daemon.  All connections will fork off a new process and setuid if allowed.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"detach", "detach", NULL, "detach", "S", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Run as a background daemon detached from any controlling terminals.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"exec", "exec", NULL, "exec", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "For staticly compiled or non-GLOBUS_LOCATION standard binary locations, specify the full "
    "path of the server binary here.  Only needed when run in daemon mode.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"chdir", "chdir", NULL, "chdir", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Change directory when the server starts. This will change directory to the dir specified "
    "by the chdir_to option.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"chdir_to", "chdir_to", NULL, "chdir-to", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Directory to chdir to after starting.  Will use / if not set.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"fork", "fork", NULL, "fork", "f", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Server will fork for each new connection.  Disabling this option is only recommended "
    "when debugging. Note that non-forked servers running as 'root' will only "
    "accept a single connection, and then exit.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"single", "single", NULL, "single", "1", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL, 
    "Exit after a single connection.", NULL, NULL,GLOBUS_FALSE, NULL},
{NULL, "Authentication, Authorization, and Security Options", NULL, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL,GLOBUS_FALSE, NULL},
 {"auth_level", "auth_level", NULL, "auth-level", NULL, GLOBUS_L_GFS_CONFIG_INT, -1, NULL,
    "Add levels together to use more than one.  0 = Disables all authorization checks. 1 = Authorize identity. "
    "2 = Authorize all file/resource accesses. 4 = Disable changing process uid to authenticated user (no setuid) -- DO NOT use this when process is started as root.  "
    "If not set uses level 2 for front ends and level 1 for data nodes.  Note that levels 2 and 4 imply level 1 as well.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"ipc_allow_from", "ipc_allow_from", NULL, "ipc-allow-from", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Only allow connections from these source ip addresses.  Specify a comma "
    "seperated list of ip address fragments.  A match is any ip address that "
    "starts with the specified fragment.  Example: '192.168.1.' will match and "
    "allow a connection from 192.168.1.45.  Note that if this option is used "
    "any address not specifically allowed will be denied.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"ipc_deny_from", "ipc_deny_from", NULL, "ipc-deny-from", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Deny connections from these source ip addresses. Specify a comma "
    "seperated list of ip address fragments.  A match is any ip address that "
    "starts with the specified fragment.  Example: '192.168.2.' will match and "
    "deny a connection from 192.168.2.45.", NULL, NULL,GLOBUS_TRUE, NULL},
 {"allow_from", "allow_from", NULL, "allow-from", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Only allow connections from these source ip addresses.  Specify a comma "
    "seperated list of ip address fragments.  A match is any ip address that "
    "starts with the specified fragment.  Example: '192.168.1.' will match and "
    "allow a connection from 192.168.1.45.  Note that if this option is used "
    "any address not specifically allowed will be denied.", NULL, NULL, GLOBUS_TRUE, NULL},
 {"deny_from", "deny_from", NULL, "deny-from", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Deny connections from these source ip addresses. Specify a comma "
    "seperated list of ip address fragments.  A match is any ip address that "
    "starts with the specified fragment.  Example: '192.168.2.' will match and "
    "deny a connection from 192.168.2.45.", NULL, NULL,GLOBUS_TRUE, NULL},
 {"cas", "cas", NULL, "cas", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Enable CAS authorization.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"secure_ipc", "secure_ipc", NULL, "secure-ipc", "si", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Use GSI security on ipc channel.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"ipc_auth_mode", "ipc_auth_mode", NULL, "ipc-auth-mode", "ia", GLOBUS_L_GFS_CONFIG_STRING, 0, "host",
    "[not implemented]", NULL, NULL,GLOBUS_FALSE, NULL},
 {"ipc_user_name", "ipc_user_name", NULL, "ipc_user_name", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "User name for IPC conncet back [not implemented]", NULL, NULL,GLOBUS_FALSE, NULL},
 {"ipc_subject", "ipc_subject", NULL, "ipc_subject", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Expected DN for IPC conncet back.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"ipc_cookie", "ipc_cookie", NULL, "ipc_cookie", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "[not implemented]", NULL, NULL,GLOBUS_FALSE, NULL},
 {"allow_anonymous", "allow_anonymous", NULL, "allow-anonymous", "aa", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Allow cleartext anonymous access. If server is running as root anonymous_user "
    "must also be set.  Disables ipc security.", NULL, NULL,GLOBUS_TRUE, NULL},
 {"anonymous_names_allowed", "anonymous_names_allowed", NULL, "anonymous-names-allowed", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Comma seperated list of names to treat as anonymous users when "
    "allowing anonymous access.  If not set, the default names of 'anonymous' "
    "and 'ftp' will be allowed.  Use '*' to allow any username.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"anonymous_user", "anonymous_user", NULL, "anonymous-user", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "User to setuid to for an anonymous connection. Only applies when running as root.", NULL, NULL,GLOBUS_TRUE, NULL},
 {"anonymous_group", "anonymous_group", NULL, "anonymous-group", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Group to setgid to for an anonymous connection. If unset, the default group "
    "of anonymous_user will be used.", NULL, NULL,GLOBUS_TRUE, NULL},
 {"pw_file", "pw_file", NULL, "password-file", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Enable cleartext access and authenticate users against this /etc/passwd formatted file.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"backends_registered", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Number of backends registered.", NULL, NULL,GLOBUS_TRUE, NULL},
 {"data_connection_max", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Data node connection count.", NULL, NULL,GLOBUS_TRUE, NULL},
 {"open_connections_count", "open_connections_count", NULL, "open_connections_count", NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Current connections.  Applicable only to daemon mode.", NULL, NULL,GLOBUS_TRUE, NULL},
 {"connections_max", "connections_max", NULL, "connections-max", NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Maximum concurrent connections allowed.  Only applies when running in daemon "
    "mode.  Unlimited if not set.", NULL, NULL,GLOBUS_TRUE, NULL},
 {"connections_disabled", "connections_disabled", NULL, "connections-disabled", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Disable all new connections.  Does not affect ongoing connections.  This would have be set "
    "in the configuration file and then the server issued a SIGHUP in order to reload that config.", NULL, NULL,GLOBUS_FALSE, NULL},
{NULL, "Logging Options", NULL, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL,GLOBUS_FALSE, NULL},
 {"log_level", "log_level", NULL, "log-level", "d", GLOBUS_L_GFS_CONFIG_STRING, 0, "ERROR",
    "Log level. A comma seperated list of levels from: 'ERROR, WARN, INFO, DUMP, ALL'. "
    "Example: error,warn,info. You may also specify a numeric level of 1-255.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"log_module", "log_module", NULL, "log-module", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "globus_logging module that will be loaded. If not set, the default 'stdio' module will "
    "be used, and the logfile options apply.  Builtin modules are 'stdio' and 'syslog'.  Log module options "
    "may be set by specifying module:opt1=val1:opt2=val2.  Available options for the builtin modules "
    "are 'interval' and 'buffer', for buffer flush interval and buffer size, respectively. "
    "The default options are a 64k buffer size and a 5 second flush interval.  A 0 second flush interval "
    "will disable periodic flushing, and the buffer will only flush when it is full.  A value of 0 for "
    "buffer will disable buffering and all messages will be written immediately.  "
    "Example: -log-module stdio:buffer=4096:interval=10", NULL, NULL,GLOBUS_FALSE, NULL},
 {"log_single", "log_single", NULL, "logfile", "l", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Path of a single file to log all activity to.  If neither this option or log_unique is set, "
    "logs will be written to stderr unless the execution mode is detached or inetd, "
    "in which case logging will be disabled.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"log_unique", "log_unique", NULL, "logdir", "L", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Partial path to which 'gridftp.(pid).log' will be appended to construct the log filename. "
    "Example: -L /var/log/gridftp/ will create a seperate log ( /var/log/gridftp/gridftp.xxxx.log ) "
    "for each process (which is normally each new client session).  If neither this option or "
    "log_single is set, logs will be written to stderr unless the execution mode is detached or inetd, "
    "in which case logging will be disabled.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"log_transfer", "log_transfer", NULL, "log-transfer", "Z", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Log netlogger style info for each transfer into this file.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"log_filemode", "log_filemode", NULL, "log-filemode", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "File access permissions of log files. Should be an octal number such as "
    "0644 (the leading 0 is required).", NULL, NULL,GLOBUS_FALSE, NULL},
 {"disable_usage_stats", "disable_usage_stats", "GLOBUS_USAGE_OPTOUT", "disable-usage-stats", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Disable transmission of per-transfer usage statistics.  See the Usage Statistics "
    "section in the online documentation for more information.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"usage_stats_target", "usage_stats_target", NULL, "usage-stats-target", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Comma seperated list of contact strings for usage statistics listeners.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"usage_stats_id", "usage_stats_id", NULL, "usage-stats-id", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Identifying tag to include in usage statistics data.", NULL, NULL, GLOBUS_TRUE, NULL},
{NULL, "Single and Striped Remote Data Node Options", NULL, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL,GLOBUS_FALSE, NULL},
 {"remote_nodes", "remote_nodes", NULL, "remote-nodes", "r", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Comma seperated list of remote node contact strings.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"data_node", "data_node", NULL, "data-node", "dn", GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "This server is a backend data node.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"stripe_blocksize", "stripe_blocksize", NULL, "stripe-blocksize", "sbs", GLOBUS_L_GFS_CONFIG_INT, (1024 * 1024), NULL,
    "Size in bytes of sequential data that each stripe will transfer.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"brain", "brain", NULL, "brain", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "switch out the default remote brain [unsuported]", NULL, NULL, GLOBUS_FALSE, NULL},
 {"extension", "extension", NULL, "extension", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "load and extension library [unsuported]", NULL, NULL, GLOBUS_FALSE, NULL},
 {"epr_outfile", "epr_outfile", NULL, "epr-outfile", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "place to write epr [unsuported]", NULL, NULL, GLOBUS_FALSE, NULL},
 {"service_port", "service_port", NULL, "service_port", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "port string for container [unsuported]", NULL, NULL, GLOBUS_FALSE, NULL},
 {"stripe_layout", "stripe_layout", NULL, "stripe-layout", "sl", GLOBUS_L_GFS_CONFIG_INT, GLOBUS_GFS_LAYOUT_BLOCKED, NULL,
    "Stripe layout. 1 = Partitioned, 2 = Blocked.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"stripe_blocksize_locked", "stripe_blocksize_locked", NULL, "stripe-blocksize-locked", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Do not allow client to override stripe blocksize with the OPTS RETR command", NULL, NULL,GLOBUS_FALSE, NULL},
 {"stripe_layout_locked", "stripe_layout_locked", NULL, "stripe-layout-locked", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Do not allow client to override stripe layout with the OPTS RETR command", NULL, NULL,GLOBUS_FALSE, NULL},
 {"stripe_mode", "stripe_mode", NULL, "stripe-mode", NULL, GLOBUS_L_GFS_CONFIG_INT, 1, NULL,
    NULL /* "Mode 1 is a 1-1 stripe configuration. Mode 2 is ALL-ALL."  */, NULL, NULL,GLOBUS_FALSE, NULL},
{NULL, "Disk Options", NULL, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL,GLOBUS_FALSE, NULL},
 {"blocksize", "blocksize", NULL, "blocksize", "bs", GLOBUS_L_GFS_CONFIG_INT, (256 * 1024), NULL,
    "Size in bytes of data blocks to read from disk before posting to the network.", NULL, NULL,GLOBUS_TRUE, NULL},
 {"sync_writes", "sync_writes", NULL, "sync-writes", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Flush disk writes before sending a restart marker.  This attempts to ensure that "
    "the range specified in the restart marker has actually been committed to disk. "
    "This option will probably impact performance, and may result in different behavior "
    "on different storage systems. See the manpage for sync() for more information.", NULL, NULL,GLOBUS_TRUE, NULL},
 {"repo_count", "repo_count", NULL, "repo-count", NULL, GLOBUS_L_GFS_CONFIG_INT, 4, NULL,
    "Maximum number of connections per transfer.", NULL, NULL,GLOBUS_FALSE, NULL},
{NULL, "Network Options", NULL, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL,GLOBUS_FALSE, NULL},
 {"port", "port", NULL, "port", "p", GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Port on which a frontend will listend for client control channel connections, "
    "or on which a data node will listen for connections from a frontend.  If not set "
    "a random port will be chosen and printed via the logging mechanism.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"control_interface", "control_interface", NULL, "control-interface", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Hostname or IP address of the interface to listen for control connections "
    "on. If not set will listen on all interfaces.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"data_interface", "data_interface", NULL, "data-interface", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Hostname or IP address of the interface to use for data connections. If not "
    "set will use the current control interface.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"ipc_interface", "ipc_interface", NULL, "ipc-interface", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Hostname or IP address of the interface to use for ipc connections. If not "
    "set will listen on all interfaces.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"hostname", "hostname", NULL, "hostname", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Effectively sets the above control_interface, data_interface and ipc_interface options.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"ipc_port", "ipc_port", NULL, "ipc-port", NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "Port on which the frontend will listen for data node connections.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"brain_listen", "brain_listen", NULL, "brain-listen", NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    "State if the brain will allow for connection back.  Should be used with --ipc-port.  This is an experimental feature.", NULL, NULL,GLOBUS_FALSE, NULL},
{NULL, "Timeouts", NULL, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL,GLOBUS_FALSE, NULL},
 {"control_preauth_timeout", "control_preauth_timeout", NULL, "control-preauth-timeout", NULL, GLOBUS_L_GFS_CONFIG_INT, 30, NULL,
    "Time in seconds to allow a client to remain connected to the control "
    "channel without activity before authenticating.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"control_idle_timeout", "control_idle_timeout", NULL, "control-idle-timeout", NULL, GLOBUS_L_GFS_CONFIG_INT, 600, NULL,
    "Time in seconds to allow a client to remain connected to the control "
    "channel without activity.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"ipc_idle_timeout", "ipc_idle_timeout", NULL, "ipc-idle-timeout", NULL, GLOBUS_L_GFS_CONFIG_INT, 600, NULL,
    "Idle time in seconds before an unused ipc connection will close.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"ipc_connect_timeout", "ipc_connect_timeout", NULL, "ipc-connect-timeout", NULL, GLOBUS_L_GFS_CONFIG_INT, 60, NULL,
    "Time in seconds before cancelling an attempted ipc connection.", NULL, NULL,GLOBUS_FALSE, NULL},
{NULL, "User Messages", NULL, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL,GLOBUS_FALSE, NULL},
 {"banner", "banner", NULL, "banner", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Message to display to the client before authentication.", NULL, NULL,GLOBUS_TRUE, NULL},
 {"banner_file", "banner_file", NULL, "banner-file", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "File to read banner message from.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"banner_terse", "banner_terse", NULL, "banner-terse", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "When this is set, the minimum allowed banner message will be displayed "
    "to unauthenticated clients.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"login_msg", "login_msg", NULL, "login-msg", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Message to display to the client after authentication.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"login_msg_file", "login_msg_file", NULL, "login-msg-file", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "File to read login message from.", NULL, NULL,GLOBUS_TRUE, NULL},
{NULL, "Module Options", NULL, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL,GLOBUS_FALSE, NULL},
 {"load_dsi_module", "load_dsi_module", NULL, "dsi", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Data Storage Interface module to load. file and remote modules are defined by the server. "
    "If not set, the file module is loaded, unless the 'remote' option is specified, in which case the remote "
    "module is loaded.  An additional configuration string can be passed to the DSI using the format " 
    "[module name]:[configuration string] to this option.  The format of the configuration "
    "string is defined by the DSI being loaded.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"allowed_modules", "allowed_modules", NULL, "allowed-modules", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    "Comma seperated list of ERET/ESTO modules to allow, and optionally specify an alias for. "
    "Example: module1,alias2:module2,module3 (module2 will be loaded when a client asks for alias2).", NULL, NULL,GLOBUS_FALSE, NULL}, 
{NULL, "Other", NULL, NULL, NULL, 0, 0, NULL, NULL, NULL, NULL,GLOBUS_FALSE, NULL},
 {"configfile", "configfile", NULL, "c", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
     "Path to configuration file that should be loaded.  Otherwise will attempt "
     "to load $GLOBUS_LOCATION/etc/gridftp.conf and /etc/grid-security/gridftp.conf.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"use_home_dirs", "use_home_dirs", NULL, "use-home-dirs", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    "Set the startup directory to the authenticated users home dir.", NULL, NULL,GLOBUS_FALSE, NULL},
 {"debug", "debug", NULL, "debug", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    "Sets options that make server easier to debug.  Forces no-fork, no-chdir, "
    "and allows core dumps on bad signals instead of exiting cleanly. "
    "Not recommended for production servers.  Note that non-forked servers running "
    "as 'root' will only accept a single connection, and then exit.", NULL, NULL,GLOBUS_FALSE, NULL}, 
/* internal use */
 {"globus_location", "globus_location", "GLOBUS_LOCATION", "G", NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    NULL, NULL, NULL} /* "GLOBUS_LOCATION." */,
 {"tcp_port_range", "tcp_port_range", NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    NULL, NULL, NULL} /*"Port range to use for PASV data connections.  Sets GLOBUS_TCP_PORT_RANGE."}*/,
 {"ignore_bad_threads", "ignore_bad_threads", NULL, "ignore-bad-threads", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    NULL, NULL, NULL,GLOBUS_FALSE, NULL}, /* allow LinuxThreads */
 {"bad_signal_exit", "bad_signal_exit", NULL, "exit", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_TRUE, NULL,
    NULL, NULL, NULL,GLOBUS_FALSE, NULL}, /* exit cleanly on bad signals (no core dump) */
 {"test_acl", NULL, NULL, NULL, "testacl", GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    NULL /* load and pass arguments to the test acl module. the string
        may include BLOCK, which will cause a failure in the callback,
        and any or all of ALL, init, or read, write, etc action to fail on */, NULL, NULL,GLOBUS_FALSE, NULL},
 {"wsdl", NULL, NULL, "wsdl", NULL, GLOBUS_L_GFS_CONFIG_STRING, GLOBUS_FALSE, NULL,
    NULL /* generate wsdl */, NULL, NULL,GLOBUS_FALSE, NULL},
 {"html", NULL, NULL, "html", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    NULL /* generate usage suitable for web docs */, NULL, NULL,GLOBUS_FALSE, NULL},
 {"docbook", NULL, NULL, "docbook", NULL, GLOBUS_L_GFS_CONFIG_BOOL, GLOBUS_FALSE, NULL,
    NULL /* generate usage suitable for web docs */, NULL, NULL,GLOBUS_FALSE, NULL},
 {"byte_transfer_count", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING,
    0, "0", NULL, NULL, NULL,GLOBUS_TRUE, NULL},
 {"file_transfer_count", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_INT,
    0, "0", NULL, NULL, NULL,GLOBUS_TRUE, NULL},
 {"fqdn", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    NULL /* hostname found by gethostname() */, NULL, NULL,GLOBUS_TRUE, NULL},
 {"loaded_config", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
     NULL /* placeholder so configfile check doesn't fail */, NULL, NULL,GLOBUS_FALSE, NULL},
 {"version_string", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
     NULL /* version string */, NULL, NULL,GLOBUS_FALSE, NULL},
 {"module_list", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_LIST, 0, NULL,
    NULL /* used to store list of allowed modules */, NULL, NULL,GLOBUS_FALSE, NULL},
 {"exec_name", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    NULL /* full path of server used when fork/execing */, NULL, NULL,GLOBUS_FALSE, NULL},
 {"dsi_options", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_STRING, 0, NULL,
    NULL /* options parsed from load_dsi_module config */, NULL, NULL,GLOBUS_FALSE, NULL},
 {"service_engine", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_VOID, 0, NULL,
    NULL, NULL, NULL,GLOBUS_FALSE, NULL},
 {"argv", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_VOID, 0, NULL,
    NULL /* original argv */, NULL, NULL,GLOBUS_FALSE, NULL},
 {"argc", NULL, NULL, NULL, NULL, GLOBUS_L_GFS_CONFIG_INT, 0, NULL,
    NULL /* original argc */, NULL, NULL, GLOBUS_FALSE, NULL}
};

static int option_count = sizeof(option_list) / sizeof(globus_l_gfs_config_option_t);

static globus_hashtable_t               option_table;


/* for string options, setting with an int_val of 1 will free the old one */ 
static
int
globus_l_gfs_config_set(
    char *                              option_name,
    int                                 int_value,
    void *                              value)
{
    globus_l_gfs_config_option_t *      option;
    int                                 i;
    int                                 rc; 
    GlobusGFSName(globus_l_gfs_config_set);
    GlobusGFSDebugEnter();

    option = (globus_l_gfs_config_option_t *) globus_hashtable_remove(
            &option_table, option_name);   
    if(!option)
    {
        option = (globus_l_gfs_config_option_t *)
            globus_calloc(1, sizeof(globus_l_gfs_config_option_t));
        for(i = 0; 
            i < option_count && option_list[i].option_name &&
                strcmp(option_name, option_list[i].option_name); 
            i++);
        if(i == option_count)
        {
            goto error;
        }    
        memcpy(option, &option_list[i], sizeof(globus_l_gfs_config_option_t));
    }
    switch(option->type)
    {
      case GLOBUS_L_GFS_CONFIG_BOOL:
      case GLOBUS_L_GFS_CONFIG_INT:
        option->int_value = int_value;
        break;
      case GLOBUS_L_GFS_CONFIG_STRING:
        if(int_value && option->value != NULL)
        {
            globus_free(option->value);
        }
      case GLOBUS_L_GFS_CONFIG_LIST:
      case GLOBUS_L_GFS_CONFIG_VOID:
        option->value = value;
        break;
      default:
        option->value = value;
        break;
    }
    rc = globus_hashtable_insert(&option_table,
        option->option_name,
        option);
    if(rc)
    {
        goto error;
    }

    GlobusGFSDebugExit();
    return 0;

error:
    globus_free(option);
    GlobusGFSDebugExitWithError();
    return 1;             
}

static
globus_result_t
globus_l_gfs_config_load_config_file(
    char *                              filename)
{
    FILE *                              fptr;
    char                                line[1024];
    char                                file_option[1024];
    char                                value[1024];
    int                                 i;
    int                                 rc;
    globus_l_gfs_config_option_t *      option;
    int                                 line_num;
    int                                 optlen;
    char *                              p;
    globus_off_t                        tmp_off;
    GlobusGFSName(globus_l_gfs_config_load_config_file);
    GlobusGFSDebugEnter();

    fptr = fopen(filename, "r");
    if(fptr == NULL)
    {
        GlobusGFSDebugExitWithError();
        return -2; /* XXX construct real error */
    }
    globus_l_gfs_config_set("loaded_config", 0, globus_libc_strdup(filename));  
    line_num = 0;
    while(fgets(line, sizeof(line), fptr) != NULL)
    {
        line_num++;
        p = line;
        optlen = 0;               
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
            rc = sscanf(p, "\"%[^\"]\"", file_option);
            optlen = 2;
        }
        else
        {
            rc = sscanf(p, "%s", file_option);
        }        
        if(rc != 1)
        {   
            goto error_parse;
        }
        optlen += strlen(file_option);
        p = p + optlen;
               
        optlen = 0;
        while(*p && isspace(*p))
        {
            p++;
        }
        if(*p == '"')
        {
            rc = sscanf(p, "\"%[^\"]\"", value);
            optlen = 2;
        }
        else
        {
            rc = sscanf(p, "%s", value);
        }        
        if(rc != 1)
        {   
            goto error_parse;
        }        
        optlen += strlen(value);
        p = p + optlen;        
        while(*p && isspace(*p))
        {
            p++;
        }
        if(*p && !isspace(*p))
        {
            goto error_parse;
        }

        for(i = 0; i < option_count; i++)
        {
            if(option_list[i].option_name == NULL)
            {
                continue;
            }
            if(!option_list[i].configfile_option || 
                strcmp(file_option, option_list[i].configfile_option))
            {
                continue;
            }
            
            option = (globus_l_gfs_config_option_t *) globus_hashtable_remove(
                    &option_table, option_list[i].option_name);   
            if(!option)
            {
                option = (globus_l_gfs_config_option_t *)
                    globus_malloc(sizeof(globus_l_gfs_config_option_t));
                memcpy(option, &option_list[i], sizeof(globus_l_gfs_config_option_t));
            }
            switch(option->type)
            {
              case GLOBUS_L_GFS_CONFIG_BOOL:
                option->int_value = (atoi(value) == 0) ? 0 : 1;
                break;
              case GLOBUS_L_GFS_CONFIG_INT:
                rc = globus_args_bytestr_to_num(value, &tmp_off);
                if(rc != 0)
                {
                    fprintf(stderr, "Invalid value for %s\n", 
                        option_list[i].option_name);
                    goto error_parse;
                }                  
                option->int_value = (int) tmp_off;
                break;
              case GLOBUS_L_GFS_CONFIG_STRING:
                option->value = globus_libc_strdup(value);
                break;
              default:
                break;
            }
            rc = globus_hashtable_insert(&option_table,
                option->option_name,
                (void *) option);
            
            if(rc)
            {
                /* XXX error, log something */
            }
        }
    }

    fclose(fptr);
    
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

error_parse:
    fclose(fptr);
    fprintf(stderr, "Problem parsing config file %s: line %d\n", 
        filename, line_num);
    GlobusGFSDebugExitWithError();
    return -1;

}

static
globus_result_t
globus_l_gfs_config_load_config_env()
{
    char *                              value;
    int                                 rc;
    int                                 i;
    globus_l_gfs_config_option_t *      option;
    globus_off_t                        tmp_off;
    GlobusGFSName(globus_l_gfs_config_load_config_env);
    GlobusGFSDebugEnter();
    

    for(i = 0; i < option_count; i++)
    {
        if(option_list[i].option_name == NULL)
        {
            continue;
        }
        if (!option_list[i].env_var_option || !*option_list[i].env_var_option)
        {
            continue;
        }

        value = globus_libc_getenv(option_list[i].env_var_option);
        
        if (!value)
        {
            continue;
        }
                            
        option = (globus_l_gfs_config_option_t *) globus_hashtable_remove(
                &option_table, option_list[i].option_name);   
        if(!option)
        {
            option = (globus_l_gfs_config_option_t *)
                globus_malloc(sizeof(globus_l_gfs_config_option_t));
            memcpy(option, &option_list[i], sizeof(globus_l_gfs_config_option_t));
        }
        switch(option->type)
        {
          case GLOBUS_L_GFS_CONFIG_BOOL:
            option->int_value = (atoi(value) == 0) ? 0 : 1;
            break;
          case GLOBUS_L_GFS_CONFIG_INT:
            rc = globus_args_bytestr_to_num(value, &tmp_off);
            if(rc != 0)
            {
                fprintf(stderr, "Invalid value for %s\n", 
                    option_list[i].option_name);
                return -1;
            }                  
            option->int_value = (int) tmp_off;
            break;
          case GLOBUS_L_GFS_CONFIG_STRING:
            option->value = globus_libc_strdup(value);
            break;
          default:
            break;
        }
        rc = globus_hashtable_insert(&option_table,
            option->option_name,
            (void *) option);
        
        if(rc)
        {
            /* XXX error, log something */
        }
    }       

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;
}


static
globus_result_t
globus_l_gfs_config_load_commandline(
    int                                 argc,
    char **                             argv)
{
    int                                 arg_num;
    char *                              argp;
    int                                 i;
    int                                 rc;
    int                                 len;
    globus_l_gfs_config_option_t *      option;
    globus_bool_t                       found;
    globus_bool_t                       negate;
    globus_off_t                        tmp_off;
    GlobusGFSName(globus_l_gfs_config_load_commandline);
    GlobusGFSDebugEnter();
    
    for(arg_num = 1; arg_num < argc; ++arg_num)
    {
        found = GLOBUS_FALSE;
        negate = GLOBUS_FALSE;
        
        argp = argv[arg_num];
        len = strlen(argp);
        
        if(len && *argp == '-')
        {
            argp++;
            len--;
        }
        if(len && *argp == '-')
        {
            argp++;
            len--;
        }
        if((len - 2) && strncasecmp(argp, "no-", 3) == 0)
        {
            argp += 3;
            len -= 3;
            negate = GLOBUS_TRUE;
        }
        else if(len && tolower(*argp) == 'n')
        {
            argp ++;
            len --;
            negate = GLOBUS_TRUE;
        }
        
        for(i = 0; i < option_count && !found && len; i++)
        {
            if(option_list[i].option_name == NULL)
            {
                continue;
            }
            if((!option_list[i].short_cmdline_option || 
                strcmp(argp, option_list[i].short_cmdline_option)) && 
                (!option_list[i].long_cmdline_option || 
                strcmp(argp, option_list[i].long_cmdline_option)) )
            {
                continue;
            }
            
            found = GLOBUS_TRUE;
                       
            option = (globus_l_gfs_config_option_t *) globus_hashtable_remove(
                    &option_table, option_list[i].option_name);   
            if(!option)
            {
                option = (globus_l_gfs_config_option_t *)
                    globus_malloc(sizeof(globus_l_gfs_config_option_t));
                memcpy(
                    option,
                    &option_list[i],
                    sizeof(globus_l_gfs_config_option_t));
            }

            switch(option->type)
            {
              case GLOBUS_L_GFS_CONFIG_BOOL:
                option->int_value = !negate;
                break;

              case GLOBUS_L_GFS_CONFIG_INT:
                if(++arg_num >= argc)
                {
                    fprintf(stderr, "Option %s is missing a value\n", argp);
                    return -1;
                }
                rc = globus_args_bytestr_to_num(argv[arg_num], &tmp_off);
                if(rc != 0)
                {
                    fprintf(stderr, "Invalid value for %s\n", argp);
                    return -1;
                }                  
                option->int_value = (int) tmp_off;
                break;
                
              case GLOBUS_L_GFS_CONFIG_STRING:
                if(++arg_num >= argc)
                {
                    fprintf(stderr, "Option %s is missing a value\n", argp);
                    return -1;
                }
                option->value = globus_libc_strdup(argv[arg_num]);
                break;

              default:
                break;
             }

            rc = globus_hashtable_insert(&option_table,
                option->option_name,
                (void *) option);
            
            if(rc)
            {
                /* XXX error, log something */
            }
            
        }
        
        if(!found)
        {
            fprintf(stderr, "Unknown option on command line: %s%s\n",
                negate ? "no-" : "", argp);
            return -1;
        }
    }
      
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;

}


static
globus_result_t
globus_l_gfs_config_load_defaults()
{
    int                                 rc;
    int                                 i;
    globus_l_gfs_config_option_t *      option;
    GlobusGFSName(globus_l_gfs_config_load_defaults);
    GlobusGFSDebugEnter();
    
    for(i = 0; i < option_count; i++)
    {        
        if(option_list[i].option_name == NULL)
        {
            continue;
        }
        option = (globus_l_gfs_config_option_t *)
            globus_malloc(sizeof(globus_l_gfs_config_option_t));
        memcpy(option, &option_list[i], sizeof(globus_l_gfs_config_option_t));
        
        rc = globus_hashtable_insert(&option_table, 
            option->option_name, 
            (void *) option);
        
        if(rc)
        {
            /* XXX error, log something */
        }
    }

    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS; 
}

static
int
globus_l_config_loadfile(
    const char *                        filename,
    char **                             data_out)
{
    FILE *                              file;
    int                                 file_len;
    char *                              out_buf;
    GlobusGFSName(globus_l_config_loadfile);
    GlobusGFSDebugEnter();
     
    file = fopen(filename, "r");
    if(!file)
    {
        goto error;
    }
         
    fseek(file, 0L, SEEK_END);
    file_len = ftell(file);
    fseek(file, 0L, SEEK_SET);	

    out_buf = (char *) malloc((file_len + 1) * sizeof(char));	
    if(!out_buf)
    {
        fclose(file);
        goto error;
    }

    fread(out_buf, sizeof(char), file_len, file);
    fclose(file);
    out_buf[file_len] = '\0';

    *data_out = out_buf;
         
    GlobusGFSDebugExit();
    return 0;

error:
    GlobusGFSDebugExitWithError();
    return 1;
}

static
void
globus_l_gfs_config_display_html_usage()
{
    int                                 i;
    globus_l_gfs_config_option_t *      o;
    GlobusGFSName(globus_l_gfs_config_display_html_usage);
    GlobusGFSDebugEnter();
    
    printf("<!-- generated by globus-gridftp-server -help -html -->\n");
    printf("<p>\n"
        "The table below lists config file options, associated command line " 
        "options (if available) and descriptions. Note that any boolean "
        "option can be negated on the command line by preceding the specified " 
        "option with '-no-' or '-n'.  example: -no-cas or -nf.\n"
        "</p>\n");

    printf("<ul>\n");
    for(i = 0; i < option_count; i++)
    {        
        o = (globus_l_gfs_config_option_t *) &option_list[i];
        if(o->option_name == NULL)
        {
            printf("  <li><a href=\"#gftpclass%d\">%s</a></li>\n",
                i, o->configfile_option);
        }
    }
    printf("</ul>\n");

    printf("\n");

    printf("<table border=\"1\" cellpadding=\"5\">\n");
    for(i = 0; i < option_count; i++)
    {        
        char *                          shortflag;
        char *                          longflag;
        char *                          value;
        char *                          defval;
        
        o = (globus_l_gfs_config_option_t *) &option_list[i];
        if(o->option_name == NULL)
        {
            printf(
                "  <tr>\n"
                "    <th colspan=\"2\" valign=\"top\"><a name=\"gftpclass%d\"></a>%s</th>\n"
                "  </tr>\n",
                i,
                o->configfile_option);
            continue;
        }
        if(o->usage == NULL)
        {
            continue;
        }

        switch(o->type)
        {
          case GLOBUS_L_GFS_CONFIG_BOOL:
            shortflag = "-";
            longflag = "-";
            value = " &lt;0|1&gt;"; 
            defval = o->int_value ? "TRUE" : "FALSE";
            break;
          case GLOBUS_L_GFS_CONFIG_INT:
            shortflag = "-";
            longflag = "-";
            value = " &lt;number&gt;"; 
            defval = o->int_value > 0 ? 
                globus_common_create_string("%d", o->int_value) : "not set";
            break;
          case GLOBUS_L_GFS_CONFIG_STRING:
            shortflag = "-";
            longflag = "-";
            value = " &lt;string&gt;"; 
            defval = o->value ? o->value : "not set";
            break;
          default:
            shortflag = "";
            longflag = "";
            value = ""; 
            defval = o->value ? o->value : "not set";
            break;
        }
        printf(
            "  <tr>\n"
            "    <td valign=\"top\">\n"
            "     <table border=\"0\" cellpadding=\"2\" width=\"100%%\">\n"
            "      <tr><td valign=\"top\"><pre>%s%s</pre></td></tr>\n"
            "      <tr><td valign=\"top\"><pre>%s%s%s%s%s%s%s</pre></td></tr>\n"
            "     </table>\n"
            "    </td>\n"
            "    <td valign=\"top\"><p>%s</p><p>Default value: %s</p></td>\n"
            "  </tr>\n", 
            o->configfile_option, 
            value,
            o->short_cmdline_option ? shortflag : "", 
            o->short_cmdline_option ? o->short_cmdline_option : "",
            o->type != GLOBUS_L_GFS_CONFIG_BOOL && 
                o->short_cmdline_option ? value : "",
            o->short_cmdline_option ? "\n" : "", 
            o->long_cmdline_option ? longflag : "",
            o->long_cmdline_option ? o->long_cmdline_option : "",
            o->type != GLOBUS_L_GFS_CONFIG_BOOL && 
                o->long_cmdline_option ? value : "",
            o->usage,
            defval);
    }
    printf("</table>\n");
    printf("<!-- end generated block -->\n");

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_config_display_wsdl()
{
    int                                 i;
    globus_l_gfs_config_option_t *      o;
    GlobusGFSName(globus_l_gfs_config_display_wsdl);
    char *                              wsdl_file;
    FILE *                              out;
    globus_bool_t                       close = GLOBUS_TRUE;
    GlobusGFSDebugEnter();

    wsdl_file = globus_common_create_string("%s.xsd",
        globus_i_gfs_config_string("wsdl"));
    out = fopen(wsdl_file, "w");
    if(out == NULL)
    {
        close = GLOBUS_FALSE;
        out = stdout;
    }
    for(i = 0; i < option_count; i++)
    {        
        o = (globus_l_gfs_config_option_t *) &option_list[i];
        if(o->option_name != NULL && o->public)
        {

            switch(o->type)
            {
                case GLOBUS_L_GFS_CONFIG_INT:
                case GLOBUS_L_GFS_CONFIG_BOOL:
                    fprintf(out, "    "
                        "<xsd:element name=\"%s\" type=\"xsd:int\"/>\n",
                        o->option_name);
                    break;

                case GLOBUS_L_GFS_CONFIG_STRING:
                    fprintf(out, "    "
                        "<xsd:element name=\"%s\" type=\"xsd:string\"/>\n",
                        o->option_name);
                    break;

                default:
                    break;
            }
        }
    }
    fprintf(out, "<xsd:element name=\"FrontendStats\">\n");
    fprintf(out, "    <xsd:complexType><xsd:sequence>\n");

    for(i = 0; i < option_count; i++)
    {        
        o = (globus_l_gfs_config_option_t *) &option_list[i];
        if(o->option_name != NULL && o->public)
        {
            switch(o->type)
            {
                case GLOBUS_L_GFS_CONFIG_STRING:
                case GLOBUS_L_GFS_CONFIG_INT:
                case GLOBUS_L_GFS_CONFIG_BOOL:
                    fprintf(out, "        "
                        "<xsd:element ref=\"tns:%s\"/>\n",
                        o->option_name);
                    break;

                default:
                    break;
            }
        }
    }
    fprintf(out, "    </xsd:sequence></xsd:complexType>\n");
    fprintf(out, "</xsd:element>\n");

    if(close)
    {
        fclose(out);
    }

    GlobusGFSDebugExit();
}

static
void
globus_l_gfs_config_display_c_service()
{
    int                                 i;
    globus_l_gfs_config_option_t *      o;
    GlobusGFSName(globus_l_gfs_config_display_c_service);
    FILE *                              out;
    globus_bool_t                       close = GLOBUS_TRUE;
    char *                              c_file;
    GlobusGFSDebugEnter();
    
    c_file = globus_common_create_string("%s.c",
        globus_i_gfs_config_string("wsdl"));
    out = fopen(c_file, "w");
    if(out == NULL)
    {
        close = GLOBUS_FALSE;
        out = stdout;
    }
    for(i = 0; i < option_count; i++)
    {        
        o = (globus_l_gfs_config_option_t *) &option_list[i];
        if(o->option_name != NULL && o->public)
        {
            switch(o->type)
            {
                case GLOBUS_L_GFS_CONFIG_STRING:
                case GLOBUS_L_GFS_CONFIG_INT:
                case GLOBUS_L_GFS_CONFIG_BOOL:
                    fprintf(out, "#include <%s.h>\n", o->option_name);
                    break;

                default:
                    break;
            }
        }
    }
    fprintf(out, "\n");
    fprintf(out, "\n");

    fprintf(out, "globus_result_t\n");
    fprintf(out, "gridftpR_l_setup_resource(\n");
    fprintf(out, "    globus_resource_t                   resource)\n");
    fprintf(out, "{\n");
    fprintf(out, "    globus_result_t                     result;\n");
    fprintf(out, "    globus_i_gfs_config_option_cb_ent_t * cb_handle;\n");
    for(i = 0; i < option_count; i++)
    {        
        o = (globus_l_gfs_config_option_t *) &option_list[i];
        if(o->option_name != NULL && o->public)
        {
            switch(o->type)
            {
                case GLOBUS_L_GFS_CONFIG_INT:
                case GLOBUS_L_GFS_CONFIG_BOOL:
                    fprintf(out, "    "
                        "globus_gfs_config_add_cb(&cb_handle, \"%s\",",
                        o->option_name);
                    fprintf(out, "        gridftpA_l_intchange_cb,");
                    fprintf(out, "        \"%s\");", o->option_name);
                    fprintf(out, "\n");
                    fprintf(out, "    "
                        "result = globus_resource_create_property_callback(\n");
                    fprintf(out, "        resource,\n");
                    fprintf(out, "        &%s_qname,\n", o->option_name);
                    fprintf(out, "        &%s_info,\n", o->option_name);
                    fprintf(out, "        griidftpR_l_int_get_cb,\n");
                    fprintf(out, "        gridftpR_l_int_set_cb,\n");
                    fprintf(out, "        cb_handle);\n");
                    fprintf(out, "    if (result != GLOBUS_SUCCESS)\n");
                    fprintf(out, "    {\n");
                    fprintf(out, "        goto error;\n");
                    fprintf(out, "    }\n");
                    fprintf(out, "\n");
                    break;

                case GLOBUS_L_GFS_CONFIG_STRING:
                    fprintf(out, "    "
                        "result = globus_resource_create_property_callback(\n");
                    fprintf(out, "        resource,\n");
                    fprintf(out, "        &%s_qname,\n", o->option_name);
                    fprintf(out, "        &%s_info,\n", o->option_name);
                    fprintf(out, "        gridftpR_l_string_get_cb,\n");
                    fprintf(out, "        gridftpR_l_string_set_cb,\n");
                    fprintf(out, "        \"%s\");\n", o->option_name);
                    fprintf(out, "    if (result != GLOBUS_SUCCESS)\n");
                    fprintf(out, "    {\n");
                    fprintf(out, "        goto error;\n");
                    fprintf(out, "    }\n");
                    fprintf(out, "\n");
                    break;

                default:
                    break;
            }
        }
    }
    fprintf(out, "\n");
    fprintf(out, "    return GLOBUS_SUCCESS;\n");
    fprintf(out, "error:\n");
    fprintf(out, "    return result;\n");
    fprintf(out, "}\n");
    fprintf(out, "\n");

    GlobusGFSDebugExit();
}


static
void
globus_l_gfs_config_display_docbook_usage()
{
    globus_bool_t                       first = GLOBUS_TRUE;
    int                                 i;
    globus_l_gfs_config_option_t *      o;
    GlobusGFSName(globus_l_gfs_config_display_docbook_usage);
    GlobusGFSDebugEnter();
    
    printf("<!-- generated by globus-gridftp-server -help -docbook -->\n");
    printf("<para>\n"
        "The table below lists config file options, associated command line " 
        "options (if available) and descriptions. Note that any boolean "
        "option can be negated on the command line by preceding the specified " 
        "option with '-no-' or '-n'.  example: -no-cas or -nf.\n"
        "</para>\n");

    printf("<!-- <itemizedlist>\n");
    for(i = 0; i < option_count; i++)
    {        
        o = (globus_l_gfs_config_option_t *) &option_list[i];
        if(o->option_name == NULL)
        {
            printf("  <listitem><simpara><ulink url=\"#gftpclass%d\">%s</ulink></simpara></listitem>\n",
                i, o->configfile_option);
        }
    }
    printf("</itemizedlist> -->\n");

    printf("\n");

    for(i = 0; i < option_count; i++)
    {        
        char *                          shortflag;
        char *                          longflag;
        char *                          value;
        char *                          defval;
        
        o = (globus_l_gfs_config_option_t *) &option_list[i];
        if(o->option_name == NULL)
        {
            if(!first)
            {
                printf("</tbody></tgroup></table>\n");
            }
            first = GLOBUS_FALSE;

            printf(
                "<table><title>%s</title>\n"
                "<tgroup cols=\"2\">\n"
                "<tbody>\n",
                o->configfile_option);
            continue;
        }
        if(o->usage == NULL)
        {
            continue;
        }

        switch(o->type)
        {
          case GLOBUS_L_GFS_CONFIG_BOOL:
            shortflag = "-";
            longflag = "-";
            value = " &lt;0|1&gt;"; 
            defval = o->int_value ? "TRUE" : "FALSE";
            break;
          case GLOBUS_L_GFS_CONFIG_INT:
            shortflag = "-";
            longflag = "-";
            value = " &lt;number&gt;"; 
            defval = o->int_value > 0 ? 
                globus_common_create_string("%d", o->int_value) : "not set";
            break;
          case GLOBUS_L_GFS_CONFIG_STRING:
            shortflag = "-";
            longflag = "-";
            value = " &lt;string&gt;"; 
            defval = o->value ? o->value : "not set";
            break;
          default:
            shortflag = "";
            longflag = "";
            value = ""; 
            defval = o->value ? o->value : "not set";
            break;
        }
        
        printf(
            "  <row>\n"
            "    <entry><para><screen>%s%s\n%s%s%s%s%s%s%s</screen></para></entry>\n"
            "    <entry><para>%s</para><para>Default value: %s</para></entry>\n"
            "  </row>\n", 
            o->configfile_option, 
            value,
            o->short_cmdline_option ? shortflag : "", 
            o->short_cmdline_option ? o->short_cmdline_option : "",
            o->type != GLOBUS_L_GFS_CONFIG_BOOL && 
                o->short_cmdline_option ? value : "",
            o->short_cmdline_option ? "\n" : "", 
            o->long_cmdline_option ? longflag : "",
            o->long_cmdline_option ? o->long_cmdline_option : "",
            o->type != GLOBUS_L_GFS_CONFIG_BOOL && 
                o->long_cmdline_option ? value : "",
            o->usage,
            defval);
    }
    if(!first)
    {
        printf("</tbody></tgroup></table>\n");
    }
    printf("<!-- end generated block -->\n");

    GlobusGFSDebugExit();
}

void
globus_i_gfs_config_display_long_usage()
{
    int                                 i;
    globus_l_gfs_config_option_t *      o;
    GlobusGFSName(globus_i_gfs_config_display_long_usage);
    GlobusGFSDebugEnter();

    if(globus_i_gfs_config_bool("html"))
    {
        globus_l_gfs_config_display_html_usage();
    }
    else if(globus_i_gfs_config_bool("docbook"))
    {
        globus_l_gfs_config_display_docbook_usage();
    }
    else if(globus_i_gfs_config_string("wsdl") != NULL)
    {
        globus_l_gfs_config_display_wsdl();
        globus_l_gfs_config_display_c_service();
    }
    else
    {        
        for(i = 0; i < option_count; i++)
        {        
            o = (globus_l_gfs_config_option_t *) &option_list[i];
            if(o->usage == NULL)
            {
                continue;
            }
            
            printf("%-14s    %s\n%-14s    %sCommand line or ENV args:", 
                o->option_name, o->usage, "",
                o->type == GLOBUS_L_GFS_CONFIG_BOOL ? "(FLAG)  " : "");
            if(o->short_cmdline_option)
            {
                printf(" -%s,", o->short_cmdline_option);
            }
            if(o->long_cmdline_option)
            {
                printf(" -%s,", o->long_cmdline_option);
            }
            if(o->env_var_option)
            {
                printf(" $%s", o->env_var_option);
            }
            printf("\n");
        }
        printf("\nAny FLAG can be negated by prepending '-no-' or '-n' to the "
            "command line \noption or setting a value of 0 in the config file.\n\n");
        printf("Check the GridFTP section at http://www.globus.org/toolkit/docs/\n"
            "for more in-depth documentation.\n\n");
    }

    GlobusGFSDebugExit();
}

static
int
globus_l_gfs_config_format_line(
    const char *                        in_str,
    int                                 rows,
    int                                 columns,
    char *                              out_buffer)
{
    int                                 len;
    int                                 i;
    int                                 j;
    int                                 count;
    int                                 last;
    int                                 blanks;
                                   
    len = strlen(in_str);
    count = 0;
    memset(out_buffer, 0, rows * columns);
    
    for(i = 0; i < rows && count < len; i++)
    {
        for(j = 0; j < columns - 1 && count < len; j++, count++) 
        {
            if(in_str[count] == ' ')
            {
                last = count;
            }
            out_buffer[i*columns+j] = in_str[count];
        }
        if(count < len && in_str[count] != ' ')
        {
            blanks = count - last;
            count = last+1;
            out_buffer[i*columns+j-blanks] = 0;
        }
        while(count < len && in_str[count] == ' ')
        {
            count++;
        }  
    }

    return 0;
}
        
void
globus_i_gfs_config_display_usage()
{
    int                                 i;
    globus_l_gfs_config_option_t *      o;
    GlobusGFSName(globus_i_gfs_config_display_short_usage);
    GlobusGFSDebugEnter();
    
    if(globus_i_gfs_config_bool("html"))
    {
        globus_l_gfs_config_display_html_usage();
    }
    else if(globus_i_gfs_config_bool("docbook"))
    {
        globus_l_gfs_config_display_docbook_usage();
    }
    else if(globus_i_gfs_config_string("wsdl"))
    {
        globus_l_gfs_config_display_wsdl();
        globus_l_gfs_config_display_c_service();
    }
    else
    {        
        for(i = 0; i < option_count; i++)
        {
            char       linebuffer[GLOBUS_GFS_HELP_ROWS * GLOBUS_GFS_HELP_COLS];
            int                         count = 0;
            char *                      usage;
            char *                      value;
            int                         col;
            int                         row;
            int                         len;
            char                        defval[255];
            o = (globus_l_gfs_config_option_t *) &option_list[i];
            if(o->option_name == NULL && o->configfile_option != NULL)
            {
                count = 0;
                printf("\n");
                len = GLOBUS_GFS_HELP_WIDTH - 
                    (strlen(o->configfile_option) + 4);
                if(len > 0)
                {
                    len = len / 2;
                }
                else
                {
                    len = 0;
                }
                count += printf(" ");
                while(len--)
                {
                    count += printf("=");
                }
                count += printf("  %s  ", o->configfile_option);
                while(count < GLOBUS_GFS_HELP_WIDTH - 1)
                {
                    count += printf("=");
                }
                printf("\n\n");
                continue;
            }
            else if(o->usage == NULL && o->short_usage == NULL)
            {
                continue;
            }
           
            switch(o->type)
            {
                case GLOBUS_L_GFS_CONFIG_BOOL:
                    value = ""; 
                    sprintf(defval, "%s", o->int_value ? "TRUE" : "FALSE");
                    break;
                case GLOBUS_L_GFS_CONFIG_INT:
                    value = "<number>"; 
                    if(o->int_value > 0) 
                    {
                        sprintf(defval, "%d", o->int_value);
                    }
                    else
                    {
                        sprintf(defval, "%s", "not set");
                    }
                    break;
                case GLOBUS_L_GFS_CONFIG_STRING:
                    value = "<string>"; 
                    sprintf(defval, "%s", 
                        o->value ? (char *) o->value : "not set");
                    break;
                default:
                    value = ""; 
                    sprintf(defval, "%s", "not set");
                    break;
            }
            
            if(o->short_cmdline_option)
            {
                count += printf(" -%s", o->short_cmdline_option);
            }
            if(o->long_cmdline_option)
            {
                count += printf(" -%s", o->long_cmdline_option);
            }
            if(o->expected_val)
            {
                count += printf(" %s", o->expected_val);
            }
            if(value)
            {
                count += printf(" %s   ", value);
            }
            usage = o->short_usage ? o->short_usage : o->usage;
            globus_l_gfs_config_format_line(
                usage, GLOBUS_GFS_HELP_ROWS, GLOBUS_GFS_HELP_COLS, linebuffer);

            len = strlen(linebuffer);
            for(row = 0; row < GLOBUS_GFS_HELP_ROWS && 
                linebuffer[row * GLOBUS_GFS_HELP_COLS]; 
                row++)
            {
                if(row == 1)
                {
                    count += printf("  Default: %s ", defval);
                }
                for(col = count; 
                    col < GLOBUS_GFS_HELP_WIDTH - GLOBUS_GFS_HELP_COLS; 
                    col++)
                {
                    printf(" ");
                }
                count = 0;

                printf("%s", &linebuffer[row * GLOBUS_GFS_HELP_COLS]);
                printf("\n");
            }
            if(row == 1)
            {
                    count += printf("  Default: %s \n", defval);
            }
            printf("\n");
        }
        printf("\nAny FLAG can be negated by prepending '-no-' or '-n' to the "
            "command line option.\n\n");
        printf("Check the GridFTP section at http://www.globus.org/toolkit/docs/\n"
            "for more in-depth documentation.\n\n");
    }

    GlobusGFSDebugExit();
}

globus_result_t
globus_l_gfs_config_hostname_to_address_string(
    char *                              hostname,
    char *                              out_buf,
    int                                 out_buf_len)                              
{
    globus_addrinfo_t                   hints;
    globus_addrinfo_t *                 addrinfo;
    globus_result_t                     result;
    
    memset(&hints, 0, sizeof(globus_addrinfo_t));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    result = globus_libc_getaddrinfo(hostname, NULL, &hints, &addrinfo);
    if(result != GLOBUS_SUCCESS || addrinfo == NULL || 
        addrinfo->ai_addr == NULL)
    {
        goto error_exit;
    }
    result = globus_libc_getnameinfo(
        (const globus_sockaddr_t *) addrinfo->ai_addr,
        out_buf,
        out_buf_len,
        NULL,
        0,
        GLOBUS_NI_NUMERICHOST);
    if(result != GLOBUS_SUCCESS)
    {
        globus_libc_freeaddrinfo(addrinfo);
        goto error_exit;
    }       
    globus_libc_freeaddrinfo(addrinfo);    
    
    return GLOBUS_SUCCESS;
    
error_exit:
    return result;
}

static
globus_result_t
globus_l_gfs_config_misc()
{
    globus_list_t *                     module_list = NULL;
    char *                              module;
    char *                              ptr;
    char *                              default_dsi;
    int                                 rc;
    globus_bool_t                       bool_value;
    char *                              value;
    char *                              data;
    globus_result_t                     result;
    char                                ipaddr[256];
    GlobusGFSName(globus_l_gfs_config_misc);
    GlobusGFSDebugEnter();
    
    if(globus_i_gfs_config_bool("detach") && 
        !globus_i_gfs_config_bool("daemon"))
    {
        globus_l_gfs_config_set("daemon", GLOBUS_TRUE, NULL);
    }
    if(!globus_i_gfs_config_bool("fork"))
    {
        globus_l_gfs_config_set("detach", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("daemon", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("chdir", GLOBUS_FALSE, NULL);
    }
    if(globus_i_gfs_config_bool("inetd"))
    {
        globus_l_gfs_config_set("single", GLOBUS_TRUE, NULL);
        globus_l_gfs_config_set("daemon", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("detach", GLOBUS_FALSE, NULL);
    }

    if(globus_i_gfs_config_bool("debug"))
    {
        globus_l_gfs_config_set("daemon", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("detach", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("fork", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("bad_signal_exit", GLOBUS_FALSE, NULL);
        globus_l_gfs_config_set("chdir", GLOBUS_FALSE, NULL);
    }

    if(globus_i_gfs_config_bool("allow_anonymous"))
    {
        globus_l_gfs_config_set("secure_ipc", GLOBUS_FALSE, NULL);
    }
    if(globus_i_gfs_config_bool("longhelp"))
    {
        globus_l_gfs_config_set("help", GLOBUS_TRUE, NULL);
    }

    if((value = 
        globus_i_gfs_config_string("control_interface")) != GLOBUS_NULL)
    {        
        memset(ipaddr, 0, sizeof(ipaddr));
        result = globus_l_gfs_config_hostname_to_address_string(
            value, ipaddr, sizeof(ipaddr));  
        if(result != GLOBUS_SUCCESS)
        {   
            goto error_exit;
        }
        globus_l_gfs_config_set(
            "control_interface", 1, globus_libc_strdup(ipaddr));
    }

    if((value = 
        globus_i_gfs_config_string("data_interface")) != GLOBUS_NULL)
    {        
        memset(ipaddr, 0, sizeof(ipaddr));
        result = globus_l_gfs_config_hostname_to_address_string(
            value, ipaddr, sizeof(ipaddr));  
        if(result != GLOBUS_SUCCESS)
        {   
            goto error_exit;
        }
        globus_l_gfs_config_set(
            "data_interface", 1, globus_libc_strdup(ipaddr));
    }

    if((value = globus_i_gfs_config_string("hostname")) != GLOBUS_NULL)
    {
        globus_l_gfs_config_set("fqdn", 0, globus_libc_strdup(value));
        
        memset(ipaddr, 0, sizeof(ipaddr));
        result = globus_l_gfs_config_hostname_to_address_string(
            value, ipaddr, sizeof(ipaddr));  
        if(result != GLOBUS_SUCCESS)
        {   
            goto error_exit;
        }
                      
        if(globus_i_gfs_config_string("control_interface") == NULL)
        {
            globus_l_gfs_config_set(
                "control_interface", 0, globus_libc_strdup(ipaddr));
        }
        if(globus_i_gfs_config_string("data_interface") == NULL)
        {
            globus_l_gfs_config_set(
                "data_interface", 0, globus_libc_strdup(ipaddr));
        }
    }
    else
    {
        char *                          hostname;
        hostname = globus_malloc(1024);
        globus_libc_gethostname(hostname, 1024);
        globus_l_gfs_config_set("fqdn", 0, globus_libc_strdup(hostname));
        globus_free(hostname);
    }            

        
    if((bool_value = globus_i_gfs_config_bool("banner_terse")) == GLOBUS_TRUE)
    {
        globus_l_gfs_config_set("banner", 0, globus_libc_strdup(""));                
    }
    else if((value = globus_i_gfs_config_string("banner_file")) != GLOBUS_NULL)
    {
        rc = globus_l_config_loadfile(value, &data);
        globus_l_gfs_config_set("banner", 0, data);                
    }
    else
    {
            data = globus_common_create_string(
                "%s GridFTP Server %d.%d (%s, %d-%d) ready.",
                globus_i_gfs_config_string("fqdn"),
                local_version.major,
                local_version.minor,
                build_flavor,
                local_version.timestamp,
                local_version.branch_id);
            globus_l_gfs_config_set("banner", 0, data);
    }

    data = globus_common_create_string(
            "%d.%d (%s, %d-%d)",
            local_version.major,
            local_version.minor,
            build_flavor,
            local_version.timestamp,
            local_version.branch_id);
    globus_l_gfs_config_set("version_string", 0, data);
            
    if((value = globus_i_gfs_config_string("login_msg_file")) != GLOBUS_NULL)
    {
        rc = globus_l_config_loadfile(value, &data);
        globus_l_gfs_config_set("login_msg", 0, data);                
    }
    
    if((value = globus_i_gfs_config_string("tcp_port_range")) != GLOBUS_NULL)
    {
        rc = globus_libc_setenv("GLOBUS_TCP_PORT_RANGE", value, 1);
        if(rc)
        {
        }
    }

    value = globus_i_gfs_config_string("load_dsi_module");
    if(value != NULL)
    {
        char *                          ptr;
        
        ptr = strchr(value, ':');
        if(ptr)
        {
            /* changing the value in the table directly here, but we'll set it
             * anyways to be clear that we are */
            *ptr = '\0';
            ptr++;
            globus_l_gfs_config_set(
                "load_dsi_module", 0, value);
            globus_l_gfs_config_set(
                "dsi_options", 0, globus_libc_strdup(ptr));
        }
    }

    value = globus_i_gfs_config_string("remote_nodes");
    {
        if(value)
        {
            if(globus_i_gfs_config_string("load_dsi_module") == NULL)
            {
                globus_l_gfs_config_set("load_dsi_module", 0, globus_libc_strdup("remote"));    
            }            
        }            
    }
    if(globus_i_gfs_config_string("load_dsi_module") == NULL)
    {
        globus_l_gfs_config_set("load_dsi_module", 0, globus_libc_strdup("file"));    
    } 

    value = globus_libc_strdup(globus_i_gfs_config_string("allowed_modules"));
    if(value != NULL)
    {
        module = value;
        while((ptr = strchr(module, ',')) != NULL)
        {
            *ptr = '\0';
            globus_list_insert(&module_list, globus_libc_strdup(module)); 
            module = ptr + 1;
        }
        if(ptr == NULL)
        {
            globus_list_insert(&module_list, globus_libc_strdup(module)); 
        }               
        globus_free(value);             
    }
    default_dsi = globus_i_gfs_config_string("load_dsi_module");
    globus_assert(default_dsi != NULL);
    globus_list_insert(&module_list, strdup(default_dsi));
    globus_l_gfs_config_set("module_list", 0, module_list);   
    
    /* if auth_level is -1 it means it has not yet been touched */
    switch(globus_i_gfs_config_int("auth_level"))
    {
        case -1:
            if(globus_i_gfs_config_bool("data_node"))
            {
                globus_l_gfs_config_set("auth_level", 1, NULL);
            }
            else
            {
                globus_l_gfs_config_set("auth_level", 3, NULL);
            }
            break;
        case 2:
            globus_l_gfs_config_set("auth_level", 3, NULL);
            break;
        case 4:
            globus_l_gfs_config_set("auth_level", 5, NULL);
            break;
        case 6:
            globus_l_gfs_config_set("auth_level", 7, NULL);
            break;
        default:
            break;
    }

    /* make sure root running process that does not fork can only run
        once */
    if(!globus_i_gfs_config_bool("daemon") && getuid() == 0)
    {
        globus_l_gfs_config_set("connections_max", 1, NULL);
        globus_l_gfs_config_set("single", 1, NULL);
    }

    if(globus_i_gfs_config_string("remote_nodes") != NULL &&
        globus_i_gfs_config_bool("data_node"))
    {
        char *                          str;

        /* XXX: not sure about this.  perhaps it can connect back after
            forking, tho that how that would work is awkward, ie
            when would it fork */
        if(globus_i_gfs_config_bool("fork"))
        {
            /* should log an error */
            globus_l_gfs_config_set("fork", GLOBUS_FALSE, NULL);   
        }

        /* set the convience conf opt */
        globus_l_gfs_config_set("data_node_client", GLOBUS_TRUE, NULL);

        /* if allow from not set for ipc specific, pull it from regular */
        str = globus_i_gfs_config_string("ipc_allow_from");
        if(str == NULL)
        {
            str = globus_i_gfs_config_string("allow_from");
            globus_l_gfs_config_set("ipc_allow_from", 0, str);
        }
        str = globus_i_gfs_config_string("ipc_deny_from");
        if(str == NULL)
        {
            str = globus_i_gfs_config_string("deny_from");
            globus_l_gfs_config_set("ipc_deny_from", 0, str);
        }
    }

    /* if it is a listening data node */
    if(globus_i_gfs_config_string("remote_nodes") == NULL &&
        globus_i_gfs_config_bool("data_node"))
    {
        int                             port;

        port = globus_i_gfs_config_int("port");
        if(port == 0)
        {
            port = globus_i_gfs_config_int("ipc_port");
            globus_l_gfs_config_set("port", port, NULL);   
        }
    } 
    if(globus_i_gfs_config_string("ipc_user_name") == NULL)
    {
        struct passwd *                 pwent;

        pwent = getpwuid(getuid());
        if(pwent == NULL)
        {
        }
        if(pwent->pw_name == NULL)
        {
        }
        globus_l_gfs_config_set("ipc_user_name", 0, 
            globus_libc_strdup(pwent->pw_name));
    }
    
    GlobusGFSDebugExit();
    return GLOBUS_SUCCESS;
    
error_exit:
    GlobusGFSDebugExitWithError();
    return result;
}
    

/**
 * load configuration.  read from defaults, file, env, and command line 
 * arguments. each overriding the other.
 * this function will log error messages and exit the server if any
 * errors occur.
 * XXX need to allow config errors to log to syslog, stderr, etc
 */
void
globus_i_gfs_config_init(
    int                                 argc,
    char **                             argv)
{
    char *                              tmp_str;
    char *                              exec_name;
    char *                              local_config_file;
    char *                              global_config_file;
    int                                 arg_num;
    char *                              argp;
    int                                 rc;
    globus_result_t                     result;
    GlobusGFSName(globus_i_gfs_config_init);
    GlobusGFSDebugEnter();
    
    globus_hashtable_init(
        &option_table,
        256,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);

    exec_name = argv[0];
    /* set default exe name */
    tmp_str = globus_module_getenv("GLOBUS_LOCATION");
    if(tmp_str)
    {
        exec_name = globus_common_create_string(
         "%s/sbin/globus-gridftp-server",
         globus_module_getenv("GLOBUS_LOCATION"));
    }
    else if(exec_name[0] == '.')
    {
        tmp_str = malloc(PATH_MAX);
        getcwd(tmp_str, PATH_MAX);
        exec_name = globus_common_create_string(
         "%s/%s", tmp_str, exec_name);
        globus_free(tmp_str);
    }
    else
    {
        exec_name = strdup(argv[0]);
    }

    global_config_file = "/etc/grid-security/gridftp.conf";
    local_config_file = NULL;

    for(arg_num = 0; arg_num < argc; arg_num++)
    {
        argp = argv[arg_num];
        if(*argp == '-' && *++argp == 'c' && argv[arg_num + 1])
        {
            local_config_file = globus_libc_strdup(argv[arg_num + 1]);
            arg_num = argc;
        }
    }
    if(local_config_file == NULL)
    {
        local_config_file = globus_common_create_string(
        "%s/etc/gridftp.conf", globus_libc_getenv("GLOBUS_LOCATION"));
    }

    globus_l_gfs_config_load_defaults();
    rc = globus_l_gfs_config_load_config_file(local_config_file);
    if(rc == -2)
    {
        rc = globus_l_gfs_config_load_config_file(global_config_file);
    }
    if(rc == -1)
    {
        goto error;
    }
    globus_l_gfs_config_load_config_env();
    rc = globus_l_gfs_config_load_commandline(argc, argv);
    if(rc == -1)
    {
        goto error;
    }
    
    result = globus_l_gfs_config_misc();
    if(result != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "Error in post config setup:\n %s", 
            globus_error_print_friendly(globus_error_peek(result)));
        goto error;
    }
    
    globus_l_gfs_config_set("exec_name", 0, exec_name);
    globus_l_gfs_config_set("argv", 0, argv);
    globus_l_gfs_config_set("argc", argc, NULL);

    globus_free(local_config_file);     

    globus_mutex_init(&globus_i_gfs_config_mutex, NULL);

    GlobusGFSDebugExit();
    return;

error:
    exit(2);     
}


int
globus_i_gfs_config_int(
    const char *                        option_name)
{
    globus_l_gfs_config_option_t *      option;
    int                                 value = 0;    
    GlobusGFSName(globus_i_gfs_config_int);
    GlobusGFSDebugEnter();
    
    option = (globus_l_gfs_config_option_t *) 
        globus_hashtable_lookup(&option_table, (void *) option_name);
        
    if(option)
    {        
        value = option->int_value;
    }

    GlobusGFSDebugExit();
    return value;
}


void *
globus_i_gfs_config_get(
    const char *                        option_name)
{
    globus_l_gfs_config_option_t *      option;
    void *                              value = NULL;    
    GlobusGFSName(globus_i_gfs_config_get);
    GlobusGFSDebugEnter();
    
    option = (globus_l_gfs_config_option_t *) 
        globus_hashtable_lookup(&option_table, (void *) option_name);
        
    if(option && option->value)
    {        
        value = option->value;
    }

    GlobusGFSDebugExit();
    return value;
}

globus_bool_t
globus_i_gfs_config_is_anonymous(
    const char *                        userid)
{
    globus_bool_t                       valid = GLOBUS_FALSE;
    char *                              anonymous_names;
    GlobusGFSName(globus_i_gfs_config_is_anonymous);
    GlobusGFSDebugEnter();

    anonymous_names = globus_i_gfs_config_string("anonymous_names_allowed");
    if(anonymous_names)
    {
        if(*anonymous_names == '*' || strstr(anonymous_names, userid))
        {
            valid = GLOBUS_TRUE;
        }
    }
    else
    {
        if(strcmp(userid, "ftp") == 0 ||
            strcmp(userid, "anonymous") == 0 ||
            strcmp(userid, ":globus-mapping:") == 0)
        {
            valid = GLOBUS_TRUE;
        }
    }
    
    GlobusGFSDebugExit();
    return valid;
}

globus_bool_t
globus_i_gfs_config_allow_addr(
    const char *                        remote_addr,
    globus_bool_t                       ipc)
{
    char *                              allow_list;
    char *                              deny_list;
    globus_bool_t                       allowed = GLOBUS_FALSE;
    char *                              addr;
    char *                              ptr;
    GlobusGFSName(globus_i_gfs_config_allow_addr);
    GlobusGFSDebugEnter();

    if(ipc)
    {
        allow_list = globus_libc_strdup(
            globus_i_gfs_config_string("ipc_allow_from"));
        deny_list = globus_libc_strdup(
            globus_i_gfs_config_string("ipc_deny_from"));
    }
    else
    { 
        allow_list = globus_libc_strdup(
            globus_i_gfs_config_string("allow_from"));
        deny_list = globus_libc_strdup(
            globus_i_gfs_config_string("deny_from"));
    }

    if(allow_list == NULL)
    {
        allowed = GLOBUS_TRUE;
    }
    else
    {
        addr = allow_list;
        while((ptr = strchr(addr, ',')) != NULL && !allowed)
        {
            *ptr = '\0';
            if(strncmp(addr, remote_addr, strlen(addr)) == 0)
            {
                allowed = GLOBUS_TRUE;
            }
            addr = ptr + 1;
        }
        if(ptr == NULL && !allowed)
        {
           if(strncmp(addr, remote_addr, strlen(addr)) == 0)
            {
                allowed = GLOBUS_TRUE;
            }
        }
        globus_free(allow_list);
    }
    if(allowed && deny_list != NULL)
    {
        addr = deny_list;
        while((ptr = strchr(addr, ',')) != NULL && allowed)
        {
            *ptr = '\0';
            if(strncmp(addr, remote_addr, strlen(addr)) == 0)
            {
                allowed = GLOBUS_FALSE;
            }
            addr = ptr + 1;
        }
        if(ptr == NULL && allowed)
        {
           if(strncmp(addr, remote_addr, strlen(addr)) == 0)
            {
                allowed = GLOBUS_FALSE;
            }
        }
        globus_free(deny_list);
    }

    GlobusGFSDebugExit();
    return allowed;
}


const char *
globus_i_gfs_config_get_module_name(
    const char *                        client_alias)
{
    globus_list_t *                     module_list;
    globus_list_t *                     list;
    const char *                        module;
    const char *                        out_module = NULL;
    char *                              alias;
    globus_bool_t                       found = GLOBUS_FALSE;
    int                                 size;
    GlobusGFSName(globus_i_gfs_config_get_module_name);
    GlobusGFSDebugEnter();

    module_list = (globus_list_t *) globus_i_gfs_config_get("module_list");  
    for(list = module_list;
        !globus_list_empty(list) && !found;
        list = globus_list_rest(list))
    {
        /* parse out module name from <module> or <alias>:<module> */
        alias = (char *) globus_list_first(list);
        module = strchr(alias, ':');
        if(module != NULL)
        {
            size = module - alias;
            module++;
        }
        else
        {
            size = strlen(alias);
            module = alias;
        }
        if(strncasecmp(alias, client_alias, size) == 0)
        {
            found = GLOBUS_TRUE;
        }
    } 
    if(found)
    {
        out_module = module;
    }

    GlobusGFSDebugExit();
    return out_module;
}


/*
 *  public (ish) functions
 */
globus_bool_t
globus_gfs_config_get_bool(
    const char *                        option_name)
{
    globus_bool_t                       rc;

    globus_mutex_lock(&globus_i_gfs_config_mutex);
    rc = globus_i_gfs_config_bool(option_name);    
    globus_mutex_unlock(&globus_i_gfs_config_mutex);
    return rc;
}

char *
globus_gfs_config_get_string(
    const char *                        option_name)
{
    char *                              rc;

    globus_mutex_lock(&globus_i_gfs_config_mutex);
    rc = globus_i_gfs_config_string(option_name);    
    globus_mutex_unlock(&globus_i_gfs_config_mutex);
    return rc;
}

globus_list_t *
globus_gfs_config_get_list(
    const char *                        option_name)
{
    globus_list_t *                     rc;

    globus_mutex_lock(&globus_i_gfs_config_mutex);
    rc = globus_i_gfs_config_list(option_name);    
    globus_mutex_unlock(&globus_i_gfs_config_mutex);
    return rc;
}

void *
globus_gfs_config_get(
    const char *                        option_name)
{
    void *                              rc;

    globus_mutex_lock(&globus_i_gfs_config_mutex);
    rc = globus_i_gfs_config_get(option_name);    
    globus_mutex_unlock(&globus_i_gfs_config_mutex);
    return rc;
}

int
globus_gfs_config_get_int(
    const char *                        option_name)
{
    int                                 rc;

    globus_mutex_lock(&globus_i_gfs_config_mutex);
    rc = globus_i_gfs_config_int(option_name);    
    globus_mutex_unlock(&globus_i_gfs_config_mutex);
    return rc;
}

static
void
globus_l_gfs_config_publish_int(
    globus_list_t *                     list,
    char *                              option_name,
    int                                 int_val)
{
    globus_i_gfs_config_set_int_cb_t    cb;
    globus_i_gfs_config_option_cb_ent_t * cb_ent;

    while(!globus_list_empty(list))
    {
        cb_ent = (globus_i_gfs_config_option_cb_ent_t *)
            globus_list_first(list);

        list = globus_list_rest(list);
        if(cb_ent->enabled)
        {
            cb = (globus_i_gfs_config_set_int_cb_t)cb_ent->cb;
            cb_ent->enabled = GLOBUS_FALSE;
            cb(option_name, int_val, cb_ent->user_arg);
            cb_ent->enabled = GLOBUS_TRUE;
        }
    }
}

int
globus_gfs_config_set_int(
    char *                              option_name,
    int                                 int_val)
{
    int                                 rc;
    globus_list_t *                     list;
    globus_l_gfs_config_option_t *      option;

    globus_mutex_lock(&globus_i_gfs_config_mutex);
    {
        rc = globus_l_gfs_config_set(option_name, int_val, NULL);
        if(rc != 0)
        {
            goto error;
        }
        option = (globus_l_gfs_config_option_t *)
            globus_hashtable_lookup(&option_table, (void *) option_name);
        if(option == NULL)
        {
            goto error;
        }
        list = option->set_list;
        globus_l_gfs_config_publish_int(list, option_name, int_val);
    }
    globus_mutex_unlock(&globus_i_gfs_config_mutex);

    return 0;
error:
    globus_mutex_unlock(&globus_i_gfs_config_mutex);
    return rc;
}

int
globus_gfs_config_inc_int(
    char *                              option_name,
    int                                 inc_val)
{
    int                                 rc;
    int                                 tmp_i;
    globus_list_t *                     list;
    globus_l_gfs_config_option_t *      option;

    globus_mutex_lock(&globus_i_gfs_config_mutex);
    {
        tmp_i = globus_i_gfs_config_int(option_name);
        tmp_i += inc_val;
        rc = globus_l_gfs_config_set(option_name, tmp_i, NULL);
        if(rc != 0)
        {
            goto error;
        }
        option = (globus_l_gfs_config_option_t *)
            globus_hashtable_lookup(&option_table, (void *) option_name);
        if(option == NULL)
        {
            goto error;
        }
        list = option->set_list;
        globus_l_gfs_config_publish_int(list, option_name, tmp_i);
    }
    globus_mutex_unlock(&globus_i_gfs_config_mutex);

    return 0;
error:
    globus_mutex_unlock(&globus_i_gfs_config_mutex);
    return rc;
}

int
globus_gfs_config_set_bool(
    char *                              option_name,
    int                                 int_val)
{
    globus_list_t *                     list;
    int                                 rc;
    globus_l_gfs_config_option_t *      option;

    globus_mutex_lock(&globus_i_gfs_config_mutex);
    {
        rc = globus_l_gfs_config_set(option_name, int_val, NULL);
        if(rc != 0)
        {
            goto error;
        }
        option = (globus_l_gfs_config_option_t *)
            globus_hashtable_lookup(&option_table, (void *) option_name);
        if(option == NULL)
        {
            goto error;
        }
        list = option->set_list;
        globus_l_gfs_config_publish_int(list, option_name, int_val);
    }
    globus_mutex_unlock(&globus_i_gfs_config_mutex);

    return 0;
error:
    globus_mutex_unlock(&globus_i_gfs_config_mutex);
    return rc;
}

int
globus_gfs_config_set_ptr(
    char *                              option_name,
    void *                              ptr)
{
    globus_i_gfs_config_set_string_cb_t cb;
    globus_i_gfs_config_option_cb_ent_t * cb_ent;
    globus_list_t *                     list;
    int                                 rc;
    globus_l_gfs_config_option_t *      option;
    GlobusGFSName(globus_gfs_config_set_ptr);
    GlobusGFSDebugEnter();

    globus_mutex_lock(&globus_i_gfs_config_mutex);
    {
        rc = globus_l_gfs_config_set(option_name, 0, ptr);
        if(rc != 0)
        {
            goto error;
        }

        option = (globus_l_gfs_config_option_t *)
            globus_hashtable_lookup(&option_table, (void *) option_name);
        if(option == NULL)
        {
            goto error;
        }
        list = option->set_list;

        while(!globus_list_empty(list))
        {
            cb_ent = (globus_i_gfs_config_option_cb_ent_t *)
                globus_list_first(list);
            list = globus_list_rest(list);

            if(cb_ent->enabled)
            {
                cb = (globus_i_gfs_config_set_string_cb_t) cb_ent->cb;
                cb_ent->enabled = GLOBUS_FALSE;
                cb(option_name, ptr, cb_ent->user_arg);
                cb_ent->enabled = GLOBUS_TRUE;
            }
        }
    }
    globus_mutex_unlock(&globus_i_gfs_config_mutex);

    return 0;
error:
    globus_mutex_unlock(&globus_i_gfs_config_mutex);
    return rc;
}

void
globus_gfs_config_enable_cb(
    globus_i_gfs_config_option_cb_ent_t * cb_ent,
    globus_bool_t                       enabled)
{

    globus_mutex_lock(&globus_i_gfs_config_mutex);
    {
        cb_ent->enabled = enabled;
    }
    globus_mutex_unlock(&globus_i_gfs_config_mutex);
}

int
globus_gfs_config_add_cb(
    globus_i_gfs_config_option_cb_ent_t ** cb_handle,
    char *                              option_name,
    void *                              cb,
    void *                              user_arg)
{
    globus_i_gfs_config_option_cb_ent_t * cb_ent;
    globus_l_gfs_config_option_t *      option;
    int                                 rc;
    GlobusGFSName(globus_gfs_config_add_cb);
    GlobusGFSDebugEnter();

    globus_mutex_lock(&globus_i_gfs_config_mutex);
    {
        option = (globus_l_gfs_config_option_t *)
            globus_hashtable_lookup(&option_table, (void *) option_name);
        if(option == NULL)
        {
            goto error;
        }
        cb_ent = (globus_i_gfs_config_option_cb_ent_t *)
            globus_calloc(1, sizeof(globus_i_gfs_config_option_cb_ent_t));
        cb_ent->cb = cb;
        cb_ent->enabled = GLOBUS_TRUE;
        cb_ent->user_arg = user_arg;
        *cb_handle = cb_ent;
        globus_list_insert(&option->set_list, cb_ent);
    }
    globus_mutex_unlock(&globus_i_gfs_config_mutex);

    return 0;
error:
    globus_mutex_unlock(&globus_i_gfs_config_mutex);
    return rc;
}


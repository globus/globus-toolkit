
/**
 * All the "boilerplate" code necessary to make the GridFTP-HDFS integration
 * function.
*/

#include <sys/resource.h>
#include <sys/prctl.h>
#include <syslog.h>
#include <sys/syscall.h>
#include <signal.h>
#include <execinfo.h>
#define __USE_XOPEN_EXTENDED
#include <ftw.h>

#include "gridftp_hdfs.h"

/*
 *  Globals for this library.
 */
globus_version_t gridftp_hdfs_local_version =
{
    0, /* major version number */
    30, /* minor/bug version number */
    1303175799,
    0 /* branch ID */
};

char err_msg[MSG_SIZE];
int local_io_block_size = 0;
int local_io_count = 0;

static void hdfs_trev(globus_gfs_event_info_t *, void *);
inline void set_done(hdfs_handle_t *, globus_result_t);
static int  hdfs_activate(void);
static int  hdfs_deactivate(void);
static void hdfs_command(globus_gfs_operation_t, globus_gfs_command_info_t *, void *);
static void hdfs_start(globus_gfs_operation_t, globus_gfs_session_info_t *);

void
hdfs_destroy(
    void *                              user_arg);

void
hdfs_start(
    globus_gfs_operation_t              op,
    globus_gfs_session_info_t *         session_info);

void
hdfs_destroy(
    void *                              user_arg);


/*
 *  Interface definitions for HDFS
 */
static globus_gfs_storage_iface_t       globus_l_gfs_hdfs_dsi_iface = 
{
    GLOBUS_GFS_DSI_DESCRIPTOR_BLOCKING | GLOBUS_GFS_DSI_DESCRIPTOR_SENDER,
    hdfs_start,
    hdfs_destroy,
    NULL, /* list */
    hdfs_send,
    hdfs_recv,
    hdfs_trev, /* trev */
    NULL, /* active */
    NULL, /* passive */
    NULL, /* data destroy */
    hdfs_command, 
    hdfs_stat,
    NULL,
    NULL
};

/*
 *  Module definitions; hooks into the Globus module system.
 *  Initialized when library loads.
 */
GlobusExtensionDefineModule(globus_gridftp_server_hdfs) =
{
    "globus_gridftp_server_hdfs",
    hdfs_activate,
    hdfs_deactivate,
    NULL,
    NULL,
    &gridftp_hdfs_local_version
};

// Custom SEGV handler due to the presence of Java handlers.
void
segv_handler (int sig)
{
  printf ("SEGV triggered in native code.\n");
  const int max_trace = 32;
  void *trace[max_trace];
  char **messages = (char **)NULL;
  int i, trace_size = 0;

  trace_size = backtrace(trace, max_trace);
  messages = backtrace_symbols(trace, trace_size);
  for (i=0; i<trace_size; ++i) {
	printf("[bt] %s\n", messages[i]);
  }
  raise (SIGQUIT);
  signal (SIGSEGV, SIG_DFL);
  raise (SIGSEGV);
}
/*
 *  Check to see if cores can be produced by gridftp; if not, turn them on.
 */
void
gridftp_check_core()
{
    int err;
    struct rlimit rlim;

    rlim.rlim_cur = RLIM_INFINITY;
    rlim.rlim_max = RLIM_INFINITY;
    err = setrlimit(RLIMIT_CORE, &rlim);
    if (err) {
        snprintf(err_msg, MSG_SIZE, "Cannot set rlimits due to %s.\n", strerror(err));
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, err_msg);
    }

    int isDumpable = prctl(PR_GET_DUMPABLE);

    if (!isDumpable) {
        err = prctl(PR_SET_DUMPABLE, 1);
    }
    if (err) {
        snprintf(err_msg, MSG_SIZE, "Cannot set dumpable: %s.\n", strerror(errno));
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, err_msg);
    }

    // Reset signal handler:
    sig_t sigerr = signal (SIGSEGV, segv_handler);
    if (sigerr == SIG_ERR) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Unable to set core handler.\n");
    }
}

static char *hdfs_classpath = NULL;

static
int
hdfs_add_jar(
    const char * pathname,
    const struct stat *statbuf,
    int type,
    struct FTW *info)
{
    long envmax = sysconf(_SC_ARG_MAX);
    char * ext;

    if (hdfs_classpath == NULL)
    {
        if (envmax < 0)
        {
            envmax = 4096;
        }

        hdfs_classpath = malloc(envmax);
        if (hdfs_classpath == NULL)
        {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Unable to allocate classpath");
            return ENOMEM;
        }
        hdfs_classpath[0] = 0;
    }
    if (type != FTW_F)
    {
        return 0;
    }
    if ((strlen(hdfs_classpath) + strlen(pathname) + 2) > envmax)
    {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Unable to populate classpath");
        return E2BIG;
    }
    ext = strrchr(pathname, '.');
    if (ext && strcmp(ext, ".jar") == 0)
    {
        strcat(hdfs_classpath, pathname);
        strcat(hdfs_classpath, ":");
    }
    return 0;
}

/*
 *  Called when the HDFS module is activated.
 *  Completely boilerplate.
 */
int
hdfs_activate(void)
{
    const char *hadoopdir = "/usr/lib/hadoop";
    const char *hdfsdir = "/usr/lib/hadoop-hdfs";
    char *cp=NULL;
    size_t cplen = 0;

    nftw(hadoopdir, hdfs_add_jar, 4, FTW_PHYS);
    nftw(hdfsdir, hdfs_add_jar, 4, FTW_PHYS);
    if (hdfs_classpath != NULL)
    {
        if (strlen(hdfs_classpath) > 1)
        {
            hdfs_classpath[strlen(hdfs_classpath)-1] = 0;
        }
        setenv("CLASSPATH", hdfs_classpath, 1);
    }

    globus_extension_registry_add(
        GLOBUS_GFS_DSI_REGISTRY,
        "hdfs",
        GlobusExtensionMyModule(globus_gridftp_server_hdfs),
        &globus_l_gfs_hdfs_dsi_iface);
    
    return 0;
}

/*
 *  Called when the HDFS module is deactivated.
 *  Completely boilerplate
 */
int
hdfs_deactivate(void)
{
    globus_extension_registry_remove(
        GLOBUS_GFS_DSI_REGISTRY, "hdfs");

    return 0;
}

static
void
hdfs_trev(
    globus_gfs_event_info_t *           event_info,
    void *                              user_arg
)
{

    hdfs_handle_t *       hdfs_handle;
    GlobusGFSName(globus_l_gfs_hdfs_trev);

    hdfs_handle = (globus_l_gfs_hdfs_handle_t *) user_arg;
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Recieved a transfer event.\n");

    switch (event_info->type) {
        case GLOBUS_GFS_EVENT_TRANSFER_ABORT:
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Got an abort request to the HDFS client.\n");
            set_done(hdfs_handle, GLOBUS_FAILURE);
            break;
        default:
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Got some other transfer event %d.\n", event_info->type);
    }
}

/*************************************************************************
 *  command
 *  -------
 *  This interface function is called when the client sends a 'command'.
 *  commands are such things as mkdir, remdir, delete.  The complete
 *  enumeration is below.
 *
 *  To determine which command is being requested look at:
 *      cmd_info->command
 *
 *      GLOBUS_GFS_CMD_MKD = 1,
 *      GLOBUS_GFS_CMD_RMD,
 *      GLOBUS_GFS_CMD_DELE,
 *      GLOBUS_GFS_CMD_RNTO,
 *      GLOBUS_GFS_CMD_RNFR,
 *      GLOBUS_GFS_CMD_CKSM,
 *      GLOBUS_GFS_CMD_SITE_CHMOD,
 *      GLOBUS_GFS_CMD_SITE_DSI
 ************************************************************************/
static void
hdfs_command(
    globus_gfs_operation_t              op,
    globus_gfs_command_info_t *         cmd_info,
    void *                              user_arg)
{
    globus_result_t                    result = GLOBUS_FAILURE;
    globus_l_gfs_hdfs_handle_t *       hdfs_handle;
    char *                             PathName;
    GlobusGFSName(hdfs_command);

    char * return_value = GLOBUS_NULL;

    hdfs_handle = (globus_l_gfs_hdfs_handle_t *) user_arg;
    
    // Get hadoop path name (ie subtract mount point)
    PathName=cmd_info->pathname;
    while (PathName[0] == '/' && PathName[1] == '/')
    {
        PathName++;
    }
    if (strncmp(PathName, hdfs_handle->mount_point, hdfs_handle->mount_point_len)==0) {
        PathName += hdfs_handle->mount_point_len;
    }
    while (PathName[0] == '/' && PathName[1] == '/')
    {
        PathName++;
    }

    GlobusGFSErrorSystemError("command", ENOSYS);
    switch (cmd_info->command) {
    case GLOBUS_GFS_CMD_MKD:
{
        errno = 0;
        if (hdfsCreateDirectory(hdfs_handle->fs, PathName) == -1) {
            if (errno) {
                result = GlobusGFSErrorSystemError("mkdir", errno);
            } else {
                GenericError(hdfs_handle, "Unable to create directory (reason unknown)", result);
            }
        } else {
            result = GLOBUS_SUCCESS;
        }
}
        break;
    case GLOBUS_GFS_CMD_RMD:
        break;
    case GLOBUS_GFS_CMD_DELE:
{
        errno = 0;
        if (hdfsDelete(hdfs_handle->fs, PathName,0) == -1) {
            if (errno) {
                result = GlobusGFSErrorSystemError("unlink", errno);
            } else {
                GenericError(hdfs_handle, "Unable to delete file (reason unknown)", result);
            }
        } else {
            result = GLOBUS_SUCCESS;
        }
}
        break;
    case GLOBUS_GFS_CMD_RNTO:
        break;
    case GLOBUS_GFS_CMD_RNFR:
        break;
    case GLOBUS_GFS_CMD_CKSM:
{
        if ((cmd_info->cksm_offset != 0) || (cmd_info->cksm_length != -1)) {
            GenericError(hdfs_handle, "Unable to retrieve partial checksums", result);
            break;
        }
        char * value = NULL;
        if ((result = hdfs_get_checksum(hdfs_handle, cmd_info->pathname, cmd_info->cksm_alg, &value)) != GLOBUS_SUCCESS) {
            break;
        }
        if (value == NULL) {
            GenericError(hdfs_handle, "Unable to retrieve check", result);
            break;
        }
        return_value = value;
}
        break;
    case GLOBUS_GFS_CMD_SITE_CHMOD:
        break;
    case GLOBUS_GFS_CMD_SITE_DSI:
        break;
    case GLOBUS_GFS_CMD_SITE_RDEL:
        break;
    case GLOBUS_GFS_CMD_SITE_AUTHZ_ASSERT:
        break;
    case GLOBUS_GFS_CMD_SITE_SETNETSTACK:
        break;
    case GLOBUS_GFS_CMD_SITE_SETDISKSTACK:
        break;
    case GLOBUS_GFS_CMD_SITE_CLIENTINFO:
        break;
    case GLOBUS_GFS_CMD_SITE_CHGRP:
        break;
    case GLOBUS_GFS_CMD_SITE_UTIME:
        break;
    case GLOBUS_GFS_CMD_SITE_SYMLINKFROM:
        break;
    case GLOBUS_GFS_CMD_SITE_SYMLINK:
        break;
    case GLOBUS_GFS_CMD_DCSC:
        break;
    }

    globus_gridftp_server_finished_command(op, result, return_value);

    if (return_value) {
        free(return_value);
    }
}

/*************************************************************************
 *  start
 *  -----
 *  This function is called when a new session is initialized, ie a user 
 *  connectes to the server.  This hook gives the dsi an oppertunity to
 *  set internal state that will be threaded through to all other
 *  function calls associated with this session. int                                 port;
    char *                              host;
    int                                 replicas; And an oppertunity to
 *  reject the user.
 *
 *  finished_info.info.session.session_arg should be set to an DSI
 *  defined data structure.  This pointer will be passed as the void *
 *  user_arg parameter to all other interface functions.
 * 
 *  NOTE: at nice wrapper function should exist that hides the details 
 *        of the finished_info structure, but it currently does not.  
 *        The DSI developer should jsut follow this template for now
 ************************************************************************/
void
hdfs_start(
    globus_gfs_operation_t              op,
    globus_gfs_session_info_t *         session_info)
{
    hdfs_handle_t*       hdfs_handle;
    globus_gfs_finished_info_t          finished_info;
    GlobusGFSName(hdfs_start);
    globus_result_t rc;

    int max_buffer_count = 200;
    int max_file_buffer_count = 1500;
    int load_limit = 20;
    int replicas;
    int port;

    hdfs_handle = (hdfs_handle_t *)globus_malloc(sizeof(hdfs_handle_t));
    memset(hdfs_handle, 0, sizeof(hdfs_handle_t));

    memset(&finished_info, 0, sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_SESSION_START;
    finished_info.result = GLOBUS_SUCCESS;
    finished_info.info.session.session_arg = hdfs_handle;
    finished_info.info.session.username = session_info->username;
    finished_info.info.session.home_dir = "/";

    if (!hdfs_handle) {
        MemoryError(hdfs_handle, "Unable to allocate a new HDFS handle.", rc);
        finished_info.result = rc;
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }

    hdfs_handle->mutex = (globus_mutex_t *)malloc(sizeof(globus_mutex_t));
    if (!(hdfs_handle->mutex)) {
        MemoryError(hdfs_handle, "Unable to allocate a new mutex for HDFS.", rc);
        finished_info.result = rc;
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }
    if (globus_mutex_init(hdfs_handle->mutex, GLOBUS_NULL)) {
        SystemError(hdfs_handle, "Unable to initialize mutex", rc);
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }

    hdfs_handle->io_block_size = 0;
    hdfs_handle->io_count = 0;

    // Copy the username from the session_info to the HDFS handle.
    size_t strlength = strlen(session_info->username)+1;
    strlength = strlength < 256 ? strlength  : 256;
    hdfs_handle->username = globus_malloc(sizeof(char)*strlength);
    if (hdfs_handle->username == NULL) {
        finished_info.result = GLOBUS_FAILURE;
        globus_gridftp_server_operation_finished(
            op, GLOBUS_FAILURE, &finished_info);
        return;
    }
    strncpy(hdfs_handle->username, session_info->username, strlength);

    // Pull configuration from environment.
    hdfs_handle->replicas = 3;
    hdfs_handle->host = "hadoop-name";
    hdfs_handle->mount_point = "/mnt/hadoop";
    hdfs_handle->port = 9000;
    char * replicas_char = getenv("GRIDFTP_HDFS_REPLICAS");
    char * namenode = getenv("GRIDFTP_HDFS_NAMENODE");
    char * port_char = getenv("GRIDFTP_HDFS_PORT");
    char * mount_point_char = getenv("GRIDFTP_HDFS_MOUNT_POINT");
    char * load_limit_char = getenv("GRIDFTP_LOAD_LIMIT");

    // Get our hostname
    hdfs_handle->local_host = globus_malloc(256);
    if (hdfs_handle->local_host) {
        memset(hdfs_handle->local_host, 0, 256);
        if (gethostname(hdfs_handle->local_host, 255)) {
            strcpy(hdfs_handle->local_host, "UNKNOWN");
        }
    }

    // Pull syslog configuration from environment.
    char * syslog_host_char = getenv("GRIDFTP_SYSLOG");
    if (syslog_host_char == NULL) {
        hdfs_handle->syslog_host = NULL;
    } else {
        hdfs_handle->syslog_host = syslog_host_char; 
        hdfs_handle->remote_host = session_info->host_id;
        openlog("GRIDFTP", 0, LOG_LOCAL2);
        hdfs_handle->syslog_msg = (char *)globus_malloc(256);
        if (hdfs_handle->syslog_msg)
            snprintf(hdfs_handle->syslog_msg, 255, "%s %s %%s %%i %%i", hdfs_handle->local_host, hdfs_handle->remote_host);
    }

    // Determine the maximum number of buffers; default to 200.
    char * max_buffer_char = getenv("GRIDFTP_BUFFER_COUNT");
    if (max_buffer_char != NULL) {
        max_buffer_count = atoi(max_buffer_char);
        if ((max_buffer_count < 5)  || (max_buffer_count > 1000))
            max_buffer_count = 200;
    }
    hdfs_handle->max_buffer_count = max_buffer_count;
    snprintf(err_msg, MSG_SIZE, "Max memory buffer count: %i.\n", hdfs_handle->max_buffer_count);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,err_msg);

    char * max_file_buffer_char = getenv("GRIDFTP_FILE_BUFFER_COUNT");
    if (max_file_buffer_char != NULL) {
        max_file_buffer_count = atoi(max_file_buffer_char);
        if ((max_file_buffer_count < max_buffer_count)  || (max_buffer_count > 50000))
            max_file_buffer_count = 3*max_buffer_count;
    }
    hdfs_handle->max_file_buffer_count = max_file_buffer_count;
    snprintf(err_msg, MSG_SIZE, "Max file buffer count: %i.\n", hdfs_handle->max_file_buffer_count);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,err_msg);

    if (load_limit_char != NULL) {
        load_limit = atoi(load_limit_char);
        if (load_limit < 1)
            load_limit = 20;
    }

    if (mount_point_char != NULL) {
        hdfs_handle->mount_point = mount_point_char;
    }
    hdfs_handle->mount_point_len = strlen(hdfs_handle->mount_point);

    if (replicas_char != NULL) {
        replicas = atoi(replicas_char);
        if ((replicas > 1) && (replicas < 20))
            hdfs_handle->replicas = replicas;
    }
    if (namenode != NULL)
        hdfs_handle->host = namenode;
    if (port_char != NULL) {
        port = atoi(port_char);
        if ((port >= 1) && (port <= 65535))
            hdfs_handle->port = port;
    }

    hdfs_handle->using_file_buffer = 0;

    hdfs_handle->cksm_root = "/cksums";

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Checking current load on the server.\n");
    // Stall stall stall!
    int fd = open("/proc/loadavg", O_RDONLY);
    int bufsize = 256, nbytes=-1;
    char buf[bufsize];
    char * buf_ptr;
    char * token;
    double load;
    int ctr = 0;
    while (fd >= 0) {
        if (ctr == 120)
            break;
        ctr += 1;
        nbytes = read(fd, buf, bufsize);
        if (nbytes < 0)
            break;
        buf[nbytes-1] = '\0';
        buf_ptr = buf;
        token = strsep(&buf_ptr, " ");
        load = strtod(token, NULL);
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Detected system load %.2f.\n", load);
        if ((load >= load_limit) && (load < 1000)) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Preventing gridftp transfer startup due to system load of %.2f.\n", load);
            sleep(5);
        } else {
            break;
        }
        close(fd);
        fd = open("/proc/loadavg", O_RDONLY);
    }

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
        "Start gridftp server; hadoop nameserver %s, port %i, replicas %i.\n",
        hdfs_handle->host, hdfs_handle->port, hdfs_handle->replicas);

    hdfs_handle->fs = hdfsConnect("default", 0);
    if (!hdfs_handle->fs) {
        finished_info.result = GLOBUS_FAILURE;
        globus_gridftp_server_operation_finished(
            op, GLOBUS_FAILURE, &finished_info);
        return;
    }

    // Parse the checksum request information
    const char * checksums_char = getenv("GRIDFTP_HDFS_CHECKSUMS");
    if (checksums_char) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
            "Checksum algorithms in use: %s.\n", checksums_char);
        hdfs_parse_checksum_types(hdfs_handle, checksums_char);
    } else {
        hdfs_handle->cksm_types = 0;
    }

    hdfs_handle->tmp_file_pattern = (char *)NULL;

    // Handle core limits
    gridftp_check_core();

    globus_gridftp_server_operation_finished(
        op, GLOBUS_SUCCESS, &finished_info);
}

/************************************************************************ 
 *  destroy
 *  -------
 *  This is called when a session ends, ie client quits or disconnects.
 ************************************************************************/
void
hdfs_destroy(
    void *                              user_arg)
{
    hdfs_handle_t *       hdfs_handle;
    hdfs_handle = (globus_l_gfs_hdfs_handle_t *) user_arg;

    if (hdfs_handle) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Destroying the HDFS connection.\n");
        if (hdfs_handle->fs) {
            hdfsDisconnect(hdfs_handle->fs);
            hdfs_handle->fs = NULL;
        }
        if (hdfs_handle->username)
            globus_free(hdfs_handle->username);
        if (hdfs_handle->local_host)
            globus_free(hdfs_handle->local_host);
        if (hdfs_handle->syslog_msg)
            globus_free(hdfs_handle->syslog_msg);
        remove_file_buffer(hdfs_handle);
        if (hdfs_handle->mutex) {
            globus_mutex_destroy(hdfs_handle->mutex);
            globus_free(hdfs_handle->mutex);
        }
        globus_free(hdfs_handle);
    }
    closelog();
}

/*************************************************************************
 *  is_done
 *  -------
 *  Check to see if a hdfs_handle is already done.
 ************************************************************************/
inline globus_bool_t
is_done(
    hdfs_handle_t *hdfs_handle)
{
    return hdfs_handle->done > 0;
}

/*************************************************************************
 *  is_close_done
 *  -------------
 *  Check to see if a hdfs_handle is already close-done.
 ************************************************************************/
inline globus_bool_t
is_close_done(
    hdfs_handle_t *hdfs_handle)
{
    return hdfs_handle->done == 2;
}

/*************************************************************************
 *  set_done
 *  --------
 *  Set the handle as done for a given reason.
 *  If the handle is already done with an error, this is a no-op.
 *  If the handle is in a success state and gets a failure, we record it.
 ************************************************************************/
inline void
set_done(
    hdfs_handle_t *hdfs_handle, globus_result_t rc)
{
    // Ignore already-done handles.
    if (is_done(hdfs_handle) && (hdfs_handle->done_status != GLOBUS_SUCCESS)) {
        return;
    }
    hdfs_handle->done = 1;
    hdfs_handle->done_status = rc;
}

/*************************************************************************
 *  set_close_done
 *  --------------
 *  Set the handle as close-done for a given reason.
 *  If the handle is already close-done, this is a no-op.
 *  If the handle was done successfully, but the close was not a success,
 *  then record it.
 ************************************************************************/
inline void
set_close_done(
    hdfs_handle_t *hdfs_handle, globus_result_t rc)
{
    // Ignore already-done handles.
    if (is_close_done(hdfs_handle)) {
        return;
    }
    hdfs_handle->done = 2;
    if ((hdfs_handle->done_status == GLOBUS_SUCCESS) && (rc != GLOBUS_SUCCESS)) {
        hdfs_handle->done_status = rc;
    }
}


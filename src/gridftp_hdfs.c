
/**
 * All the "boilerplate" code necessary to make the GridFTP-HDFS integration
 * function.
*/

#include "gridftp_hdfs.h"

/*
 *  Globals for this library.
 */
const globus_version_t gridftp_hdfs_local_version =
{
    0, /* major version number */
    30, /* minor/bug version number */
    1303175799,
    0 /* branch ID */
};

char err_msg[MSG_SIZE];
int local_io_block_size = 0;
int local_io_count = 0;

/*
 *  Interface definitions for HDFS
 */
static globus_gfs_storage_iface_t       globus_l_gfs_hdfs_dsi_iface = 
{
    GLOBUS_GFS_DSI_DESCRIPTOR_BLOCKING | GLOBUS_GFS_DSI_DESCRIPTOR_SENDER,
    globus_l_gfs_hdfs_start,
    globus_l_gfs_hdfs_destroy,
    NULL, /* list */
    globus_l_gfs_hdfs_send,
    globus_l_gfs_hdfs_recv,
    NULL, /*globus_l_gfs_hdfs_trev, */ /* trev */
    NULL, /* active */
    NULL, /* passive */
    NULL, /* data destroy */
    globus_l_gfs_hdfs_command, 
    globus_l_gfs_hdfs_stat,
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
    globus_l_gfs_hdfs_activate,
    globus_l_gfs_hdfs_deactivate,
    NULL,
    NULL,
    &gridftp_hdfs_local_version
};

/*
 *  Called when the HDFS module is activated.
 *  Completely boilerplate.
 */
int
globus_l_gfs_hdfs_activate(void)
{
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
globus_l_gfs_hdfs_deactivate(void)
{
    globus_extension_registry_remove(
        GLOBUS_GFS_DSI_REGISTRY, "hdfs");

    return 0;
}

void
globus_l_gfs_hdfs_trev(
    globus_gfs_event_info_t *           event_info,
    void *                              user_arg
)
{

		  globus_l_gfs_hdfs_handle_t *       hdfs_handle;
		  GlobusGFSName(globus_l_gfs_hdfs_trev);

		  hdfs_handle = (globus_l_gfs_hdfs_handle_t *) user_arg;
		  globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Recieved a transfer event.\n");

		  switch (event_info->type) {
					 case GLOBUS_GFS_EVENT_TRANSFER_ABORT:
								globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Got an abort request to the HDFS client.\n");
								break;
					 default:
								printf("Got some other transfer event.\n");
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
void
globus_l_gfs_hdfs_command(
    globus_gfs_operation_t              op,
    globus_gfs_command_info_t *         cmd_info,
    void *                              user_arg)
{
    globus_l_gfs_hdfs_handle_t *       hdfs_handle;
     //printf("Globus HDFS command.\n");
    GlobusGFSName(globus_l_gfs_hdfs_command);

    hdfs_handle = (globus_l_gfs_hdfs_handle_t *) user_arg;

    int success = GLOBUS_FALSE;
    switch (cmd_info->command) {
    case GLOBUS_GFS_CMD_MKD:
        break;
    case GLOBUS_GFS_CMD_RMD:
        break;
    case GLOBUS_GFS_CMD_DELE:
        break;
    case GLOBUS_GFS_CMD_RNTO:
        break;
    case GLOBUS_GFS_CMD_RNFR:
        break;
    case GLOBUS_GFS_CMD_CKSM:
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
    }
    if (success)
        globus_gridftp_server_finished_command(op, GLOBUS_SUCCESS, GLOBUS_NULL);
    else
        globus_gridftp_server_finished_command(op, GLOBUS_FAILURE, GLOBUS_NULL);
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
globus_l_gfs_hdfs_start(
    globus_gfs_operation_t              op,
    globus_gfs_session_info_t *         session_info)
{
    globus_l_gfs_hdfs_handle_t *       hdfs_handle;
    globus_gfs_finished_info_t          finished_info;
    GlobusGFSName(globus_l_gfs_hdfs_start);

    int max_buffer_count = 200;
    int max_file_buffer_count = 1500;
    int load_limit = 20;
    int replicas;
    int port;

    hdfs_handle = (globus_l_gfs_hdfs_handle_t *)
        globus_malloc(sizeof(globus_l_gfs_hdfs_handle_t));

    globus_mutex_init(&hdfs_handle->mutex, GLOBUS_NULL);

    memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_SESSION_START;
    finished_info.result = GLOBUS_SUCCESS;
    finished_info.info.session.session_arg = hdfs_handle;
    finished_info.info.session.username = session_info->username;
    finished_info.info.session.home_dir = "/";

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

    // Pull syslog configuration from environment.
    char * syslog_host_char = getenv("GRIDFTP_SYSLOG");
    if (syslog_host_char == NULL) {
        hdfs_handle->syslog_host = NULL;
        hdfs_handle->local_host = NULL;
    } else {
        hdfs_handle->syslog_host = syslog_host_char;
        hdfs_handle->local_host = globus_malloc(sizeof(char)*256);
        memset(hdfs_handle->local_host, '\0', sizeof(char)*256);
        if (gethostname(hdfs_handle->local_host, 255) != 0) {
            sprintf(hdfs_handle->local_host, "UNKNOWN");
        }
        hdfs_handle->remote_host = session_info->host_id;
        openlog("GRIDFTP", 0, LOG_LOCAL2);
        sprintf(hdfs_handle->syslog_msg, "%s %s %%s %%i %%i", hdfs_handle->local_host, hdfs_handle->remote_host);
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
        snprintf(err_msg, MSG_SIZE, "Detected system load %.2f.\n", load);
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, err_msg);
        if ((load >= load_limit) && (load < 1000)) {
            snprintf(err_msg, MSG_SIZE, "Preventing gridftp transfer startup due to system load of %.2f.\n", load);
            globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,err_msg);
            sleep(5);
        } else {
            break;
        }
        close(fd);
        fd = open("/proc/loadavg", O_RDONLY);
    }

    snprintf(err_msg, MSG_SIZE, "Start gridftp server; hadoop nameserver %s, port %i, replicas %i.\n", hdfs_handle->host, hdfs_handle->port, hdfs_handle->replicas);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,err_msg);

    hdfs_handle->fs = hdfsConnect("default", 0);
    if (!hdfs_handle->fs) {
        finished_info.result = GLOBUS_FAILURE;
        globus_gridftp_server_operation_finished(
            op, GLOBUS_FAILURE, &finished_info);
        return;
    }

    hdfs_handle->tmp_file_pattern = (char *)NULL;

    globus_gridftp_server_operation_finished(
        op, GLOBUS_SUCCESS, &finished_info);
}

/*************************************************************************
 *  destroy
 *  -------
 *  This is called when a session ends, ie client quits or disconnects.
 *  The dsi should clean up all memory they associated wit the session
 *  here. 
 ************************************************************************/
void
globus_l_gfs_hdfs_destroy(
    void *                              user_arg)
{
    globus_l_gfs_hdfs_handle_t *       hdfs_handle;
    hdfs_handle = (globus_l_gfs_hdfs_handle_t *) user_arg;

    if (hdfs_handle) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Destroying the HDFS connection.\n");
        if (hdfs_handle->fs)
            hdfsDisconnect(hdfs_handle->fs);
        if (hdfs_handle->username)
            globus_free(hdfs_handle->username);
        if (hdfs_handle->local_host)
            globus_free(hdfs_handle->local_host);
        remove_file_buffer(hdfs_handle);
        globus_mutex_destroy(&hdfs_handle->mutex);
        globus_free(hdfs_handle);
    }
    closelog();
}


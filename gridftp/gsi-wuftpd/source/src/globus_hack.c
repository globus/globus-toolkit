#include "config.h"
#if defined(USE_GLOBUS_DATA_CODE)
#include  "globus_common.h"
#include  "globus_io.h"
#include "proto.h"
#include "../support/ftp.h"
#include <syslog.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef GLOBUS_AUTHORIZATION
#include "globus_gsi_authz.h"
#endif /* GLOBUS_AUTHORIZATION */

#define TIME_DELAY_112  5

/*
#define PROXY_BACKEND   1
*/
extern int                                      TCPwindowsize;
extern globus_ftp_control_layout_t		g_layout;
extern globus_ftp_control_parallelism_t		g_parallelism;
extern globus_bool_t				g_send_restart_info;
extern int mode;
extern globus_size_t                            g_striped_file_size;
gss_cred_id_t                            	g_deleg_cred = GSS_C_NO_CREDENTIAL;

extern SIGNAL_TYPE         
lostconn(int sig);

extern globus_fifo_t				            g_restarts;
extern globus_ftp_control_dcau_t                g_dcau;
extern globus_ftp_control_delay_passive_t       g_delayed_passive;
static globus_bool_t                            g_send_perf_update;
static globus_bool_t                            g_send_range;

#ifdef GLOBUS_AUTHORIZATION
#define FTP_PROTO_STRING "ftp://"
#define FTP_SERVICE_NAME "file"
extern char chroot_path[];   /* From ftpd.c */
static char *Urlbase = 0;
static globus_gsi_authz_handle_t	    Authz_handle = 0;

static void
ftp_l_authz_handle_init_callback(void *				cb_arg,
				 globus_gsi_authz_handle_t 	handle,
				 globus_result_t		result);

static void
ftp_l_authorize_callback(void *				cb_arg,
			 globus_gsi_authz_handle_t 	handle,
			 globus_result_t		result);

static void
ftp_l_authz_handle_destroy_callback(void *				cb_arg,
				 globus_gsi_authz_handle_t 	handle,
				 globus_result_t		result);

static void
ftp_l_authz_get_authorization_identity_callback(
    void *			cb_arg,
    globus_gsi_authz_handle_t 	handle,
    globus_result_t		result);

#endif /* GLOBUS_AUTHORIZATION */

globus_bool_t g_eof_receive = GLOBUS_FALSE;

#ifdef BUFFER_SIZE
static globus_size_t                            g_blksize = BUFFER_SIZE;
#else
static globus_size_t                            g_blksize = 65536;
#endif

/*
 *  globals used for netlogger times
 */
static int                                      g_perf_log_file_fd = -1;
static int                                      g_tcp_buffer_size = 0;
static char *                                   g_perf_progname = NULL;
static char                                     g_perf_hostname[256];
static struct timeval                           g_perf_start_tv;
static struct timeval                           g_perf_end_tv;
static globus_ftp_control_host_port_t           g_perf_address;
/* externally visible */
char *                                          g_perf_log_file_name = NULL;
char **                                         g_mountPts;

void
setup_volumetable();

void
get_volume(
    const char *                                name,
    char *                                      volume);

void
g_write_to_log_file(
    globus_ftp_control_handle_t *               handle,
    struct timeval *                            start_gtd_time,
    struct timeval *                            end_gtd_time,
    globus_ftp_control_host_port_t *            dest_host_port,
    globus_size_t                               blksize,
    globus_size_t                               buffer_size,
    const char *                                fname,
    globus_size_t                               nbytes,
    int                                         code,
    char *                                      type);


/*
#define G_DEBUG 1
*/

#if G_DEBUG
FILE * g_out;

#define DEBUG_OPEN() \
g_out = fopen("/disks/space1/wuftpd_out", "w")

#define DEBUG_CLOSE() \
fclose(g_out)

#else

#define DEBUG_OPEN()
#define DEBUG_CLOSE()

#endif

void
debug_printf(char * fmt, ...)
{
#if G_DEBUG
    va_list          ap;

    va_start(ap, fmt);
    vfprintf(g_out, fmt, ap);

    va_end(ap);
#endif
}

/*
 *  The enter and exit macros need to be around any code that will
 *  cause globus to poll, ex: globus_cond_wait(), globus_poll().
 *  Otherwise the SIGPIPE handler in wuftpd can cause errors in
 *  the globus_io callback mecanism.
 */
#define G_ENTER()                  \
{                                  \
    signal(SIGPIPE, SIG_IGN);      \
}

#define G_EXIT()                   \
{                                  \
    signal(SIGPIPE, lostconn);     \
}

typedef struct
{
    off_t			offset;
    off_t			length;
}
globus_l_wu_range_t;

typedef struct globus_i_wu_monitor_s
{
    globus_mutex_t             mutex;
    globus_cond_t              cond;
    globus_bool_t              done;

    globus_object_t *          error;
    globus_bool_t              timed_out;
    globus_bool_t              abort;
    int                        count;
    int                        fd;
    int                        code;

    off_t	               offset; 
    int                        callback_count;

    /* Range response messages */
    time_t		       last_range_update;
    globus_fifo_t	       ranges;

    /* Performance update messages */
    time_t		       last_perf_update;
    globus_off_t	       all_transferred;
    globus_callback_handle_t   callback_handle;
    globus_ftp_control_handle_t *
			       handle;
    globus_io_handle_t         io_handle;

    char *                     fname;

} globus_i_wu_monitor_t;

/*
 *  global varials from ftpd.c
 */
extern int logged_in;
extern int transflag;
extern int retrieve_is_data;
extern int type;
extern unsigned int timeout_data;
extern unsigned int timeout_connect;
extern unsigned int timeout_accept;
extern int data_count_total;
extern int data_count_in;
extern int data_count_out;
extern int byte_count_total;
extern int byte_count_in;
extern int byte_count_out;
extern off_t file_size;
extern off_t byte_count;
extern int file_count_total;
extern int file_count_in;
extern int file_count_out;
extern int xfer_count_total;
extern int xfer_count_in;
extern int xfer_count_out;
extern struct sockaddr_in ctrl_addr;
extern struct sockaddr_in his_addr;
/**********************************************************n
 * local function prototypes
 ************************************************************/
int 
g_seek(
    FILE *                               fin,
    off_t                                  ndx);

void
g_force_close(
    int                                         cb_count);

void
connect_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    unsigned int                                stripe_ndx,
    globus_bool_t                               reuse,
    globus_object_t *                           error);

void
data_read_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                offset,
    globus_bool_t                               eof);

void
data_write_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                offset,
    globus_bool_t                               eof);

void 
data_close_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    globus_object_t *                           error);

static char *
globus_l_wu_create_range_string(globus_fifo_t * ranges);

static
void
globus_l_wu_perf_update_callback(
    void *				user_args);

static globus_bool_t
globus_l_wu_perf_update(
    globus_i_wu_monitor_t *              mon);

void
send_range(
    globus_i_wu_monitor_t *                      monitor);

/*************************************************************
 *   global vairables 
 ************************************************************/
globus_ftp_control_handle_t                     g_data_handle;

static globus_i_wu_monitor_t                     g_monitor;

/*
 *  define macros for file handling
 */
#define G_File_Open(handle, fname, flags, fd)  \
    globus_open(handle,fd)

#define G_File_Read(handle, fd, buffer, length, offset, offset_out) \
    globus_read(handle, buffer, length, offset, offset_out)

#define G_File_Write(handle, fd, buffer, length, offset) \
    globus_write(handle, buffer, length, offset)

#define G_File_Close(handle, fd) \
    globus_close(handle)


int globus_open(
    globus_io_handle_t *   handle,
    int                    fd)
{
    globus_result_t        res;
    int                    my_fd = fd;
  
/* xio does not close coverted fds */
#ifndef GLOBUS_IO_OVER_XIO
    my_fd = dup(fd);
#endif

    res = globus_io_file_posix_convert(my_fd,
				       GLOBUS_NULL,
				       handle);

    return (res == GLOBUS_SUCCESS) ? 0 : -1;
}


int globus_close(
    globus_io_handle_t *   handle)
{
    globus_result_t        res;

    res = globus_io_close(handle);

    return (res == GLOBUS_SUCCESS) ? 0 : -1;
}


int
globus_read(    
    globus_io_handle_t *                handle,
    globus_byte_t *                     buffer,
    int                                 length,
    off_t                               offset,
    off_t *                             offs_out)
{
    globus_size_t                       bytes_read;
    globus_result_t                     res;

    *offs_out = offset;

    res = globus_io_read(handle, 
			 buffer, 
			 length, 
			 length, 
			 &bytes_read);

    return bytes_read;
}

int 
globus_write(
    globus_io_handle_t *                handle,
    globus_byte_t *                     buffer,
    int                                 length,
    off_t                               offset)
{
    globus_result_t                     res;
    globus_size_t                       bytes_written;

    res = globus_io_file_seek(handle,
			      offset,
			      GLOBUS_IO_SEEK_SET);
    if(res != GLOBUS_SUCCESS)
    {
        return -1;
    }
    
    res = globus_io_write(handle, 
			  buffer, 
			  length,
			  &bytes_written);

    return (res == GLOBUS_SUCCESS) ? bytes_written : -1;
}

/*
 *  PROXY_BACKEND
 */
#if defined(PROXY_BACKEND)

#include "globus_time.h"

static globus_bool_t                    g_log_active = GLOBUS_FALSE;
static globus_netlogger_handle_t        g_log_globus_nl_handle;

static globus_off_t                     g_log_total_nbytes = 0;
static globus_abstime_t                 g_log_last_time;

static long                             g_log_min_msec = 800;
static int                              g_log_stripe_ndx = 0;
static int                              g_my_uid;


void
create_netlogger_connection()
{
    char *                              stripe_ndx_str;
    char *                              netlogger_delay;
    globus_result_t                     res;

    stripe_ndx_str = globus_libc_getenv("GLOBUS_STRIPE_NDX");
    if(stripe_ndx_str != NULL)
    {
        g_log_stripe_ndx = atoi(stripe_ndx_str);
    }  
    netlogger_delay = globus_libc_getenv("GLOBUS_NETLOGGER_DELAY");
    if(netlogger_delay != NULL)
    {
        g_log_min_msec = atoi(netlogger_delay);
    }  

    res = globus_netlogger_handle_init(
              &g_log_globus_nl_handle,
              g_perf_hostname,
              g_perf_progname,
              "BACKEND");
    if(res == GLOBUS_SUCCESS)
    {
        g_log_active = GLOBUS_TRUE;
    }
}

void
close_netlogger_connection()
{
    if(!g_log_active)
    {
        return;
    }
    globus_netlogger_handle_destroy(&g_log_globus_nl_handle);
}

void
log_start_transfer()
{
    char                                buf[128];
    char                                id[32];
    globus_result_t                     res;

    if(!g_log_active)
    {
        return;
    }
    g_log_total_nbytes = 0;
    GlobusTimeAbstimeGetCurrent(g_log_last_time);

    sprintf(id, "BackendProxy-%d", g_log_stripe_ndx);
    sprintf(buf, 
        "BE.ID=%d",
        g_my_uid);
    res = globus_netlogger_write(
              &g_log_globus_nl_handle,
              "GPFTPD_START",
              id,
              "Emergency",
              buf);
    if(res != GLOBUS_SUCCESS)
    {
        close_netlogger_connection();
        create_netlogger_connection();
    }
}

/*
 *
 */
void
log_throughput(
    globus_size_t                       nbytes,
    globus_bool_t                       last)
{
    globus_abstime_t                    time_now;
    globus_reltime_t                    time_diff;
    long                                usec;
    long                                msec;
    long                                sec;
    char                                id[32];
    char                                buf[128];
    char *                              event_str;
    char *                              last_str = "GPFTPD_LAST";
    char *                              data_str = "GPFTPD_DATA";
    globus_result_t                     res;
    int                                 mypid;

    if(!g_log_active)
    {
        return;
    }
    GlobusTimeAbstimeGetCurrent(time_now);
    GlobusTimeAbstimeDiff(time_diff, time_now, g_log_last_time);

    GlobusTimeReltimeGet(time_diff, sec, usec);
    g_log_total_nbytes += nbytes;
    /*
     * if enough time has expired
     */
    msec = (usec / 1000) + (sec * 1000);
    if(msec < g_log_min_msec && !last)
    {
        return;
    }
    if(last)
    {
        event_str = last_str;
    }
    else
    {
        event_str = data_str;
    }

    sprintf(id, "BackendProxy-%d", g_log_stripe_ndx);
    sprintf(buf, 
        "FTP_NBYTES=%"GLOBUS_OFF_T_FORMAT
        " BE.ID=%d "
        "FTP_MS=%ld", 
        g_log_total_nbytes,
        g_my_uid,
        (long)msec);
    res = globus_netlogger_write(
              &g_log_globus_nl_handle,
              event_str,
              id,
              "Emergency",
              buf);
    if(res != GLOBUS_SUCCESS)
    {
        close_netlogger_connection();
        create_netlogger_connection();
    }

    /* update values for next call */
    g_log_total_nbytes = 0;
    GlobusTimeAbstimeCopy(g_log_last_time, time_now);
}

#else /* PROXYBACKEND */

#define create_netlogger_connection()
#define close_netlogger_connection()
#define log_throughput(n, l)
#define log_start_transfer()

#endif /* PROXYBACKEND */

void
g_set_blksize(
    globus_size_t                      size)
{
    g_blksize = size;
}


int
std_read(    
    int                                 fd,
    globus_byte_t *                     buffer,
    int                                 length,
    off_t                               offset,
    off_t *                             offs_out)
{
    *offs_out = offset;

    return read(fd, buffer, length);
}

int 
std_write(
    int                                 fd,
    globus_byte_t *                     buffer,
    int                                 length,
    off_t                               offset)
{
    int                                 ret;

    ret = lseek(fd, offset, SEEK_SET);
    if(ret < 0)
    {
        return ret;
    }
    ret = write(fd, buffer, length);

    return ret;
}

void
wu_monitor_reset(
    globus_i_wu_monitor_t *                      mon)
{
    mon->done = GLOBUS_FALSE;
    mon->timed_out = GLOBUS_FALSE;
    mon->abort = GLOBUS_FALSE;
    mon->count = 0;
    mon->offset = -1;
    mon->fd = -1;
    mon->last_perf_update = time(GLOBUS_NULL);
    mon->last_range_update = mon->last_perf_update;
    mon->callback_handle = 0;
    globus_fifo_destroy(&mon->ranges);
    globus_fifo_init(&mon->ranges);
}

void
wu_monitor_init(
    globus_i_wu_monitor_t *                      mon)
{
    globus_mutex_init(&mon->mutex, GLOBUS_NULL);
    globus_cond_init(&mon->cond, GLOBUS_NULL);
    globus_fifo_init(&mon->ranges);
    
    wu_monitor_reset(mon);
}

void
wu_monitor_destroy(
    globus_i_wu_monitor_t *                      mon)
{
    globus_mutex_destroy(&mon->mutex);
    globus_cond_destroy(&mon->cond);

    globus_fifo_destroy(&mon->ranges);
}

static
void
g_timeout_wakeup(
    void *                                      user_args)
{
    globus_mutex_lock(&g_monitor.mutex);
    {   
        globus_cond_signal(&g_monitor.cond);
    }
    globus_mutex_unlock(&g_monitor.mutex);
}

void
g_pre_fork()
{

}

void
g_start(
    int                               argc,
    char **                           argv)
{
    char *                            a;
    globus_ftp_control_host_port_t    host_port;
    int			              rc;
    globus_reltime_t                  delay_time;
    globus_reltime_t                  period_time;
    globus_result_t		      res;
DEBUG_OPEN();
G_ENTER();

    rc = globus_module_activate(GLOBUS_FTP_CONTROL_MODULE);
    assert(rc == GLOBUS_SUCCESS);

    g_perf_progname = "wuftpd";
    if(gethostname(g_perf_hostname, 256) != 0)
    {
        g_perf_hostname[0] = '\0';
    }

    if(g_perf_log_file_name != NULL)
    {
        g_perf_log_file_fd = open(g_perf_log_file_name, 
                                 O_WRONLY | O_CREAT | O_APPEND,
                                 S_IRUSR | S_IRGRP | S_IROTH);
    }
    setup_volumetable();

    /* added for SC01 ProxyServer demo */
    create_netlogger_connection();
#if defined(PROXY_BACKEND)
    g_my_uid = getpid() + time(NULL) + g_log_stripe_ndx;
#endif
    wu_monitor_init(&g_monitor);
    g_monitor.handle = &g_data_handle;

    globus_ftp_control_handle_init(&g_data_handle);

#if defined(NETLOGGER_ON)
    g_globus_nl_handle = NetLoggerOpen(g_perf_progname, NULL, NL_ENV);
    globus_netlogger_handle_init(
        &g_nl_handle,
        g_globus_nl_handle);
    globus_ftp_control_set_netlogger(
        &g_data_handle,
        &g_nl_handle,
        GLOBUS_TRUE,
        GLOBUS_FALSE);
#endif

    g_dcau.mode = GLOBUS_FTP_CONTROL_DCAU_SELF;
    res = globus_ftp_control_local_dcau(
	    &g_data_handle,
	    &g_dcau,
            g_deleg_cred);
    assert(res == GLOBUS_SUCCESS);

    a = (char *)&his_addr;
    host_port.host[0] = (int)a[0];
    host_port.host[1] = (int)a[1];
    host_port.host[2] = (int)a[2];
    host_port.host[3] = (int)a[3];
    host_port.port = 21;

    res = globus_ftp_control_local_port(
              &g_data_handle,
              &host_port);
    assert(res == GLOBUS_SUCCESS);

    g_parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_NONE;
    g_parallelism.base.size = 1;
    g_layout.mode = GLOBUS_FTP_CONTROL_STRIPING_NONE;

    globus_ftp_control_local_parallelism(
              &g_data_handle,
              &g_parallelism);

    GlobusTimeReltimeSet(delay_time, timeout_connect / 2, 0);
    GlobusTimeReltimeSet(period_time, timeout_connect / 2, 0);

    globus_fifo_init(&g_restarts);

    debug_printf("registering wakeup at %d secs\n", timeout_connect / 2);
    res = globus_callback_register_periodic(
             GLOBUS_NULL,
             &delay_time,
             &period_time,
             g_timeout_wakeup,
             GLOBUS_NULL);
    assert(res == GLOBUS_SUCCESS);

G_EXIT();
}

void
g_end()
{
    globus_i_wu_monitor_t                            monitor;
    globus_result_t                                 res;

    G_ENTER();

    wu_monitor_init(&monitor);
    /*
     *  force close the data connection
     */
    monitor.done = GLOBUS_FALSE;
    res = globus_ftp_control_data_force_close(
              &g_data_handle,
              data_close_callback,
              (void*)&monitor);
    if(res == GLOBUS_SUCCESS)
    {
        globus_mutex_lock(&monitor.mutex);
        {   
            while(!monitor.done)
            {
                globus_cond_wait(&monitor.cond, &monitor.mutex);
            }
        }
        globus_mutex_unlock(&monitor.mutex);
    }

    wu_monitor_destroy(&monitor);

    /* added for SC01 ProxyServer demo */
    close_netlogger_connection();

    globus_ftp_control_handle_destroy(&g_data_handle);
    globus_module_deactivate(GLOBUS_FTP_CONTROL_MODULE);

DEBUG_CLOSE();
    G_EXIT();
}

void
g_abort()
{
    globus_mutex_lock(&g_monitor.mutex);
    {   
        g_monitor.abort = GLOBUS_TRUE;
        globus_cond_signal(&g_monitor.cond);
    }
    globus_mutex_unlock(&g_monitor.mutex);
}

void
g_passive_port_alloc(globus_bool_t spas)
{
    globus_result_t                             res;
    globus_ftp_control_host_port_t              host_port;
    int                                         hi;
    int                                         low;
    unsigned char *                             a;

    if (!logged_in)   
    {
        reply(530, "Login with USER first.");
        return;
    }

    host_port.port = 0;
    host_port.host[0] = 0;
    host_port.host[1] = 0;
    host_port.host[2] = 0;
    host_port.host[3] = 0;

    res = globus_ftp_control_local_pasv(
              &g_data_handle,
              &host_port);
    if(res != GLOBUS_SUCCESS)
    {
        perror_reply(425, 
                 globus_object_printable_to_string(globus_error_get(res)));

        return;
    }

    a = (unsigned char *)&ctrl_addr.sin_addr;
    host_port.host[0] = (int) a[0];
    host_port.host[1] = (int) a[1];
    host_port.host[2] = (int) a[2];
    host_port.host[3] = (int) a[3];

    hi = host_port.port / 256;
    low = host_port.port % 256;

    if(spas)
    {
	lreply(229, "Entering Striped Passive Mode");
	lreply(0, " %d,%d,%d,%d,%d,%d",
	       host_port.host[0],
	       host_port.host[1],
	       host_port.host[2],
	       host_port.host[3],
	       hi,
	       low);
	reply(229, "End");

    }
    else
    {
	reply(227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", 
	      host_port.host[0],
	      host_port.host[1],
	      host_port.host[2],
	      host_port.host[3],
	      hi,
	      low);
    }
}

void
g_passive(globus_bool_t spas)
{
	if( g_delayed_passive)
	{
	/*		must wait until later to alloc the port
			XXX must find out what code to really return here!
	*/
        reply(000, "Delayed passive mode on, will return port later");
	}
	else 
	{
		g_passive_port_alloc(spas);
	}
	
}

/*
 *  what to do if it times out
 *
 *  send error message on control connection
 */
static SIGNAL_TYPE 
g_alarm_signal(
    int                                             sig)
{
    globus_mutex_lock(&g_monitor.mutex);
    {
        g_monitor.timed_out = GLOBUS_TRUE;
        g_monitor.done = GLOBUS_TRUE;
        globus_cond_signal(&g_monitor.cond);
    }
    globus_mutex_unlock(&g_monitor.mutex);
}

/*
 *  if the restart marker is bad return 0 - -1
 */
int
invert_restart(
    off_t *                                        offset_a, 
    off_t *                                        length_a) 
{
    int                                            start = 0;
    globus_l_wu_range_t *			   tmp;

    if(globus_fifo_size(&g_restarts) == 0)
    {
        offset_a[0] = 0;
        length_a[0] = -1;
  
        return 1;
    }
    tmp = (globus_l_wu_range_t *) globus_fifo_peek(&g_restarts);

    if(tmp->offset != 0)
    {
        offset_a[0] = 0;
        length_a[0] = tmp->offset;
        start++;
    }

    while(globus_fifo_size(&g_restarts) != 1)
    {
	tmp = (globus_l_wu_range_t *) globus_fifo_dequeue(&g_restarts);

	offset_a[start] = tmp->offset + tmp->length;
	globus_libc_free(tmp);

	tmp = (globus_l_wu_range_t *) globus_fifo_peek(&g_restarts);
        length_a[start] = tmp->offset - offset_a[start];

        start++;
    }
    tmp = (globus_l_wu_range_t *) globus_fifo_dequeue(&g_restarts);

    offset_a[start] = tmp->offset + tmp->length;
    length_a[start] = -1;

    globus_libc_free(tmp);
    start++;
    return start;
}

/*
 *  globusified send data routine
 */
int
g_send_data(
    char *                                          name,
    FILE *                                          instr,
    globus_ftp_control_handle_t *                   handle,
    off_t                                           offset,
    off_t					    logical_offset,
    off_t                                           length,
    off_t					    size)
{
    int                                             jb_count;
    int                                             jb_len;
    register int                                    cnt = 0;
    globus_byte_t *                                 buf = GLOBUS_NULL;
    int                                             filefd;
    globus_bool_t                                   eof = GLOBUS_FALSE;
    globus_bool_t                                   aborted;
    int                                             cb_count = 0;
    globus_result_t                                 res;
    int                                             connection_count = 4;
    globus_bool_t                                   l_timed_out = GLOBUS_FALSE;
    globus_ftp_control_parallelism_t                parallelism;
    off_t *                                         offset_a;
    off_t *                                         length_a;
    int                                             count_a;
    int                                             ctr;
    char                                            error_buf[1024];
    off_t                                           offs_out = -1;
    off_t                                           blksize;
    globus_size_t                                   total_nbytes = 0;
    int                                             tmp_i;
#ifdef THROUGHPUT
    int                                             bps;
    double                                          bpsmult;
    time_t                                          t1;
    time_t                                          t2;
#endif

    G_ENTER();

    error_buf[0] = '\0';
#ifdef THROUGHPUT
    throughput_calc(name, &bps, &bpsmult);
#endif

    blksize = g_blksize;

    wu_monitor_reset(&g_monitor);
    g_monitor.fname = name;
    g_monitor.all_transferred = 0;

    gettimeofday(&g_perf_start_tv, NULL);

    if(G_File_Open(
	&(g_monitor.io_handle),
	NULL,
	NULL,
	fileno(instr)) != 0)
     {
         sprintf(error_buf, "file_open failed");
         goto data_err;
     }
           
    if(offset == -1)
    {
        offset = 0;
    }
    /*
     *  perhaps a time out should be added here
     */
    log_start_transfer();
    (void) signal(SIGALRM, g_alarm_signal);
    alarm(timeout_connect);

    if(mode == MODE_E)
    {
	if(g_layout.mode == GLOBUS_FTP_CONTROL_STRIPING_PARTITIONED)
	{
	    if(retrieve_is_data)
	    {
		g_layout.partitioned.size = size;

		globus_ftp_control_local_layout(handle, &g_layout, 0);
	    }
	}
	else
	{
	    globus_ftp_control_local_layout(handle, &g_layout, 0);
	}
	globus_ftp_control_local_parallelism(handle,
					     &g_parallelism);

    }
    wu_monitor_reset(&g_monitor);
    res = globus_ftp_control_data_connect_write(
              handle,
              connect_callback,
              (void *)&g_monitor);
    if(res != GLOBUS_SUCCESS)
    {
        sprintf(error_buf,
		"Connect_write() failed: %s.",
		globus_object_printable_to_string(globus_error_get(res)));
        goto data_err;
    }

    globus_mutex_lock(&g_monitor.mutex);
    {
        while(!g_monitor.done)
        {
            globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
        }
        l_timed_out = g_monitor.timed_out;
    }
    globus_mutex_unlock(&g_monitor.mutex);

    tmp_i = 1;
    res = globus_ftp_control_data_get_remote_hosts(
              handle,
              &g_perf_address,
              &tmp_i);

    if(l_timed_out)
    {
        goto connect_err;
    }
    if(g_monitor.error != GLOBUS_NULL)
    {
        sprintf(error_buf, "data_connect_failed() failed: %s", 
                globus_object_printable_to_string(g_monitor.error));
        globus_object_free(g_monitor.error);

        goto connect_err;
    }

    G_EXIT();
    if(g_monitor.code == 150)
    {
       reply(150, "Opening %s mode data connection.",
              type == TYPE_A ? "ASCII" : "BINARY");
    }
    else
    {
       reply(125, "Reusing %s mode data connection.",
              type == TYPE_A ? "ASCII" : "BINARY");
    }
    G_ENTER();

    transflag++;
    switch (type) 
    {

    case TYPE_A:
    case TYPE_I:
    case TYPE_L:

#       ifdef THROUGHPUT
        {
            if (bps != -1)
            {
                blksize = bps;
            }
        }
#       endif

        filefd = fileno(instr);

        /*
         *  set timeout
         */
        (void) signal(SIGALRM, g_alarm_signal);
        alarm(timeout_data);

#       ifdef THROUGHPUT
        {
            if (bps != -1)
            {
                t1 = time(NULL);
            }
       }
#      endif

        if(!globus_fifo_empty(&g_restarts))
        {
            offset_a = (off_t
			*)globus_malloc(sizeof(off_t)*
					(globus_fifo_size(&g_restarts) + 1));
            length_a = (off_t *)globus_malloc(sizeof(off_t)*(
		                               globus_fifo_size(&g_restarts) + 1));
            count_a = invert_restart(offset_a, length_a);
        }
        else
        {
            offset_a = (off_t *)globus_malloc(sizeof(off_t));
            length_a = (off_t *)globus_malloc(sizeof(off_t));
            offset_a[0] = offset;
            length_a[0] = length;
            count_a = 1;
        }

        wu_monitor_reset(&g_monitor);
        for(ctr = 0; ctr < count_a && !eof; ctr++)
        {
            g_seek(instr, offset_a[ctr]);

            offset = offset_a[ctr];
            length = length_a[ctr];
            jb_count = 0;
            while ((jb_count <= length || length == -1) && !eof)
            {
                /*
                 *  allocate a buffer for each send
                 */
                if ((buf = (globus_byte_t *) globus_malloc(blksize)) == NULL)  
                {
                    transflag = 0;
 
                    G_EXIT();
                    perror_reply(451, "Local resource failure: malloc");
                    retrieve_is_data = 1;
		    globus_free(offset_a);
                    globus_free(length_a);
		    goto bail0;
                }

                if(length == -1 || length - jb_count >= blksize)
                {
                    jb_len = blksize;
                }
                else
                {
                    jb_len = length - jb_count;
                }
                offs_out = -1;
                cnt = G_File_Read(
		          &g_monitor.io_handle,
                          filefd,
                          buf,
                          jb_len,
                          offset,
                          &offs_out);

               if(offs_out > 0 && cnt > 0)
               {
                   offset = offs_out;
               }  

               if (cnt <= 0 )
               {
                  offset = 0;
                  cnt = 0;
               }

                /*
                 *  if file eof, or we have read the portion we want  to 
                 *  send in a partial file transfer set eof to true
                 */
                if(cnt <= 0 || 
                   (jb_count + cnt == length && length != -1 && ((ctr+1) == count_a)))
		{
                    eof = GLOBUS_TRUE;
                }

                res = globus_ftp_control_data_write(
                          handle,
                          buf,
                          cnt,
                          offset - logical_offset,
                          eof,
                          data_write_callback,
                          &g_monitor);
                if(res != GLOBUS_SUCCESS)
                {
                    sprintf(error_buf, "data_write() failed: %s", 
                        globus_object_printable_to_string(
                            globus_error_get(res)));
                    globus_free(offset_a);
                    globus_free(length_a);
                    goto data_err;
                }
		buf = GLOBUS_NULL; /* So that time outs or or other goto
				      data errs don't free the buffer. */
                cb_count++;
                offset += cnt;
                jb_count += cnt;
                total_nbytes += cnt;

		res = globus_ftp_control_get_parallelism(
			  handle,
			  &parallelism);
                assert(res == GLOBUS_SUCCESS);

		connection_count = 2*parallelism.base.size;

                globus_mutex_lock(&g_monitor.mutex);
                {   
                    g_monitor.count++;
                    while(g_monitor.count == connection_count && 
                          !g_monitor.abort &&
                          !g_monitor.timed_out)
                    {
                        globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
                    }
                }
                globus_mutex_unlock(&g_monitor.mutex);

#           ifdef THROUGHPUT
            {
                if (bps != -1)
                {
                    t2 = time(NULL);
                    if (t2 == t1)
                    {
                        sleep(1);
                    }
                    t1 = time(NULL);
                }
            }
#           endif

            } /* end while */
            globus_mutex_lock(&g_monitor.mutex);
            {   
                while(g_monitor.count != 0)
                {
                    globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
                }
            }
            globus_mutex_unlock(&g_monitor.mutex);

            byte_count += cnt;
#           ifdef TRANSFER_COUNT
            {
                if (retrieve_is_data)
                {
#                   ifdef RATIO
                    {
                        if(freefile)
                        {
                            total_free_dl += cnt;
                        }
                    }
#                   endif /* RATIO */

                    data_count_total += cnt;
                    data_count_out += cnt;
                }
                byte_count_total += cnt;
                byte_count_out += cnt;

            }    
#           endif

        } /* end for */
        
        globus_free(offset_a);
        globus_free(length_a);
        
#       ifdef THROUGHPUT
        {
            if (bps != -1)
            {
                throughput_adjust(name);
            }
        }
#       endif


        /*
         *  wait until the eof callback is received
         */
        globus_mutex_lock(&g_monitor.mutex);
        {   
            while(g_monitor.count > 0)
            {
                globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
            }
            l_timed_out = g_monitor.timed_out;
            aborted = g_monitor.abort;
        }
        globus_mutex_unlock(&g_monitor.mutex);

        transflag = 0;
        if(aborted)
        {
            alarm(0);
            transflag = 0;
            retrieve_is_data = 1;
    
            g_force_close(cb_count);

            G_EXIT();
	    goto bail0;
        }

        if(l_timed_out)
        {
            sprintf(error_buf, "Timed out");
            goto data_err;
        }

        /* 
         *  unset alarm 
         */
        alarm(0);

        G_EXIT();

        reply(226, "Transfer complete.");
        G_ENTER();

#       ifdef TRANSFER_COUNT
        {
            if (retrieve_is_data) 
            {
                file_count_total++;
                file_count_out++;
            }
            xfer_count_total++;
            xfer_count_out++;
        }
#       endif
 
        retrieve_is_data = 1;

        /*
         *  EXIT POINT 
         */
        goto clean_exit;


    default:
        transflag = 0;

        G_EXIT();
        reply(550, "Unimplemented TYPE %d in send_data", type);
        retrieve_is_data = 1;

	goto bail1;
    }
 
  /* 
   *  DATA_ERR
   */
  data_err:
    alarm(0);
    transflag = 0;

    g_force_close(cb_count);

    if(buf != GLOBUS_NULL)
    {
        globus_free(buf);
    }

    G_EXIT();
    reply(426, "Data connection. %s", error_buf);
 
    retrieve_is_data = 1;

    goto bail0;

  connect_err:
    alarm(0);
    transflag = 0;

    G_EXIT();
    reply(425, "Can't open data connection. %s.", error_buf);

    goto bail0;

  /*
   *  FILE_ERR
   */
    alarm(0);
    transflag = 0;
    G_EXIT();
    perror_reply(551, "Error on input file");
    retrieve_is_data = 1;

    goto bail0;

  bail0:
    G_File_Close(&g_monitor.io_handle, 0);

    globus_i_wu_free_ranges(&g_restarts);

    return (0);
  bail1:
    G_File_Close(&g_monitor.io_handle, 0);
    globus_i_wu_free_ranges(&g_restarts);

    return (1);

  clean_exit:

    G_File_Close(&g_monitor.io_handle, 0);
    globus_i_wu_free_ranges(&g_restarts);

    G_EXIT();

    return (1);
}

/*
 *  force close the data connection
 *  wait for all of the callbacks to return and for the 
 *  close callback
 */
void
g_force_close(
    int                                     cb_count)
{
    globus_result_t                         res;

    G_ENTER();

    g_monitor.done = GLOBUS_FALSE;
    res = globus_ftp_control_data_force_close(
              &g_data_handle,
              data_close_callback,
              (void*)&g_monitor);
    if(res == GLOBUS_SUCCESS)
    {
        /*
         *  wait for close all of the calbacks and for the
         *  close callback.
         */
        globus_mutex_lock(&g_monitor.mutex);
        {   
            while(!g_monitor.done || g_monitor.count < cb_count)
            {
                globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
            }
        }
        globus_mutex_unlock(&g_monitor.mutex);
    }

    G_EXIT();
}

void 
data_close_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    globus_object_t *                           error)
{
    globus_i_wu_monitor_t *                      monitor;

    monitor = (globus_i_wu_monitor_t *)callback_arg;

    globus_mutex_lock(&monitor->mutex);
    {
        monitor->done = GLOBUS_TRUE;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);
}


void
data_write_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                offset,
    globus_bool_t                               eof)
{
    globus_i_wu_monitor_t *                         monitor;

    monitor = (globus_i_wu_monitor_t *)callback_arg;
    
    (void) signal(SIGALRM, g_alarm_signal);
    alarm(timeout_data);
    
    /* added for SC01 ProxyServer demo */
    if(!error)
    {
        log_throughput(length, eof);
    }

    globus_mutex_lock(&monitor->mutex);
    {
        monitor->count--;
        globus_cond_signal(&monitor->cond);
	monitor->all_transferred += length;
    }
    globus_mutex_unlock(&monitor->mutex);

    if(eof && !error)
    {
        gettimeofday(&g_perf_end_tv, NULL);
        g_write_to_log_file(
            handle,
            &g_perf_start_tv,
            &g_perf_end_tv,
            &g_perf_address,
            g_blksize,
            g_tcp_buffer_size,
            monitor->fname,
            monitor->all_transferred,
            226,
            "RETR");
    }
    globus_free(buffer);
}

/*
 *  globus hacked receive data
 *  --------------------------
 */
int 
g_receive_data(
    globus_ftp_control_handle_t *            handle,
    FILE *                                   outstr,
    off_t                                    offset,
    char *                                   fname)
{
    globus_byte_t *                          buf;
    int                                      filefd;
    globus_bool_t                            l_timed_out;
    globus_bool_t                            l_error;
    globus_bool_t                            aborted;
    globus_result_t                          res;
    int                                      ctr;
    int                                      cb_count = 0;
    unsigned int                             data_connection_count = 1;
    globus_reltime_t			     five_seconds;
    char                                     error_buf[1024];
    int                                      tmp_i;
    size_t                                   buffer_size;

    buffer_size = g_blksize;

    G_ENTER();
    error_buf[0] = '\0';
    wu_monitor_reset(&g_monitor);
    g_monitor.offset = offset;
    g_monitor.fname = fname;

    (void) signal(SIGALRM, g_alarm_signal);
    alarm(timeout_accept);

    gettimeofday(&g_perf_start_tv, NULL);
    if(G_File_Open(
	&(g_monitor.io_handle),
	GLOBUS_NULL,
	GLOBUS_NULL,
	fileno(outstr)) != 0)
    {
	sprintf(error_buf, "file_open() failed");
	goto data_err;
    }

    /* added for SC01 proxy server demo */				 
    log_start_transfer();

    res = globus_ftp_control_data_connect_read(
              handle,
              connect_callback,
              (void *)&g_monitor);
    if(res != GLOBUS_SUCCESS)
    {
             sprintf(error_buf, "connect_read() failed");
        goto data_err;
    }

    globus_mutex_lock(&g_monitor.mutex);
    {
        while(!g_monitor.done)
        {
            globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
        }
        l_timed_out = g_monitor.timed_out;
    }
    globus_mutex_unlock(&g_monitor.mutex);

    tmp_i = 1;
    res = globus_ftp_control_data_get_remote_hosts(
              handle,
              &g_perf_address,
              &tmp_i);

    if(l_timed_out)
    {
        sprintf(error_buf, "timed out() failed");
        goto connect_err;
    }
    if(g_monitor.error != GLOBUS_NULL)
    {
        sprintf(error_buf, "data_connect_failed() failed: %s", 
                globus_object_printable_to_string(g_monitor.error));
        globus_object_free(g_monitor.error);

        goto connect_err;
    }

    G_EXIT();
    if(g_monitor.code == 150)
    {
       reply(150, "Opening %s mode data connection.",
              type == TYPE_A ? "ASCII" : "BINARY");
    }
    else
    {
       reply(125, "Reusing %s mode data connection.",
              type == TYPE_A ? "ASCII" : "BINARY");
    }
    G_ENTER();
    
    transflag++;
    switch (type) 
    {

    case TYPE_I:
    case TYPE_L:
    case TYPE_A:

    /* the globus code should handle ascii mode */

        filefd = fileno(outstr);

        (void) signal(SIGALRM, g_alarm_signal);
        alarm(timeout_data);

        g_monitor.count = 0;
        g_monitor.done = GLOBUS_FALSE;
        g_monitor.fd = filefd;
        cb_count = 0;
#ifndef BUILD_LITE
        /** XXX JoeL
         */
	res = globus_ftp_control_data_query_channels(
			  handle,
                          &data_connection_count,
                          0);
	assert(res == GLOBUS_SUCCESS);

	debug_printf("receive data parallelism: %u", 
		     data_connection_count);

        if(res == GLOBUS_SUCCESS)
        {
            data_connection_count *= 2;
        }
        else
        {
            data_connection_count = 2;
        }
#endif
	GlobusTimeReltimeSet(five_seconds, TIME_DELAY_112, 0);

        g_send_range = GLOBUS_FALSE;
        g_send_perf_update = GLOBUS_FALSE;
	globus_callback_register_periodic(
	    &g_monitor.callback_handle,
	    &five_seconds,
	    &five_seconds,
	    globus_l_wu_perf_update_callback,
	    &g_monitor);
        globus_l_wu_perf_update(&g_monitor);
        g_monitor.callback_count = 0; 

#ifndef BUILD_LITE
        /** XXX JoeL
         */
        for(ctr = 0; ctr < data_connection_count; ctr++)
        {
#endif
            if ((buf = (globus_byte_t *) globus_malloc(buffer_size)) == NULL)
            {
                transflag = 0;
		globus_callback_unregister(
		    g_monitor.callback_handle,
		    GLOBUS_NULL,
		    GLOBUS_NULL,
            GLOBUS_NULL);

                G_EXIT();
                perror_reply(451, "Local resource failure: malloc");
                goto bail;
            }

            res = globus_ftp_control_data_read(
                      handle,
                      buf,
                      buffer_size,
                      data_read_callback,
                      (void *)&g_monitor);
            if(res != GLOBUS_SUCCESS)
            {
                globus_free(buf);
                sprintf(error_buf, "data_read() failed");
                goto data_err;
            }
            g_monitor.callback_count++;
            cb_count++;
#ifndef BUILD_LITE
        /** XXX JoeL
         */
        }
#endif
        globus_mutex_lock(&g_monitor.mutex);
        {
            while(!g_monitor.done && 
                  g_monitor.count < g_monitor.callback_count &&
                  !g_monitor.abort &&
                  !g_monitor.timed_out)
            {
                globus_cond_wait(&g_monitor.cond, &g_monitor.mutex);
		if(g_send_perf_update)
		{
		    g_send_perf_update = GLOBUS_FALSE;
		    globus_l_wu_perf_update(&g_monitor);
		}
		    if(g_send_range)
		{
		    g_send_range = GLOBUS_FALSE;
		    send_range(&g_monitor);
		}
            }
            l_timed_out = g_monitor.timed_out;
            l_error = g_monitor.done;
            aborted = g_monitor.abort;
        }
        globus_mutex_unlock(&g_monitor.mutex);

        transflag = 0;
        if(aborted)
        {
            alarm(0);
            g_force_close(cb_count);
	    globus_callback_unregister(
		    g_monitor.callback_handle,
		    GLOBUS_NULL,
		    GLOBUS_NULL,
            GLOBUS_NULL);

            G_EXIT();
	    goto bail;
        }

        if(l_timed_out || l_error)
        {
             sprintf(error_buf, "timed out failed");
            goto data_err;
        }

        alarm(0);

#       ifdef TRANSFER_COUNT
        {
            file_count_total++;
            file_count_in++;
            xfer_count_total++;
            xfer_count_in++;
        }
#       endif

        goto clean_exit;

    case TYPE_E:

        G_EXIT();
        reply(553, "TYPE E not implemented.");
        transflag = 0;
        goto bail;

    default:

        G_EXIT();
        reply(550, "Unimplemented TYPE %d in receive_data", type);
        transflag = 0;
	goto  bail;
    }

  data_err:

    g_force_close(cb_count);

    globus_callback_unregister(
        g_monitor.callback_handle,
        GLOBUS_NULL,
        GLOBUS_NULL,
        GLOBUS_NULL);

    alarm(0);
    transflag = 0;
   
    G_EXIT();
    reply(426, "Data Connection. %s", error_buf);
    goto bail;

  connect_err:
    alarm(0);
    transflag = 0;

    G_EXIT();
    reply(425, "Can't open data connection. %s.", error_buf);

    goto bail;


    globus_callback_unregister(
        g_monitor.callback_handle,
        GLOBUS_NULL,
        GLOBUS_NULL,
        GLOBUS_NULL);

    alarm(0);
    transflag = 0;

    G_EXIT();
    perror_reply(452, "Error writing file");

    bail:
    G_File_Close(&g_monitor.io_handle, 0);
    globus_i_wu_free_ranges(&g_restarts);

    return (-1);

  clean_exit:
    G_File_Close(&g_monitor.io_handle, 0);
    globus_callback_unregister(
        g_monitor.callback_handle,
        GLOBUS_NULL,
        GLOBUS_NULL,
        GLOBUS_NULL);

    G_EXIT();

    return (0);
}

void
connect_callback(
    void *                                      callback_arg,
    struct globus_ftp_control_handle_s *        handle,
    unsigned int                                stripe_ndx,
    globus_bool_t                               reuse,
    globus_object_t *                           error)
{
    globus_i_wu_monitor_t *                      monitor;

    monitor = (globus_i_wu_monitor_t *)callback_arg;

    globus_mutex_lock(&monitor->mutex);
    {
         if(error != GLOBUS_NULL)
         {
             monitor->error = globus_object_copy(error);
         }
         else
         {
             monitor->error = GLOBUS_NULL;
         }

         monitor->done = GLOBUS_TRUE; 
         if(reuse) 
         {
             monitor->code = 125;
         }
         else
         {
             monitor->code = 150;
         }
         globus_cond_signal(&monitor->cond);
    }
    globus_mutex_unlock(&monitor->mutex);
}

void
send_range(
    globus_i_wu_monitor_t *                      monitor)
{
    char *		                        range_str;

    G_EXIT();

    range_str =
        globus_l_wu_create_range_string(&monitor->ranges);
		    
    reply(111, "Range Marker %s", range_str);
    globus_libc_free(range_str);

    G_ENTER();
}

void
data_read_callback(
    void *                                      callback_arg,
    globus_ftp_control_handle_t *               handle,
    globus_object_t *                           error,
    globus_byte_t *                             buffer,
    globus_size_t                               length,
    globus_off_t                                offset,
    globus_bool_t                               eof)
{
    globus_i_wu_monitor_t *                     monitor;
    globus_result_t                             res;
    int                                         ret;
#ifdef BUFFER_SIZE
    size_t                                      buffer_size = BUFFER_SIZE;
#else
    size_t                                      buffer_size = BUFSIZ;
#endif

    monitor = (globus_i_wu_monitor_t *)callback_arg;

    globus_mutex_lock(&monitor->mutex);
    {
        /* added for SC01 ProxyServer demo */
        if(!error)
        {
            log_throughput(length, eof);
        }
        if(error != GLOBUS_NULL)
        {
            monitor->count++;
            globus_cond_signal(&monitor->cond);
            globus_mutex_unlock(&monitor->mutex);

            return;
        }

        if(length > 0)
        {
            if(monitor->offset > 0)
            {
                offset = offset + monitor->offset;
            }
            ret = G_File_Write(
                      &monitor->io_handle,
                      monitor->fd,
                      buffer,
                      length,
                      offset);
            if(ret <= 0)
            {
                /* How to signal error ? */
                assert(0);
                return;
            }

            byte_count += length;
#           ifdef TRANSFER_COUNT
            {
                data_count_total += length;
                data_count_in += length;
                byte_count_total += length;
                byte_count_in += length;
            }
#           endif
        }

	if(g_send_restart_info)
	{
	    time_t				t;

	    t = time(NULL);

	    globus_i_wu_insert_range(&monitor->ranges, offset, length);

	    if(t - monitor->last_range_update > 10)
	    {
                g_send_range = GLOBUS_TRUE;
                monitor->last_range_update = t;
                globus_cond_signal(&monitor->cond);
	    }
	}
	monitor->all_transferred += length;

        if(eof)
        {
            if(!error) 
            {
                gettimeofday(&g_perf_end_tv, NULL);
                g_write_to_log_file(
                    handle,
                    &g_perf_start_tv,
                    &g_perf_end_tv,
                    &g_perf_address,
                    g_blksize,
                    g_tcp_buffer_size,
                    monitor->fname,
                    monitor->all_transferred,
                    226,
                    "STOR");
            }
            g_eof_receive = GLOBUS_TRUE;
            monitor->count++;
            globus_cond_signal(&monitor->cond);
            globus_free(buffer);
        }
        else
        {

#ifndef BUILD_LITE
            /** XXX JoeL
             * due to reetrancy issues caused by the blocking write above
             * we cant have any more than one read callback outstanding
             * -- a better solution for this would be to add callback space
             * support to data channel code.
             */
            unsigned int                 data_connection_count;
            int                          new_callbacks;
            int                          ctr;

	    res = globus_ftp_control_data_query_channels(
	  		  handle,
                          &data_connection_count,
                          0);
	    assert(res == GLOBUS_SUCCESS);

            new_callbacks = 1;

            /*
             * this is done in case new connections have come in
             */
            if((data_connection_count * 2) > monitor->callback_count) 
            {
                new_callbacks = (data_connection_count * 2) -  monitor->callback_count + 1;
            }

                monitor->callback_count += (new_callbacks - 1);
            for(ctr = 0; ctr < new_callbacks; ctr++)
            {
#endif
                res = globus_ftp_control_data_read(
                          handle,
                          buffer,
                          buffer_size,
                          data_read_callback,
                          (void *)monitor);
                if(res != GLOBUS_SUCCESS)
                {
                    monitor->count++;
                    globus_free(buffer);
                    monitor->done = GLOBUS_TRUE;
                    globus_cond_signal(&monitor->cond);
            
                    globus_mutex_unlock(&monitor->mutex);

                    return;
                }
#ifndef BUILD_LITE
                /** XXX JoeL
                 */
		if(ctr < new_callbacks-1)
		{
		    buffer = (globus_byte_t *) globus_malloc(buffer_size);
		}
            }
#endif
        }

        (void) signal(SIGALRM, g_alarm_signal);
        alarm(timeout_data);
    }
    globus_mutex_unlock(&monitor->mutex);
}

void
globus_i_wu_insert_range(
    globus_fifo_t *				ranges,
    globus_off_t				offset,
    globus_off_t				length)
{
    globus_fifo_t				tmp;
    globus_l_wu_range_t *			range;
    globus_l_wu_range_t *			newrange;

    globus_fifo_move(&tmp, ranges);

    while(!globus_fifo_empty(&tmp))
    {
	range = globus_fifo_dequeue(&tmp);
	if(offset <= range->offset)
	{
	    if(offset + length < range->offset)
	    {
		newrange = globus_malloc(sizeof(globus_l_wu_range_t));
		newrange->offset = offset;
		newrange->length = length;

		globus_fifo_enqueue(ranges, newrange);
		globus_fifo_enqueue(ranges, range);
		goto copy_rest;
	    }
	    else if(offset+length == range->offset)
	    {
		length += range->length;
		globus_libc_free(range);
	    }
	    else
	    {
		int newlength;

		/* weird.... overlapping data */
		newlength = range->offset + range->length - offset;
		if(newlength < length)
		{
		    newlength = length;
		}
		length = newlength;
		globus_libc_free(range);
	    }
	}
	else
	{
	    if(range->offset + range->length < offset)
	    {
		globus_fifo_enqueue(ranges, range);
	    }
	    else if(range->offset + range->length == offset)
	    {
		offset = range->offset;
		length += range->length;
		globus_libc_free(range);
	    }
	    else
	    {
		globus_fifo_enqueue(ranges, range);
	    }
	}
    }

    newrange = globus_malloc(sizeof(globus_l_wu_range_t));
    newrange->offset = offset;
    newrange->length = length;
    globus_fifo_enqueue(ranges, newrange);
copy_rest:
    while(! globus_fifo_empty(&tmp))
    {
	globus_fifo_enqueue(ranges, globus_fifo_dequeue(&tmp));
    }
    
    globus_fifo_destroy(&tmp);
}

void
globus_i_wu_free_ranges(
    globus_fifo_t *				ranges)
{
    while(!globus_fifo_empty(ranges))
    {
	globus_l_wu_range_t *			range;
	range = (globus_l_wu_range_t *) globus_fifo_dequeue(ranges);
	globus_libc_free(range);
    }
}

static int
globus_l_wu_count_digits(globus_off_t num)
{
    int digits = 1;

    if(num < 0)
    {
	digits++;
	num = -num;
    }
    while(0 < (num = (num / 10))) digits++;

    return digits;
}

static char *
globus_l_wu_create_range_string(
    globus_fifo_t *                     ranges)
{
    int					length = 0, mylen;
    char *				buf = GLOBUS_NULL;
    globus_l_wu_range_t *		range;

    while((! globus_fifo_empty(ranges)) && (length < 4*1024))
    {
	range = globus_fifo_dequeue(ranges);

	mylen = globus_l_wu_count_digits(range->offset);
	mylen++;
	mylen += globus_l_wu_count_digits(range->offset+range->length);
	mylen++;

	buf = realloc(buf, length + mylen + 1);
	length += globus_libc_sprint_off_t(buf + length,
					   range->offset);
	length += sprintf(buf+length, "-");

	length += globus_libc_sprint_off_t(buf + length,
					   range->offset +
					   range->length);
	length += sprintf(buf + length, ",");
	globus_libc_free(range);
    }
    buf[strlen(buf)-1] = '\0';

    return buf;
}

static
void
globus_l_wu_perf_update_callback(
    void *				user_args)
{
    globus_i_wu_monitor_t *		monitor;

    monitor = (globus_i_wu_monitor_t *) user_args;

    globus_mutex_lock(&monitor->mutex);
    {
        g_send_perf_update = GLOBUS_TRUE;
        globus_cond_signal(&monitor->cond);
    }
    globus_mutex_lock(&monitor->mutex);
}

static globus_bool_t 
globus_l_wu_perf_update(
    globus_i_wu_monitor_t *		monitor)
{
    globus_ftp_control_handle_t *	handle;
    int                                 tenth;
    struct timeval                      tv;

    if(!g_send_restart_info)
    {
	return GLOBUS_TRUE;
    }
    handle = monitor->handle;

    gettimeofday(&tv, GLOBUS_NULL);
    tenth = tv.tv_usec / 100000;
	
    G_EXIT();	
    lreply(112, "Perf Marker");
    lreply(0, " Timestamp: %ld.%1d", (long) tv.tv_sec, tenth);
    lreply(0, " Stripe Index: 0");
    lreply(0, " Total Stripe Count: 1");
    lreply(0, " Stripe Bytes Transferred: %" GLOBUS_OFF_T_FORMAT, 
	    monitor->all_transferred);
    reply(112, "End");

    monitor->last_perf_update = tv.tv_sec;

    return GLOBUS_TRUE;
}

int 
g_seek(
    FILE *                               fin,
    off_t                                ndx)
{
    register int i;
    register int n;
    register int c;

    if (type == TYPE_A) 
    {
        n = ndx;
        i = 0;
        while (i++ < n) 
        {
            if ((c = getc(fin)) == EOF) 
            {
                return -1;
            }
            if (c == '\n')
            {
                i++;
            }
        }
    }
    else if (lseek(fileno(fin), ndx, SEEK_SET) < 0) 
    {
        return -1;
    }

    return 0;
}
    
void
g_set_tcp_buffer(int size)
{
    globus_ftp_control_tcpbuffer_t           tcpbuffer;

    if(size != 0)
    {
	tcpbuffer.mode = GLOBUS_FTP_CONTROL_TCPBUFFER_FIXED;
	tcpbuffer.fixed.size = size;

        globus_ftp_control_local_tcp_buffer(&g_data_handle,
	                                    &tcpbuffer);
    }
    else
    {
	tcpbuffer.mode = GLOBUS_FTP_CONTROL_TCPBUFFER_DEFAULT;
        globus_ftp_control_local_tcp_buffer(&g_data_handle,
	                                    &tcpbuffer);
    }
}

void
get_volume(
    const char *                           name, 
    char *                                 volume)
{
    int                                    ctr; 
    int                                    max = 0;
    char *                                 p;

    ctr = 0;
    while(g_mountPts[ctr] != NULL)
    {
        if((p = (char *)strstr(name, g_mountPts[ctr])) && 
            (strlen(p) == strlen(name)))
        {
            if(strlen(g_mountPts[ctr]) > max)
            {
                max = strlen(g_mountPts[ctr]);
                strcpy(volume, g_mountPts[ctr]);
            }
        }
        ctr++;
    }
}

void
globus_tmp_libc_flock(int fd)
{
    struct flock fl;

    fl.l_type   = F_WRLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK    */
    fl.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
    fl.l_start  = 0;        /* Offset from l_whence         */
    fl.l_len    = 0;        /* length, 0 = to EOF           */
    fl.l_pid    = getpid(); /* our PID                      */

    fcntl(fd, F_SETLKW, &fl);  /* F_GETLK, F_SETLK, F_SETLKW */
}

void
globus_tmp_libc_funlock(int fd)
{
    struct flock fl;

    fl.l_type   = F_UNLCK;  /* F_RDLCK, F_WRLCK, F_UNLCK    */
    fl.l_whence = SEEK_SET; /* SEEK_SET, SEEK_CUR, SEEK_END */
    fl.l_start  = 0;        /* Offset from l_whence         */
    fl.l_len    = 0;        /* length, 0 = to EOF           */
    fl.l_pid    = getpid(); /* our PID                      */

    fcntl(fd, F_SETLKW, &fl);  /* F_GETLK, F_SETLK, F_SETLKW */
}


void
setup_volumetable()
{
    FILE *fp;
    char buf[80];
    int  ctr; 
    int max_mpt_ptrs = 32;

    /* if fd is -1 we are not logging */
    if(g_perf_log_file_fd == -1)
    {
        return;
    }

    ctr = 0;
    g_mountPts = malloc(sizeof(char *) * max_mpt_ptrs);
    fp = popen("mount | awk '{print $3}'", "r");
    while(fgets(buf, 80, fp)) 
    {
        buf[strlen(buf) - 1] = '\0';
        if(ctr >= max_mpt_ptrs)
        {
            max_mpt_ptrs *= 2;
            g_mountPts = realloc(g_mountPts, sizeof(char *) * max_mpt_ptrs);
        }
        g_mountPts[ctr] = strdup(buf);
        ctr++;
    }
    g_mountPts[ctr] = NULL;
    pclose(fp);
}

void
g_write_to_log_file(
    globus_ftp_control_handle_t *           handle,
    struct timeval *                        start_gtd_time,
    struct timeval *                        end_gtd_time,
    globus_ftp_control_host_port_t *        dest_host_port,
    globus_size_t                           blksize,
    globus_size_t                           buffer_size,
    const char *                            fname,
    globus_size_t                           nbytes,
    int                                     code,
    char *                                  type)
{
    time_t                                  start_time_time;
    time_t                                  end_time_time;
    struct tm *                             tmp_tm_time;
    struct tm                               start_tm_time;
    struct tm                               end_tm_time;
    char                                    out_buf[512];
    char                                    user_buf[32];
    int                                     stream_count; 
    int                                     stripe_count; 
    globus_result_t                         res;
    int                                     ctr;
    unsigned int                            tmp_i;
    char                                    volume[80];
    char                                    cwd[124];
    char                                    l_fname[124];
    struct passwd *                         pw_ent;
    long                                     win_size;
    int                                     opt_dir;

    /* if fd is -1 we are not logging */
    if(g_perf_log_file_fd == -1)
    {
        return;
    }

    start_time_time = (time_t)start_gtd_time->tv_sec;
    tmp_tm_time = gmtime(&start_time_time);
    if(tmp_tm_time == NULL)
    {
        return;
    }
    start_tm_time = *tmp_tm_time;

    end_time_time = (time_t)end_gtd_time->tv_sec;
    tmp_tm_time = gmtime(&end_time_time);
    if(tmp_tm_time == NULL)
    {
        return;
    }
    end_tm_time = *tmp_tm_time;

    pw_ent = getpwuid(geteuid());
    if(pw_ent != NULL)
    {
        sprintf(user_buf, "USER=%s", pw_ent->pw_name);
    }
    else
    {
        user_buf[0] = '\0';
    }

    getcwd(cwd, 124);
    if(fname[0] != '/')
    {
        sprintf(l_fname, "%s/%s", cwd, fname);
        fname = l_fname;
    }
    get_volume(fname, volume);

    res = globus_ftp_control_get_stripe_count(
              handle,
              &stripe_count);
    if(res != GLOBUS_SUCCESS)
    { 
        sprintf(out_buf, "ERROR 1: %s\n", globus_object_printable_to_string(globus_error_get(res)));
        return;
    }

    stream_count = 0;
    for(ctr = 0; ctr < stripe_count; ctr++)
    {
        res = globus_ftp_control_data_get_total_data_channels(
                  handle,
                  &tmp_i,
                  ctr);
        if(res != GLOBUS_SUCCESS)
        {
        sprintf(out_buf, "ERROR 2: %s\n", globus_object_printable_to_string(globus_error_get(res)));
            goto write;
        }
        stream_count += tmp_i;
    }

    if(buffer_size == 0)
    {
        int                            sock;
        int                            opt_len;

        if(strcmp(type, "RETR") == 0 || strcmp(type, "ERET") == 0)
        {
            opt_dir = SO_SNDBUF;
            sock = STDOUT_FILENO;
        }
        else
        {
            opt_dir = SO_RCVBUF;
            sock = STDIN_FILENO;
        }
	win_size = 0;
        opt_len = sizeof(win_size);
        getsockopt(sock, SOL_SOCKET, opt_dir, &win_size, &opt_len);
    }
    else
    {
        win_size = buffer_size;
    }

    sprintf(out_buf, 
        "DATE=%04d%02d%02d%02d%02d%02d.%d "
        "HOST=%s "
        "PROG=%s "
        "NL.EVNT=FTP_INFO "
        "START=%04d%02d%02d%02d%02d%02d.%d "
        "%s "
        "FILE=%s "
        "BUFFER=%ld "
        "BLOCK=%ld "
        "NBYTES=%ld "
        "VOLUME=%s "
        "STREAMS=%d "
        "STRIPES=%d "
        "DEST=1[%d.%d.%d.%d] " 
        "TYPE=%s " 
        "CODE=%d\n",
        /* end time */
        end_tm_time.tm_year,
        end_tm_time.tm_mon,
        end_tm_time.tm_mday,
        end_tm_time.tm_hour,
        end_tm_time.tm_min,
        end_tm_time.tm_sec,
        (int) end_gtd_time->tv_usec,
        g_perf_hostname,
        g_perf_progname,
        /* start time */
        start_tm_time.tm_year,
        start_tm_time.tm_mon,
        start_tm_time.tm_mday,
        start_tm_time.tm_hour,
        start_tm_time.tm_min,
        start_tm_time.tm_sec,
        (int) start_gtd_time->tv_usec,
        /* other args */
        user_buf,
        fname,
        win_size,
        (long) blksize,
        (long) nbytes,
        volume,
        stream_count, 
        stripe_count,
        dest_host_port->host[0], dest_host_port->host[1], 
           dest_host_port->host[2], dest_host_port->host[3],
        type, 
        code);

    /*
     *  lock and write the string
     */
  write:
    globus_tmp_libc_flock(g_perf_log_file_fd);
    write(g_perf_log_file_fd, out_buf, strlen(out_buf));
    globus_tmp_libc_funlock(g_perf_log_file_fd);
}

#endif /* USE_GLOBUS_DATA_CODE */

#ifdef GLOBUS_AUTHORIZATION

/*
 * ftp_check_authorization()
 *
 * calls globus_authorization routines to evaluate requests
 *
 * Parameters:  object - The full path to the file or directory which will be
 *                       accessed.
 *
 *              action - ftp protocol command which describes the requested
 *                       action on the file
 * returns:    1 if authorization is ok
 *             0 otherwise
 */
 
int ftp_check_authorization(char * object,
                            char * action)
{
    char                realname[MAXPATHLEN];
    char		url[2*(MAXPATHLEN)];
    int			nchars;
    globus_result_t	result;

    if (! (object && action && *action))
    {
	syslog(LOG_INFO, "ftp_check_authorization: null object or action");
	return(0);
    }

    if (! (Urlbase && *Urlbase))
    {
	syslog(LOG_NOTICE,
	       "ftp_check_authorization:  ftp authorization system was not initialized");
	return(0);
    }

    /*
     * I believe this function basically just appends object to
     * chroot and returns the result in realname.
     * It will return NULL on error (buffer overflow).
     */
    if (wu_realpath(object, realname, chroot_path) == NULL)
    {
	syslog(LOG_INFO,
	       "ftp_check_authorization: could not get pathname for object '%s'",
	       object);
	syslog(LOG_DEBUG,
	       "ftp_check_authorization: chroot_path was '%s'",
	       (chroot_path ? chroot_path : ""));
	return(0);
    }

    nchars = globus_libc_snprintf(url,
				  sizeof(url),
				  "%s%s",
				  Urlbase,
				  realname);
    if ((nchars < 0) || (nchars >= sizeof(url)-1))
    {
	syslog(LOG_INFO,
	       "ftp_check_authorization: could not construct URL for object '%s'",
	       object);
	syslog(LOG_DEBUG,
	       "ftp_check_authorization: Urlbase was '%s'",
	       Urlbase);
	syslog(LOG_DEBUG,
	       "ftp_check_authorization: realpath was '%s'",
	       realpath);
	return(0);
    }

    syslog(LOG_DEBUG, "ftp_check_authorization: url is '%s'", url);
    result = globus_gsi_authorize(Authz_handle,
				  action,
				  url,
				  ftp_l_authorize_callback, 
				  0);
    if (result != GLOBUS_SUCCESS)
    {
	syslog(LOG_INFO,
	       "ftp_check_authorization: authz denied or failed: %s",
	       globus_error_print_chain(globus_error_get(result)));
	return(0);
    }

    return(1);
}

char **
ftp_i_list_possible_actions()
{
    static char *actions[] =
    {
	"create",
	"read",
	"lookup",
	"write",
	"delete",
	"chdir",
	0
    };
    return(actions);
}

/*
 * ftp_authorization_initialize()
 *
 * Initializes the globus authorization handle
 *
 * Parameters: use_hostname  -use <use_hostname> (instead of gethostname()) 
 *                            when comparing URLs in policy statements
 *             errstr        -Buffer for returning an error message
 *             errstr_len    -length of errstr buffer
 * 
 * returns:    1  success
 *             0  failure
 */

int ftp_authorization_initialize(char *         use_hostname,
				 char *		errstr,
                                 int            errstr_len)
{
    globus_result_t	                result;
    char *              	        service_type = "file";
    char                                hostbuf[256];
    char *				hostname = 0;

    if (use_hostname && *use_hostname)
    {
	hostname = use_hostname;
    }
    else
    {
	if(globus_libc_gethostname(hostbuf, sizeof(hostbuf)-1) == -1)
	{
	    strncpy(errstr,
		    "Unable to resolve ftp server hostname",
		    errstr_len);
	    return 0;
	}
	
	hostbuf[sizeof(hostbuf)-1]='\0';
	hostname = hostbuf;
    }

    if ((Urlbase = globus_libc_malloc(sizeof(FTP_PROTO_STRING) +
				      strlen(hostname) + 1)) == 0)
    {
	strncpy(errstr, "malloc failed", errstr_len);
	return 0;
    }

    sprintf(Urlbase, "%s%s", FTP_PROTO_STRING, hostname);

    if (globus_module_activate(GLOBUS_GSI_AUTHZ_MODULE) != GLOBUS_SUCCESS)
    {
	strncpy(errstr, "activation of authz module failed", errstr_len);
	return 0;
    }

    return 1;
}

/*
 * ftp_authorization_initialize_sc()
 *
 * Initializes the globus authorization handle with the security context
 * of the most recent gss authenticated client
 *
 * Parameters: ctx - a gss security context 
 *             errstr - buffer for returning an error message
 *             errstr_len - length of errstr buffer
 *
 * returns:    1  success
 *             0  failure
 */ 

int ftp_authorization_initialize_sc(gss_ctx_id_t        ctx,
                                    char *              errstr,
                                    int                 errstr_len)
{
    globus_result_t	            result;
    syslog(LOG_DEBUG, "entering ftp_init_sc");        
    result = globus_gsi_authz_handle_init(&Authz_handle,
					  FTP_SERVICE_NAME,
					  ctx,
					  ftp_l_authz_handle_init_callback,
					  0);

    if (result != GLOBUS_SUCCESS)
    {
	strncpy(errstr,
		globus_error_print_chain(globus_error_get(result)),
		errstr_len);
        return 0;
    }
    syslog(LOG_DEBUG, "ftp_init_sc succeeded");    
    return 1;
}

/*
 * ftp_authorization_clean_up()
 *
 * de-allocates the internal globus_auth structure  
 *
 * parameters: none
 *
 * returns: nothing 
 *
 */ 

void ftp_authorization_cleanup(void)
{

   (void)globus_gsi_authz_handle_destroy(Authz_handle,
					 ftp_l_authz_handle_destroy_callback,
					 0);
   Authz_handle = 0;

   (void)globus_module_deactivate(GLOBUS_GSI_AUTHZ_MODULE);
}


char *
ftp_authz_identity()
{
    globus_result_t	result;
    char *		identity = 0;

    result = globus_gsi_authz_get_authorization_identity (
	Authz_handle,
	&identity,
	ftp_l_authz_get_authorization_identity_callback,
	0);
    if (result != GLOBUS_SUCCESS)
    {
	syslog(LOG_INFO, "error getting authorization identity");
	return(0);
    }
    return(identity);
}

static void
ftp_l_authz_handle_init_callback(void *				cb_arg,
				 globus_gsi_authz_handle_t 	handle,
				 globus_result_t		result)
{
}

static void
ftp_l_authorize_callback(void *				cb_arg,
			 globus_gsi_authz_handle_t 	handle,
			 globus_result_t		result)
{
}

static void
ftp_l_authz_handle_destroy_callback(void *				cb_arg,
				    globus_gsi_authz_handle_t 	handle,
				    globus_result_t		result)
{
}

static void
ftp_l_authz_get_authorization_identity_callback(
    void *			cb_arg,
    globus_gsi_authz_handle_t 	handle,
    globus_result_t		result)
{
}

#endif /* GLOBUS_AUTHORIZATION */

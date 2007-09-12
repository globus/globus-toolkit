#include "globus_gridftp_server_control.h"
#include "globus_common.h"
#include "globus_xio.h"
#include "globus_xio_tcp_driver.h"
#include "openssl/des.h"
#include "version.h"
#include "globus_xio_telnet.h"
#include "globus_xio_gssapi_ftp.h"
#include "globus_error_generic.h"
#include "globus_xio_gsi.h"
#include <unistd.h>

#if !defined(GLOBUS_I_FTP2GRID_H)
#define GLOBUS_I_FTP2GRID_H 1

#define GlobusFTP2GridError(error_msg, _type)                                \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            NULL,                                                           \
            NULL,                                                           \
            _type,                                                          \
            __FILE__,                                                       \
            _gwtftp_func_name,                                             \
            __LINE__,                                                       \
            "%s",                                                           \
            (error_msg)))

#ifdef __GNUC__
#define GlobusFTP2GridFuncName(func) static const char * _gwtftp_func_name __attribute__((__unused__)) = #func
#else
#define GlobusFTP2GridFuncName(func) static const char * _gwtftp_func_name = #func
#endif

#define FTP_220_MSG                     "220 FTP2GRID\r\n"
#define FTP_220_MSG_LENGTH              strlen(FTP_220_MSG)
#define FAKE_BUFFER                     gwtftp_l_fake_buf
#define FAKE_BUFFER_LENGTH              1

extern globus_byte_t                    gwtftp_l_fake_buf[1];

#define FTP_530_MSG                     "530 USER not accepted.  Possibly a bad proxy format\r\n"
#define FTP_530_MSG_LENGTH              strlen(FTP_530_MSG)

#define FTP_331_MSG                     "331 Please specify the password.\r\n"
#define FTP_331_MSG_LENGTH              strlen(FTP_331_MSG)
enum
{
    GLOBUS_FTP2GRID_ERROR_PARM = 1,
    GLOBUS_FTP2GRID_ERROR_IP,
    GLOBUS_FTP2GRID_ERROR_MALLOC
};

enum
{
    FTP2GRID_LOG_MUST,
    FTP2GRID_LOG_ERROR,
    FTP2GRID_LOG_WARN,
    FTP2GRID_LOG_INFO
};

typedef struct globus_i_gwtftp_cmd_opts_s
{
    int                                 port;
    globus_bool_t                       quiet;
    globus_bool_t                       daemon;
    globus_bool_t                       child;
    int                                 log_mask;
    char *                              log_file;
    char *                              pw_file;
    globus_list_t *                     ip_list;
} globus_i_gwtftp_cmd_opts_t;

typedef struct gwtftp_l_data_s
{
    globus_xio_stack_t                  active_stack;
    globus_xio_stack_t                  passive_stack;
    globus_xio_server_t                 server;
    globus_xio_handle_t                 passive_xio;
    globus_xio_handle_t                 active_xio;
    globus_mutex_t                      mutex;
    globus_byte_t *                     active_buffer;
    globus_byte_t *                     passive_buffer;
    globus_result_t                     error_result;
    globus_size_t                       buffer_size;
    globus_xio_callback_t               close_cb;
    void *                              user_arg;
    int                                 state;
    char *                              active_cs;
} gwtftp_i_data_t;

globus_result_t
gwtftp_i_data_new(
    gwtftp_i_data_t **                  out_handle,
    globus_xio_stack_t                  active_stack,
    globus_xio_stack_t                  passive_stack,
    char *                              active_cs,
    char **                             out_passive_cs,
    globus_xio_callback_t               close_cb,
    void *                              user_arg);

void
gwtftp_i_data_close(
    gwtftp_i_data_t *                   data_h);

globus_result_t
globus_gwtftp_new_session(
    globus_xio_handle_t                 client_xio,
    globus_xio_handle_t                 server_xio);

void
gwtftp_i_close(
    globus_xio_handle_t                 handle,
    globus_xio_callback_t               close_cb,
    void *                              user_arg);

void
gwtftp_i_log(
    int                                 level,
    char *                              fmt,
    ...);

void
gwtftp_i_log_result(
    int                                 level,
    globus_result_t                     result,
    char *                              fmt,
    ...);

globus_result_t
gwtftp_i_ip_ok(
    globus_xio_handle_t                 handle);

globus_bool_t
gwtftp_i_pass_ok(
    const char *                        pw);

globus_result_t
gwtftp_i_new_connection(
    globus_xio_handle_t                 handle,
    globus_xio_attr_t                   attr);

globus_result_t
gwtftp_i_server_conn_open(
    globus_xio_handle_t                 server_xio,
    char *                              cs,
    globus_xio_handle_t                 client_xio,
    char *                              subject);

void
gwtftp_i_authorized_user(
    globus_xio_handle_t                 client_xio,
    const char *                        full_username,
    const char *                        pass);

void
gwtftp_i_server_init();

extern globus_xio_driver_t             gwtftp_l_tcp_driver;
extern globus_xio_driver_t             gwtftp_l_gsi_driver;
extern globus_xio_stack_t              gwtftp_l_data_tcp_stack;
extern globus_xio_stack_t              gwtftp_l_data_gsi_stack;

extern globus_xio_driver_t             gwtftp_l_gssapi_driver;

#endif

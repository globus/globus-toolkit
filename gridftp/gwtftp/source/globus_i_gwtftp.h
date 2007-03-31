#include "globus_gridftp_server_control.h"
#include "globus_common.h"
#include "globus_xio.h"
#include "globus_xio_tcp_driver.h"
#include "openssl/des.h"
#include "version.h"
#include "globus_xio_telnet.h"
#include "globus_xio_gssapi_ftp.h"

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
    GLOBUS_FTP2GRID_ERROR_PARM = 1
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
} globus_i_gwtftp_cmd_opts_t;

globus_result_t
globus_gwtftp_new_session(
    globus_xio_handle_t                 client_xio,
    globus_xio_handle_t                 server_xio);

void
gwtftp_i_close(
    globus_xio_handle_t                 handle);

void
gwtftp_i_log(
    int                                 level,
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
    globus_xio_handle_t                 handle);

globus_result_t
gwtftp_i_server_conn_open(
    globus_xio_handle_t                 server_xio,
    char *                              cs,
    globus_xio_handle_t                 client_xio);

void
gwtftp_i_authorized_user(
    globus_xio_handle_t                 client_xio,
    const char *                        full_username,
    const char *                        pass);

void
gwtftp_i_server_init();

#endif

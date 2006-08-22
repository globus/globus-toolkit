#include "globus_common.h"
#include "globus_xio.h"
#include "globus_xio_tcp_driver.h"
#include "globus_xio_mode_e_driver.h"
#include "version.h"


#if !defined(GLOBUS_I_XIOPERF_H)
#define GLOBUS_I_XIOPERF_H 1

#define GlobusXIOPerfError(error_msg, _type)                                \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            NULL,                                                           \
            NULL,                                                           \
            _type,                                                          \
            __FILE__,                                                       \
            _xioperf_func_name,                                             \
            __LINE__,                                                       \
            "%s",                                                           \
            (error_msg)))

#ifdef __GNUC__
#define GlobusXIOPerfFuncName(func) static const char * _xioperf_func_name __attribute__((__unused__)) = #func
#else
#define GlobusXIOPerfFuncName(func) static const char * _xioperf_func_name = #func
#endif

enum
{
    GLOBUS_XIO_PERF_ERROR_PARM = 1
};

typedef struct globus_i_xioperf_info_s
{
    char                                format;
    int                                 interval;
    globus_off_t                        len;
    int                                 port;
    globus_off_t                        window;
    char *                              bind_addr;
    globus_bool_t                       nodelay;
    globus_bool_t                       server;
    globus_bool_t                       reader;
    globus_bool_t                       writer;
    globus_bool_t                       dual;
    char *                              client;
    char *                              file;
    char *                              subject;
    globus_off_t                        bytes_to_transfer;
    globus_off_t                        bytes_sent;
    globus_off_t                        bytes_recv;
    globus_bool_t                       daemon;
    globus_size_t                       block_size;
    globus_size_t                       next_buf_size;
    int                                 stream_count;
    globus_xio_stack_t                  stack;
    globus_reltime_t                    time;
    globus_mutex_t                      mutex;
    globus_cond_t                       cond;
    globus_bool_t                       write_done;
    globus_bool_t                       read_done;
    globus_bool_t                       die;
    globus_bool_t                       eof;
    globus_object_t *                   err;
    int                                 ref;
    FILE *                              fptr;
    globus_xio_handle_t                 xio_handle;
    globus_byte_t *                     next_write_buffer;
    globus_xio_server_t                 server_handle;
    globus_abstime_t                    start_time;
    globus_abstime_t                    end_time;
    globus_xio_attr_t                   attr;
    globus_bool_t                       quiet;
    globus_fifo_t                       driver_name_q;
} globus_i_xioperf_info_t;

#endif

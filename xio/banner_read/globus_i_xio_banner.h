#include "globus_common.h"
#include "globus_xio.h"
#include "globus_xio_tcp_driver.h"
#include "version.h"


#if !defined(GLOBUS_I_XIOPERF_H)
#define GLOBUS_I_XIOPERF_H 1

#define GlobusXIOBannerError(error_msg, _type)                              \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            NULL,                                                           \
            NULL,                                                           \
            _type,                                                          \
            __FILE__,                                                       \
            _xiobanner_func_name,                                             \
            __LINE__,                                                       \
            "%s",                                                           \
            (error_msg)))

#ifdef __GNUC__
#define GlobusXIOBannerFuncName(func) static const char * _xiobanner_func_name __attribute__((__unused__)) = #func
#else
#define GlobusXIOBannerFuncName(func) static const char * _xiobanner_func_name = #func
#endif

enum
{
    GLOBUS_XIO_BANNER_ERROR_PARM = 1
};

typedef struct globus_i_xiobanner_info_s
{
    globus_mutex_t                      mutex;
    int                                 driver_count;
    int                                 port;
    int                                 max_len;
    globus_xio_stack_t                  stack;
    globus_reltime_t                    time;
    globus_hashtable_t                  driver_table;
    FILE *                              fptr;
    globus_xio_handle_t                 xio_handle;
    globus_xio_attr_t                   attr;
    globus_bool_t                       quiet;
    char *                              deliminator;
    globus_bool_t                       done;
    char *                              cs;
} globus_i_xiobanner_info_t;

#endif

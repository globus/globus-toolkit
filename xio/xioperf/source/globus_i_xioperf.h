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

typedef struct globus_i_xioperf_info_s
{
    char                                format;
    int                                 interval;
    int                                 len;
    int                                 port;
    int                                 window;
    char *                              bind_addr;
    globus_bool_t                       nodelay;
    globus_bool_t                       server;
    char *                              client;
    char *                              file;
    int                                 kbytes_to_transfer;
    int                                 stream_count;
    globus_xio_stack_t                  stack;
    globus_abstime_t                    time; 
} globus_i_xioperf_info_t;


#endif

#ifndef GLOBUS_XIO_UTIL_INCLUDE
#define GLOBUS_XIO_UTIL_INCLUDE

/* all macros in this file require each function to 'declare' their name with
 * this
 */
#define GlobusXIOName(func) static const char * _xio_name = #func

#define GlobusXIOErrorCanceled()                                            \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_ERROR_CANCELED,                                      \
            "[%s:%d] Operation was canceled",                               \
            _xio_name, __LINE__))                                           
                                                                            
#define GlobusXIOErrorTimedout()                                            \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_ERROR_TIMEDOUT,                                      \
            "[%s:%d] Operation timed out",                                  \
            _xio_name, __LINE__))                                           
                                                                            
#define GlobusXIOErrorEOF()                                                 \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_ERROR_EOF,                                           \
            "[%s:%d] An end of file occurred",                              \
            _xio_name, __LINE__))                                           
                                                                            
#define GlobusXIOErrorInvalidCommand(cmd_number)                            \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_ERROR_COMMAND,                                       \
            "[%s:%d] An invalid command (%d) was issued",                   \
            _xio_name, __LINE__, (cmd_number)))                             
                                                                            
#define GlobusXIOErrorContactString(reason)                                 \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_ERROR_CONTACT_STRING,                                \
            "[%s:%d] Contact string invalid. %s",                           \
            _xio_name, __LINE__, (reason)))                                 
                                                                            
#define GlobusXIOErrorParameter(param_name)                                 \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_ERROR_PARAMETER,                                     \
            "[%s:%d] Bad parameter, %s",                                    \
            _xio_name, __LINE__, (param_name)))                             
                                                                            
#define GlobusXIOErrorMemory(mem_name)                                      \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_ERROR_MEMORY,                                        \
            "[%s:%d] Memory allocation failed on %s",                       \
            _xio_name, __LINE__, (mem_name)))                               
                                                                            
#define GlobusXIOErrorSystemError(system_func, errno)                       \
    globus_error_put(                                                       \
        globus_error_wrap_errno_error(                                      \
            GLOBUS_XIO_MODULE,                                              \
            (errno),                                                        \
            GLOBUS_XIO_ERROR_SYSTEM_ERROR,                                  \
            "[%s:%d] System error in %s",                                   \
            _xio_name, __LINE__, (system_func)))                            
                                                                            
#define GlobusXIOErrorSystemResource(reason)                                \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_ERROR_SYSTEM_RESOURCE,                               \
            "[%s:%d] System resource error, %s",                            \
            _xio_name, __LINE__, (reason)))                                 
                                                                            
#define GlobusXIOErrorInvalidStack(reason)                                  \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_ERROR_STACK,                                         \
            "[%s:%d] Invalid stack, %s",                                    \
            _xio_name, __LINE__, (reason)))                                 
                                                                            
#define GlobusXIOErrorInvalidDriver(reason)                                 \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_ERROR_DRIVER,                                        \
            "[%s:%d] Invalid Driver, %s",                                   \
            _xio_name, __LINE__, (reason)))                                 
                                                                            
#define GlobusXIOErrorPass()                                                \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_ERROR_PASS,                                          \
            "[%s:%d] Operation passed too far",                             \
            _xio_name, __LINE__))                                           
                                                                            
#define GlobusXIOErrorAlreadyRegistered()                                   \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_ERROR_ALREADY_REGISTERED,                            \
            "[%s:%d] Operation already registered",                         \
            _xio_name, __LINE__))                                           
                                                                            
#define GlobusXIOErrorInvalidState(state)                                   \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_ERROR_STATE,                                         \
            "[%s:%d] Unexpected state, %d",                                 \
            _xio_name, __LINE__, (state)))                                  
                                                                            
#define GlobusXIOErrorWrapFailed(failed_func, result)                       \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GLOBUS_XIO_MODULE,                                              \
            globus_error_get((result)),                                     \
            GLOBUS_XIO_ERROR_WRAPPED,                                       \
            "[%s:%d] %s failed.",                                           \
            _xio_name, __LINE__, (failed_func)))                            
                                                                            
#define GlobusIXIOUtilTransferIovec(iovec, xiovec, iovc)                    \
    do                                                                      \
    {                                                                       \
        int                             _i;                                 \
        globus_xio_iovec_t *            _xiovec;                            \
        struct iovec *                  _iov;                               \
        int                             _iovc;                              \
                                                                            \
        _xiovec = (xiovec);                                                 \
        _iovec = (iovec);                                                   \
        _iovc = (iovc);                                                     \
                                                                            \
        for(_i = 0; _i < _iovc; _i++)                                       \
        {                                                                   \
            _iovec[_i].iov_base = _xiovec[_i].iov_base;                     \
            _iovec[_i].iov_len = _xiovec[_i].iov_len;                       \
        }                                                                   \
    } while(0)

#define GlobusIXIOUtilAdjustIovec(iov, iovc, nbytes)                        \
    do                                                                      \
    {                                                                       \
        globus_ssize_t                  _n;                                 \
        struct iovec *                  _iov;                               \
        int                             _iovc;                              \
        int                             _i;                                 \
                                                                            \
        _iov = (iov);                                                       \
        _iovc = (iovc);                                                     \
                                                                            \
        /* skip all completely filled iovecs */                             \
        for(_i = 0, _n = (nbytes);                                          \
            _i < _iovc &&  _n >= _iov[_i].iov_len;                          \
            _n -= _iov[_i].iov_len, _i++);                                  \
                                                                            \
        if(_i < _iovc)                                                      \
        {                                                                   \
            _iov[_i].iov_base = (char *) _iov[_i].iov_base + _n;            \
            _iov[_i].iov_len -= _n;                                         \
            (iov) += _i;                                                    \
        }                                                                   \
                                                                            \
        (iovc) -= _i;                                                       \
    } while(0)

#define GlobusIXIOUtilTransferAdjustedIovec(                                \
    new_iov, new_iovc, iov, iovc, nbytes)                                   \
    do                                                                      \
    {                                                                       \
        globus_ssize_t                  _n;                                 \
        struct iovec *                  _iov;                               \
        int                             _iovc;                              \
        struct iovec *                  _new_iov;                           \
        int                             _i;                                 \
        int                             _j;                                 \
                                                                            \
        _iov = (iov);                                                       \
        _iovc = (iovc);                                                     \
        _new_iov = (new_iov);                                               \
                                                                            \
        /* skip all completely filled iovecs */                             \
        for(_i = 0, _n = (nbytes);                                          \
            _i < _iovc &&  _n >= _iov[_i].iov_len;                          \
            _n -= _iov[_i].iov_len, _i++);                                  \
                                                                            \
        if(_i < _iovc)                                                      \
        {                                                                   \
            _new_iov[0].iov_base = (char *) _iov[_i].iov_base + _n;         \
            _new_iov[0].iov_len = _iov[_i].iov_len - _n;                    \
                                                                            \
            /* copy remaining */                                            \
            for(_j = 1, _i++; _i < _iovc; _j++, _i++)                       \
            {                                                               \
                _new_iov[_j].iov_base = _iov[_i].iov_base;                  \
                _new_iov[_j].iov_len = _iov[_i].iov_len;                    \
            }                                                               \
        }                                                                   \
                                                                            \
        (new_iovc) = _iovc - _i;                                            \
    } while(0)

#endif

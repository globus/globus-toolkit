#ifndef GLOBUS_XIO_TCP_DRIVER_INCLUDE
#define GLOBUS_XIO_TCP_DRIVER_INCLUDE

#include "globus_xio_system.h"

/**
 *  possible commands for attr cntl
 */

#define GLOBUS_XIO_TCP_INVALID_HANDLE GLOBUS_XIO_SYSTEM_INVALID_HANDLE

typedef enum
{
    GLOBUS_XIO_TCP_SET_MODE,
    GLOBUS_XIO_TCP_GET_MODE,
    GLOBUS_XIO_TCP_SET_FLAGS,
    GLOBUS_XIO_TCP_GET_FLAGS,
    GLOBUS_XIO_TCP_SET_HANDLE,
    GLOBUS_XIO_TCP_GET_HANDLE
} globus_xio_file_attr_cmd_t;

typedef enum
{
    GLOBUS_XIO_TCP_CREAT               = O_CREAT,
    GLOBUS_XIO_TCP_EXCL                = O_EXCL,
    GLOBUS_XIO_TCP_RDONLY              = O_RDONLY,
    GLOBUS_XIO_TCP_WRONLY              = O_WRONLY,
    GLOBUS_XIO_TCP_RDWR                = O_RDWR,
    GLOBUS_XIO_TCP_TRUNC               = O_TRUNC,
    GLOBUS_XIO_TCP_APPEND              = O_APPEND,
#ifdef TARGET_ARCH_CYGWIN
    GLOBUS_XIO_TCP_BINARY              = O_BINARY,
    GLOBUS_XIO_TCP_TEXT                = O_TEXT
#else
    GLOBUS_XIO_TCP_BINARY              = 0,
    GLOBUS_XIO_TCP_TEXT                = 0
#endif
} globus_xio_file_flag_t;

typedef enum
{
    GLOBUS_XIO_TCP_IRWXU               = S_IRWXU,
    GLOBUS_XIO_TCP_IRUSR               = S_IRUSR,
    GLOBUS_XIO_TCP_IWUSR               = S_IWUSR,
    GLOBUS_XIO_TCP_IXUSR               = S_IXUSR,
    GLOBUS_XIO_TCP_IRWXO               = S_IRWXO,
    GLOBUS_XIO_TCP_IROTH               = S_IROTH,
    GLOBUS_XIO_TCP_IWOTH               = S_IWOTH,
    GLOBUS_XIO_TCP_IXOTH               = S_IXOTH,
    GLOBUS_XIO_TCP_IRWXG               = S_IRWXG,
    GLOBUS_XIO_TCP_IRGRP               = S_IRGRP,
    GLOBUS_XIO_TCP_IWGRP               = S_IWGRP,
    GLOBUS_XIO_TCP_IXGRP               = S_IXGRP
} globus_xio_file_mode_t;

typedef enum
{
    GLOBUS_XIO_TCP_SEEK
} globus_xio_file_cntl_cmd_t;

typedef enum
{
    GLOBUS_XIO_SEEK_SET                 = SEEK_SET,
    GLOBUS_XIO_SEEK_CUR                 = SEEK_CUR,
    GLOBUS_XIO_SEEK_END                 = SEEK_END
} globus_xio_file_whence_t;

#endif

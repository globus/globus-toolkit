#ifndef GLOBUS_XIO_GRIDFTP_DRIVER_INCLUDE
#define GLOBUS_XIO_GRIDFTP_DRIVER_INCLUDE

#include "globus_xio_system.h"
#include "globus_common.h"

#define GLOBUS_XIO_GRIDFTP_OP_INFO_COUNT 8

typedef enum
{
    /*
     * handle cntls
     */		

    GLOBUS_XIO_GRIDFTP_SEEK,

    /*
     * attr cntls
     */

    GLOBUS_XIO_GRIDFTP_SET_HANDLE,

    GLOBUS_XIO_GRIDFTP_GET_HANDLE,

    GLOBUS_XIO_GRIDFTP_SET_PARTIAL_TRANSFER,

    GLOBUS_XIO_GRIDFTP_GET_PARTIAL_TRANSFER,

    GLOBUS_XIO_GRIDFTP_SET_NUM_STREAMS,

    GLOBUS_XIO_GRIDFTP_GET_NUM_STREAMS,

    GLOBUS_XIO_GRIDFTP_SET_TCP_BUFFER,

    GLOBUS_XIO_GRIDFTP_GET_TCP_BUFFER,

    GLOBUS_XIO_GRIDFTP_SET_TYPE,

    GLOBUS_XIO_GRIDFTP_GET_TYPE,

    GLOBUS_XIO_GRIDFTP_SET_MODE,
 
    GLOBUS_XIO_GRIDFTP_GET_MODE,

    GLOBUS_XIO_GRIDFTP_SET_AUTH,

    GLOBUS_XIO_GRIDFTP_GET_AUTH,

    GLOBUS_XIO_GRIDFTP_SET_DCAU,

    GLOBUS_XIO_GRIDFTP_GET_DCAU,

    GLOBUS_XIO_GRIDFTP_SET_DATA_PROTECTION,

    GLOBUS_XIO_GRIDFTP_GET_DATA_PROTECTION,

    GLOBUS_XIO_GRIDFTP_SET_CONTROL_PROTECTION,

    GLOBUS_XIO_GRIDFTP_GET_CONTROL_PROTECTION,

} globus_xio_gridftp_cmd_t;	


typedef enum globus_i_xio_gridftp_state_s
{

    GLOBUS_XIO_GRIDFTP_NONE,
    GLOBUS_XIO_GRIDFTP_OPEN,
    GLOBUS_XIO_GRIDFTP_IO_PENDING,
    GLOBUS_XIO_GRIDFTP_IO_DONE,
    GLOBUS_XIO_GRIDFTP_ABORT_PENDING,
    GLOBUS_XIO_GRIDFTP_ABORT_PENDING_IO_PENDING,
    GLOBUS_XIO_GRIDFTP_ABORT_PENDING_CLOSING,

} globus_i_xio_gridftp_state_t;

typedef enum globus_l_xio_gridftp_type_e
{
    GLOBUS_XIO_GRIDFTP_TYPE_NONE,
    GLOBUS_XIO_GRIDFTP_TYPE_ASCII = 'A',
    GLOBUS_XIO_GRIDFTP_TYPE_EBCDIC = 'E',
    GLOBUS_XIO_GRIDFTP_TYPE_IMAGE = 'I',
    GLOBUS_XIO_GRIDFTP_TYPE_LOCAL = 'L'
} globus_l_xio_gridftp_type_t;

typedef enum globus_l_xio_gridftp_mode_e
{
    GLOBUS_XIO_GRIDFTP_MODE_NONE,
    GLOBUS_XIO_GRIDFTP_MODE_STREAM = 'S',
    GLOBUS_XIO_GRIDFTP_MODE_BLOCK = 'B',
    GLOBUS_XIO_GRIDFTP_MODE_EXTENDED_BLOCK = 'E',
    GLOBUS_XIO_GRIDFTP_MODE_COMPRESSED = 'C'
} globus_l_xio_gridftp_mode_t;

typedef enum globus_l_xio_gridftp_dcau_mode_e
{
    GLOBUS_XIO_GRIDFTP_DCAU_NONE = 'N',
    GLOBUS_XIO_GRIDFTP_DCAU_SELF = 'A',
    GLOBUS_XIO_GRIDFTP_DCAU_SUBJECT = 'S',
    GLOBUS_XIO_GRIDFTP_DCAU_DEFAULT
} globus_l_xio_gridftp_dcau_mode_t;


typedef enum globus_l_xio_gridftp_protection_e
{
    GLOBUS_XIO_GRIDFTP_PROTECTION_CLEAR = 'C',
    GLOBUS_XIO_GRIDFTP_PROTECTION_SAFE = 'S',
    GLOBUS_XIO_GRIDFTP_PROTECTION_CONFIDENTIAL = 'E',
    GLOBUS_XIO_GRIDFTP_PROTECTION_PRIVATE = 'P'
} globus_l_xio_gridftp_protection_t;


#define GlobusXIOGridftpHandleError()                                       \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(gridftp),                                     \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GRIDFTP_HANDLE_ERROR,                                \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Handle creation error"))

#define GlobusXIOGridftpOpenError(str)                                      \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(gridftp),                                     \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GRIDFTP_OPEN_ERROR,                                  \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Open error: %s",                                               \
            str))

#define GlobusXIOGridftpIOError(str) 	                                    \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(gridftp),                                     \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GRIDFTP_IO_ERROR, 	                            \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "IO error: %s",						    \
	    str))

#define GlobusXIOGridftpSeekError()                                         \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(gridftp),                                     \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GRIDFTP_SEEK_ERROR,                                  \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Seek error: operation is outstanding"))

#define GlobusXIOGridftpOutstandingReadError()                              \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(gridftp),                                     \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GRIDFTP_OUTSTANDING_READ_ERROR,                      \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Read is outstanding"))

#define GlobusXIOGridftpOutstandingWriteError()                             \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(gridftp),                                     \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GRIDFTP_OUTSTANDING_WRITE_ERROR,                     \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Write is outstanding"))

#define GlobusXIOGridftpPendingReadError()                                  \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(gridftp),                                     \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GRIDFTP_PENDING_READ_ERROR,                          \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Read pending"))

#define GlobusXIOGridftpPendingWriteError()                                 \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(gridftp),                                     \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GRIDFTP_PENDING_WRITE_ERROR,                         \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "Write pending"))

#define GlobusXIOGridftpOutstandingPartialXferError()                       \
    globus_error_put(                                                       \
        globus_error_construct_error(                                       \
            GlobusXIOMyModule(gridftp),                                     \
            GLOBUS_NULL,                                                    \
            GLOBUS_XIO_GRIDFTP_OUTSTANDING_PARTIAL_XFER_ERROR,              \
            __FILE__,                                                       \
            _xio_name,                                                      \
            __LINE__,                                                       \
            "A Partial Xfer is outstanding"))

enum
{

    GLOBUS_XIO_GRIDFTP_HANDLE_ERROR, 
    GLOBUS_XIO_GRIDFTP_OPEN_ERROR, 
    GLOBUS_XIO_GRIDFTP_IO_ERROR, 
    GLOBUS_XIO_GRIDFTP_SEEK_ERROR,                                  
    GLOBUS_XIO_GRIDFTP_OUTSTANDING_READ_ERROR,                      
    GLOBUS_XIO_GRIDFTP_OUTSTANDING_WRITE_ERROR,
    GLOBUS_XIO_GRIDFTP_PENDING_READ_ERROR,                      
    GLOBUS_XIO_GRIDFTP_PENDING_WRITE_ERROR,
    GLOBUS_XIO_GRIDFTP_OUTSTANDING_PARTIAL_XFER_ERROR

};

#endif

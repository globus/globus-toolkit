#if !defined GLOBUS_XIO_TEST_TRANSPORT_H
#define GLOBUS_XIO_TEST_TRANSPORT_H 1

#include "globus_common.h"

#define GlobusXIOErrorTestError(location)                               \
    globus_error_put(                                                   \
        globus_error_construct_error(                                   \
            GLOBUS_XIO_TEST_TRANSPORT_DRIVER_MODULE,                    \
            NULL,                                                       \
            location,                                                   \
            __FILE__,                                                   \
            _xio_name,                                                  \
            __LINE__,                                                   \
            "I am soooo lazy"))


typedef enum globus_xio_test_failure_e
{
    GLOBUS_XIO_TEST_FAIL_NONE,
    GLOBUS_XIO_TEST_FAIL_PASS_OPEN,
    GLOBUS_XIO_TEST_FAIL_FINISH_OPEN,
    GLOBUS_XIO_TEST_FAIL_PASS_CLOSE,
    GLOBUS_XIO_TEST_FAIL_FINISH_CLOSE,
    GLOBUS_XIO_TEST_FAIL_PASS_READ,
    GLOBUS_XIO_TEST_FAIL_FINISH_READ,
    GLOBUS_XIO_TEST_FAIL_PASS_WRITE,
    GLOBUS_XIO_TEST_FAIL_FINISH_WRITE,
    GLOBUS_XIO_TEST_FAIL_PASS_ACCEPT,
    GLOBUS_XIO_TEST_FAIL_FINISH_ACCEPT
} globus_xio_test_failure_t;

enum
{
    GLOBUS_XIO_TEST_SET_INLINE,
    GLOBUS_XIO_TEST_SET_FAILURES,
    GLOBUS_XIO_TEST_SET_USECS,
    GLOBUS_XIO_TEST_READ_EOF_BYTES,
    GLOBUS_XIO_TEST_CHUNK_SIZE,
    GLOBUS_XIO_TEST_RANDOM
};

globus_module_descriptor_t              globus_i_xio_test_module;
#define GLOBUS_XIO_TEST_TRANSPORT_DRIVER_MODULE &globus_i_xio_test_module

#endif

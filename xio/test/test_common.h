#if !defined(TEST_COMMON_H)
#define TEST_COMMON_H 1

#include "globus_xio.h"
#include "test_common.h"
#include "globus_common.h"
#include "globus_xio_test_transport.h"

typedef struct test_info_s
{
    int                                     write_count;
    int                                     read_count;

    /* always points to nothing */
    globus_byte_t *                         buffer;
    globus_size_t                           buffer_length;
    globus_size_t                           chunk_size;

    globus_size_t                           nwritten;
    globus_size_t                           nread;
    globus_size_t                           total_write_bytes;
    globus_size_t                           total_read_bytes;

    int                                     failure;
    int                                     closed;
    globus_bool_t                           write_done;
    globus_bool_t                           read_done;

    globus_bool_t                           server;

    globus_mutex_t                          mutex;
} test_info_t;

extern test_info_t                         globus_l_test_info;

void
failed_exit(
    char *                                  fmt,
    ...);
void
test_res(
    int                                     location,
    globus_result_t                         res,
    int                                     line);

void
parse_parameters(
    int                                     argc,
    char **                                 argv,
    globus_xio_driver_t                     driver,
    globus_xio_attr_t                       attr);


#endif

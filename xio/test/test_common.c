#include "test_common.h"
#include "globus_common.h"

static int                                  globus_l_argc;
static char **                              globus_l_argv;
test_info_t                                 globus_l_test_info;


void
failed_exit(
    char *                                  fmt,
    ...)
{   
    va_list                                 ap;
    
#   ifdef HAVE_STDARG_H
    {
        va_start(ap, fmt);
    }
#   else
    {
        va_start(ap);
    }
#   endif

    fprintf(stderr, "ERROR: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");

    va_end(ap);

    globus_assert(0);
}
    
void
test_res(
    int                                     location,
    globus_result_t                         res,
    int                                     line)
{
    if(res != GLOBUS_SUCCESS)
    {
#if 0
/** need to create error match wrapper that uses driver name instead of module name... i will add this when i get back
**/
        if(location != GLOBUS_XIO_TEST_FAIL_NONE &&
            globus_error_match(
                globus_error_peek(res),
                GLOBUS_XIO_TEST_TRANSPORT_DRIVER_MODULE,
                location))
        {
            fprintf(stdout, "Success: failed in the correct spot.\n");
            exit(0);
        }
#endif

        failed_exit("error at line %d.", line);
    }
    else if(location == globus_l_test_info.failure &&
            location != GLOBUS_XIO_TEST_FAIL_NONE)
    {
        failed_exit("Should have failed at point %d on line %d.", 
            location, line);
    }
}

void
parse_parameters(
    int                                     argc,
    char **                                 argv,
    globus_xio_driver_t                     driver,
    globus_xio_attr_t                       attr)
{   
    int                                     failure = 
                                    GLOBUS_XIO_TEST_FAIL_NONE;
    globus_bool_t                           inline_finish = GLOBUS_FALSE;
    globus_result_t                         res;
    int                                     chunk_size = -1;
    int                                     delay = 1000;
    int                                     eof_bytes = -1;
    char                                    c;
    globus_size_t                           buffer_length = 2048;
    int                                     read_count = 0; 
    int                                     write_count = 0;
    int                                     total_write_bytes = 2048 * 10;
    int                                     total_read_bytes = 2048 * 10;
    
    globus_l_argc = argc;
    globus_l_argv = argv;
    
    /* parse the parameters */
    globus_l_test_info.server = GLOBUS_FALSE;
    while((c = getopt(argc, argv, "siF:d:c:R:W:r:w:b:")) != -1)
    {
        switch(c)
        {
            case 'F':
                failure = atoi(optarg);
                break;

            case 'i':
                inline_finish = GLOBUS_TRUE;
                break;

            case 'd':
                delay = atoi(optarg);
                break;

            case 'c':
                chunk_size = atoi(optarg);
                break;

            case 's':
                globus_l_test_info.server = GLOBUS_TRUE;
                break;

            case 'b':
                buffer_length = atoi(optarg);
                break;

            case 'r':
                read_count = atoi(optarg);
                break;

            case 'w':
                write_count = atoi(optarg);
                break;

            case 'R':
                total_read_bytes = atoi(optarg);
                break;

            case 'W':
                total_write_bytes = atoi(optarg);
                break;

            default:
                break;
        }
    }

    globus_l_test_info.failure = failure;
    globus_l_test_info.write_count = write_count;
    globus_l_test_info.read_count = read_count;
    globus_l_test_info.buffer = (void *)0x10;
    globus_l_test_info.buffer_length = buffer_length;
    globus_l_test_info.chunk_size = chunk_size;
    globus_mutex_init(&globus_l_test_info.mutex, NULL);

    globus_l_test_info.nwritten = 0;
    globus_l_test_info.nread = 0;
    globus_l_test_info.total_write_bytes = total_write_bytes;
    globus_l_test_info.total_read_bytes = total_read_bytes;
    globus_l_test_info.closed = 0;
    globus_l_test_info.write_done = GLOBUS_FALSE;
    globus_l_test_info.read_done = GLOBUS_FALSE;


    /* set up the attr */
    res = globus_xio_attr_cntl(
            attr,
            driver,
            GLOBUS_XIO_TEST_SET_INLINE,
            inline_finish);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_attr_cntl(
            attr,
            driver,
            GLOBUS_XIO_TEST_SET_FAILURES,
            failure);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_attr_cntl(
            attr,
            driver,
            GLOBUS_XIO_TEST_SET_USECS,
            delay);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_attr_cntl(
            attr,
            driver,
            GLOBUS_XIO_TEST_CHUNK_SIZE,
            chunk_size);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_attr_cntl(
            attr,
            driver,
            GLOBUS_XIO_TEST_READ_EOF_BYTES,
            eof_bytes);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
}


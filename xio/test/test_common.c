#include "test_common.h"
#include "globus_common.h"

typedef  int
(*main_func_t)(
    int                                     argc,
    char **                                 argv);

static int                                  globus_l_argc;
static char **                              globus_l_argv;
static char *                               globus_l_program_name;
test_info_t                                 globus_l_test_info;

static globus_hashtable_t                   globus_l_test_hash;

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
        if(location != GLOBUS_XIO_TEST_FAIL_NONE &&
            globus_error_match(
                globus_error_peek(res),
                GLOBUS_XIO_TEST_TRANSPORT_DRIVER_MODULE,
                location))
        {
            fprintf(stdout, "Success: failed in the correct spot.\n");
            exit(0);
        }

        failed_exit("error at line %d.", line);
    }
    else if(location == globus_l_test_info.failure &&
            location != GLOBUS_XIO_TEST_FAIL_NONE)
    {
        failed_exit("Should have failed at point %d on line %d.", 
            location, line);
    }
}

int
parse_parameters(
    int                                     argc,
    char **                                 argv,
    globus_xio_stack_t                      stack,
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
    globus_xio_driver_t                     driver;
    globus_xio_driver_t                     base_driver;
    int                                     seed = 0;

    globus_l_argc = argc;
    globus_l_argv = argv;

    /* get the transport driver, and put it on the stack */
    res = globus_xio_driver_load("test", &base_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    res = globus_xio_stack_push_driver(stack, base_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    
    /* parse the parameters */
    globus_l_test_info.server = GLOBUS_FALSE;
    while((c = getopt(argc, argv, "siF:d:c:R:W:r:w:b:D:X:")) != -1)
    {
        switch(c)
        {
            case 'F':
                failure = atoi(optarg);
                break;

            case 'D':
                res = globus_xio_driver_load(optarg, &driver);
                test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
                res = globus_xio_stack_push_driver(stack, driver);
                test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
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

            case 'X':
                seed = atoi(optarg);
                break;

            default:
                break;
        }
    }

    globus_l_test_info.failure = failure;
    globus_l_test_info.write_count = write_count;
    globus_l_test_info.read_count = read_count;
    globus_l_test_info.buffer = globus_malloc(buffer_length);
    globus_l_test_info.buffer_length = buffer_length;
    globus_l_test_info.chunk_size = chunk_size;
    globus_mutex_init(&globus_l_test_info.mutex, NULL);

    GlobusTimeReltimeSet(globus_l_test_info.delay, 0, delay);

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
            base_driver,
            GLOBUS_XIO_TEST_SET_INLINE,
            inline_finish);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_attr_cntl(
            attr,
            base_driver,
            GLOBUS_XIO_TEST_SET_FAILURES,
            failure);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_attr_cntl(
            attr,
            base_driver,
            GLOBUS_XIO_TEST_SET_USECS,
            delay);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_attr_cntl(
            attr,
            base_driver,
            GLOBUS_XIO_TEST_CHUNK_SIZE,
            chunk_size);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    res = globus_xio_attr_cntl(
            attr,
            base_driver,
            GLOBUS_XIO_TEST_READ_EOF_BYTES,
            eof_bytes);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);

    if(seed != 0)
    {
        res = globus_xio_attr_cntl(
                attr,
                base_driver,
                GLOBUS_XIO_TEST_RANDOM,
                eof_bytes);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__);
    }

    return optind;
}

int
call_test(
    int                                         argc,
    char **                                     argv)
{
    main_func_t                                 main_func;
    int                                         rc;

    main_func = (main_func_t) globus_hashtable_lookup(
                                &globus_l_test_hash,
                                argv[0]);
    if(main_func == NULL)
    {
        fprintf(stderr, "%s test not found.\n", argv[0]);
        return 1;
    }

    rc = main_func(argc, argv);

    return rc;
}

int
main(
    int                                         argc,
    char **                                     argv)
{
    int                                         ctr;
    int                                         rc = 0;
    globus_bool_t                               done = GLOBUS_FALSE;
    globus_bool_t                               activate = GLOBUS_TRUE;
    globus_bool_t                               file = GLOBUS_FALSE;
    char *                                      name = NULL;

    globus_l_program_name = argv[0];

    /* add all the known tests to hash table */
    globus_hashtable_init(
        &globus_l_test_hash, 
        16,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
    globus_hashtable_insert(
        &globus_l_test_hash, 
        "read_barrier",
        read_barrier_main);
    globus_hashtable_insert(
        &globus_l_test_hash, 
        "close_barrier",
        close_barrier_main);
    globus_hashtable_insert(
        &globus_l_test_hash, 
        "framework",
        framework_main);
    globus_hashtable_insert(
        &globus_l_test_hash, 
        "timeout",
        timeout_main);

    for(ctr = 1; ctr < argc && !done; ctr++)
    {
        if(strcmp(argv[ctr], "-A") == 0)
        {
            activate = GLOBUS_FALSE;
        }
        else if (strcmp(argv[ctr], "-D") == 0)
        {
            file = GLOBUS_TRUE;
        }
        else
        {
            done = GLOBUS_TRUE;
            ctr--;
        }
    }

    argv += ctr;
    argc -= ctr;

    if(argc < 1)
    {
        fprintf(stderr, 
            "%s: [-A -D] <test name | file name> [test options]\n", 
            globus_l_program_name);
        return 1;
    }

    /* actiavte now to prevent xio from getting actiavted and deactivated
        in every test */
    if(activate)
    {
        rc = globus_module_activate(GLOBUS_XIO_MODULE);
        globus_assert(rc == GLOBUS_SUCCESS);
    }
    name = argv[argc];
    if(file)
    {
        /* TODO: call function that opens file and walks through
            all the tests in that file */
    }
    else
    {
        rc = call_test(argc, argv);
    }

    if(activate)
    {
        globus_module_deactivate(GLOBUS_XIO_MODULE);
    }

    globus_hashtable_destroy(&globus_l_test_hash);

    return rc;
}

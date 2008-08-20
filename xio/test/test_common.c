/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "globus_common.h"
#include "globus_hashtable.h"
#include "globus_xio_bounce.h"
#include "globus_xio_op.h"
#include "globus_xio_null.h"
#include "globus_xio_null_pass.h"
#include "globus_xio_debug.h"
#include "globus_xio_stack_driver.h"
#include "globus_xio_verify.h"
#include "test_common.h"

typedef  int
(*main_func_t)(
    int                                     argc,
    char **                                 argv);

static globus_list_t *                      globus_l_driver_list = NULL;
static int                                  globus_l_argc;
static char **                              globus_l_argv;
static char *                               globus_l_program_name;
test_info_t                                 globus_l_test_info;

static globus_hashtable_t                   globus_l_test_hash;
static int                                  globus_l_test_count = 0;

static globus_xio_driver_t                  globus_l_base_driver;

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

    abort();
}
    
void
test_res(
    int                                     location,
    globus_result_t                         res,
    int                                     line,
    char *                                  file)
{
    if(res != GLOBUS_SUCCESS)
    {
        /* XXX this sort of bumbs */
        if(location != GLOBUS_XIO_TEST_FAIL_NONE &&
            globus_xio_driver_error_match(
                globus_l_base_driver,
                globus_error_peek(res),
                location))
        {
            fprintf(stdout, "Success: failed in the correct spot.\n");
            exit(0);
        }

        failed_exit("error :%s: at %s:%d.", 
            globus_object_printable_to_string(globus_error_get(res)), 
            file, line);
    }
    else if(location == globus_l_test_info.failure &&
            location != GLOBUS_XIO_TEST_FAIL_NONE)
    {
        failed_exit("Should have failed at point %d on line %s:%d.", 
            location, file, line);
    }
}

void
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
    int                                     delay = 0;
    int                                     eof_bytes = -1;
    char                                    c;
    globus_size_t                           buffer_length = 2048;
    int                                     read_count = 0; 
    int                                     write_count = 0;
    int                                     total_write_bytes = 2048 * 10;
    int                                     total_read_bytes = 2048 * 10;
    globus_xio_driver_t                     driver;
    int                                     seed = 0;

    globus_l_argc = argc;
    globus_l_argv = argv;

    /* get the transport driver, and put it on the stack */
    res = globus_xio_driver_load("test", &globus_l_base_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    res = globus_xio_stack_push_driver(stack, globus_l_base_driver);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    globus_list_insert(&globus_l_driver_list, globus_l_base_driver);

    /* parse the parameters */
    globus_l_test_info.server = GLOBUS_FALSE;
    while((c = (char)getopt(argc, argv, "siF:d:c:R:W:r:w:b:D:X:")) != (char)EOF)
    {
        switch(c)
        {
            case 'F':
                failure = atoi(optarg);
                break;

            case 'D':
                res = globus_xio_driver_load(optarg, &driver);
                test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
                res = globus_xio_stack_push_driver(stack, driver);
                test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    
                globus_list_insert(&globus_l_driver_list, driver);
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
            globus_l_base_driver,
            GLOBUS_XIO_TEST_SET_INLINE,
            inline_finish);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_attr_cntl(
            attr,
            globus_l_base_driver,
            GLOBUS_XIO_TEST_SET_FAILURES,
            failure);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_attr_cntl(
            attr,
            globus_l_base_driver,
            GLOBUS_XIO_TEST_SET_USECS,
            delay);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_attr_cntl(
            attr,
            globus_l_base_driver,
            GLOBUS_XIO_TEST_CHUNK_SIZE,
            chunk_size);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    res = globus_xio_attr_cntl(
            attr,
            globus_l_base_driver,
            GLOBUS_XIO_TEST_READ_EOF_BYTES,
            eof_bytes);
    test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);

    if(seed != 0)
    {
        res = globus_xio_attr_cntl(
                attr,
                globus_l_base_driver,
                GLOBUS_XIO_TEST_RANDOM,
                seed);
        test_res(GLOBUS_XIO_TEST_FAIL_NONE, res, __LINE__, __FILE__);
    }
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
    globus_l_test_count++;

    return rc;
}


void
test_common_end()
{
    while(!globus_list_empty(globus_l_driver_list))
    {
        globus_xio_driver_t                         tmp_driver;

        tmp_driver = (globus_xio_driver_t)
            globus_list_remove(&globus_l_driver_list, globus_l_driver_list);

        globus_xio_driver_unload(tmp_driver);
    }

    globus_free(globus_l_test_info.buffer);
}

int
make_argv(
    char *                                      line, 
    char ***                                    out_argv)
{
    globus_list_t *                             list = NULL;
    char *                                      tmp_ptr;
    char **                                     argv;
    int                                         size;
    int                                         ctr;

    tmp_ptr = strtok(line, " ");
    while(tmp_ptr != NULL)
    {
        if(strcmp("\n", tmp_ptr) != 0)
        {
            globus_list_insert(&list, strdup(tmp_ptr));
        }        
        tmp_ptr = strtok(NULL, " ");
    }

    size = globus_list_size(list);
    argv = (char **) globus_malloc((size + 1) * sizeof(char *));

    argv[size] = NULL;
    ctr = size - 1;
    while(!globus_list_empty(list))
    {
        argv[ctr] = (char *) globus_list_remove(&list, list);
        ctr--;
    } 

    *out_argv = argv;

    return size;
}

int
main(
    int                                         argc,
    char **                                     argv)
{
    int                                         ctr;
    int                                         rc = 0;
    globus_bool_t                               done = GLOBUS_FALSE;
    globus_bool_t                               file = GLOBUS_FALSE;
    char *                                      name = NULL;
    globus_result_t                             res;

    globus_l_program_name = argv[0];

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_assert(rc == 0);
    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);
    rc = globus_extension_activate("globus_xio_test_drivers");
    globus_assert(rc == 0 && "couldnt load drivers");


    /* lame parameter checking */
    res = globus_xio_open(NULL, NULL, NULL);

    if(!globus_xio_error_match(res, GLOBUS_XIO_ERROR_PARAMETER))
    {
        globus_assert(0 && "parameter test failed");
    }

    /* add all the known tests to hash table */
    rc = globus_hashtable_init(
        &globus_l_test_hash, 
        16,
        globus_hashtable_string_hash,
        globus_hashtable_string_keyeq);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "read_barrier",
        read_barrier_main);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "close_barrier",
        close_barrier_main);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "close2_barrier",
        close_barrier2_main);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "framework",
        framework_main);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "timeout",
        timeout_main);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "cancel",
        cancel_main);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "attr",
        attr_main);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "close_cancel",
        close_cancel_main);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "space",
        space_main);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "server2",
        server2_main);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "block_barrier",
        block_barrier_main);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "blocking_dd",
        blocking_dd_main);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "unload",
        unload_main);
    globus_assert(rc == 0);
    rc = globus_hashtable_insert(
        &globus_l_test_hash, 
        "stack",
        stack_main);
    globus_assert(rc == 0);


    for(ctr = 1; ctr < argc && !done; ctr++)
    {
        if (strcmp(argv[ctr], "-D") == 0)
        {
            file = GLOBUS_TRUE;
        }
        else
        {
            done = GLOBUS_TRUE;
            name = argv[ctr];
        }
    }

    if(name == NULL)
    {
        fprintf(stderr, 
            "%s: [-A -D] <test name | file name> [test options]\n", 
            globus_l_program_name);
        return 1;
    }

    if(file)
    {
        FILE *                          in;
        char                            line[512];
        int                             cnt;
        char **                         out_argv;

        in = fopen(name, "r");
        globus_assert(in != NULL);

        while(fgets(line, 512, in) != NULL && rc == 0)
        {
            if(line[strlen(line) - 1] == '\n')
            {
                line[strlen(line) - 1] = '\0';
            }
            cnt = make_argv(line, &out_argv);
            rc = call_test(cnt, out_argv);

            for(ctr = 0; ctr < cnt; ctr++)
            {
                globus_free(out_argv[ctr]);
            }
            globus_free(out_argv);
        }
    }
    else
    {
        argv++;
        argc--;
        rc = call_test(argc, argv);
    }

    globus_hashtable_destroy(&globus_l_test_hash);

    globus_extension_deactivate("globus_xio_test_drivers");
    globus_module_deactivate_all();

    return rc;
}

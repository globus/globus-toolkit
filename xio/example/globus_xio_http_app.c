#include "globus_xio.h"
#include "globus_xio_http.h"

#define SIZE 4096
#define LINE_LEN 256

void
test_res(
         globus_result_t                         res)
{
    if(res == GLOBUS_SUCCESS)
        {
            return;
        }

    fprintf(stderr, "ERROR: %s\n", globus_error_print_chain(
                                                            globus_error_peek(res)));

    globus_assert(0);
}


void
help()
{
    fprintf(stdout,
            "globus-xio-http-app [options]\n"
            "options:\n"
            "-c <contact_string> : use this contact string (required for client)\n"
            "-s : be a server\n");
}


int
main(
     int                                     argc,
     char **                                 argv)
{
    globus_xio_driver_t                     http_driver;
    globus_xio_driver_t                     tcp_driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    globus_xio_server_t			    server;
    globus_xio_target_t                     target;
    globus_xio_attr_t                       attr = NULL;
    char *                                  cs = (char*)globus_malloc(512);
    globus_result_t                         res;
    int                                     ctr;
    globus_bool_t                           be_server = GLOBUS_FALSE;
    globus_hashtable_t*			    hashtable = (globus_hashtable_t*) globus_malloc(sizeof(globus_hashtable_t));
    int                                     rc;
    FILE*				    fp;
    char				    buffer[SIZE];
    char*				    uri = (char*)globus_malloc(sizeof(char)*LINE_LEN); 
    int					    nbytes;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    globus_hashtable_init(hashtable,
                          16,  /*XXX how to decide this size? */
                          globus_hashtable_string_hash,
                          globus_hashtable_string_keyeq);

    res = globus_xio_driver_load("http", &http_driver);
    test_res(res);
    res = globus_xio_driver_load("tcp", &tcp_driver);
    test_res(res);
    res = globus_xio_stack_init(&stack, NULL);
    test_res(res);
    res = globus_xio_stack_push_driver(stack, tcp_driver);
    test_res(res);
    res = globus_xio_stack_push_driver(stack, http_driver);
    test_res(res); 

    for(ctr = 1; ctr < argc; ctr++)
        {
            if(strcmp(argv[ctr], "-h") == 0)
                {
                    help();
                    return 0;
                }
            else if(strcmp(argv[ctr], "-c") == 0 && ctr + 1 < argc)
                {
                    strcpy(cs, argv[ctr + 1]);
                    ctr++;
                }
            else if(strcmp(argv[ctr], "-s") == 0)
                {
                    be_server = GLOBUS_TRUE;
                }
        }
    
    if(!be_server && !*cs)
        {
            help();
            exit(1);
        }
     
    if (be_server)
        {
            res = globus_xio_server_create(&server, attr, stack);
            test_res(res);
            res = globus_xio_server_accept(&target, server, attr);
            test_res(res);
            res = globus_xio_stack_destroy(stack);
            test_res(res);
            res = globus_xio_open(&xio_handle, attr, target);
            test_res(res);
            res = globus_xio_handle_cntl(
                                         xio_handle,
                                         http_driver,
                                         GLOBUS_XIO_HTTP_GET_CONTACT,
                                         cs);
            test_res(res);
            fprintf(stdout, "contact: %s\n", cs);
            globus_free(cs);
            res = globus_xio_handle_cntl(
                                         xio_handle,
                                         http_driver,
                                         GLOBUS_XIO_HTTP_GET_HEADERS,
                                         hashtable);
            test_res(res); 
            uri = (char*)globus_hashtable_lookup(hashtable, "Content-Length");
            printf("length: %s\n", uri);

            nbytes = SIZE;
            res = globus_xio_read(
                                  xio_handle,
                                  buffer,
                                  sizeof(buffer),
                                  0,
                                  &nbytes,
                                  NULL);

            printf("%s", buffer);
            fp = fopen("/home/wellner/usenet.sig", "r");
            res = globus_xio_handle_cntl(
                                         xio_handle,
                                         http_driver,
                                         GLOBUS_XIO_HTTP_SET_EXIT_CODE,
                                         "100");
            res = globus_xio_handle_cntl(
                                         xio_handle,
                                         http_driver,
                                         GLOBUS_XIO_HTTP_SET_EXIT_TEXT,
                                         "Much Love");
            res = globus_xio_handle_cntl(
                                         xio_handle,
                                         http_driver,
                                         GLOBUS_XIO_HTTP_SET_HEADERS,
                                         "Content: bob\r\n");

            while (!feof(fp))
                {
                    fgets(buffer, sizeof(buffer), fp);
                    nbytes = strlen(buffer);
                    printf("app: %s\n", buffer);
                    res = globus_xio_write(
                                           xio_handle,
                                           buffer,
                                           nbytes,
                                           nbytes,
                                           &nbytes,
                                           NULL);
                    test_res(res);
                }
            fclose(fp);
        }
    else
        {
            res = globus_xio_target_init(&target, NULL, cs, stack);
            test_res(res);
            res = globus_xio_stack_destroy(stack);
            test_res(res);
            res = globus_xio_open(&xio_handle, attr, target);
            test_res(res);
            res = globus_xio_read(
                                  xio_handle,
                                  buffer,
                                  sizeof(buffer),
                                  nbytes,
                                  &nbytes,
                                  NULL);
            test_res(res);
            fp = fopen("out", "w");
            fputs(buffer, fp);
        }
    
    res = globus_xio_close(xio_handle, NULL);
    test_res(res);

    res = globus_xio_driver_unload(http_driver);
    test_res(res);
    res = globus_xio_driver_unload(tcp_driver);
    test_res(res);

    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    return 0;
}

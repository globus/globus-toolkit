#include <stdio.h>
#include "globus_xio.h"

#define LINE_LEN 1024

void
test_res(
    globus_result_t                         res,
    int                                     line)
{
    if(res == GLOBUS_SUCCESS)
    {
        return;
    }

    fprintf(stderr, "ERROR on line %d: %s\n", line, globus_error_print_friendly(
        globus_error_get(res)));

    globus_assert(0);
}

int
main(
    int                                 argc, 
    char **                             argv)
{
    unsigned char                       buffer[LINE_LEN];
    globus_size_t                       nbytes;
    globus_result_t                     res;
    globus_xio_attr_t                   attr;
    char *                              opts = NULL;

    if(argc < 2)
    {
        fprintf(stderr, "usage: %s url\n", argv[0]);
        return -1;
    }
    if(argc > 2)
    {
        opts = argv[2];
    }
    globus_module_activate(GLOBUS_XIO_MODULE);

    globus_xio_attr_init(&attr);
    globus_xio_handle_t             myhandle;

    res = globus_xio_handle_create_from_url(
        &myhandle,
        argv[1],
        attr,
        opts);
    test_res(res, __LINE__);

    res = globus_xio_open(myhandle, argv[1], attr);
    test_res(res, __LINE__);
    while(res == GLOBUS_SUCCESS)
    {
        res = globus_xio_read(myhandle, buffer, LINE_LEN, 1, &nbytes, NULL);
        buffer[nbytes] = '\0';
        printf("%s", buffer);
    }
    if(!globus_xio_error_is_eof(res))
    {
        printf("Error before EOF\n");
        test_res(res, __LINE__);
    }
    globus_xio_close(myhandle, NULL);
    globus_xio_attr_destroy(attr);

    globus_module_deactivate(GLOBUS_XIO_MODULE);

    return 0;
}

#include "globus_xio.h"
#include "globus_xio_util.h"
#include "globus_xio_gridftp_driver.h"

#define CHUNK_SIZE 5000
#define FILE_NAME_LEN 25

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
        "globus-xio-gridftp [options]\n"
        "-----------------\n"
	"specify -c <contact string> to communicate with the server"
	"\n"
	"-f : file name"
	"\n"
        "use -r to read the file from server"
        "\n"
        "-w to write the file to server"
        "\n");
}

int
main(
    int                                     argc,
    char **                                 argv)
{
    globus_xio_driver_t                     gridftp_driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    globus_xio_attr_t                       attr = NULL;
    char *                                  cs = NULL;
    globus_result_t                         res;
    int                                     ctr;
    globus_bool_t                           read = GLOBUS_FALSE;
    int                                     rc;
    char				    filename[FILE_NAME_LEN];
    FILE *				    fp;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    res = globus_xio_driver_load("gridftp", &gridftp_driver);
    test_res(res);
    res = globus_xio_stack_init(&stack, NULL);
    test_res(res);
    res = globus_xio_stack_push_driver(stack, gridftp_driver);
    test_res(res);

    if (argc < 3)
    {
        help();
        exit(1);
    }
    for(ctr = 1; ctr < argc; ctr++)
    {
        if(strcmp(argv[ctr], "-h") == 0)
        {
            help();
            return 0;
        }
        if(strcmp(argv[ctr], "-c") == 0)
        {
	    if (ctr + 1 < argc)
	    {
		cs = argv[ctr + 1];
		ctr++;
	    }
	    else	
	    {
		help();
		exit(1);
	    }
        }
	else if(strcmp(argv[ctr], "-f") == 0)
	{
	    if (ctr + 1 < argc)
	    {
	        strcpy(filename, argv[ctr + 1]);
		ctr++;
	    }
	    else	
	    {
		help();
		exit(1);
	    }
	}
	else if(strcmp(argv[ctr], "-r") == 0)
	{
	    read = GLOBUS_TRUE;
	}	
	else if(strcmp(argv[ctr], "-w") == 0)
	{
	    read = GLOBUS_FALSE;
	}
	else
	{
	    help();
	    exit(1);
	}	
    }
    
  
    res = globus_xio_handle_create(&xio_handle, stack);
    test_res(res);
    res = globus_xio_stack_destroy(stack);
    test_res(res);
    res = globus_xio_attr_init(&attr);
    test_res(res);
    res = globus_xio_open(xio_handle, cs, attr);
    test_res(res);

    if(!read)
    {
        char                            buffer[CHUNK_SIZE + 1];
        int                             nbytes;
	int i, x;
        fp = fopen(filename, "r");
        while(!feof(fp))
	{
 	    for (i = 0; i< CHUNK_SIZE + 1; i++)
                buffer[i] = '\0';
	    x = fread(buffer, CHUNK_SIZE, 1, fp);
            nbytes = strlen(buffer);
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
        char                            buffer[CHUNK_SIZE];
        int	                        nbytes;
        int				i;
 	fp = fopen(filename, "w");
        while(1)
        {
            for (i=0; i<CHUNK_SIZE; i++)
		buffer[i] = '\0';
            res = globus_xio_read(
                xio_handle,
                buffer,
                sizeof(buffer),
                sizeof(buffer),
                &nbytes,
                NULL);
            fputs(buffer, fp);
	    if (res != GLOBUS_SUCCESS)
		break;
	}
        fclose(fp);
    }

    res = globus_xio_close(xio_handle, NULL);
    test_res(res);

    res = globus_xio_driver_unload(gridftp_driver);
    test_res(res);
 
    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    return 0;
}

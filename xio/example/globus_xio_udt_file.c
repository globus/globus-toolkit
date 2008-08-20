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

#include "globus_xio.h"
#include "globus_xio_util.h"
#include "globus_xio_udt.h"

#define CHUNK_SIZE 50000
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
        "globus-xio-udt-bw [options]\n"
        "-----------------\n"
        "using the -s switch sets up a server."  
        "\n"
        "specify -c <contact string> to communicate with the server\n"
        "\n"
        "options:\n"
        "-c <contact_string> : use this contact string (required for client)\n"
        "-s : be a server\n"
        "-p : server port (optional)\n"
	"-f : file name\n");
}

int
main(
    int                                     argc,
    char **                                 argv)
{
    globus_xio_driver_t                     udt_driver;
    globus_xio_stack_t                      stack;
    globus_xio_handle_t                     xio_handle;
    globus_xio_server_t			    server;	
    globus_xio_attr_t                       attr = NULL;
    char *                                  cs = NULL;
    globus_result_t                         res;
    int                                     ctr;
    globus_bool_t                           be_server = GLOBUS_FALSE;
    int                                     rc;
    char				    filename[FILE_NAME_LEN];
    FILE *				    fp;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    res = globus_xio_driver_load("udt", &udt_driver);
    test_res(res);
    res = globus_xio_stack_init(&stack, NULL);
    test_res(res);
    res = globus_xio_stack_push_driver(stack, udt_driver);
    test_res(res);

    if (argc < 4)
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
        else if(strcmp(argv[ctr], "-c") == 0)
        {
	    if (argc < 5)
	    {
		help();
		exit(1);
	    }
            cs = argv[ctr + 1];
            ctr++;
        }
        else if(strcmp(argv[ctr], "-s") == 0)
        {
            be_server = GLOBUS_TRUE;
        }
        else if(strcmp(argv[ctr], "-p") == 0)
        {
	    if (argc < 6)
	    {
		help();
		exit(1);
	    }
            test_res(globus_xio_attr_init(&attr));
            test_res(globus_xio_attr_cntl(
                attr,
                udt_driver,
                GLOBUS_XIO_UDT_SET_PORT,
                atoi(argv[ctr + 1])));
        } 
	else if(strcmp(argv[ctr], "-f") == 0)
	{
	    if (ctr + 1 < argc)
	    {
	        strcpy(filename, argv[ctr + 1]);
	    }
	    else	
	    {
		help();
		exit(1);
	    }
	}

    }
    
    if (!be_server && (!cs || !*cs))
    {
        help();
        exit(1);
    }
    

  
    if(be_server)
    {
        char                            buffer[CHUNK_SIZE + 1];
        int                             nbytes;
	int i, x;
	res = globus_xio_server_create(&server, attr, stack);
    	test_res(res);
        globus_xio_server_get_contact_string(server, &cs);
        fprintf(stdout, "Contact: %s\n", cs);   
	res = globus_xio_server_accept(&xio_handle, server);
    	test_res(res);
	res = globus_xio_open(xio_handle, NULL, attr);
	test_res(res);
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
        res = globus_xio_handle_create(&xio_handle, stack);
        test_res(res);
        res = globus_xio_stack_destroy(stack);
        test_res(res);
   	res = globus_xio_open(xio_handle, cs, attr);
   	test_res(res);
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

    res = globus_xio_driver_unload(udt_driver);
    test_res(res);
 
    rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    return 0;
}

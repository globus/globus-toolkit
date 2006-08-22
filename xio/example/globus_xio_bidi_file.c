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
#include "globus_xio_mode_e_driver.h"
#include "globus_xio_tcp_driver.h"
#include "globus_xio_bidi_driver.h"

#define CHUNK_SIZE 5000
#define FILE_NAME_LEN 25

globus_xio_driver_t                     mode_e_driver;
globus_xio_driver_t                     tcp_driver;
int					y = 12;
int					port = 0;
globus_mutex_t				mutex;
globus_cond_t				cond;

void
read_cb(
    globus_xio_handle_t                	handle,
    globus_result_t                     res,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);

void
write_cb(
    globus_xio_handle_t                	handle,
    globus_result_t                     res,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg);


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
        "globus-xio-mode-e-file [options]\n"
        "-----------------\n"
        "using the -s switch sets up a server\n"
        "specify -c <contact string> to communicate with the server\n"
        "server can only read and the client can only write\n"
        "\n"
        "options:\n"
        "-c <host:port> (required for client)\n"
        "-s : be a server\n"
        "-p : port (optional server option, client ignores this option)\n"
        "-P : num streams (optional client option, server ignores this)\n"
        "-f : file name (required for both server and client\n");
}

void
write_cb(
    globus_xio_handle_t                	handle,
    globus_result_t                     res,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    globus_free(buffer);
    globus_mutex_lock(&mutex);
    if (--y == 0)
    {
        globus_mutex_unlock(&mutex);
	globus_cond_signal(&cond);
    }
    else
    {
        globus_mutex_unlock(&mutex);
    }
}


void
read_cb(
    globus_xio_handle_t                	handle,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       len,
    globus_size_t                       nbytes,
    globus_xio_data_descriptor_t        data_desc,
    void *                              user_arg)
{
    FILE * 				fp;
    fp = (FILE*)user_arg;
    fputs(buffer, fp);
    globus_free(buffer);
    if (result != GLOBUS_SUCCESS)
    {
	fclose(fp);  
    }
    globus_mutex_lock(&mutex);
    if (--y == 0)
    {
        globus_mutex_unlock(&mutex);
	globus_cond_signal(&cond);
    }
    else
    {
        globus_mutex_unlock(&mutex);
    }
}

globus_result_t
attr_cntl_cb(
    globus_xio_attr_t			    attr)
{
    globus_result_t			    result;
    result = globus_xio_attr_cntl(
	attr,
	tcp_driver,
	GLOBUS_XIO_TCP_SET_PORT,
	port);
    return result;
}

int
main(
    int                                     argc,
    char **                                 argv)
{
    globus_xio_stack_t                      stack;
    globus_xio_stack_t                      mode_e_stack;
    globus_xio_handle_t                     xio_handle;
    globus_xio_server_t			    server;	
    globus_xio_attr_t                       attr = NULL;
    char *                                  cs = NULL;
    globus_result_t                         res;
    int                                     ctr;
    int					    num_streams = 1;
    globus_bool_t                           be_server = GLOBUS_FALSE;
    int                                     rc;
    char				    filename[FILE_NAME_LEN];
    FILE *				    fp;

    rc = globus_module_activate(GLOBUS_XIO_MODULE);
    globus_assert(rc == GLOBUS_SUCCESS);

    res = globus_xio_driver_load("bidi", &mode_e_driver);
    test_res(res);
    res = globus_xio_stack_init(&stack, NULL);
    test_res(res);
    res = globus_xio_stack_push_driver(stack, mode_e_driver);
    test_res(res);
    res = globus_xio_driver_load("tcp", &tcp_driver);
    test_res(res);
    res = globus_xio_stack_init(&mode_e_stack, NULL);
    test_res(res);
    res = globus_xio_stack_push_driver(mode_e_stack, tcp_driver);
    test_res(res);

    globus_mutex_init(&mutex, NULL);
    globus_cond_init(&cond, NULL);

    if (argc < 4)
    {
        help();
        exit(1);
    }
    test_res(globus_xio_attr_init(&attr));
    /*
    test_res(globus_xio_attr_cntl(
	attr,
	mode_e_driver,
	GLOBUS_XIO_MODE_E_SET_STACK,
	mode_e_stack));*/
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
            port = atoi(argv[ctr+1]);
          /*  test_res(globus_xio_attr_cntl(
                attr,
                mode_e_driver,
		GLOBUS_XIO_MODE_E_APPLY_ATTR_CNTLS,
		attr_cntl_cb));*/
        } 
        else if(strcmp(argv[ctr], "-P") == 0)
        {
	    if (argc < 6)
	    {
		help();
		exit(1);
	    }
            num_streams = atoi(argv[ctr+1]);
            test_res(globus_xio_attr_cntl(
                attr,
                mode_e_driver,
                GLOBUS_XIO_BIDI_SET_MAX_WRITE_STREAMS,
                num_streams));
	}
	
        else if(strcmp(argv[ctr], "-NP") == 0)
        {
            test_res(globus_xio_attr_cntl(
                attr,
                mode_e_driver,
                GLOBUS_XIO_BIDI_SET_PULSING,
                GLOBUS_FALSE));
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
	globus_size_t size = CHUNK_SIZE + 1;
	int i, x = 12;
	res = globus_xio_server_create(&server, attr, stack);
	test_res(res);
	globus_xio_server_get_contact_string(server, &cs);
	fprintf(stdout, "Contact: %s\n", cs);   
	res = globus_xio_server_accept(&xio_handle, server);
	test_res(res);
	res = globus_xio_open(xio_handle, NULL, attr);
	test_res(res);
	fp = fopen(filename, "w");
	while(x)
	{
	    char * buffer;
	    buffer = (char *) globus_malloc(size);
	    for (i=0; i<size; i++)
		buffer[i] = '\0';
	    res = globus_xio_register_read(
		xio_handle,
		buffer,
		size - 1,
		1,
		NULL,
		read_cb,
		fp);
	    if (res != GLOBUS_SUCCESS)
		break;
	    --x;
	}
	/*globus_mutex_lock(&mutex);
	while(y)
	{
	    globus_cond_wait(&cond, &mutex);
	}
	globus_mutex_unlock(&mutex);*/
	res = globus_xio_close(xio_handle, NULL);
	test_res(res);
	res = globus_xio_server_close(server);
	test_res(res);
	res = globus_xio_driver_unload(mode_e_driver);
	test_res(res);
	rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
	globus_assert(rc == GLOBUS_SUCCESS);
        
    }
    else
    {
	globus_size_t 			size = CHUNK_SIZE + 1;
        int	                        nbytes;
        int				i,x;
        res = globus_xio_handle_create(&xio_handle, stack);
        test_res(res);
        res = globus_xio_stack_destroy(stack);
        test_res(res);
   	res = globus_xio_open(xio_handle, cs, attr);
   	test_res(res);
        fp = fopen(filename, "r");
        while(!feof(fp))
	{
            char * buffer;
	    buffer = (char *) globus_malloc(size);
 	    for (i = 0; i < size; i++)
	    {
                buffer[i] = getc(fp);
		if(feof(fp))
		{
		  break;
		}
	    }
	    /*x = fread(buffer, CHUNK_SIZE, 1, fp);*/
            /*nbytes = strlen(buffer);*/
	    nbytes = i;
            res = globus_xio_register_write(
                xio_handle,
                buffer,
                nbytes,
                nbytes,
                NULL,
		write_cb,
		NULL);
            test_res(res); 
        } 
        fclose(fp);
/*        test_res(globus_xio_data_descriptor_init(&dd, xio_handle));
        test_res(globus_xio_data_descriptor_cntl(
            dd,
            mode_e_driver,
            GLOBUS_XIO_MODE_E_SEND_EOD,
            GLOBUS_TRUE));
        res = globus_xio_write(
                xio_handle,
                buffer,
                nbytes,
                nbytes,
                &nbytes,
                NULL);
        test_res(res); */
	/*globus_mutex_lock(&mutex);
	while(y)
	{
	    globus_cond_wait(&cond, &mutex);
	}
	globus_mutex_unlock(&mutex);*/
	res = globus_xio_close(xio_handle, attr);
	test_res(res);
	res = globus_xio_driver_unload(mode_e_driver);
	test_res(res);
	rc = globus_module_deactivate(GLOBUS_XIO_MODULE);
	globus_assert(rc == GLOBUS_SUCCESS);

    }
    globus_mutex_destroy(&mutex);
    globus_cond_destroy(&cond);
    return 0;
}

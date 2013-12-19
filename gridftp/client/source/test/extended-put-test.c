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

/*
 * extended block mode put.
 *
 * makes sure that the ftp client and control libraries will handle the
 * transfer of a file in extended block mode.
 */

#include "globus_ftp_client.h"
#include "globus_ftp_client_test_common.h"

static globus_mutex_t lock;
static globus_cond_t cond;
static globus_bool_t done;
static globus_bool_t error = GLOBUS_FALSE;
#define MYSIZE (64*1024)

static
void
done_cb(
	void *					user_arg,
	globus_ftp_client_handle_t *		handle,
	globus_object_t *			err)
{
    char * tmpstr;

    if(err) { tmpstr = globus_object_printable_to_string(err);
	      printf("done with error: %s\n", tmpstr); 
              error = GLOBUS_TRUE;
	      globus_libc_free(tmpstr); }
    globus_mutex_lock(&lock);
    done = GLOBUS_TRUE;
    globus_cond_signal(&cond);
    globus_mutex_unlock(&lock);
       
}
int global_offset;

static
void
data_cb(
    void *					user_arg,
    globus_ftp_client_handle_t *		handle,
    globus_object_t *				err,
    globus_byte_t *				buffer,
    globus_size_t				length,
    globus_off_t				offset,
    globus_bool_t				eof)
{
    if(!eof)
    {
	int rc;
        globus_mutex_lock(&lock);
    	rc = read(0, buffer, MYSIZE);
	globus_ftp_client_register_write(
	    handle,
	    buffer,
	    rc,
	    global_offset,
	    rc == 0,
	    data_cb,
	    0);
	global_offset += rc;
	globus_mutex_unlock(&lock);
    }
    else
    {
        globus_libc_free(buffer);
    }
}

int main(int argc, char **argv)
{
    globus_ftp_client_handle_t			handle;
    globus_ftp_client_operationattr_t		attr;
    globus_byte_t *				buffer;
    globus_result_t				result;
    globus_ftp_client_handleattr_t		handle_attr;
    char *					src;
    char *					dst;
    int						i;
    globus_size_t				parallelism_level = 1;
    globus_ftp_control_parallelism_t		parallelism;
    globus_ftp_control_layout_t			layout;

    globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    globus_ftp_client_handleattr_init(&handle_attr);
    globus_ftp_client_operationattr_init(&attr);

    /* Parse local arguments */
    for(i = 1; i < argc; i++)
    {
	if(strcmp(argv[i], "-P") == 0 && i + 1 < argc)
	{
	    parallelism_level = atoi(argv[i+1]);

	    test_remove_arg(&argc, argv, &i, 1);
	}
    }
    test_parse_args(argc,
		    argv,
		    &handle_attr,
		    &attr,
		    &src,
		    &dst);
    if(parallelism_level < 1) 
    {
	parallelism_level = 1;
    }
    parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
    parallelism.fixed.size = parallelism_level;
    layout.mode = GLOBUS_FTP_CONTROL_STRIPING_BLOCKED_ROUND_ROBIN;
    layout.round_robin.block_size = 64*1024;

    globus_mutex_init(&lock, GLOBUS_NULL);
    globus_cond_init(&cond, GLOBUS_NULL);

    globus_ftp_client_operationattr_set_mode(
        &attr,
        GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK);
    globus_ftp_client_operationattr_set_parallelism(&attr,
					            &parallelism);

    globus_ftp_client_operationattr_set_layout(&attr,
				               &layout);

    globus_ftp_client_handle_init(&handle,  &handle_attr);

    done = GLOBUS_FALSE;
    result = globus_ftp_client_put(&handle,
				   dst,
				   &attr,
				   GLOBUS_NULL,
				   done_cb,
				   0);
    globus_mutex_lock(&lock);
    if(result != GLOBUS_SUCCESS)
    {
	globus_object_t * err;
	err = globus_error_get(result);
	fprintf(stderr, "%s", globus_object_printable_to_string(err));
	done = GLOBUS_TRUE;
    }
    else
    {
	int rc=1;
	int i;

	for(i = 0; i < parallelism_level && rc != 0; i++)
	{
	    buffer = malloc(MYSIZE);

	    rc = read(0, buffer, MYSIZE);
	    globus_ftp_client_register_write(
		&handle,
		buffer,
		rc,
		global_offset,
		rc == 0,
		data_cb,
		0);
	    global_offset += rc;
	}
    }
    while(!done)
    {
	globus_cond_wait(&cond, &lock);
    }
    globus_mutex_unlock(&lock);

    globus_ftp_client_handle_destroy(&handle);
    globus_module_deactivate_all();
    
    if(test_abort_count && error)
    {
	return 0;
    }
    return error;
}

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
 * partial authenticated put.
 *
 * makes sure that the ftp client and control libraries will handle the
 * partial transfer of a file.
 */

#include "globus_ftp_client.h"
#include "globus_ftp_client_test_common.h"

static globus_mutex_t lock;
static globus_cond_t cond;
static globus_bool_t done;
static globus_bool_t error = GLOBUS_FALSE;
#define SIZE 42

static
void
done_cb(
	void *					user_arg,
	globus_ftp_client_handle_t *		handle,
	globus_object_t *			err)
{
    char * tmpstr;

    if(err) tmpstr = " an";
    else    tmpstr = "out";

    if(err) { printf("done with%s error\n", tmpstr); 
              error = GLOBUS_TRUE; }
    globus_mutex_lock(&lock);
    done = GLOBUS_TRUE;
    globus_cond_signal(&cond);
    globus_mutex_unlock(&lock);
       
}

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
    int rc;

    static int first = 1;
    fprintf(stdout, "%s[%ld,%ld]\n", first?"":"\n", (long)offset, (long)length);
    first = 0;
    fwrite(buffer, 1, length, stdout);

    if(!eof)
    {
	rc = read(0, buffer, SIZE);
	globus_ftp_client_register_write(
	    handle,
	    buffer,
	    rc,
	    offset+length,
	    rc == 0,
	    data_cb,
	    0);
    }
}

int main(int argc, char **argv)
{
    globus_ftp_client_handle_t			handle;
    globus_ftp_client_operationattr_t		attr;
    globus_byte_t				buffer[SIZE];
    globus_size_t				buffer_length = sizeof(buffer);
    globus_result_t				result;
    globus_ftp_client_handleattr_t		handle_attr;
    char *					src;
    char *					dst;
    globus_off_t				start_offset=5;
    int						i;
    globus_ftp_control_mode_t			mode;

    mode = GLOBUS_FTP_CONTROL_MODE_STREAM;

    globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    globus_ftp_client_handleattr_init(&handle_attr);
    globus_ftp_client_operationattr_init(&attr);

    /* Parse local arguments */
    for(i = 1; i < argc; i++)
    {
	if(strcmp(argv[i], "-R") == 0 && i + 1 < argc)
	{
	    sscanf(argv[i+1], "%"GLOBUS_OFF_T_FORMAT, &start_offset);

	    test_remove_arg(&argc, argv, &i, 1);
	}
	else if(strcmp(argv[i], "-E") == 0 && i < argc)
	{
	    mode = GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK;

	    test_remove_arg(&argc, argv, &i, 0);
	}
    }
    test_parse_args(argc,
		    argv,
		    &handle_attr,
		    &attr,
		    &src,
		    &dst);

    if(start_offset < 0) start_offset = 0;

    globus_mutex_init(&lock, GLOBUS_NULL);
    globus_cond_init(&cond, GLOBUS_NULL);

    globus_ftp_client_handle_init(&handle,  &handle_attr);

    globus_ftp_client_operationattr_set_mode(&attr,
				             mode);

    done = GLOBUS_FALSE;
    result = globus_ftp_client_partial_put(&handle,
					   dst,
					   &attr,
					   GLOBUS_NULL,
					   start_offset,
					   -1,
					   done_cb,
					   0);
    if(result != GLOBUS_SUCCESS)
    {
	error = GLOBUS_TRUE;
	done = GLOBUS_TRUE;
    }
    else
    {
	int rc;

	rc = read(0, buffer, buffer_length);
	globus_ftp_client_register_write(
	    &handle,
	    buffer,
	    rc,
	    start_offset,
	    rc == 0,
	    data_cb,
	    0);
    }
    globus_mutex_lock(&lock);
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

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
 * test restart markers.
 *
 * basically just an extended transfer test with restart markers
 * enter on commandline via -R s1-e1,s2-e2,s3-e3... (start-end offset)
 */
#include "globus_ftp_client.h"
#include "globus_ftp_client_test_common.h"

static globus_mutex_t lock;
static globus_cond_t cond;
static globus_bool_t done;
static globus_bool_t error = GLOBUS_FALSE;
#define SIZE 4200

static
void
done_cb(
	void *					user_arg,
	globus_ftp_client_handle_t *		handle,
	globus_object_t *			err)
{
    char * tmpstr;

    if(err)
    {
	tmpstr = globus_object_printable_to_string(err);
	printf("%s\n", tmpstr); 
        error = GLOBUS_TRUE;
	globus_libc_free(tmpstr);
    }

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
    static int first = 1;
    fprintf(stdout, "%s[%ld,%ld]\n", first?"":"\n", (long)offset, (long)length);
    first = 0;
    fwrite(buffer, 1, length, stdout);
    if(!eof)
    {
	globus_ftp_client_register_read(handle,
					buffer,
					SIZE,
					data_cb,
					0);
    }
}

int main(int argc,
	 char *argv[])
{
    globus_ftp_client_handle_t			handle;
    globus_ftp_client_operationattr_t		attr;
    globus_byte_t				buffer[SIZE];
    globus_size_t				buffer_length = sizeof(buffer);
    globus_result_t				result;
    char *					src;
    char *					dst;
    globus_ftp_client_handleattr_t		handle_attr;
    globus_ftp_control_layout_t			layout;
    globus_ftp_control_parallelism_t		parallelism;
    int						i;
    globus_ftp_client_restart_marker_t		restart;

    LTDL_SET_PRELOADED_SYMBOLS();
    globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);

    globus_ftp_client_handleattr_init(&handle_attr);
    globus_ftp_client_operationattr_init(&attr);

    layout.mode = GLOBUS_FTP_CONTROL_STRIPING_NONE;
    parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_NONE;

    globus_ftp_client_restart_marker_init(&restart);

    /* Parse local arguments */
    for(i = 1; i < argc; i++)
    {
	if(strcmp(argv[i], "-S") == 0 && i < argc)
	{
	    layout.mode =
		GLOBUS_FTP_CONTROL_STRIPING_BLOCKED_ROUND_ROBIN;
	    layout.round_robin.block_size = 15;

	    test_remove_arg(&argc, argv, &i, 0);
	}
	else if(strcmp(argv[i], "-P") == 0 && i + 1 < argc)
	{
	    parallelism.mode = GLOBUS_FTP_CONTROL_PARALLELISM_FIXED;
	    parallelism.fixed.size = atoi(argv[i+1]);

	    test_remove_arg(&argc, argv, &i, 1);
	}
	else if(strcmp(argv[i], "-R") == 0 && i+1 < argc)
	{
	    char * p;
	    globus_off_t offset, end;
	    int bytes;

	    p = argv[i+1];
	    while((*p) && (sscanf(p,
				  "%"GLOBUS_OFF_T_FORMAT
				  "-%"GLOBUS_OFF_T_FORMAT"%n",
				  &offset,
				  &end,
				  &bytes) >= 2))
	    {
		globus_ftp_client_restart_marker_insert_range(
		    &restart,
		    offset,
		    end);
		p += bytes;
		if(*p && *p == ',') p++;
	    }

	    test_remove_arg(&argc, argv, &i, 1);
	}
    }
    test_parse_args(argc, 
		    argv,
		    &handle_attr,
		    &attr,
		    &src,
		    &dst);

    globus_mutex_init(&lock, GLOBUS_NULL);
    globus_cond_init(&cond, GLOBUS_NULL);

    globus_ftp_client_operationattr_set_mode(
        &attr,
        GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK);
    globus_ftp_client_operationattr_set_layout(&attr,
	                                       &layout);
    globus_ftp_client_operationattr_set_parallelism(&attr,
					              &parallelism);
    globus_ftp_client_handle_init(&handle,  &handle_attr);
    globus_ftp_client_handle_cache_url_state(&handle,
	                                     src);

    for(i = 0; i < 1; i++)
    {
	done = GLOBUS_FALSE;
	result = globus_ftp_client_third_party_transfer(&handle,
            src,
            &attr,
            dst,
            &attr,
            &restart,
            done_cb,
            0);
	if(result != GLOBUS_SUCCESS)
	{
	    fprintf(stderr,
		    "%s",
		    globus_object_printable_to_string(
			globus_error_get(result)));
	    done = GLOBUS_TRUE;
	    error = GLOBUS_TRUE;
	}
	else
	{
	    globus_ftp_client_register_read(
		&handle,
		buffer,
		buffer_length,
		data_cb,
		0);
	}
	globus_mutex_lock(&lock);
	while(!done)
	{
	    globus_cond_wait(&cond, &lock);
	}
	globus_mutex_unlock(&lock);
    }
    
    globus_ftp_client_handle_destroy(&handle);

    globus_module_deactivate_all();

    if(test_abort_count && (error==2))
    {
	return 0;
    }
    return error;
}

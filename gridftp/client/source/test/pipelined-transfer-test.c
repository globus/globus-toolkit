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
 * simple pipelined transfer test.  Will transfer src (-s) to dest (-d) 
 * -A times (10 by default), each consecutive file will be named dest<count>.
 */
#include "globus_ftp_client.h"
#include "globus_ftp_client_test_common.h"

static globus_mutex_t lock;
static globus_cond_t cond;
static globus_bool_t done;
static globus_bool_t error = GLOBUS_FALSE;

#define FTP_NUM_PIPLINED_FILES 10


typedef struct globus_l_gridftp_test_url_pairs_s
{
    char **                             source_array;
    char **                             dest_array;
    int                                 index;
    int                                 count;
} globus_l_gridftp_test_url_pairs_t;

static
void
done_cb(
        void *                                  user_arg,
        globus_ftp_client_handle_t *            handle,
        globus_object_t *                       err)
{
    char * tmpstr;

    if(err) tmpstr = " an";
    else    tmpstr = "out";

    if(err)
    { 
        printf("done with%s error: %s\n", tmpstr, globus_object_printable_to_string(err)); 
        error++; 
    }

    globus_mutex_lock(&lock);
    done = GLOBUS_TRUE;
    globus_cond_signal(&cond);
    globus_mutex_unlock(&lock);
       
}

static
void 
pipeline_cb(
    globus_ftp_client_handle_t *                handle,
    char **                                     source_url,
    char **                                     dest_url,
    void *                                      user_arg)
{
    globus_l_gridftp_test_url_pairs_t *         url_pairs;
    
    url_pairs = user_arg;
    if(url_pairs->index < url_pairs->count)
    {
        *source_url = url_pairs->source_array[url_pairs->index];
        *dest_url = url_pairs->dest_array[url_pairs->index];
        url_pairs->index++;
    }
    else
    {
        *source_url = NULL;
        *dest_url = NULL;
    }        
}

int main(int argc, char **argv)
{
    globus_ftp_client_handle_t                  handle;
    globus_ftp_client_operationattr_t           attr;
    globus_result_t                             result;
    int                                         i;
    globus_ftp_client_handleattr_t              handle_attr;
    char *                                      src;
    char *                                      dst;
    extern char *                               optarg;
    extern int                                  optind;
    int                                         c;
    globus_l_gridftp_test_url_pairs_t           url_pairs;

    globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);

    globus_ftp_client_handleattr_init(&handle_attr);
    globus_ftp_client_operationattr_init(&attr);

    globus_mutex_init(&lock, GLOBUS_NULL);
    globus_cond_init(&cond, GLOBUS_NULL);


    test_parse_args(argc,
                    argv,
                    &handle_attr,
                    &attr,
                    &src,
                    &dst);

    url_pairs.count = FTP_NUM_PIPLINED_FILES;

    optind = 1;
    while((c = getopt(argc, argv, "A:")) != -1)
    {
	switch(c)
	{
	  case 'A':
	    url_pairs.count = strtol(optarg, NULL, 0);
	    break;
	}
    }	

    url_pairs.source_array = globus_malloc(url_pairs.count * sizeof(char *));
    url_pairs.dest_array = globus_malloc(url_pairs.count * sizeof(char *));
    for(i = 0; i < url_pairs.count; i++)
    {
        url_pairs.source_array[i] = globus_common_create_string("%s", src);
        url_pairs.dest_array[i] = globus_common_create_string("%s%d", dst, i);
    }
    url_pairs.index = 1;
    
    globus_ftp_client_handleattr_set_pipeline(
            &handle_attr, 0, pipeline_cb, &url_pairs);
  
    globus_ftp_client_handle_init(&handle, &handle_attr);

    globus_ftp_client_operationattr_set_mode(
        &attr, GLOBUS_FTP_CONTROL_MODE_EXTENDED_BLOCK);

    done = GLOBUS_FALSE;
    result = globus_ftp_client_third_party_transfer(
        &handle,
        url_pairs.source_array[0],
        &attr,
        url_pairs.dest_array[0],
        &attr,
        GLOBUS_NULL,
        done_cb,
        0);
    if(result != GLOBUS_SUCCESS)
    {
        done = GLOBUS_TRUE;
    }
    
    globus_mutex_lock(&lock);
    while(!done)
    {
        globus_cond_wait(&cond, &lock);
    }
    globus_mutex_unlock(&lock);

    for(i = 0; i < url_pairs.count; i++)
    {
        globus_free(url_pairs.source_array[i]);
        globus_free(url_pairs.dest_array[i]);
    }
    globus_free(url_pairs.source_array);
    globus_free(url_pairs.dest_array);
    
    globus_ftp_client_handle_destroy(&handle);

    globus_ftp_client_handleattr_destroy(&handle_attr);
    globus_ftp_client_operationattr_destroy(&attr);

    globus_mutex_destroy(&lock);
    globus_cond_destroy(&cond);
    
    globus_module_deactivate_all();

    if(test_abort_count && error)
    {
        return 0;
    }

    return error;
}

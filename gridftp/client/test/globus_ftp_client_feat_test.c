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

#include "globus_ftp_client.h"
#include "globus_ftp_client_test_common.h"

static globus_mutex_t                   lock;
static globus_cond_t                    cond;
static globus_bool_t                    done;
static globus_bool_t                    error = GLOBUS_FALSE;
static globus_result_t                  result;

void quick_exit(char *stage) 
{
    globus_libc_printf( "\nThe following stage failed: %s\n", stage);
    globus_libc_fprintf(stderr,globus_object_printable_to_string(globus_error_get(result)));
    printf("\nExiting.\n");
    exit(1);
}

/* Assert result and possibly Exit
 */
void assert_result(char* stage) 
{
    if (GLOBUS_SUCCESS != result) 
        quick_exit(stage);
}

void complete_callback(
    void *                         user_arg,
    globus_ftp_client_handle_t *   handle, 
    globus_object_t *              err)
{
    if(err) 
    {
        char *                          tmp_str;
        
        error = GLOBUS_TRUE;
        tmp_str = globus_object_printable_to_string(err);
        globus_libc_fprintf(stderr, "callback: %s\n", tmp_str);
        globus_free(tmp_str);
    }
    
    globus_mutex_lock(&lock);
    {
        done = GLOBUS_TRUE;
        globus_cond_signal(&cond);
    }
    globus_mutex_unlock(&lock);
}

void
print_features(
    globus_ftp_client_features_t *      features)
{
    globus_ftp_client_tristate_t        answer;
    int                                 i;
    
    char * feature_names[] = {
        "GLOBUS_FTP_CLIENT_FEATURE_RETRBUFSIZE",
	"GLOBUS_FTP_CLIENT_FEATURE_RBUFSZ",
	"GLOBUS_FTP_CLIENT_FEATURE_RBUFSIZ",
	"GLOBUS_FTP_CLIENT_FEATURE_STORBUFSIZE",
	"GLOBUS_FTP_CLIENT_FEATURE_SBUSSZ",
	"GLOBUS_FTP_CLIENT_FEATURE_SBUFSIZ",
	"GLOBUS_FTP_CLIENT_FEATURE_BUFSIZE",
	"GLOBUS_FTP_CLIENT_FEATURE_SBUF",
	"GLOBUS_FTP_CLIENT_FEATURE_ABUF",
	
	"GLOBUS_FTP_CLIENT_FEATURE_REST_STREAM",
	"GLOBUS_FTP_CLIENT_FEATURE_PARALLELISM",
	"GLOBUS_FTP_CLIENT_FEATURE_DCAU",
	"GLOBUS_FTP_CLIENT_FEATURE_ESTO",
	"GLOBUS_FTP_CLIENT_FEATURE_ERET",
	"GLOBUS_FTP_CLIENT_FEATURE_SIZE",
	"GLOBUS_FTP_CLIENT_FEATURE_MLST",
	"GLOBUS_FTP_CLIENT_FEATURE_MAX",
	"GLOBUS_FTP_CLIENT_LAST_BUFFER_COMMAND",
	"GLOBUS_FTP_CLIENT_FIRST_FEAT_FEATURE"
    };
    
    for (i = 0; i < GLOBUS_FTP_CLIENT_FEATURE_MAX; i++)
    {
        result = globus_ftp_client_is_feature_supported(features, &answer, i);
	assert_result("is_feature_supported");
	
	printf("%d\t(%s)\t", i, feature_names[i]);
	if (answer == GLOBUS_FTP_CLIENT_TRUE)    
	  printf("yes\n");
	else if (answer == GLOBUS_FTP_CLIENT_MAYBE)
	  printf("maybe\n");
	else printf("no\n");
    }
    
    printf("\n");
}

int main(
    int                                 argc,
    char **                             argv) 
{
    globus_ftp_client_handle_t		handle;
    globus_ftp_client_operationattr_t	attr;
    globus_result_t			result;
    globus_ftp_client_handleattr_t	handle_attr;
    char *				src;
    char *                              dst;
    globus_ftp_client_features_t        features;
    int                                 i;
    
    globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    globus_ftp_client_handleattr_init(&handle_attr);
    globus_mutex_init(&lock, GLOBUS_NULL);
    globus_cond_init(&cond, GLOBUS_NULL);

    globus_ftp_client_operationattr_init(&attr);

    test_parse_args(argc,
		    argv,
		    &handle_attr,
		    &attr,
		    &src,
		    &dst);
    
    globus_ftp_client_handleattr_set_cache_all(&handle_attr, GLOBUS_TRUE);
    globus_ftp_client_handle_init(&handle,  &handle_attr);
    
    result = globus_ftp_client_features_init(&features);
    assert_result("features init");
    
    print_features(&features);
    
    for(i = 0; i < 2; i++)
    {
        done = GLOBUS_FALSE;
        result = globus_ftp_client_feat(
            &handle, src, &attr, &features, complete_callback, NULL);
    				    
        if(result != GLOBUS_SUCCESS)
        {
            char *                      tmpstr;
            globus_object_t *           err;
            
            err = globus_error_get(result);
            
            tmpstr = globus_object_printable_to_string(err);
            fprintf(stderr, "Error: %s", tmpstr);
            globus_object_free(err);
            globus_libc_free(tmpstr);
            error = GLOBUS_TRUE;
            done = GLOBUS_TRUE;
        }
        
        globus_mutex_lock(&lock);
        while(!done)
        {
    	    globus_cond_wait(&cond, &lock);
        }
        globus_mutex_unlock(&lock);
        
        print_features(&features);
    }
    
    globus_ftp_client_features_destroy(&features);
    globus_ftp_client_operationattr_destroy(&attr);
    globus_ftp_client_handleattr_destroy(&handle_attr);
    globus_ftp_client_handle_destroy(&handle);
    globus_module_deactivate_all();

    return error;
}

#include "globus_ftp_client.h"

#define PRINT_OKAYS 1

globus_bool_t done=GLOBUS_FALSE;
globus_bool_t error=GLOBUS_FALSE;
globus_mutex_t mutex;
globus_cond_t cond;

static globus_result_t result=GLOBUS_SUCCESS;



void quick_exit(char *stage) 
{
    globus_libc_printf( "\nThe following stage failed: %s\n", stage);
    globus_libc_fprintf(stderr,globus_object_printable_to_string(globus_error_get(result)));
    printf("\nExiting.\n");
    exit(1);
}

void okay(char *stage) 
{
#ifdef PRINT_OKAYS
    globus_libc_printf( "\ncompleted: %s\n", stage);
#endif /*PRINT_OKAYS*/
}

/* Assert result and possibly Exit
 */
void assert_result(char* stage) 
{
    if (GLOBUS_SUCCESS != result) 
        quick_exit(stage);
    else okay(stage);
}

void complete_callback(
    void *                         user_arg,
    globus_ftp_client_handle_t *   handle, 
    globus_object_t *              err)
{
    if (err) 
    {
       error = GLOBUS_TRUE;
     globus_libc_fprintf(
			 stderr, 
			 "callback: %s\n", 
			 globus_object_printable_to_string(err));
    }
    globus_mutex_lock(&mutex);
    done=GLOBUS_TRUE;
    globus_cond_signal(&cond);
    globus_mutex_unlock(&mutex);
    printf("callback terminating...\n");
}

		   
int main() 
{
    char * feature_names[20]={
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
	"GLOBUS_FTP_CLIENT_FEATURE_MAX",
	"GLOBUS_FTP_CLIENT_LAST_BUFFER_COMMAND",
	"GLOBUS_FTP_CLIENT_FIRST_FEAT_FEATURE"
    };

    globus_ftp_client_handle_t handle;
    globus_ftp_client_handleattr_t attr;

    char* url="gsiftp://localhost/etc/passwd";
    globus_ftp_client_tristate_t answer;
    int i;
    globus_ftp_client_features_t  features;
    result = globus_ftp_client_features_init(&features);
    assert_result("features init");

    printf("Initiated features");
    printf("(before connecting):\n");

    for (i=0; i<GLOBUS_FTP_CLIENT_FEATURE_MAX; i++)
    {
        result=globus_ftp_client_is_feature_supported(
						      &features, 
						      &answer, 
						      i);
	if (result) assert_result("is_feature_supported");
	printf("%d\t(%s)\t", i, feature_names[i]);
	if (answer == GLOBUS_FTP_CLIENT_TRUE)    
	  printf("yes\n");
	else if (answer == GLOBUS_FTP_CLIENT_MAYBE)
	  printf("maybe\n");
	else printf("no\n");
    }


    result = (globus_result_t) globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    assert_result("module activate");
    globus_mutex_init(&mutex, NULL);
    globus_cond_init(&cond, NULL);
    globus_ftp_client_handleattr_init(&attr);
    assert_result("handleattr init");
    result = globus_ftp_client_handle_init(&handle, &attr);
    assert_result("handle init");
    result = globus_ftp_client_feat(
				    &handle,
				    url,
				    NULL,
				    &features,
				    complete_callback,
				    NULL);
    assert_result("feat");

    globus_mutex_lock(&mutex);
    while(!done) 
      globus_cond_wait(&cond, &mutex);
    globus_mutex_unlock(&mutex);

    if(error) 
    {
        printf("Error: returned by feat\n");
	exit(-1);
    }
    result = globus_ftp_client_handle_destroy(&handle);
    assert_result("client handle destroy");
    result = globus_ftp_client_handleattr_destroy(&attr);
    assert_result("handleattr destroy");
    result = (globus_result_t) globus_module_deactivate_all();
    assert_result("module deact");


    printf("\nFeatures supported by server:\n\n");
    
    for (i=0; i<GLOBUS_FTP_CLIENT_FEATURE_MAX; i++)
    {
        result=globus_ftp_client_is_feature_supported(
						      &features, 
						      &answer, 
						      i);
	if (result) assert_result("is_feature_supported");
	printf("%d\t(%s)\t", i, feature_names[i]);
	if (answer == GLOBUS_FTP_CLIENT_TRUE)    
	  printf("yes\n");
	else if (answer == GLOBUS_FTP_CLIENT_FALSE)
	  printf("no\n");
	else if (answer == GLOBUS_FTP_CLIENT_MAYBE)
	  printf("maybe\n");
	else 
	{
	  printf("Error: feature %d has unsupported value %d", i, answer);
	  exit(-1);
	}
    }

    result = globus_ftp_client_features_destroy(&features);
    assert_result("features  destroy");

    return GLOBUS_SUCCESS;
}

#include "globus_gram_job_manager.h"
#include <string.h>

int
globus_gram_job_manager_remote_io_file_create(
    globus_gram_jobmanager_request_t *	request)
{
    char *				cache_url;
    const char *			format = "%sdev/remote_io_url";
    unsigned long			timestamp;
    FILE *				fp;
    int					rc = GLOBUS_SUCCESS;

    cache_url = globus_libc_malloc(strlen(request->cache_tag) + 
	                           strlen(format));
    if(cache_url == NULL)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_REMOTE_IO_URL;

	goto malloc_failed;
    }
    rc = sprintf(cache_url, format, request->cache_tag);
    if(rc < 0)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_REMOTE_IO_URL;

	goto sprintf_failed;
    }

    rc = globus_gass_cache_add(&request->cache_handle,
	                       cache_url,
			       request->cache_tag,
			       GLOBUS_TRUE,
			       &timestamp,
			       &request->remote_io_url_file);
    if(rc != GLOBUS_GASS_CACHE_ADD_EXISTS &&
       rc != GLOBUS_GASS_CACHE_ADD_NEW)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_REMOTE_IO_URL;

	goto cache_add_failed;
    }
    fp = fopen(request->remote_io_url_file, "w");

    if(fp == GLOBUS_NULL)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_REMOTE_IO_URL;

	goto fopen_failed;
    }

    rc = fprintf(fp, "%s\n", request->remote_io_url);
    if(rc < 0)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_REMOTE_IO_URL;

	goto fprintf_failed;
    }

    rc = globus_gass_cache_add_done(&request->cache_handle,
				    cache_url,
				    request->cache_tag,
				    timestamp);
    if(rc != GLOBUS_SUCCESS)
    {
	rc = GLOBUS_GRAM_PROTOCOL_ERROR_WRITING_REMOTE_IO_URL;
    }

  fprintf_failed:
    fclose(fp);
    if(rc != GLOBUS_SUCCESS)
    {
	remove(request->remote_io_url_file);
    }
  fopen_failed:
    if(rc != GLOBUS_SUCCESS)
    {
	globus_libc_free(request->remote_io_url_file);
	request->remote_io_url_file = NULL;
	globus_gass_cache_delete(&request->cache_handle,
				 cache_url,
				 request->cache_tag,
				 timestamp,
				 GLOBUS_TRUE);
    }
  cache_add_failed:
  sprintf_failed:
    globus_libc_free(cache_url);
  malloc_failed:
    return rc;
}
/* globus_gram_job_mangaer_remote_io_file_create() */

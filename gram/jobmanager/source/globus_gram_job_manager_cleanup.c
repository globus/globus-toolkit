#include "globus_gram_job_manager.h"
#include <string.h>

int
globus_gram_job_manager_clean_cache(
    globus_gram_jobmanager_request_t *	request)
{
    int					rc;
    int					i;
    globus_gass_cache_entry_t *         cache_entries;
    int                                 cache_size;
    int					tag_index;

    globus_gram_job_manager_request_log(request,
	                  "JM: Cleaning GASS cache\n");

    if(request->cache_tag == NULL)
    {
	return GLOBUS_SUCCESS;
    }

    rc =  globus_gass_cache_list(&request->cache_handle,
				    &cache_entries,
				    &cache_size);
    if(rc == GLOBUS_SUCCESS)
    {
	for(i=0; i<cache_size; i++)
	{
	    for(tag_index=0; tag_index<cache_entries[i].num_tags; tag_index++)
	    {
		if (!strcmp(cache_entries[i].tags[tag_index].tag,
			    request->cache_tag))
		{
		    globus_gram_job_manager_request_log(
			    request,
			    "Trying to clean up with <url=%s> <tag=%s>\n",
			    cache_entries[i].url,
			    request->cache_tag);

		    globus_gass_cache_cleanup_tag(
			    &request->cache_handle,
			    cache_entries[i].url,
			    request->cache_tag);
		}
	    }
	}
	globus_gass_cache_list_free(cache_entries, cache_size);
    }
    return rc;
}
/* globus_gram_job_manager_cleanup_cache() */

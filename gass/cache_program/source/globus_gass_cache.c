/******************************************************************************
gass_cache.c 

Description:

CVS Information:

    $Source$
    $Date$
    $Revision$
    $Author$
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_common.h"

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#include "lber.h"
#include "ldap.h"
#include "globus_gram_client.h"
#include "globus_gass_server_ez.h"
#include "globus_gass_client.h"
#include "globus_gass_cache.h"
#include "globus_nexus.h"

char *get_contact_string(LDAP *ldap_server, LDAPMessage* entry);

typedef enum {
    GASSL_ADD,
    GASSL_DELETE,
    GASSL_CLEANUP_TAG,
    GASSL_CLEANUP_FILE,
    GASSL_LIST
} gassl_cache_op_t;

static int usage(char *n);
static char *get_rm_contact(char *resource);
static void remote_cache(gassl_cache_op_t op,
			 char *tag,
			 char *url,
			 char *rm_contact);
static void local_cache(gassl_cache_op_t op,
			char *tag,
			char *url);
static void print_url(globus_gass_cache_entry_t *entry,
		      char *tag);
static globus_mutex_t mutex;
static globus_cond_t cond;
static globus_bool_t done = GLOBUS_FALSE;

int main(int argc, char **argv)
{
    int i;
    gassl_cache_op_t op;
    int arg = 1;
    char *resource=GLOBUS_NULL,
	*url = GLOBUS_NULL,
	*rm_contact = GLOBUS_NULL,
	*tag=GLOBUS_NULL;
    if(argc < 2)
    {
	return usage(argv[0]);
    }
    /* parse op */
    if(strncmp("add", argv[arg], strlen(argv[arg])) == 0)
    {
	op = GASSL_ADD;
    }
    else if(strncmp("delete", argv[arg], strlen(argv[arg])) == 0)
    {
	op = GASSL_DELETE;
    }
    else if(
	strncmp("cleanup_tag", argv[arg], strlen(argv[arg])) == 0 &&
	strncmp("cleanup_file", argv[arg], strlen(argv[arg])) != 0)
    {
	op = GASSL_CLEANUP_TAG;
    }
    else if(
	strncmp("cleanup_file", argv[arg], strlen(argv[arg])) == 0 &&
	strncmp("cleanup_tag", argv[arg], strlen(argv[arg])) != 0)
    {
	op = GASSL_CLEANUP_FILE;
    }
    else if(strncmp("list", argv[arg], strlen(argv[arg])) == 0)
    {
	op = GASSL_LIST;
    }
    else
    {
	return usage(argv[0]);
    }
    arg++;
    /* parse options [-t tag] [-r resource] */
    while(arg < argc)
    {
	if(strcmp("-t", argv[arg]) == 0)
	{
	    arg++;
	    if(arg == argc)
	    {
		return usage(argv[0]);
	    }
	    tag = argv[arg++];
	}
	else if(strcmp("-r", argv[arg]) == 0)
	{
	    arg++;
	    if(arg == argc)
	    {
		return usage(argv[0]);
	    }
	    resource = argv[arg++];
	}
	else
	{
	    if(url != GLOBUS_NULL)
	    {
		return usage(argv[0]);
	    }
	    url = argv[arg++];
	}
    }

    /* verify usage */
    if(op == GASSL_ADD ||
       op == GASSL_DELETE ||
       op == GASSL_CLEANUP_FILE)
    {
	if(url == GLOBUS_NULL)
	{
	    return usage(argv[0]);
	}
    }
    
    if(resource != GLOBUS_NULL)
    {
	rm_contact = get_rm_contact(resource);
	if(strlen(rm_contact) == 0)
	{
	    printf("Couldn't find resource %s\n", resource);
	    exit(1);
	}
    }

    if(rm_contact != GLOBUS_NULL)
    {
	remote_cache(op, tag, url, rm_contact);
    }
    else
    {
	local_cache(op, tag, url);
    }
    return 0;
}

static char *
get_rm_contact(char *resource)
{
    LDAP *ldap_server;
    int port=389;
    char *base_dn="o=Globus, c=US";
    char *search_string;
    char *server = "mds.globus.org";
    LDAPMessage *reply;
    LDAPMessage *entry;
    char *attrs[3];
    
    attrs[0] = "contact";
    attrs[1] = "hn";
    attrs[2] = GLOBUS_NULL;
    
    if(strchr(resource, (int) ':') != GLOBUS_NULL)
    {
	return strdup(resource);
    }
	
    if((ldap_server = ldap_open(server, port)) == GLOBUS_NULL)
    {
	ldap_perror(ldap_server, "ldap_open");
	exit(1);
    }

    if(ldap_simple_bind_s(ldap_server, "", "") != LDAP_SUCCESS)
    {
	ldap_perror(ldap_server, "ldap_simple_bind_s");
	ldap_unbind(ldap_server);
	exit(1);
    }

    search_string=malloc(strlen(resource)+5);

    sprintf(search_string, "mn=%s", resource);
    
    if(ldap_search_s(ldap_server,
		     base_dn,
		     LDAP_SCOPE_SUBTREE,
		     search_string,
		     attrs,
		     0,
		     &reply) != LDAP_SUCCESS)
    {
	ldap_perror(ldap_server, "ldap_search");
	ldap_unbind(ldap_server);
	exit(1);
    }

    for(entry = ldap_first_entry(ldap_server, reply);
	entry != GLOBUS_NULL;
	entry = ldap_next_entry(ldap_server, entry))
    {
	char *contact;
	contact = get_contact_string(ldap_server, entry);
	if(contact != GLOBUS_NULL)
	{
	    ldap_unbind(ldap_server);
	    return contact;
	}
    }
    ldap_unbind(ldap_server);
    return GLOBUS_NULL;
}

static int
usage(char *n)
{
    char *m;

    m = n + strlen(n)-1;

    while(m != n)
    {
	if(*m == '/')
	{
	    m++;
	    break;
	}
	m--;
    }
    printf("usage: %s\n"
#if 0
	   "  add [-t tag] [-r resource_manager_contact|resource_manager] url\n"
	   "  delete [-t tag] [-r resource_manager_contact|resource_manager] url\n"
	   "  cleanup_tag [-t tag] [-r resource_manager_contact|resource_manager] [url]\n"
	   "  cleanup_file [-r resource_manager_contact|resource_manager] url\n"
	   "  list [-t tag] [-r resource_manager_contact|resource_manager] [url]\n",
#else
	   "  add [-t tag] url\n"
	   "  delete [-t tag] url\n"
	   "  cleanup_tag [-t tag] [url]\n"
	   "  cleanup_file url\n"
	   "  list [-t tag] [url]\n",
#endif
	   m);
    return 1;
}


char *
get_contact_string(LDAP *ldap_server, LDAPMessage* entry)
{
    char *a, *dn;
    BerElement *ber;
    char** values;
    int numValues;
    int i;
    char *contact=GLOBUS_NULL;

    for (a = ldap_first_attribute(ldap_server,entry,&ber); a != NULL;
	 a = ldap_next_attribute(ldap_server,entry,ber) )
    {
	values = ldap_get_values(ldap_server,entry,a);
	numValues = ldap_count_values(values);
	
	if(strcmp(a, "contact") == 0)
	{
	    contact = strdup(values[0]);
	    ldap_value_free(values);
	    break;
	}
    }
    return contact;
}

static char *
gassl_tag_arg(char *tag)
{
    static char arg[1024];

    if(tag != GLOBUS_NULL)
    {
	sprintf(arg,
		"-t %s",
		tag);
    }
    else
    {
	arg[0]='\0';
    }

    return arg;
}

static char *
gassl_op_string(gassl_cache_op_t op)
{
    static char str[1024];

    switch(op)
    {
    case GASSL_ADD:
	return "add";
    case GASSL_DELETE:
	return "delete";
    case GASSL_CLEANUP_TAG:
	return "cleanup_tag";
    case GASSL_CLEANUP_FILE:
	return "cleanup_file";
    case GASSL_LIST:
	return "list";
    default:
	return "";
    }
}

static void
callback_func(void *arg,
	      char *job_contact,
	      int state,
	      int errorcode)
{
    if(state == GLOBUS_GRAM_CLIENT_JOB_STATE_FAILED ||
       state == GLOBUS_GRAM_CLIENT_JOB_STATE_DONE)
    {
	globus_mutex_lock(&mutex);
	done = GLOBUS_TRUE;
	globus_cond_signal(&cond);
	globus_mutex_unlock(&mutex);
    }
}

static void
remote_cache(gassl_cache_op_t op,
	     char *tag,
	     char *url,
	     char *rm_contact)
{
    char spec[1024];
    char *server_url;
    unsigned short port=0;
    char *callback_contact;
    char *job_contact;
    
    globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);
    globus_gram_client_callback_allow(callback_func,
			       GLOBUS_NULL,
			       &callback_contact);
    
    globus_gass_server_ez_init(&port,
			&server_url,
			GLOBUS_GASS_SERVER_EZ_STDOUT_ENABLE|
			GLOBUS_GASS_SERVER_EZ_STDERR_ENABLE|
			GLOBUS_GASS_SERVER_EZ_LINE_BUFFER,
			(globus_gass_server_ez_client_shutdown_t) GLOBUS_NULL);


    sprintf(spec,
	    "&(executable=$(GLOBUS_PREFIX)/bin/globus_gass_cache)"
	    " (stdout=%s/dev/stdout)"
	    " (stderr=%s/dev/stdout)"
	    " (stdin=/dev/null)"
	    " (arguments='%s %s %s')",
	    server_url,
	    server_url,
	    gassl_op_string(op),
	    gassl_tag_arg(tag),
	    url == GLOBUS_NULL ? "" : url);

    globus_mutex_init(&mutex, GLOBUS_NULL);
    globus_cond_init(&cond, GLOBUS_NULL);

    globus_mutex_lock(&mutex);
    
    globus_gram_client_job_request(rm_contact,
			    spec,
			    31,
			    callback_contact,
			    &job_contact);
				
    while(!done)
    {
	globus_cond_wait(&cond, &mutex);
    }
    globus_mutex_unlock(&mutex);
    globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);
    globus_gass_server_ez_shutdown(port);
}

static void
local_cache(gassl_cache_op_t op,
	    char *tag,
	    char *url)
{
    globus_gass_cache_t cache_handle;
    unsigned long timestamp;
    char *local_filename;
    int rc;
    globus_gass_cache_entry_t *entries;
    int size=0;
    int i, j;
    
    globus_module_activate(GLOBUS_GASS_CLIENT_MODULE);
    globus_gass_cache_open(GLOBUS_NULL, &cache_handle);
    
    switch(op)
    {
    case GASSL_ADD:
	rc = globus_gass_cache_add(&cache_handle,
			    url,
			    tag,
			    GLOBUS_TRUE,
			    &timestamp,
			    &local_filename);
	if(rc == GLOBUS_GASS_CACHE_ADD_EXISTS)
	{
	    globus_gass_cache_add_done(&cache_handle,
				url,
				tag,
				timestamp);
	}
	else if(rc == GLOBUS_GASS_CACHE_ADD_NEW)
	{
	    int fd = open(local_filename, O_WRONLY|O_TRUNC);

	    globus_gass_client_get_fd(url,
			       GLOBUS_NULL,
			       fd,
			       GLOBUS_GASS_LENGTH_UNKNOWN,
			       &timestamp,
			       GLOBUS_NULL,
			       GLOBUS_NULL);
	    close(fd);
	    globus_gass_cache_add_done(&cache_handle,
				url,
				tag,
				timestamp);
	}
	free(local_filename);
	break;
    case GASSL_DELETE:
	globus_gass_cache_delete_start(&cache_handle,
				url,
				tag,
				&timestamp);
	globus_gass_cache_delete(&cache_handle,
			  url,
			  tag,
			  timestamp,
			  GLOBUS_TRUE);
	break;
    case GASSL_CLEANUP_TAG:
	if(url == GLOBUS_NULL)
	{
	    globus_gass_cache_list(&cache_handle,
			    &entries,
			    &size);

            for(i = 0; i < size; i++)
	    {
		globus_gass_cache_cleanup_tag(&cache_handle,
				       entries[i].url,
				       tag);
	    }
	    globus_gass_cache_list_free(entries, size);
	}
	else
	{
	    globus_gass_cache_cleanup_tag(&cache_handle,
			           url,
			           tag);
	}
	break;
	
    case GASSL_CLEANUP_FILE:
	globus_gass_cache_cleanup_file(&cache_handle,
				url);
	break;
    case GASSL_LIST:
	globus_gass_cache_list(&cache_handle,
			&entries,
			&size);

	for(i = 0; i < size; i++)
	{
	    if(url != GLOBUS_NULL)
	    {
		if(strcmp(url, entries[i].url) == 0)
		{
		    print_url(&entries[i], tag);
		}
	    }
	    else
	    {
		print_url(&entries[i], tag);
	    }
	}
	globus_gass_cache_list_free(entries, size);
	break;
    }
    globus_gass_cache_close(&cache_handle);
}

static void
print_url(globus_gass_cache_entry_t *entry,
	  char *tag)
{
    int j;
    globus_bool_t print_all_tags=GLOBUS_FALSE;

    if(tag == GLOBUS_NULL)
    {
	print_all_tags = GLOBUS_TRUE;
    }

    printf("%s\n", entry->url);
    for(j = 0; j < entry->num_tags; j++)
    {
	if(print_all_tags || strcmp(tag, entry->tags[j].tag) == 0)
	{
	    printf("\ttag '%s' (%i refs)\n",
		   entry->tags[j].tag,
		   entry->tags[j].count);
	}
    }
}

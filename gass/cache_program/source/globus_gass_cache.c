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
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include "lber.h"
#include "ldap.h"
#include "gram_client.h"
#include "globus_gass_server_ez.h"
#include "globus_gass_client.h"
#include "globus_gass_cache.h"

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
static void print_url(gass_cache_entry_t *entry,
		      char *tag);

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
	if(rm_contact != GLOBUS_NULL)
	{
	    printf("Should submit job through %s\n", rm_contact);
	}
	else
	{
	    printf("I don't know how to connect to resource '%s'\n", resource);
	    
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

    search_string=globus_malloc(strlen(resource)+5);

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

static void
remote_cache(gassl_cache_op_t op,
	     char *tag,
	     char *url,
	     char *rm_contact)
{
}

static void
local_cache(gassl_cache_op_t op,
	    char *tag,
	    char *url)
{
    gass_cache_t cache_handle;
    unsigned long timestamp;
    char *local_filename;
    int rc;
    gass_cache_entry_t *entries;
    int size=0;
    int i, j;
    
    gass_client_init();
    gass_cache_open(GLOBUS_NULL, &cache_handle);
    
    switch(op)
    {
    case GASSL_ADD:
	rc = gass_cache_add(&cache_handle,
			    url,
			    tag,
			    GLOBUS_TRUE,
			    &timestamp,
			    &local_filename);
	if(rc == GASS_CACHE_ADD_EXISTS)
	{
	    gass_cache_add_done(&cache_handle,
				url,
				tag,
				timestamp);
	}
	else if(rc == GASS_CACHE_ADD_NEW)
	{
	    int fd = open(local_filename, O_WRONLY|O_TRUNC);

	    gass_client_get_fd(url,
			       GLOBUS_NULL,
			       fd,
			       GASS_LENGTH_UNKNOWN,
			       &timestamp,
			       GLOBUS_NULL,
			       GLOBUS_NULL);
	    close(fd);
	    gass_cache_add_done(&cache_handle,
				url,
				tag,
				timestamp);
	}
	globus_free(local_filename);
	break;
    case GASSL_DELETE:
	gass_cache_delete_start(&cache_handle,
				url,
				tag,
				&timestamp);
	gass_cache_delete(&cache_handle,
			  url,
			  tag,
			  timestamp,
			  GLOBUS_TRUE);
	break;
    case GASSL_CLEANUP_TAG:
	if(url == GLOBUS_NULL)
	{
	    gass_cache_list(&cache_handle,
			    &entries,
			    &size);

            for(i = 0; i < size; i++)
	    {
		gass_cache_cleanup_tag(&cache_handle,
				       entries[i].url,
				       tag);
	    }
	    gass_cache_list_free(entries, size);
	}
	else
	{
	    gass_cache_cleanup_tag(&cache_handle,
			           url,
			           tag);
	}
	break;
	
    case GASSL_CLEANUP_FILE:
	gass_cache_cleanup_file(&cache_handle,
				url);
	break;
    case GASSL_LIST:
	gass_cache_list(&cache_handle,
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
	gass_cache_list_free(entries, size);
	break;
    }
    gass_cache_close(&cache_handle);
}

static void
print_url(gass_cache_entry_t *entry,
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

#include "globus_common.h"

/* 
#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
*/

#include <string.h>


#if !defined(PATH_MAX) && defined(MAXPATHLEN)
#   define PATH_MAX MAXPATHLEN 
#endif

/*
#include "globus_nexus.h"
#include "globus_duroc_control.h"
#include "globus_gram_client.h"
#include "globus_gass_server_ez.h"
#include "globus_rsl.h"
*/

#include "lber.h"
#include "ldap.h"

static char *
globus_rsl_assist_get_contact_string(LDAP *ldap_server, LDAPMessage* entry);


/******************************************************************************
Function: globus_rsl_assist_get_rm_contact()
 
Description: 
 
Parameters: 
 
Returns: 
******************************************************************************/
char *
globus_rsl_assist_get_rm_contact(char *resource)
{
    LDAP *ldap_server;
    int port=atoi(GLOBUS_MDS_PORT);
    char *base_dn=GLOBUS_MDS_ROOT_DN;
    char *search_string;
    char *server = GLOBUS_MDS_HOST;
    LDAPMessage *reply;
    LDAPMessage *entry;
    char *attrs[3];
    char *search_format=
	"(&(objectclass=GlobusResourceManager)"
	  "(|(cn=%s)))";
    attrs[0] = "contact";
    attrs[1] = GLOBUS_NULL;
    
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

    search_string=globus_malloc((2*strlen(resource))+
				strlen(search_format)+
				1);

    sprintf(search_string, search_format, resource, resource);
    
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
	contact = globus_rsl_assist_get_contact_string(ldap_server, entry);
	if(contact != GLOBUS_NULL)
	{
	    ldap_unbind(ldap_server);
	    return contact;
	}
    }
    ldap_unbind(ldap_server);
    return GLOBUS_NULL;
} /* globus_rsl_assist_get_rm_contact() */

/******************************************************************************
Function: globus_rsl_assist_get_contact_string()
 
Description: 
 
Parameters: 
 
Returns: 
******************************************************************************/
static char *
globus_rsl_assist_get_contact_string(LDAP *ldap_server,
				      LDAPMessage* entry)
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
} /* globus_rsl_assist_get_contact_string() */


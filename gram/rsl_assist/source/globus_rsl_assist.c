/******************************************************************************
 * globus_rsl_assist.c
 *
 * Description:
 *   The rsl_assist library provide a set of function to help parsing an RSL.
 *   It also contains some function to access the MDS; those function will be
 *   moved to a new library "mds_assist" in future release of GLOBUS.
 *   
 * CVS Information:
 *
 *   $Source$
 *   $Date$
 *   $Revision$
 *   $Author$
 *****************************************************************************/
#include "globus_common.h"

#include <string.h>


#if !defined(PATH_MAX) && defined(MAXPATHLEN)
#   define PATH_MAX MAXPATHLEN 
#endif

#include "lber.h"
#include "ldap.h"

/******************************************************************************
forward declarations 
******************************************************************************/
static char *
globus_l_rsl_assist_get_contact_string(LDAP *ldap_server, LDAPMessage* entry);
static char *
globus_l_rsl_assist_parse_ldap_reply(LDAP *ldap_server,
			LDAPMessage* entry);
static char *
globus_l_rsl_assist_query_ldap(char *resource);


/*
 * Function: globus_rsl_assist_replace_manager_name()
 *
 * Uses the Globus RSL library and the UMich LDAP
 * library to modify an RSL specification, changing instances of
 *
 * resourceManagerName=x
 *
 * with
 *
 * resourceManagerContact=y
 *
 * where y is obtained by querying the MDS ldap server, searching
 * for an object which matches the following filter
 *
 *   (&(objectclass=GlobusResourceManager)(cn=x))
 *
 * and extracting the contact value for that object.
 * 
 * Parameters: 
 *  
 * Returns: 
 */
int
globus_rsl_assist_replace_manager_name(globus_rsl_t * rsl)
{
    
} /* globus_rsl_assist_replace_manager_name() */

/*
 * Function: globus_rsl_assist_get_rm_contact()
 *
 * Parameters: 
 * 
 * Returns: 
 */
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
	contact = globus_l_rsl_assist_get_contact_string(ldap_server, entry);
	if(contact != GLOBUS_NULL)
	{
	    ldap_unbind(ldap_server);
	    return contact;
	}
    }
    ldap_unbind(ldap_server);
    return GLOBUS_NULL;
} /* globus_rsl_assist_get_rm_contact() */

/*
 * Function: globus_l_rsl_assist_get_contact_string()
 *
 * Parameters: 
 * 
 * Returns: 
 */
static
char *
globus_l_rsl_assist_get_contact_string(
    LDAP *ldap_server,
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
} /* globus_l_rsl_assist_get_contact_string() */

/*
 * Function: globus_l_rsl_assist_query_ldap()
 *
 * Connect to the ldap server, and search for the contact string
 * associated with the resourceManagerName.
 *
 * Parameters: 
 * 
 * Returns: 
 */ 
static
char *
globus_l_rsl_assist_query_ldap(
    char *resource)
{
    LDAP *			ldap_server;
    int				port=atoi(GLOBUS_MDS_PORT);
    char *			base_dn=GLOBUS_MDS_ROOT_DN;
    char *			search_string;
    char *			server = GLOBUS_MDS_HOST;
    LDAPMessage *		reply;
    LDAPMessage *		entry;
    char *			attrs[3];
    char *			search_format=
	"(&(objectclass=GlobusResourceManager)"
	  "(cn=%s))";

    /* connect to the ldap server */
    if((ldap_server = ldap_open(server, port)) == GLOBUS_NULL)
    {
	ldap_perror(ldap_server, "ldap_open");
	exit(1);
    }

    /* bind anonymously (we can only read public records now */
    if(ldap_simple_bind_s(ldap_server, "", "") != LDAP_SUCCESS)
    {
	ldap_perror(ldap_server, "ldap_simple_bind_s");
	ldap_unbind(ldap_server);
	exit(1);
    }


    /* malloc the string we will be filling with our query */
    search_string=globus_malloc(strlen(resource)+
				strlen(search_format)+
				1);

    /* format our query string */
    sprintf(search_string, search_format, resource);
    
    /* We are only interested in the "contact" attribute of
     * the object
     */
    attrs[0] = "contact";
    attrs[1] = GLOBUS_NULL;
	
    /* do a synchronous search of the entire ldap tree,
     * and return the desired attribute
     */
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

    /* we'll be satisfied with the first matching record
     * in the ldap directory
     */ 
    for(entry = ldap_first_entry(ldap_server, reply);
	entry != GLOBUS_NULL;
	entry = ldap_next_entry(ldap_server, entry))
    {
	char *contact;
	contact = parse_ldap_reply(ldap_server, entry);
	if(contact != GLOBUS_NULL)
	{
	    ldap_unbind(ldap_server);
	    return contact;
	}
    }
    /* disconnect from the server */
    ldap_unbind(ldap_server);
    return GLOBUS_NULL;
} /* globus_l_rsl_assist_query_ldap() */


/*
 * Function: globus_l_rsl_assist_parse_ldap_reply()
 *
 * Parse the ldap reply from the server, and obtain the "contact"
 * attribute
 *
 * Parameters: 
 * 
 * Returns: 
 */
static
char *
globus_l_rsl_assist_parse_ldap_reply(
    LDAP *ldap_server,
    LDAPMessage* entry)
{
    char *a, *dn;
    BerElement *ber;
    char** values;
    int numValues;
    int i;
    char *contact=GLOBUS_NULL;

    /* look at each record, and retrieve the desired "contact"
     * attribute
     */
    for (a = ldap_first_attribute(ldap_server,entry,&ber); a != NULL;
	 a = ldap_next_attribute(ldap_server,entry,ber) )
    {
	values = ldap_get_values(ldap_server,entry,a);
	numValues = ldap_count_values(values);
	
	/* got our match, so copy and return it*/
	if(strcmp(a, "contact") == 0)
	{
	    contact = strdup(values[0]);
	    ldap_value_free(values);
	    break;
	}
    }
    return contact;
} /* globus_l_rsl_assist_parse_ldap_reply() */


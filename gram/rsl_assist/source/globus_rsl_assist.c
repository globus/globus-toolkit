/******************************************************************************
 * globus_rsl_assist.c
 *
 * Description:
 *   The rsl_assist library provide a set of function to help working with
 *   an RSL.
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
#include "globus_rsl_assist.h"

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
globus_l_rsl_assist_parse_ldap_reply(
    LDAP *ldap_server,
    LDAPMessage* entry);
static char *
globus_l_rsl_assist_query_ldap(
    char *resource);


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
 *     rsl - Poiter to the RSL structure in which you want to replace the
 *     manager Name by its Contact
 * Returns:
 *     GLOBUS_SUCCESS or
 *     
 */
int
globus_rsl_assist_replace_manager_name(globus_rsl_t * rsl)
{
    /* only handles boolean requests of the form
     *     &(attr1=value1)(attr2=value2) ...
     * or
     *     |(attr1=value1)(attr2=value2) ...
     * or
     *     +(attr1=value1)(attr2=value2) ...
     * or a recursive nesting of the above, joined
     *     by one of the above operators:
     *     +
     *         (&(attr1=value1)(attr2=value2))
     *         (+(|(attr1=value1))
     *             (&(attr1=value1)(attr2=value2))
     *         )
     *         (|(attr1=value1)(attr2=value2))
     * 
     */
    int rc;
    globus_list_t *		lists;
    
    /*
     * if the request is a multirequest, run this function repeatedly 
     * over the list of requests
     */
    if (globus_rsl_is_boolean_multi(rsl))
    {
	lists = (globus_list_t *) globus_rsl_boolean_get_operand_list(rsl);
	while (!globus_list_empty(lists))
	{
	    rc=globus_rsl_assist_replace_manager_name(globus_list_first(lists));
	    lists=globus_list_rest(lists);
	}
	return rc;
    }

    /* if we are not a boolean operation, don't handle it */
    if(globus_rsl_is_boolean(rsl))
    {

	/* get the operands of the boolean operator, in the example
	 * of &(foo=x)(bar=y)
	 * this would be the list containing the relations
	 *   foo=x
	 *   bar=y
	 */
	lists = globus_rsl_boolean_get_operand_list(rsl);

	/* look at each operand of the boolean, and figure out if
	 * it is a nested boolean, or a relation (x=y)
	 */
	while(!globus_list_empty(lists))
	{
	    globus_rsl_t *	head;

	    head = globus_list_first(lists);

	    /* if boolean, recursively process the request */
	    if(globus_rsl_is_boolean(head))
	    {
		if((rc = globus_rsl_assist_replace_manager_name(head)) != 0)
		{
		    /* JST Should'nt I free some stuff here ? */
		    return rc;
		}
	    }
	    /* if a relation, check to see if it's one we can deal with */
	    else if(globus_rsl_is_relation_eq(head))
	    {
		/* RSL attributes are case insensitive */
		if(strcasecmp(globus_rsl_relation_get_attribute(head),
			      "resourceManagerName") == 0)
		{
		    globus_rsl_value_t * value;
		    
		    /* The value of a relation may be a
		           single literal:  "foo"
		           substitution: $(SOMETHING)
			   list: ("foo" $(SOMETHING))
		       We only deal with single literals here. lists
		       don't make sense as the value for a
		       resourceManagerName.

		       They are always stored as a sequence, but
		       the globus_rsl_relation_get_single_value
		       function will pull out the value of a single
		       literal
		     */
		    value = globus_rsl_relation_get_single_value(head);
		    
		    if(value == NULL)
		    {
			/* ill-formed RSL, abort */
			return GLOBUS_RSL_ASSIST_ERROR_RSL_INVALID;
		    }
		    else if(!globus_rsl_value_is_literal(value))
		    {
		        /* don't process substitutions */
			return GLOBUS_RSL_ASSIST_ERROR_MANAGER_NAME_IS_NOT_LITERAL;
		    }
		    else
		    {
			char * resource_name;
			char * resource_contact;
			globus_rsl_value_t * resource_contact_value;
			globus_rsl_t * resource_contact_relation;
			globus_list_t * sequence = GLOBUS_NULL;

			/* get the string of the value */
			resource_name =
			    globus_rsl_value_literal_get_string(value);
			
			/* query the ldap server to get a replacement */
			resource_contact =
			    globus_l_rsl_assist_query_ldap(resource_name);
			if (resource_contact == GLOBUS_NULL)
			{
			    
			    return GLOBUS_RSL_ASSIST_ERROR_GETTING_MANAGER_CONTACT;			    
			}

			/* make that into a sequence of a single literal
			 * remember that values are always sequences
			 */
			resource_contact_value = 
			    globus_rsl_value_make_literal(resource_contact);
			globus_list_insert(&sequence,
					   resource_contact_value);

			/* make a relation out of the desired attribute,
			 * and the new value:
			 * resourceManagerContact=<result>
		         */
			resource_contact_relation = 
			    globus_rsl_make_relation(
				GLOBUS_RSL_EQ,
				"resourceManagerContact",
				globus_rsl_value_make_sequence(
				    sequence));

#                       if 0
			/* Code replaced by globus_list_replace_first() below*/
			
			/* remove this node from the list of operands
			 * to the boolean
		         */
			
			globus_list_remove(
			    globus_rsl_boolean_get_operand_list_ref(rsl),
			    lists);
			globus_rsl_free(head);

			/* insert our new relation into the list */
			globus_list_insert(
			    globus_rsl_boolean_get_operand_list_ref(rsl),
					   (void *)resource_contact_relation);
#                       endif
			globus_list_replace_first(lists,
						  resource_contact_relation);
			globus_free(resource_contact);
		    }
		}
	    }
	    lists = globus_list_rest(lists);
	}	
    }
    return GLOBUS_SUCCESS;    
} /* globus_rsl_assist_replace_manager_name() */

/*
 * Function: globus_rsl_assist_get_rm_contact()
 *
 * Connect to the ldap server, and search for the contact string
 * associated with the resourceManagerName, by querying the MDS.
 *
 * For the moment, just a wrapper around globus_l_rsl_assist_query_ldap(),
 * until globus_l_rsl_assist_query_ldap(), get more general...
 *
 * Parameters:
 *    resourceManagerName - String containing the Name of the Resource Manager
 *
 * Returns:
 *    Pointer to a newly allocated string containing the Resource
 *    Manager Contact. This string MUST be freed by the user.
 *    OR
 *    GLOBUS_NULL in case of failure.
 */
char*
globus_i_rsl_assist_get_rm_contact(
    char* resource)
{
    return globus_l_rsl_assist_query_ldap(resource);
} /* globus_rsl_assist_get_rm_contact() */

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
	return GLOBUS_NULL;
    }

    /* bind anonymously (we can only read public records now */
    if(ldap_simple_bind_s(ldap_server, "", "") != LDAP_SUCCESS)
    {
	ldap_perror(ldap_server, "ldap_simple_bind_s");
	ldap_unbind(ldap_server);
	return GLOBUS_NULL;
    }


    /* malloc the string we will be filling with our query */
    search_string=globus_malloc(strlen(resource)+
				strlen(search_format)+
				1);
    if (search_string==GLOBUS_NULL)
    {
	ldap_unbind(ldap_server);	
	return GLOBUS_NULL;
    }
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
	/* ? ldap close ? */
	globus_libc_free(search_string);
	return GLOBUS_NULL;
    }

    /* we'll be satisfied with the first matching record
     * in the ldap directory
     */ 
    for(entry = ldap_first_entry(ldap_server, reply);
	entry != GLOBUS_NULL;
	entry = ldap_next_entry(ldap_server, entry))
    {
	char *contact;
	contact = globus_l_rsl_assist_parse_ldap_reply(ldap_server, entry);
	if(contact != GLOBUS_NULL)
	{
	    ldap_unbind(ldap_server);
	    globus_libc_free(search_string);
	    return contact;
	}
    }
    /* disconnect from the server */
    ldap_unbind(ldap_server);
    globus_libc_free(search_string);
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
    /* int numValues;*/
    int i;
    char *contact=GLOBUS_NULL;

    /* look at each record, and retrieve the desired "contact"
     * attribute
     */
    for (a = ldap_first_attribute(ldap_server,entry,&ber); a != NULL;
	 a = ldap_next_attribute(ldap_server,entry,ber) )
    {
	
	/* got our match, so copy and return it*/
	if(strcmp(a, "contact") == 0)
	{
	    values = ldap_get_values(ldap_server,entry,a);
	    /* numValues = ldap_count_values(values); */
	    contact = strdup(values[0]);
	    ldap_value_free(values);
	    break;
	}
    }
    return contact;
} /* globus_l_rsl_assist_parse_ldap_reply() */


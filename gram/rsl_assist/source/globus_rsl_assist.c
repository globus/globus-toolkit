/******************************************************************************
 * globus_rsl_assist.c
 *
 * Description:
 *   The rsl_assist library provide a set of functions to help working with
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
#include "globus_common.h"
#include "globus_rsl_assist.h"
#include "globus_i_rsl_assist.h"

#include <string.h>


#if !defined(PATH_MAX) && defined(MAXPATHLEN)
#   define PATH_MAX MAXPATHLEN 
#endif

/******************************************************************************
forward declarations 
******************************************************************************/

static 
int
globus_l_rsl_assist_simple_query_ldap(
    char *           attribute,
    int              maximum,
    char *           search_format,
    globus_list_t ** value_list);


/* XXX MEI XXX */
#if 0

/*
 * Function: globus_l_rsl_assist_query_ldap()
 *
 * Connect to the ldap server, and return all the value of the
 * fields "attribute" contained in the entry maching a search string.
 *
 * Parameters:
 *     attribute -     field for which we want the list of value returned.
 *     maximum -       maximum number of string returned in the list.
 *     search_string - Search string to use to select the entry for which
 *                     we will return the values of the field attribute.
 * 
 * Returns:
 *     a list of string containing the result.
 *     
 */ 
static
int
globus_l_rsl_assist_simple_query_ldap(
    char *            attribute,
    int               maximum,
    char *            search_string,
    globus_list_t **  value_list)
{
    LDAP *			ldap_server;
    int				port;
    char *			base_dn;
    char *			server;
    LDAPMessage *		reply;
    LDAPMessage *		entry;
    char *			attrs[3];
    int                         rc;
    
    * value_list = GLOBUS_NULL;
    
    rc = globus_i_rsl_assist_get_ldap_param(&server, &port, &base_dn);
    if (rc != GLOBUS_SUCCESS)
    {
	return -1;
    }

    /* connect to the ldap server */
    if((ldap_server = ldap_open(server, port)) == GLOBUS_NULL)
    {
	ldap_perror(ldap_server, "ldap_open");
	globus_libc_free(server);
	globus_libc_free(base_dn);
	return -1;
    }
    globus_libc_free(server);

    /* bind anonymously (we can only read public records now */
    if(ldap_simple_bind_s(ldap_server, "", "") != LDAP_SUCCESS)
    {
	ldap_perror(ldap_server, "ldap_simple_bind_s");
	ldap_unbind(ldap_server);
	globus_libc_free(base_dn);
	return -1;
    }

    
    /* I should verify the attribute is a valid string...     */
    /* the function allows only one attribute to be returned  */
    attrs[0] = attribute;
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
	globus_libc_free(base_dn);
	ldap_unbind(ldap_server);
	return -1;
    }
    globus_libc_free(base_dn);

    
    for ( entry = ldap_first_entry(ldap_server, reply);
	  (entry) && (maximum);
	  entry = ldap_next_entry(ldap_server, entry) )
    {
	char *         attr_value;
	char *         a;
	BerElement *   ber;
	int            numValues;
	char **        values;
	int            i;
	
	for (a = ldap_first_attribute(ldap_server,entry,&ber);
	     a;
	     a = ldap_next_attribute(ldap_server,entry,ber) )
	{
	    if (strcmp(a, attrs[0]) == 0)
	    {
		/* got our match, so copy and return it*/

		values = ldap_get_values(ldap_server,entry,a);
		numValues = ldap_count_values(values);
		for (i=0; i<numValues; i++)
		{
		    attr_value = strdup(values[i]);
		    globus_list_insert(value_list,attr_value);
		    if (--maximum==0)
			break;
		}
		ldap_value_free(values);
		
		/* we never have 2 time the same attibute for the same entry */
		break;
	    }
	}
    }
    /* disconnect from the server */
    ldap_unbind(ldap_server);
    /* to avoid a leak in ldap code */
    ldap_msgfree(reply);
    return GLOBUS_SUCCESS;
} /* globus_l_rsl_assist_simple_query_ldap() */


#else

/*
 * Function: globus_l_rsl_assist_query_ldap()
 *
 * Connect to the ldap server, and return all the value of the
 * fields "attribute" contained in the entry maching a search string.
 *
 * Parameters:
 *     attribute -     field for which we want the list of value returned.
 *     maximum -       maximum number of string returned in the list.
 *     search_string - Search string to use to select the entry for which
 *                     we will return the values of the field attribute.
 * 
 * Returns:
 *     a list of string containing the result.
 *     
 */ 
static int retrieve_attr_values(
    LDAP *            ldap_server,
    LDAPMessage *     reply,
    char *            attribute,
    int               maximum,
    char *            search_string,
    globus_list_t **  value_list)
{
    LDAPMessage *               entry;
    int cnt=0;
    
    for ( entry = ldap_first_entry(ldap_server, reply);
	  (entry) && (maximum);
	  entry = ldap_next_entry(ldap_server, entry) )
    {
	char *         attr_value;
	char *         a;
	BerElement *   ber;
	int            numValues;
	char **        values;
	int            i;
	
	for (a = ldap_first_attribute(ldap_server,entry,&ber);
	     a;
	     a = ldap_next_attribute(ldap_server,entry,ber) )
	{
	    if (strcmp(a, attribute) == 0)
	    {
		/* got our match, so copy and return it*/
                cnt++;
		values = ldap_get_values(ldap_server,entry,a);
		numValues = ldap_count_values(values);
		for (i=0; i<numValues; i++)
		{
		    attr_value = strdup(values[i]);
		    globus_list_insert(value_list,attr_value);
		    if (--maximum==0)
			break;
		}
		ldap_value_free(values);
		
		/* we never have 2 time the same attibute for the same entry,
                   steveF said this is not always the case XXX */
		break;
	    }
	}
    }
   return cnt;
} /* retrieve_attr_values */

static void set_ld_timeout(LDAP  *ld, int timeout_val, char *env_string)
{

  if(timeout_val > 0) {
    ld->ld_timeout=timeout_val;
    } else { /* check the environment variable */
      char *tmp=getenv(env_string);
      int tmp_int=0;
      if(tmp) tmp_int=atoi(tmp);
      if(tmp_int>0) ld->ld_timeout=tmp_int;
  }
}

static
int
globus_l_rsl_assist_simple_query_ldap(
    char *            attribute,
    int               maximum,
    char *            search_string,
    globus_list_t **  value_list)
{
    LDAP *			ldap_server;
    int				port;
    char *			base_dn;
    char *			server;
    LDAPMessage *		reply;
    LDAPMessage *		entry;
    char *			attrs[3];
    int                         rc;
    int                         match;
    
    * value_list = GLOBUS_NULL;
    match=0;
    
    rc = globus_i_rsl_assist_get_ldap_param(&server, &port, &base_dn);
    if (rc != GLOBUS_SUCCESS)
    {
	return -1;
    }

    /* connect to the ldap server */
    if((ldap_server = ldap_open(server, port)) == GLOBUS_NULL)
    {
	ldap_perror(ldap_server, "rsl_assist:ldap_open");
	globus_libc_free(server);
	globus_libc_free(base_dn);
	return -1;
    }
    globus_libc_free(server);

    set_ld_timeout(ldap_server, 0, "GRID_INFO_TIMEOUT");


    /* bind anonymously (we can only read public records now */
    if(ldap_simple_bind_s(ldap_server, "", "") != LDAP_SUCCESS)
    {
	ldap_perror(ldap_server, "rsl_assist:ldap_simple_bind_s");
	ldap_unbind(ldap_server);
	globus_libc_free(base_dn);
	return -1;
    }

    
    /* I should verify the attribute is a valid string...     */
    /* the function allows only one attribute to be returned  */
    attrs[0] = attribute;
    attrs[1] = GLOBUS_NULL;
    
    
    /* do a search of the entire ldap tree,
     * and return the desired attribute
     */
    if ( ldap_search( ldap_server, base_dn, LDAP_SCOPE_SUBTREE,
                          search_string, attrs, 0 ) == -1 ) {
        ldap_perror( ldap_server, "rsl_assist:ldap_search" );
        return( ldap_server->ld_errno );
    }

    while ( (rc = ldap_result( ldap_server, LDAP_RES_ANY, 0, NULL, &reply ))
            == LDAP_RES_SEARCH_ENTRY || ldap_server->ld_errno==LDAP_TIMEOUT) {
        if(ldap_server->ld_errno==LDAP_TIMEOUT) {
           continue;
        }
        match += retrieve_attr_values(ldap_server,reply, attrs[0],
                                 maximum, search_string, value_list);
        if(match) break; /* this is to follow the old globusrun code to return just 1 set */
    }

    if( rc == -1 ) {
      ldap_perror(ldap_server, "rsl_assist:ldap_search");
    }
    /* to avoid a leak in ldap code */
    ldap_msgfree(reply);

    /* disconnect from the server */
    ldap_unbind(ldap_server);
    globus_libc_free(base_dn);

    if(match)
      return GLOBUS_SUCCESS;
      else return rc;

} /* globus_l_rsl_assist_simple_query_ldap() */


#endif


/*
 * Function: globus_i_rsl_assist_get_user_job_list()
 *
 * Connect to the ldap server, and search for the contact string
 * associated with the resourceManagerName.
 *
 * Parameters: 
 * 
 * Returns: 
 */ 
int
globus_i_rsl_assist_get_user_job_list(
    char *           globaluserid,
    globus_list_t ** job_contact_list)
{
    char *     search_string;
    char *     format = "(&(objectclass=GlobusQueueEntry)(globalusername=%s))";

    search_string = globus_libc_malloc(strlen(format) + strlen(globaluserid));

    globus_libc_sprintf(search_string,format,globaluserid);

    return globus_l_rsl_assist_simple_query_ldap(
	"globaljobid",
	-1,
	search_string,
	job_contact_list);

} /* globus_i_rsl_assist_get_user_job_list() */


/*
 * Function:globus_i_rsl_assist_get_ldap_param()
 *
 * Assume arguments parsing has already overwritten env variable when
 * option -mdshost, -mdsport or -mdsbasedn used.
 */
int
globus_i_rsl_assist_get_ldap_param(char ** server,
				   int  *  port,
				   char ** base_dn)
{
    char *		       	port_str=GLOBUS_NULL;
    char *		       	tmp_port_str=GLOBUS_NULL;
    char *			tmp_base_dn=GLOBUS_NULL;
    char *			tmp_server=GLOBUS_NULL;
    char *                      inst_path=GLOBUS_NULL;
    char *                      mds_conf_path=GLOBUS_NULL;
    FILE *                      mds_conf;
    char                        buf[512];

    *server=GLOBUS_NULL;
    *base_dn=GLOBUS_NULL;
    
    if ((tmp_port_str=globus_libc_getenv("GRID_INFO_PORT"))!=GLOBUS_NULL)
    {
	globus_libc_lock();
	port_str=strdup(tmp_port_str);
	globus_libc_unlock();
	if (port_str==GLOBUS_NULL)
	{
	    goto globus_i_rsl_assist_get_ldap_param_ERR;
	}
    }
    if ((tmp_server  =globus_libc_getenv("GRID_INFO_HOST"))!=GLOBUS_NULL)
    {
	globus_libc_lock();
	*server=strdup(tmp_server);
	globus_libc_unlock();
	if (*server==GLOBUS_NULL)
	{
	    goto globus_i_rsl_assist_get_ldap_param_ERR;
	}
    }
    if ((tmp_base_dn =globus_libc_getenv("GRID_INFO_BASEDN"))!=GLOBUS_NULL)
    {
	globus_libc_lock();
	*base_dn=strdup(tmp_base_dn);
	globus_libc_unlock();
	if (*base_dn==GLOBUS_NULL)
	{
	    goto globus_i_rsl_assist_get_ldap_param_ERR;
	}
    }
    
    if (port_str==GLOBUS_NULL ||
	*server  ==GLOBUS_NULL ||
	*base_dn ==GLOBUS_NULL)
    {
	/* try to get them from conf file */
	globus_result_t res = globus_common_install_path( &inst_path );
	if (res != GLOBUS_SUCCESS)
	    goto globus_i_rsl_assist_get_ldap_param_ERR;

	mds_conf_path=globus_libc_malloc(strlen(inst_path)+
					 strlen("/etc/grid-info.conf")+1);
	if (mds_conf_path==GLOBUS_NULL)
	    goto globus_i_rsl_assist_get_ldap_param_ERR;

	globus_libc_sprintf(mds_conf_path,
			    "%s%s",
			    inst_path,
			    "/etc/grid-info.conf");

	mds_conf = fopen(mds_conf_path, "r");
	globus_libc_free(mds_conf_path);
        if(mds_conf != GLOBUS_NULL)
	{
	    while(fgets(buf, 512, mds_conf) != GLOBUS_NULL)
	    {
		/* break off comments */
		strtok(buf, "#");
		if(strlen(buf) > 0U)
		{
		    if(strncmp(buf,
			       "GRID_INFO_HOST=",
			       strlen("GRID_INFO_HOST=")) == 0)
		    {
			if (*server==GLOBUS_NULL)
			{
			    globus_libc_lock();
			    *server=strdup(buf+strlen("GRID_INFO_HOST=\""));
			    (*server)[strlen(*server)-2] = '\0';
			    globus_libc_unlock();
			}
		    }
		    else if(strncmp(buf,
				    "GRID_INFO_PORT=",
				    strlen("GRID_INFO_PORT=")) == 0)
		    {		    
			if (port_str==GLOBUS_NULL)
			{
			    globus_libc_lock();
			    port_str=strdup(buf+strlen("GRID_INFO_PORT=\""));
			    port_str[strlen(port_str)-2] = '\0';
			    globus_libc_unlock();
			}
		    }
		    else if(strncmp(buf,
				    "GRID_INFO_BASEDN=",
				    strlen("GRID_INFO_BASEDN=")) == 0)
		    {
			if (*base_dn ==GLOBUS_NULL)
			{
			    globus_libc_lock();
			    *base_dn= strdup(buf + strlen("GRID_INFO_BASEDN=\""));
			    (*base_dn)[strlen(*base_dn)-2] = '\0';
			    globus_libc_unlock();
			}
		    }
		}
	    }
	    fclose(mds_conf);
	}

    }
    /* fall back to defaults */
    if (*server  ==GLOBUS_NULL)
    {
	globus_libc_lock();
	*server=strdup(GRID_INFO_HOST);
	globus_libc_unlock();
    }
    if (*base_dn==GLOBUS_NULL)
    {
	globus_libc_lock();
	*base_dn=strdup(GRID_INFO_BASEDN);
	globus_libc_unlock();
    }
    if (port_str==GLOBUS_NULL)
    {
	*port=atoi(GRID_INFO_PORT);
    }
    else
    {
	*port=atoi(port_str);
	globus_libc_free(port_str);
    }

    /*globus_libc_printf("RESULT %s %s %d\n",*server,*base_dn, *port);
     */
    return GLOBUS_SUCCESS;
    
globus_i_rsl_assist_get_ldap_param_ERR:
	globus_libc_free(port_str);
	globus_libc_free(*server);
	globus_libc_free(*base_dn);
	globus_libc_free(mds_conf_path);
	return -1;
    
}/* globus_i_rsl_assist_get_ldap_param() */


/*
 * Function: globus_rsl_assist_attributes_canonicalize()
 *
 * Givin an RSL tree (parsed RSL), walk the tree finding all attributes of
 * RSL relations (i.e. (var=value) pairs) and canonicalize them by calling the
 * ..._string_canonicalize function.
 *
 * Returns:
 *     GLOBUS_SUCCESS or GLOBUS_FAILURE.  If GLOBUS_SUCCESS is returned then
 * any and all attributes contained in the passed in RSL tree will have been
 * canonicalized.
 */
int
globus_rsl_assist_attributes_canonicalize(globus_rsl_t * rsl)
{
 
    globus_list_t *             lists=GLOBUS_NULL;
    globus_rsl_t *              an_rsl;

    /*
     * if the request is a multirequest, run this function repeatedly
     * over the list of requests
     */
    if (globus_rsl_is_boolean_multi(rsl))
    {
        lists = (globus_list_t *) globus_rsl_boolean_get_operand_list(rsl);
        while (!globus_list_empty(lists))
        {
            an_rsl=globus_list_first(lists);
            if (globus_rsl_assist_attributes_canonicalize(an_rsl) 
                != GLOBUS_SUCCESS)
            {
                return GLOBUS_FAILURE;
            }
            lists=globus_list_rest(lists);
        }
        return GLOBUS_SUCCESS;
    }
    else if (globus_rsl_is_boolean(rsl))
    {
        lists = globus_rsl_boolean_get_operand_list(rsl);

        /* look at each operand of the boolean, and figure out if
         * it is a nested boolean, or a relation (x=y)
         */
        while(!globus_list_empty(lists))
        {
            an_rsl = globus_list_first(lists);

            /* if boolean, recursively process the request */
            if (globus_rsl_is_boolean(an_rsl))
            {
                if (globus_rsl_assist_attributes_canonicalize(an_rsl)
                       != GLOBUS_SUCCESS)
                {
                    return GLOBUS_FAILURE;
                }
            }
            else if (globus_rsl_is_relation(an_rsl))
            {
                globus_rsl_assist_string_canonicalize(
                       globus_rsl_relation_get_attribute(an_rsl));
            }
            lists = globus_list_rest(lists);
        }
        return GLOBUS_SUCCESS;
    }
    else if (globus_rsl_is_relation(rsl))
    {
        globus_rsl_assist_string_canonicalize(
               globus_rsl_relation_get_attribute(rsl));
    }
    else
    {
        return GLOBUS_FAILURE;
    }

    return GLOBUS_SUCCESS;

} /* globus_rsl_assist_attributes_canonicalize() */


/*
 * Function: globus_rsl_assist_string_canonicalize()
 *
 * Canonizing a string in this implementation means to remove any
 * underscores and moving all characters to lowercase.
 *
 * Returns: void
 */
void
globus_rsl_assist_string_canonicalize(char * ptr)
{
    char * tmp_p;

    if (ptr == GLOBUS_NULL)
        return;

    for (tmp_p=ptr; *ptr != '\0'; ptr++)
    {
        if ( *ptr == '_' )
        {
            continue;
        }

        *tmp_p = tolower(*ptr);
        tmp_p++;
    }
    *tmp_p = '\0';

    return;

} /* globus_rsl_assist_string_canonicalize() */

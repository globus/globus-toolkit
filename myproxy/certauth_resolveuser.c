#include "myproxy_common.h"

#ifdef HAVE_LIBLDAP
#include <ldap.h>
#endif

int resolve_via_mapfile ( char * username, char ** dn ) {

  int return_value = 0;
  char * userdn = NULL;

  myproxy_debug("resolve_via_mapfile()");

  if ( globus_gss_assist_map_local_user( username,
					 &userdn ) ) {
    return_value = 1;
    goto end;
  }

  *dn = userdn;

 end:
  if (return_value) {
    if (userdn) {
      free(userdn);
      userdn = NULL;
    }
  }
  return return_value;

}

#define DN_BUFFER_SIZE 512

int resolve_via_mapapp ( char * app_string, char * username, char ** dn ) {

  pid_t childpid;
  int fds[3];
  int return_value = 0;
  char * userdn = NULL;
  FILE * app_stream = NULL;
  int exit_status;

  myproxy_debug("resolve_via_mapapp(%s, %s)", app_string, username);

  userdn = malloc(DN_BUFFER_SIZE);
  if (userdn == NULL) {
    verror_put_string("malloc() failed.");
    goto end;
  }
  memset(userdn, '\0', DN_BUFFER_SIZE);

  if ((childpid = myproxy_popen(fds, app_string, username, NULL)) < 0) {
     return -1; /* myproxy_popen will set verror */
  }
  close(fds[0]);

  /* wait for child */
  if (waitpid(childpid, &exit_status, 0) == -1) {
      verror_put_string("wait() failed for mapapp child");
      verror_put_errno(errno);
      return -1;
  }

  if (exit_status != 0) {
      FILE *fp = NULL;
      char buf[100];
      verror_put_string("Mapping call-out returned error");
      fp = fdopen(fds[1], "r");
      if (fp) {
	  while (fgets(buf, 100, fp) != NULL) {
	      verror_put_string(buf);
	  }
	  fclose(fp);
      } else {
	  close(fds[1]);
      }
      fp = fdopen(fds[2], "r");
      if (fp) {
	  while (fgets(buf, 100, fp) != NULL) {
	      verror_put_string(buf);
	  }
	  fclose(fp);
      } else {
	  close(fds[2]);
      }
      return_value = 1;
      goto end;
  }
  close(fds[2]);

  app_stream = fdopen(fds[1], "r");

  if (fgets(userdn, DN_BUFFER_SIZE, app_stream) == NULL) {
    fclose(app_stream);
    verror_put_string("Error reading from mapping application.");
    return_value = 1;
    goto end;
  }

  fclose(app_stream);
  app_stream = NULL;

  /* Chop trailing newline if present */
  if (userdn[strlen(userdn) - 1] == '\n') {
    userdn[strlen(userdn) - 1] = '\0';
  }

  if (strlen(userdn) == 0) {
    verror_put_string("Got zero-length DN from mapping application.");
    return_value = 1;
    goto end;
  }

  *dn = userdn;

 end:
  if (return_value) {
    if (userdn) {
      free(userdn);
      userdn = NULL;
    }
    *dn = NULL;
  }
  return return_value;

}


#ifdef HAVE_LIBLDAP

int resolve_via_ldap    ( char * username, char ** dn,
			  myproxy_server_context_t *server_context ) {

  int return_value = 0;

  char * userdn = NULL;

  LDAP *ld = NULL;
  int rc;

  int ldap_version = LDAP_VERSION3;
  char * binduser = NULL;

  struct berval   cred;
  struct berval   *servcred;

  LDAPMessage *results = NULL;
  LDAPMessage *entry = NULL;

  char * dnbuffer = NULL;
  char * searchfilter = NULL;

  char * attr;
  BerElement *ber = NULL;
  struct berval **vals = NULL;
  int found_attribute;

  LDAPDN tmpDN;
  int dn_set = 0;

  size_t filterlen;

  myproxy_debug("resolve_via_ldap()");
  myproxy_debug("ca_ldap_server: %s", 
		server_context->ca_ldap_server);
  myproxy_debug("ca_ldap_uid_attribute: %s", 
		server_context->ca_ldap_uid_attribute);
  myproxy_debug("ca_ldap_searchbase: %s", 
		server_context->ca_ldap_searchbase);
  myproxy_debug("ca_ldap_connect_dn: %s", 
		server_context->ca_ldap_connect_dn);
  myproxy_debug("ca_ldap_connect_passphase: %s", 
		server_context->ca_ldap_connect_passphrase);
  myproxy_debug("ca_ldap_dn_attribute: %s", 
		server_context->ca_ldap_dn_attribute);

  /* check directives to make sure all is in order.... */

  if ( server_context->ca_ldap_uid_attribute == NULL ) {
    verror_put_string("Required directive ca_ldap_uid_attribute not set.");
    return_value = 1;
    goto end;
  }

  if ( server_context->ca_ldap_searchbase == NULL ) {
    verror_put_string("Required directive ca_ldap_searchbase not set.");
    return_value = 1;
    goto end;
  }

  /* prodeed with the connection */

  rc = ldap_initialize( &ld, server_context->ca_ldap_server );

  if ( rc != LDAP_SUCCESS ) {
    verror_put_string("ldap_initialize() failed");
    verror_put_string("ldap_initialize(): %s", ldap_err2string( rc ) );
    return_value = 1;
    goto end;
  } else {
    myproxy_debug("LDAP initialized");
  }

  rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);

  if ( rc != LDAP_SUCCESS ) {
    verror_put_string("ldap_set_option() failed");
    verror_put_string("ldap_set_option(): %s", ldap_err2string( rc ) );
    return_value = 1;
    goto end;
  } else {
    myproxy_debug("LDAP version set to V.3");
  }

  if ( server_context->ca_ldap_connect_passphrase != NULL ) {
    cred.bv_val = server_context->ca_ldap_connect_passphrase;
    cred.bv_len = sizeof(server_context->ca_ldap_connect_passphrase) - 1;
  } else {
    cred.bv_val = "";
    cred.bv_len = sizeof("") - 1;
  }

  if ( server_context->ca_ldap_connect_dn != NULL ) {
    binduser = strdup( server_context->ca_ldap_connect_dn );
  } else {
    binduser = strdup("");
  }

  /* NOTE: the other bind functions have been deprecated out of the current
     openldap api.  Even though this has the rather misleading name of
     _sasl_bind_, this is the function currently in favor and it is
     only performing a vanilla ldap simple authentication - mmg */

  rc = ldap_sasl_bind_s(ld, binduser, LDAP_SASL_SIMPLE,
			&cred, NULL, NULL, &servcred);

  if ( rc != LDAP_SUCCESS ) {
    verror_put_string("ldap_sasl_bind() failed");
    verror_put_string("ldap_sasl_bind(): %s", ldap_err2string( rc ) );
    return_value = 1;
    goto end;
  } else {
    myproxy_debug("Bind to %s successful", server_context->ca_ldap_server );
  }

  /* set up query filter strings and run the search */

  filterlen = strlen( server_context->ca_ldap_uid_attribute ) \
    + strlen( username ) + 4;

  searchfilter = malloc( filterlen );
  memset( searchfilter, '\0', filterlen );

  sprintf(searchfilter, "(%s=%s)", server_context->ca_ldap_uid_attribute,
	  username);

  myproxy_debug("Using search filter: %s", searchfilter);

  rc = ldap_search_ext_s(ld, server_context->ca_ldap_searchbase,
			 LDAP_SCOPE_SUBTREE, searchfilter, NULL, 0,
			 NULL, NULL, NULL, 0, &results);

  if ( rc != LDAP_SUCCESS ) {
    verror_put_string("ldap_search_ext_s() failed");
    verror_put_string("ldap_search_ext_s(): %s", ldap_err2string( rc ) );
    return_value = 1;
    goto end;
  } else {
    myproxy_debug("Search on base %s successful", 
		  server_context->ca_ldap_searchbase );
  }

  /* look at what we got back.... */

  if ( ldap_count_entries(ld, results) != 1 ) {
    verror_put_string("LDAP search returned %d results - resolution failed",
		      ldap_count_entries(ld, results));
    return_value = 1;
    goto end;
  } else {
    myproxy_debug("LDAP query returned one result - processing");
  }

  entry = ldap_first_entry( ld, results );

  if ( entry == NULL ) {
    verror_put_string("Error getting ldap entry from search results");
    return_value = 1;
    goto end;
  } else {
    myproxy_debug("Obtained LDAP entry from search results");
  }

  /* extract and process the DN - the default is to use the dn of the
     retrieved record.  If ca_ldap_dn_attribute is specified, attempt
     to retrieve a value from the specified attribute */

  if ( server_context->ca_ldap_dn_attribute != NULL ) {

    myproxy_debug("Pulling DN from attribute");

    found_attribute = 0;

    for ( attr = ldap_first_attribute( ld, entry, &ber ) ;
	  attr != NULL ; attr = ldap_next_attribute( ld, entry, ber ) ) {

      if ( strcmp( attr, server_context->ca_ldap_dn_attribute ) == 0 ) {

	myproxy_debug("Found attribute: %s", attr );

	if ( ( vals = ldap_get_values_len( ld, entry, attr ) ) == NULL ) {
	  myproxy_debug("No value found for attribute %s", attr);
	  break;
	} else {
	  myproxy_debug("Attribute value: %s", vals[0]->bv_val );
	  dnbuffer = strdup( vals[0]->bv_val );
	  found_attribute = 1;
	  break;
	}
      }
    }

    if ( !found_attribute ) {
      verror_put_string("DN Attribute Error");
      verror_put_string("Could not find attribute/value pair");
      return_value = 1;
      goto end;
    }

  } else {

    myproxy_debug("Using record DN");

    dnbuffer = ldap_get_dn(ld, entry);

  }

  if ( dnbuffer == NULL ) {
    verror_put_string("Could not obtain DN from search entry");
    return_value = 1;
    goto end;
  } else {
    myproxy_debug("Obtained DN: %s", dnbuffer);
  }

  /* attempt to parse and load the dn input */

  if ( ldap_str2dn( dnbuffer, &tmpDN, LDAP_DN_FORMAT_LDAPV3 ) 
       == LDAP_SUCCESS ) {
    myproxy_debug("LDAP V3 Style DN");
  } else if ( ldap_str2dn( dnbuffer, &tmpDN, LDAP_DN_FORMAT_LDAPV2 ) 
	      == LDAP_SUCCESS ) {
    myproxy_debug("LDAP V2 Style DN");
  } else if ( ldap_str2dn( dnbuffer, &tmpDN, LDAP_DN_FORMAT_DCE ) 
	      == LDAP_SUCCESS ) {
    myproxy_debug("DCE Style DN");
  } else {
    /* give up then */
    verror_put_string("Could not parse DN: %s", dnbuffer);
    return_value = 1;
    goto end;
  }

  dn_set = 1;

  /* recover the DN in DCE format */

  if ( ldap_dn2str(tmpDN, &userdn, LDAP_DN_FORMAT_DCE) != LDAP_SUCCESS ) {
    verror_put_string("Error formatting DN to DCE format");
    return_value = 1;
    goto end;
  } else {
    myproxy_debug("Fomatted DN: %s", userdn);
  }

  *dn = userdn;

 end:

  if (return_value) {
    if (userdn) {
      free(userdn);
      userdn = NULL;
    }
  }

  /* also free()s the ld pointer */
  ldap_unbind_ext_s( ld, NULL, NULL );

  if (binduser != NULL) {
    free(binduser);
    binduser = NULL;
  }

  if (searchfilter != NULL) {
    free(searchfilter);
    searchfilter = NULL;
  }
  if (results != NULL) {
    ldap_msgfree(results);
    results = NULL;
  }
  if (dnbuffer != NULL) {
    free(dnbuffer);
    dnbuffer = NULL;
  }
  if ( servcred != NULL ) {
    ldap_memfree( servcred );
  }
  if ( dn_set ) {
    ldap_dnfree( tmpDN );
  }
  if ( ber != NULL ) {
    ber_free( ber, 0 );
  }
  if ( server_context->ca_ldap_dn_attribute != NULL ) {
    if ( vals != NULL ) {
      ber_bvecfree( vals );
    }
  }

  return return_value;

}

#else /* ldap resolution configured but server not built with ldap support */

int resolve_via_ldap    ( char * username, char ** dn,
			  myproxy_server_context_t *server_context ) {

  verror_put_string("CA NOT build with LDAP support");
  verror_put_string("Can not do user -> DN resolution via ldap");
  return(1);

}

#endif  /* HAVE_LIBLDAP */

int user_dn_lookup( char * username, char ** dn,
		    myproxy_server_context_t *server_context ) {

  int return_value = 0;
  char * userdn = NULL;

  myproxy_debug("user_dn_lookup()");

  if ( server_context->ca_ldap_server != NULL ) {
    if ( resolve_via_ldap( username, &userdn, server_context ) ) {
      verror_put_string("Failed to map username to DN via LDAP");
      return_value = 1;
      goto end;
    }
  } else if (server_context->certificate_mapapp != NULL) {
    if (resolve_via_mapapp( server_context->certificate_mapapp,
			    username, &userdn ) ) {
      verror_put_string("Failed to map username to DN via call-out");
      return_value = 1;
      goto end;
    }
  } else {
    if ( resolve_via_mapfile( username, &userdn ) ) {
      verror_put_string("Failed to map username to DN via grid-mapfile");
      return_value = 1;
      goto end;
    }
  }

  *dn = userdn;

 end:
  if (return_value) {
    if (userdn) {
      free(userdn);
      userdn = NULL;
    }
  }
  return return_value;

}

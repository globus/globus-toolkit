/*
  Defines a function to be called by myproxy_server.c and certauth_extensions.c
  to do username to DN resolution when the internal CA is being used.
  The mode of resolution (grid-mapfile or ldap query) is decided on the basis
  of configuration file directives.  Returns a slash-delimited DN.
*/


int user_dn_lookup( char *  username, char ** userdn,
		    myproxy_server_context_t *server_context );

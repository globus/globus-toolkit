/*
 * gssapi-local.h
 *
 * Local gssapi include file not to be confused with the gssapi.h file.
 */

#ifndef __GSSAPI_LOCAL_H
#define __GSSAPI_LOCAL_H	1

/* All of these are in gssapi.c */
void gssapi_setup_environment();
char *gssapi_identity();
int gssapi_check_authorization();
int gssapi_unwrap_message();
int gssapi_wrap_message();
int gssapi_can_encrypt();
int gssapi_handle_auth_data();

#ifdef GSSAPI_GLOBUS
char *globus_local_name();
#endif /* GSSAPI_GLOBUS */

#endif /* ! __GSSAPI_LOCAL_H */

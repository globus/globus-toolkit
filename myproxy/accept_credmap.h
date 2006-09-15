/*
 * @file    accept_credmap.h
 * @author  Terry Fleury (tfleury@ncsa.uiuc.edu)
 * @version 3.7 2006-09-15
 * 
 * This function is called by myproxy_server.c.  When one of 
 * accepted_credentials_mapfile or accepted_credentials_mapapp has been
 * defined in the config file, we need to check if the userdn / username
 * combination is valid.  If the mapfile is used, then we check if there is
 * a line containing the userdn and username.  If the mapapp is used, then
 * the call-out should accept the userdn and username as parameters and
 * return a zero value if that combination is acceptable.  Basically, we
 * want to restrict a credential (which has a particular userdn) to be
 * stored under a particular username.  This function returns 0 upon success
 * (either the userdn/username was successfully mapped by the mapfile or the
 * mapapp, or there was no need to consult a mapfile or mapapp) and 1 upon
 * failure.
 *
 * @param userdn         The C-string credential user (subject)
 *                       distinguished name.
 * @param username       The C-string username for storing the credential.
 * @param server_context A pointer to the server context for the current
 *                       request.
 * @return 0 upon successful mapping of userdn/username (or if no accepted
 *         credentials map check was necessary), 1 upon failure.
 */

#ifndef __ACCEPT_CREDMAP_H
#define __ACCEPT_CREDMAP_H

int accept_credmap( char * userdn, char * username,
                    myproxy_server_context_t * server_context );

#endif /* __ACCEPT_CREDMAP_H */


/*
 * globus_i_rsl_assist.h
 *
 * Description:
 *
 *   This header contains the interface prototypes for some internal function
 *   from globus_rsl_assist.a. Those function are kept internal because they 
 *   should be moved in the future in a new "mds_assist" library. 
 *   
 * CVS Information:
 *
 * $Source$
 * $Date$
 * $Revision$
 * $Author$
 */
#ifndef _GLOBUS_I_RSL_ASSIST_INCLUDE_GLOBUS_RSL_ASSIST_H_
#define _GLOBUS_I_RSL_ASSIST_INCLUDE_GLOBUS_RSL_ASSIST_H_

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

/*
 * Function:globus_i_rsl_assist_get_ldap_param()
 *
 * This function return the correct values to use when contacting/searching
 * the MDS, as defined below:
 *
 * - Scan the environment variable GRID_INFO_PORT, GRID_INFO_HOST and
 *   GRID_INFO_BASE_DN and return there value if set.
 *   Assumes arguments parsing has already overwritten env variable when
 *   option -mdshost, -mdsport or -mdsbasedn used.
 * - for each one not set, search for a grid-info.conf file and uses its
 *   content to return a value. To determine the path to the file, use first
 *   the environment variable GLOBUS_INSTALL_PATH if set; if not set, uses
 *   GLOBUS_SYSCONFDIR, as defined at compile time;
 * - If a value is still not defined after checking env variables
 *   and grid-info.conf, uses the default -hard coded at compile time- values.
 *
 * Parameters:
 *     server  -  name of the MDS ldap server to contact
 *     port    -  port to use when contacting the above server
 *     base_dn -  DN to use as root for query/search on the above server.
 *
 * Note : server and base_dn are dynamically allocated strings which must be
 *        freed by the user when not used any more
 *
 * Returns:
 *     GLOBUS_SUCCESS or error code
 */
int
globus_i_rsl_assist_get_ldap_param(char ** server,
				   int *   port,
				   char ** base_dn);
				   
#endif



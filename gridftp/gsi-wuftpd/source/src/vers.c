/*!

@file vers.c
@brief Replace shell script to generate version string
@date 7/30/02

*/

#include "config.h"
#include "globus_common.h"
#include "version.h"

// Global, allocated at runtime
char* version;

#define GSI_WUFTP_VER_LEN_MAX 128

/*!
@brief Builds global version string from module information

This calls globus_module_get_version to build the servers' version
string that it sends to clients. This replaces the shell script 
newvers.sh / Makefile combination.

Designed to be called once at startup by main() to populate 
the variable.

@retval
       - GLOBUS_SUCCESS 
       - GLOBUS_FAILURE if malloc fails

@date 7/3/02
*/

int 
gsi_wuftp_get_version(void)
{
  int                           rc;
  const char                    server_name[] = "GridFTP Server";
  const char                    gsi_string[] = 
    " -- CAS enabled [GSI patch 0.5] wu-2.6.2(1)";

  /* Allocate space in the global space for the version string */
  version = globus_libc_malloc(sizeof(char) * GSI_WUFTP_VER_LEN_MAX);
  if(version == GLOBUS_NULL)
    return(GLOBUS_FAILURE);

  rc = globus_libc_sprintf(version, "%s %d.%d %s (%d, %d)",
			   server_name,
			   local_version.major,
			   local_version.minor,
			   gsi_string,
			   local_version.timestamp,
			   local_version.branch_id);

  return(GLOBUS_SUCCESS);
}

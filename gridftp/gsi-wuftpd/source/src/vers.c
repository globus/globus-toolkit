/*!

@file vers.c
@brief Replace shell script to generate version string
@date 7/30/02

*/

/* to remove dependency on globus common */
typedef struct
{
    int                                 major;
    int                                 minor;
    unsigned long                       timestamp;
    int                                 branch_id;
} globus_version_t;

#include "config.h"
#include "version.h"

/* Global, allocated at runtime */
char* version;

#define GSI_WUFTP_VER_LEN_MAX 1024

/*!
@brief Builds global version string from module information

This calls globus_module_get_version to build the servers' version
string that it sends to clients. This replaces the shell script 
newvers.sh / Makefile combination.

Designed to be called once at startup by main() to populate 
the variable.

@retval
       - 0 
       - 1 if malloc fails

@date 7/3/02
*/

int 
gsi_wuftp_get_version(void)
{
  int                           rc;

  /* Allocate space in the global space for the version string */
  version = malloc(sizeof(char) * GSI_WUFTP_VER_LEN_MAX);
  if(version == NULL)
    return(0);

  rc = sprintf(
      version,
      "GridFTP Server %d.%d"
#ifdef GLOBUS_AUTHORIZATION
      " CAS/SAML enabled" 
#endif
      " GSSAPI type"
#ifdef GSSAPI_GLOBUS
      " Globus/GSI"
#endif
#ifdef GSSAPI_KRB5
      " Kerberos 5"
#endif
      " wu-2.6.2 (%s, %lu-%d)",
      local_version.major,
      local_version.minor,
      flavor,
      local_version.timestamp,
      local_version.branch_id);

  return(0);
}


#include "globus_common.h"
#if defined(HAVE_NETDB_H)
#    include <netdb.h>
#endif

#if !defined(MAXHOSTNAMELEN)
#    define MAXHOSTNAMELEN 1024
#endif

int main()
{
    int rc;
    char host[MAXHOSTNAMELEN];

    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    rc = globus_libc_gethostname(host, MAXHOSTNAMELEN);
    if(rc != GLOBUS_SUCCESS)
    {
	return rc;
    }

    globus_libc_printf("%s\n", host);

    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    return 0;
}

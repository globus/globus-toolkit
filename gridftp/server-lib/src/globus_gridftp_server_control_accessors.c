#include "globus_i_gridftp_server_control.h"
#include "version.h"
#include <sys/utsname.h>

/*************************************************************************
 *                      get functions
 *                      -------------
 ************************************************************************/
globus_bool_t
globus_gridftp_server_control_authenticated(
    globus_gridftp_server_control_t         server)
{
    globus_bool_t                           rc;
    globus_i_gsc_server_handle_t *          i_server;
    GlobusGridFTPServerName(globus_gridftp_server_control_authenticated);

    i_server = (globus_i_gsc_server_handle_t *) server;

    if(server == NULL)
    {
        return GLOBUS_FALSE;
    }

    return rc;
}

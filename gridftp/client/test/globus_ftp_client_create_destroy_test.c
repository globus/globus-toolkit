/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

/*
 * Verify that handle destruction works even if no operation was done
 * on the handle.
 */
#include "globus_ftp_client.h"

int main()
{
    globus_ftp_client_handle_t			handle;
    globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    globus_ftp_client_handle_init(&handle, GLOBUS_NULL);
    globus_ftp_client_handle_destroy(&handle);
    globus_module_deactivate_all();

    return 0;
}

/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

/*
 * Copyright 1999-2008 University of Chicago
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

#include "gssapi.h"
#include "globus_gss_assist.h"

#define SIZEOF_ARRAY(a) (sizeof(a) / sizeof(a[0]))

int
main(int argc, char *argv[])
{
    char *dn, *local_username;
    int rc;
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s dn local-username\n", argv[0]);
        exit(1);
    }
    dn = argv[1];
    local_username = argv[2];

    rc = globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
    if (rc != 0)
    {
        fprintf(stderr, "Error activating GLOBUS_GSI_GSS_ASSIST_MODULE\n");
        exit(1);
    }

    rc = globus_gss_assist_userok(dn, local_username);
    if (rc != 0)
    {
        fprintf(stderr, "globus_gss_assist_userok failed [%s for %s]\n", local_username, dn);
        exit(1);
    }

    exit(0);
}
/* main() */

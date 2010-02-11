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

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_i_url_sync_activation.c
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#include "globus_url_sync.h"
#include "globus_i_url_sync.h"
#include "globus_i_url_sync_log.h"
#include "globus_ftp_client.h"
#include "globus_common_include.h"
#include "version.h"

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL

static int globus_l_url_sync_activate(void);
static int globus_l_url_sync_deactivate(void);

/**
 * Module descriptor.
 */
globus_module_descriptor_t		globus_i_url_sync_module =
{
    "globus_url_sync",
    globus_l_url_sync_activate,
    globus_l_url_sync_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Module activation
 */
static
int
globus_l_url_sync_activate(void)
{
    char *                              tmp_string;

    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_FTP_CLIENT_MODULE);
    globus_i_url_sync_log_activate();

    tmp_string = globus_module_getenv(GLOBUS_URL_SYNC_LOGLEVEL);
    if(tmp_string != GLOBUS_NULL)
    {
	int log_level = atoi(tmp_string);

	if(log_level < 0)
	{
	    log_level = 0;
	}

        globus_url_sync_log_set_level((globus_url_sync_log_level_t) log_level);
    }

    globus_i_url_sync_log_write(GLOBUS_URL_SYNC_LOG_LEVEL_VERBOSE,
            "Activated: %s\n",
            globus_i_url_sync_module.module_name);

    return GLOBUS_SUCCESS;
}


/**
 * Module deactivation
 */
static
int
globus_l_url_sync_deactivate(void)
{
	globus_i_url_sync_log_debug(
        "Deactivating: %s\n",
        globus_i_url_sync_module.module_name);

    globus_i_url_sync_log_deactivate();
    globus_module_deactivate(GLOBUS_FTP_CLIENT_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
    return GLOBUS_SUCCESS;
}

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

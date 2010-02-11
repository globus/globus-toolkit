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
 * CVS Information
 *
 * $Source$
 * $Date$
 * $Revision$
 */

#ifndef _GLOBUS_I_URL_SYNC_ARGS_H
#define _GLOBUS_I_URL_SYNC_ARGS_H

#include "globus_url.h"
#include "globus_common_include.h"

EXTERN_C_BEGIN

extern globus_url_t *           globus_i_url_sync_args_source;
extern globus_url_t *           globus_i_url_sync_args_destination;
extern globus_bool_t            globus_i_url_sync_args_verbose;
extern globus_bool_t            globus_i_url_sync_args_debug;
extern globus_bool_t			globus_i_url_sync_args_modify;
extern globus_bool_t			globus_i_url_sync_args_size;
extern globus_bool_t			globus_i_url_sync_args_filetype;
extern globus_bool_t			globus_i_url_sync_args_cache;

globus_result_t globus_i_url_sync_parse_args(int argc, char *argv[]);

EXTERN_C_END

#endif /* _GLOBUS_I_URL_SYNC_ARGS_H */

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
 * @file globus_i_url_sync.h
 * Globus URL Synchronize Library
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#ifndef _GLOBUS_I_URL_SYNC_H
#define	_GLOBUS_I_URL_SYNC_H

#include "globus_common_include.h"

#ifndef EXTERN_C_BEGIN
#   ifdef  __cplusplus
#       define EXTERN_C_BEGIN extern "C" {
#       define EXTERN_C_END }
#   else
#       define EXTERN_C_BEGIN
#       define EXTERN_C_END
#   endif
#endif

#define GLOBUS_I_URL_SYNC_ERROR_NULL_PARAMETER(param) \
	globus_error_construct_error(\
		GLOBUS_URL_SYNC_MODULE,\
		GLOBUS_NULL,\
		GLOBUS_URL_SYNC_ERROR_PARAMETER, \
		__FILE__, \
		_globus_func_name, \
		__LINE__, \
		"a NULL value for %s was used", param)

#define GLOBUS_I_URL_SYNC_ERROR_INVALID_PARAMETER(param) \
	globus_error_construct_error(\
		GLOBUS_URL_SYNC_MODULE,\
		GLOBUS_NULL,\
		GLOBUS_URL_SYNC_ERROR_PARAMETER, \
		__FILE__, \
		_globus_func_name, \
		__LINE__, \
		"an invalid value for %s was used", param)

#define GLOBUS_I_URL_SYNC_ERROR_INVALID_PARAMETER_URL(param) \
	globus_error_construct_error(\
		GLOBUS_URL_SYNC_MODULE,\
		GLOBUS_NULL,\
		GLOBUS_URL_SYNC_ERROR_PARAMETER, \
		__FILE__, \
		_globus_func_name, \
		__LINE__, \
		"URL (%s) must be a directory (must end with \"/\")", param)
        
#define GLOBUS_I_URL_SYNC_ERROR_OUT_OF_MEMORY() \
	globus_error_construct_error(\
		GLOBUS_URL_SYNC_MODULE,\
		GLOBUS_NULL,\
		GLOBUS_URL_SYNC_ERROR_MEMORY, \
		__FILE__, \
		_globus_func_name, \
		__LINE__, \
		"a memory allocation failed")

#define GLOBUS_I_URL_SYNC_ERROR_HANDLE_IN_USE() \
	globus_error_construct_error(\
		GLOBUS_URL_SYNC_MODULE,\
		GLOBUS_NULL,\
		GLOBUS_URL_SYNC_ERROR_IN_USE, \
		__FILE__, \
		_globus_func_name, \
		__LINE__, \
		"handle is in use")

#define GLOBUS_I_URL_SYNC_ERROR_HANDLE_NOT_IN_USE() \
	globus_error_construct_error(\
		GLOBUS_URL_SYNC_MODULE,\
		GLOBUS_NULL,\
		GLOBUS_URL_SYNC_ERROR_NOT_IN_USE, \
		__FILE__, \
		_globus_func_name, \
		__LINE__, \
		"handle is not in use")

#define GLOBUS_I_URL_SYNC_ERROR_REMOTE(param) \
	globus_error_construct_error(\
		GLOBUS_URL_SYNC_MODULE,\
		GLOBUS_NULL,\
		GLOBUS_URL_SYNC_ERROR_REMOTE, \
		__FILE__, \
		_globus_func_name, \
		__LINE__, \
		"remote error: %s", param)

EXTERN_C_END

#endif	/* _GLOBUS_I_URL_SYNC_H */

#endif  /* GLOBUS_DONT_DOCUMENT_INTERNAL */
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
 * @file globus_i_url_sync_log.h
 *
 * $RCSfile$
 * $Revision$
 * $Date$
 */

#ifndef _GLOBUS_I_URL_SYNC_LOG_H
#define	_GLOBUS_I_URL_SYNC_LOG_H

#include "globus_common_include.h"
#include "globus_url_sync.h"

#ifndef EXTERN_C_BEGIN
#   ifdef  __cplusplus
#       define EXTERN_C_BEGIN extern "C" {
#       define EXTERN_C_END }
#   else
#       define EXTERN_C_BEGIN
#       define EXTERN_C_END
#   endif
#endif

#define GLOBUS_I_URL_SYNC_LOG_DEBUG_ENTER(n, s)		    \
	globus_i_url_sync_log_write(                        \
		GLOBUS_URL_SYNC_LOG_LEVEL_DEBUG,            \
		"%s : %s (%d) : enter (%x, %s)\n",                   \
		__FILE__,                                   \
		_globus_func_name,                          \
		__LINE__				\
		, n, s)
#define GLOBUS_I_URL_SYNC_LOG_DEBUG_EXIT(n, s)		    \
	globus_i_url_sync_log_write(                        \
		GLOBUS_URL_SYNC_LOG_LEVEL_DEBUG,            \
		"%s : %s (%d) : exit (%x, %s)\n",                    \
		__FILE__,                                   \
		_globus_func_name,                          \
		__LINE__	\
		, n, s)

#define globus_i_url_sync_log_debug(...)                    \
	globus_i_url_sync_log_write(                        \
		GLOBUS_URL_SYNC_LOG_LEVEL_DEBUG,            \
		__VA_ARGS__)

#define globus_i_url_sync_log_error(error)                  \
        {                                                   \
            char * s = globus_error_print_friendly(error);  \
            globus_i_url_sync_log_write(                    \
                GLOBUS_URL_SYNC_LOG_LEVEL_ERROR, s);        \
            globus_libc_free(s);                            \
        }

/**
 * Activation and deactivation of the debug function group.
 * @ingroup globus_url_sync_debug
 */
globus_result_t
globus_i_url_sync_log_activate();

globus_result_t
globus_i_url_sync_log_deactivate();

/**
 * Writes to the log.
 * @ingroup globus_url_sync_debug
 *
 * @param log_level
 *        The log level of the message.
 * @param fmt
 *        Formatted output of the message
 * @param ...
 *        Output values for the formatted message.
 */
void
globus_i_url_sync_log_write(
    globus_url_sync_log_level_t             log_level,
    char *                                  fmt,
                                            ...);

EXTERN_C_END

#endif	/* _GLOBUS_I_URL_SYNC_LOG_H */

#endif  /* GLOBUS_DONT_DOCUMENT_INTERNAL */

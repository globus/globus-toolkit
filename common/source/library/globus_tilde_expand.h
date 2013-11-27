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

/** @file globus_tilde_expand.h Home Directory ~ expansion */

#ifndef GLOBUS_TILDE_EXPAND_H
#define GLOBUS_TILDE_EXPAND_H 1
 
#include "globus_common_include.h"
 
#ifdef __cplusplus
extern "C" {
#endif
 
#define GLOBUS_TILDE_EXPAND             2UL
#define GLOBUS_TILDE_USER_EXPAND        4UL

/**
 * @brief Expand ~ in file paths
 * @ingroup globus_common
 * @details
 * Expand the leading ~ (or ~user) characters from inpath to the home directory
 * path of the current user (or user specified in ~user); the result is stored
 * in a newly allocated buffer *outpath (which will need to be freed but a call
 * to globus_free.) The string following the ~/or ~user/ is also transmitted in
 * the output string.
 *
 * @param options
 *     The expansion is conditionned by the options as defined in
 *     globus_tilde_expand.h:
 *     - if GLOBUS_TILDE_EXPAND is set in the option, ~ will be expanded
 *     - if GLOBUS_TILDE_USER_EXPAND is set in the option, ~user will be
 *       expanded
 *     Otherwise, the corresponding form is not expanded (just copied into the
 *     output path)
 * @param url_form 
 *     True if the inpath follows an URL format (/~)
 *     Used when expanding an url (for : &lt;scheme&gt;://host[:port][/path]
 *     were /path  can be of the form /~[user][/...]
 *     Otherwise, the form ~[user][/...] is expected.
 * @param inpath
 *     Input string to expand.
 * @param outpath
 *     Output string; Need to be freed when not used anymore.
 */
int
globus_tilde_expand(
    unsigned long options,
    globus_bool_t url_form,  /* True if the inpath follows an URL format (/~)*/
    char *inpath,
    char **outpath);

#ifdef __cplusplus
}
#endif

#endif /* GLOBUS_TILDE_EXPAND_H */

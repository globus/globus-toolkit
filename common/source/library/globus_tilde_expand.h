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
 
#include "globus_types.h"
 
#ifdef __cplusplus
extern "C" {
#endif
 
/** @brief Expand ~
 * @ingroup globus_common
 * @hideinitializer
 */
#define GLOBUS_TILDE_EXPAND             2UL
/** @brief Expand ~user
 * @ingroup globus_common
 * @hideinitializer
 */
#define GLOBUS_TILDE_USER_EXPAND        4UL

int
globus_tilde_expand(
    unsigned long options,
    globus_bool_t url_form,
    char *inpath,
    char **outpath);

#ifdef __cplusplus
}
#endif

#endif /* GLOBUS_TILDE_EXPAND_H */

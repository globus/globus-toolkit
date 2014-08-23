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
 * @file globus_i_error_gssapi.h
 * Globus Gssapi Error
 */

#ifndef GLOBUS_I_INCLUDE_GSSAPI_ERROR_H
#define GLOBUS_I_INCLUDE_GSSAPI_ERROR_H

#include "globus_common.h"
#include "gssapi.h"
#include "globus_error_gssapi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * GSSAPI Error object instance data definition
 * @ingroup globus_gssapi_error_object
 * @internal
 *
 * This structure contains all of the data associated with a Globus
 * GSSAPI Error.
 *
 * @see globus_error_construct_gssapi_error(),
 *      globus_error_initialize_gssapi_error(),
 *      globus_l_error_free_gssapi()
 */

typedef struct globus_l_gssapi_error_data_s
{
    /** the major status */
    OM_uint32                           major_status;
    /** the minor status */
    OM_uint32                           minor_status;
    globus_bool_t                       is_globus_gsi;
}
globus_l_gssapi_error_data_t;

#ifdef __cplusplus
}
#endif

#endif /* GLOBUS_I_INCLUDE_GSSAPI_ERROR_H */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

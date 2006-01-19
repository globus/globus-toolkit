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

#ifndef GLOBUS_ERROR_STRING_H
#define GLOBUS_ERROR_STRING_H

#include "globus_common_include.h"
#include "globus_error.h"

 
EXTERN_C_BEGIN

extern const globus_object_type_t GLOBUS_ERROR_TYPE_STRING_DEFINITION;

#define GLOBUS_ERROR_TYPE_STRING (&GLOBUS_ERROR_TYPE_STRING_DEFINITION)

/* allocate and initialize an error of type
 * GLOBUS_ERROR_TYPE_STRING
 */ 
extern globus_object_t *
globus_error_construct_string(
    globus_module_descriptor_t *	base_source,
    globus_object_t *			base_cause,
    const char *			fmt,
    ...);

/* initialize and return an error of type
 * GLOBUS_ERROR_TYPE_STRING
 */
extern globus_object_t *
globus_error_initialize_string(
    globus_object_t *			error,
    globus_module_descriptor_t *	base_source,
    globus_object_t *			base_cause,
    const char *			fmt,
    va_list				ap);

EXTERN_C_END

#endif /* GLOBUS_ERROR_STRING_H */



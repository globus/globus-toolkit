/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
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



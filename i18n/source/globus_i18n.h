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

#include "unicode/udata.h"     /* ICU API for data handling. */
#include "unicode/ures.h"      /* ICU API for resource loading */
#include "unicode/ustring.h"


char * globus_get_string_by_key(char * locale,
		                char * resource_name,
				char * key);


char * globus_get_string_by_index(char * locale,
		                  char * resource_name,
				  int32_t index);

char * globus_get_error_def(char * resource_name,
			    char * key);


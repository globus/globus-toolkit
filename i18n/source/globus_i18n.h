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


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


#include "unicode/udata.h"     /* ICU API for data handling. */
#include "unicode/ures.h"      /* ICU API for resource loading */
#include "unicode/ustring.h"

typedef UResourceBundle* globus_resource_bundle_t;



char * globus_getstringbykey(globus_resource_bundle_t  resource,
		                          char * resource_name,
					  char * key);


globus_result_t globus_set_default_locale(char * locale);

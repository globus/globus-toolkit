#include "globus_common.h"
#include "globus_i18n.h"
#include "globus_error_string.h"
#include "unicode/udata.h"     /* ICU API for data handling. */ 
#include "unicode/ures.h"      /* ICU API for resource loading */
#include "unicode/ustring.h"


/*what is the dealy o fuck*/
char * globus_getstringbykey(globus_resource_bundle_t resource,
	         	  char * resource_name,
			  char * key)
{
    UErrorCode	uerr	=U_ZERO_ERROR;
    char * resource_path;
    static char * currdir = NULL;
    char * utf8string;
    const UChar * string;
    int32_t	len;
    UResourceBundle * myResources;

    currdir = getcwd(NULL, 0);
    resource_path = globus_common_create_string(
	            "%s/share", globus_libc_getenv("GLOBUS_LOCATION"));

    myResources = ures_open(resource_path, "resource_name", &uerr);

    globus_free(resource_path);

    if (U_FAILURE(uerr)) 
    {
        fprintf(stderr,
		"%s: ures_open failed with error \"%s\"\n", "globus_common", 
		u_errorName(uerr));
       	exit(-1);
    }

    string = ures_getStringByKey(myResources, key, &len, &uerr);

    if (U_FAILURE(uerr)) 
    { 
	fprintf(stderr, 
		"%s: ures_open failed with error \"%s\"\n", 
		"globus_common", 
		u_errorName(uerr)); 
	exit(-1);
    }

    
    u_strToUTF8(NULL, 0, &len, string, -1, &uerr);
    utf8string=(char *)malloc(sizeof(char *)*len); 
    uerr=U_ZERO_ERROR; 
    utf8string=u_strToUTF8(utf8string, len, NULL, string, -1, &uerr);

    return utf8string;
}

globus_result_t globus_set_default_locale(char * locale)
{
	return GLOBUS_SUCCESS;
    }


#include "globus_common.h"
#include "globus_i18n.h"
#include "globus_error_string.h"
#include "unicode/udata.h"     /* ICU API for data handling. */ 
#include "unicode/ures.h"      /* ICU API for resource loading */
#include "unicode/ustring.h"


char * globus_get_string_by_key( char * locale,
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
	            "%s/share/%s", 
		    globus_libc_getenv("GLOBUS_LOCATION"), 
		    resource_name);

    myResources = ures_open(resource_path, locale, &uerr);

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



char * globus_get_string_by_index(char * locale,
	         	  char * resource_name,
			  int32_t index)
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
	            "%s/share/%s", 
		    globus_libc_getenv("GLOBUS_LOCATION"), 
		    resource_name);

    myResources = ures_open(resource_path, locale, &uerr);

    globus_free(resource_path);

    if (U_FAILURE(uerr)) 
    {
        fprintf(stderr,
		"%s: ures_open failed with error \"%s\"\n", 
		resource_name, 
		u_errorName(uerr));
       	exit(-1);
    }

    string = ures_getStringByIndex(myResources, index, &len, &uerr);

    if (U_FAILURE(uerr)) 
    { 
	fprintf(stderr, 
		"%s: ures_open failed with error \"%s\"\n", 
		resource_name, 
		u_errorName(uerr)); 
	exit(-1);
    }

    
    u_strToUTF8(NULL, 0, &len, string, -1, &uerr);
    utf8string=(char *)malloc(sizeof(char *)*len); 
    uerr=U_ZERO_ERROR; 
    utf8string=u_strToUTF8(utf8string, len, NULL, string, -1, &uerr);

    return utf8string;
}


char * globus_get_error_def(char * resource_name,
		            char * key)
{
	return globus_get_string_by_key(GLOBUS_NULL, resource_name, key);
}
	

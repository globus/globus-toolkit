#include "globus_common.h"
#include "globus_error_string.h"

int main()
{
    globus_object_t * err;
    char * s;
    static char * myname = "main";

    globus_module_activate(GLOBUS_COMMON_MODULE);

    err = globus_error_construct_string(GLOBUS_COMMON_MODULE,
	    GLOBUS_ERROR_NO_INFO,
	    "[%s]: Error doing something hard at %s:%d\n",
	    GLOBUS_COMMON_MODULE->module_name,
	    myname,
	    __LINE__);
    s = globus_object_printable_to_string(err);

    globus_libc_printf(s);
    return globus_module_deactivate_all();
}

#include <stdlib.h>
#include <stdio.h>
#include "globus_common.h"

#ifndef WIN32
globus_result_t
chainc_test_callout(va_list ap)
#else
globus_result_t
__declspec(dllexport) chainc_test_callout(va_list ap)
#endif
{
    vprintf("Callout C Got arguments 1) %s 2) %s\n", ap);
    return GLOBUS_SUCCESS;
}



#include <stdlib.h>
#include <stdio.h>
#include "globus_common.h"

#ifndef WIN32
globus_result_t
test_callout(va_list ap)
#else
globus_result_t
__declspec(dllexport) test_callout(va_list ap)
#endif
{
    vprintf("Got arguments 1) %s 2) %s\n", ap);
    return GLOBUS_SUCCESS;
}



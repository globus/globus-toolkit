#include <stdlib.h>
#include <stdio.h>
#include "globus_common.h"


globus_result_t
test_callout(va_list ap)
{
    vprintf("Got arguments 1) %s 2) %s\n", ap);
    return GLOBUS_SUCCESS;
}



#include "globus_i_xio_http.h"
#include "globus_i_xio_http_responses.h"

extern
const char *
globus_i_xio_http_lookup_reason(
    int                                 code)
{
    char                                code_str[4];
    int                                 i;

    if (code < 100 || code > 599)
    {
        return "Unknown status";
    }
    sprintf(&code_str[0], "%d", code);

    for (i = 0; i < GLOBUS_XIO_ARRAY_LENGTH(globus_l_http_descriptions); i+=2)
    {
        if (strcmp(code_str, globus_l_http_descriptions[i]) == 0)
        {
            return globus_l_http_descriptions[i+1];
        }
    }
    return "Unknown status";
}
/* globus_i_xio_http_lookup_reason() */

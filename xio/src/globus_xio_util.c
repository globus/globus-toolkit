#include "globus_xio_util.h"
#include "globus_xio_types.h"
#include "globus_common.h"

globus_bool_t
globus_xio_error_is_eof(
    globus_result_t                             res)
{
    globus_object_t *                           obj;
    int                                         type;
    globus_module_descriptor_t *                mod;

    obj = globus_error_peek(res);

    type = globus_error_get_type(obj);
    if(type == GLOBUS_XIO_ERROR_EOF)
    {
        mod = globus_error_get_source(obj);
        if(mod == GLOBUS_XIO_MODULE)
        {
            return GLOBUS_TRUE;
        }
    }

    return GLOBUS_FALSE;
}
/* not sure yet */

#include <stdlib.h>
#include "globus_common.h"
#include "gssapi.h"
#include "rsl.h"
#include "rsl_assist.h"

globus_result_t
globus_gram_jobmanager_callout(va_list ap)
{
    gss_ctx_id_t                        job_initiator_ctx;
    gss_ctx_id_t                        requester_ctx;
    char *                              job_id;
    char *                              action;
    globus_rsl_t *                      rsl;
    globus_result_t                     result = GLOBUS_SUCCES;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;
    
    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    globus_module_activate(GLOBUS_RSL_MODULE);
    
    job_initiator_ctx = va_arg(ap, gss_ctx_id_t);
    requester_ctx = va_arg(ap, gss_ctx_id_t);
    job_id = va_arg(ap, char *);
    rsl = va_arg(ap, globus_rsl_t *);
    action = va_arg(ap, char *);
    
    globus_module_deactivate(GLOBUS_RSL_MODULE);
    globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return result;
}



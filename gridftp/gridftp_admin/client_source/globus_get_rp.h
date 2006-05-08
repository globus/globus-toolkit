#if !defined(GLOBUS_GET_RP_H)
#define GLOBUS_GET_RP_H 1

#include "globus_options.h"
#include "globus_wsrf_core_tools.h"
#include "globus_common.h"
#include "globus_xml_buffer.h"
#include "gssapi.h"
#include "globus_soap_client.h"
#include "globus_soap_message.h"
#include "wsrp_GetResourcePropertyResponseType.h"
#include "globus_soap_message_handle.h"
#include "globus_soap_message_utils.h"
#include "wsnt_ResourceUnknownFaultType.h"
#include "wsnt_ResourceUnknownFault.h"

typedef struct globus_get_rp_info_s
{
    globus_bool_t                       debug;
    globus_bool_t                       quiet;
    globus_bool_t                       verbose;
    char *                              epr_file;
    char *                              endpoint;
    globus_soap_message_attr_t          attr;
    wsa_EndpointReferenceType *         epr;
} globus_get_rp_info_t;

extern globus_options_entry_t           getrp_i_opts_table[];
#endif



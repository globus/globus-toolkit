#include "gssapi.h"
#include "globus_gss_assist.h"
#include "gssapi_openssl.h"


int main()
{
    char *                              subject;
    char *                              error_str;
    gss_name_t                          gss_name;
    gss_buffer_desc                     name_tok;
    gss_OID                             name_type;
    OM_uint32                           major_status;
    OM_uint32                           minor_status;

    subject = "service@cvs.globus.org";

    name_tok.value = subject;

    name_tok.length = strlen(subject) + 1;

    name_type = GSS_C_NT_HOSTBASED_SERVICE;
    
    major_status = gss_import_name(&minor_status,
                                   &name_tok,
                                   name_type,
                                   &gss_name);

    if(major_status != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             major_status,
                                             minor_status,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }

    major_status = gss_display_name(&minor_status,
                                    gss_name,
                                    &name_tok,
                                    NULL);
    
    if(major_status != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             major_status,
                                             minor_status,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }

    printf("Expected subject name \"/CN=service/pitcairn.mcs.anl.gov\" got \"%s\"\n",
        name_tok.value);

    return 0;
}

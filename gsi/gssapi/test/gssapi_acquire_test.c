
#include "gssapi_openssl.h"
#include "gssapi.h"

int main()
{
    OM_uint32                           minor_status;
    OM_uint32                           major_status;
    gss_cred_id_t                       cred;
    char *                              error_str;

   major_status = gss_acquire_cred(
       &minor_status,
       NULL,
       GSS_C_INDEFINITE,
       GSS_C_NO_OID_SET,
       GSS_C_BOTH,
       &cred,
       NULL,
       NULL);

   if(GSS_ERROR(major_status))
   {
       globus_gss_assist_display_status_str(&error_str,
					    NULL,
					    major_status,
					    minor_status,
					    0);
       printf("\nLINE %d ERROR: %s\n", __LINE__, error_str);
       free(error_str);
       return 1;
   }

   major_status = gss_release_cred(
       &minor_status,
       cred);
   
   if(GSS_ERROR(major_status))
   {
       globus_gss_assist_display_status_str(&error_str,
					    NULL,
					    major_status,
					    minor_status,
					    0);
       printf("\nLINE %d ERROR: %s\n", __LINE__, error_str);
       free(error_str);
       return 1;
   }
   
   return 0;
}

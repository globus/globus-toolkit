/**********************************************************************

acquire_cred.c:

Description:
	GSSAPI routine to acquire the local credential
	See: <draft-ietf-cat-gssv2-cbind-04.txt>

CVS Information:
	$Source$
	$Date$
	$Revision$
	$Author$

**********************************************************************/

static char *rcsid = "$Header$";

/**********************************************************************
                             Include header files
**********************************************************************/

#include "gssapi.h"
#include "gssapi_ssleay.h"
#include "gssutils.h"
#include <stdlib.h>
#include <sys/stat.h>

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/

/*
 * DEE? Need to add the callback using this: 
 * user can override this to point to thier routines  
 * we will provide it to SSL for its password prompt
 * callback 
 */
char * (*tis_gss_user_supplied_getpass)(char *);

/**********************************************************************
Function:   gss_acquire_cred()

Description:
	Gets the local credentials.  The proxy_init_cred does most of the
	work of setting up the SSL_ctx, getting the user's cert, key, etc. 

	The globusid will be obtained from the certificate. (Minus
	and /CN=proxy entries.)

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_acquire_cred(
    OM_uint32 *                         minor_status,
    const gss_name_t                    desired_name_P,
    OM_uint32                           time_req,
    const gss_OID_set                   desired_mechs,
    gss_cred_usage_t                    cred_usage,
    gss_cred_id_t *                     output_cred_handle_P,
    gss_OID_set *                       actual_mechs,
    OM_uint32 *                         time_rec) 
{
    OM_uint32                           major_status = GSS_S_NO_CRED;

#ifdef DEBUG
    fprintf(stderr,"acquire_cred:usage=%d\n",cred_usage);
    fprintf(stderr,"uid=%d, pid=%d$HOME=%s\n",getuid(),getpid(),
            getenv("HOME")?getenv("HOME"):"NO_HOME");
#endif /* DEBUG */
  
    *minor_status = 0;
  
    /* module activation if not already done by calling
     * globus_module_activate
     */
    
    globus_thread_once(
        &once_control,
        (void (*)(void))globus_i_gsi_gssapi_module.activation_func);

    if (actual_mechs != NULL)
    {
        major_status = gss_indicate_mechs(minor_status,
                                          actual_mechs);
        if (major_status != GSS_S_COMPLETE)
        {
            *minor_status = gsi_generate_minor_status();
            return  major_status;
        }
    }

    if (time_rec != NULL)
    {
        *time_rec = GSS_C_INDEFINITE ;
    }


    major_status = gss_create_and_fill_cred(output_cred_handle_P,
                                            cred_usage,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL);
    if (GSS_ERROR(major_status))
    {
        *minor_status = gsi_generate_minor_status();
    }
        
#ifdef DEBUG
    fprintf(stderr,"acquire_cred:major_status:%08x\n",major_status);
#endif
    return major_status;
}



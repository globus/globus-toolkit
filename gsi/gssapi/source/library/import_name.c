/**********************************************************************

import_name.c:

Description:
    GSSAPI routine to take an appl version of the name 
	and convert it to internal form. 
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

#include "gssapi_ssleay.h"
#include "gssutils.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/**********************************************************************
                               Type definitions
**********************************************************************/

/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/

/**********************************************************************
Function:  gss_import_name

Description:
	Accept a name as any one of four formats:
	(0) If the OID is GSS_C_NT_HOSTBASED_SERVICE
		Then it is assumed the name is  service@FQDN
		We will make up a name with only /CN=service/FQDN
		This is done to match the Kerberos service names.          
		For example the service name of host is used for logins etc. 
    (1) /x=y/x=y... i.e. x500 type name

Parameters:

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_import_name(
    OM_uint32 *                         minor_status,
    const gss_buffer_t                  input_name_buffer,
    const gss_OID                       input_name_type,
    gss_name_t *                        output_name_P)
{
    OM_uint32                           major_status = GSS_S_COMPLETE;
    gss_name_desc *                     output_name;
    X509_NAME *                         x509n;
    X509_NAME_ENTRY *                   ne;
    int                                 nid;
    char *                              buf;
    char *                              cp;
    char *                              np;
    char *                              vp;
    char *                              qp;
    char *                              ep;
    int                                 len;

    *minor_status = 0;
    ne = NULL;
    output_name = NULL;
    buf = NULL;

    output_name = (gss_name_t) malloc(sizeof(gss_name_desc));
    
    if (output_name == NULL)
    {
        GSSerr(GSSERR_F_IMPORT_NAME, GSSERR_R_OUT_OF_MEMORY);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    } 
    
    output_name->group = NULL;
    output_name->group_types = NULL;

    
    if(g_OID_equal(input_name_type,
                   GSS_C_NT_ANONYMOUS))
    {
        output_name->name_oid = input_name_type;
        output_name->x509n = NULL;
        *output_name_P = output_name;
        return major_status;
    }
    
    x509n = X509_NAME_new();
    
    if (x509n == NULL)
    {
        GSSerr(GSSERR_F_IMPORT_NAME, GSSERR_R_OUT_OF_MEMORY);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err; 
    }
   
    /*
     * copy input, so it has trailing zero, and can be written over
     * during parse
     */
    
    len = input_name_buffer->length;
    if ((buf = (char *)malloc(len+1)) == NULL)
    {
        GSSerr(GSSERR_F_IMPORT_NAME, GSSERR_R_OUT_OF_MEMORY);
        *minor_status = gsi_generate_minor_status();
        major_status = GSS_S_FAILURE;
        goto err;
    }

    memcpy(buf, input_name_buffer->value, len);
    
    buf[len] = '\0';
    cp = buf;

    /* 
     * take the same form Kerberos does,i.e. service@FQDN
     * and get the FQDN as a CN
     * DEE need to convert to FQDN-host for globus conventions
     * but leave off for now, as this may change.
     */

    if (g_OID_equal(GSS_C_NT_HOSTBASED_SERVICE, input_name_type))
    {
        vp = strchr(cp,'@');
        if (vp)
        {
            *vp = '/';   /* replace with a / */
        }
        
        ne=X509_NAME_ENTRY_create_by_NID(&ne,
                                         OBJ_txt2nid("CN"),
                                         V_ASN1_APP_CHOOSE,
                                         (unsigned char *)cp,
                                         -1);
        X509_NAME_add_entry(x509n,ne,0,0);
    }
    
    /*
     * The SSLeay does not have a string to x509 name, 
     * so we will define one here. 
     * Accept names in three forms:
     * /xx=yy/xx=yy i.e. the X500 type, which allows any name. 
     *
     * The first case assumes that there are no "/"s in the name
     * The xx must be valid short or long names in the objects
     */

    else
    {
        if (*cp == '/')
        {
            cp++;                 /* skip first / */
            while ((cp != NULL) && (*cp != '\0'))
            {
                np = cp;              /* point at name= */
                cp = strchr(np,'=');
                if (cp == NULL)
                {
                    GSSerr(GSSERR_F_IMPORT_NAME, GSSERR_R_UNEXPECTED_FORMAT);
                    *minor_status = gsi_generate_minor_status();
                    major_status = GSS_S_BAD_NAME;
                    goto err;
                }
                *cp = '\0';           /* terminate name string */
                cp++;                 /* point at value */
                vp = cp;
                cp = strchr(vp,'=');   /* find next =, then last / */
                if (cp != NULL)
                {
                    ep = cp;
                    *ep = '\0';	/* for now set = to 0 */
                    cp = strrchr(vp,'/');   /* find last / in  value */
                    *ep = '=';	/* reset = */
                    if (cp != NULL)
                    {
                        *cp = '\0'; /* terminate value string */
                        cp++;
                    }
                }
                nid=OBJ_txt2nid(np);

                if (nid == NID_undef)
                {
                    /* 
                     * not found, lets try upper case instead
                     */
                    qp = np;
                    while (*qp != '\0')
                    {
			*qp = toupper(*qp);
			qp++;
                    }
                    nid=OBJ_txt2nid(np);
                    if (nid == NID_undef)
                    {
                        GSSerr(GSSERR_F_IMPORT_NAME,
                               GSSERR_R_UNEXPECTED_FORMAT);
                        *minor_status = gsi_generate_minor_status();
                        major_status = GSS_S_BAD_NAME;
                        goto err;
                    }
                }
                ne=X509_NAME_ENTRY_create_by_NID(&ne,
                                                 nid,
                                                 V_ASN1_APP_CHOOSE, 
                                                 (unsigned char *)vp,
                                                 -1);
                if (ne == NULL)
                {
                    GSSerr(GSSERR_F_IMPORT_NAME, GSSERR_R_UNEXPECTED_FORMAT);
                    *minor_status = gsi_generate_minor_status();
                    major_status = GSS_S_BAD_NAME;
                    goto err;
                }
                
                if (!X509_NAME_add_entry(x509n,
                                         ne, 
                                         X509_NAME_entry_count(x509n),
                                         0))
                {
                    GSSerr(GSSERR_F_IMPORT_NAME, GSSERR_R_UNEXPECTED_FORMAT);
                    *minor_status = gsi_generate_minor_status();
                    major_status = GSS_S_BAD_NAME;
                    goto err;
                }
            }
        }
        else
        {
            GSSerr(GSSERR_F_IMPORT_NAME, GSSERR_R_UNEXPECTED_FORMAT);
            *minor_status = gsi_generate_minor_status();
            major_status = GSS_S_BAD_NAME;
            goto err;
        }
    }
  
#ifdef DEBUG
    {
        char *s;
        s = X509_NAME_oneline(x509n,NULL,0);
        fprintf(stderr,"gss_import_name:%s\n",s);
        free(s);
    }
#endif
    
    if (ne)
    {
        X509_NAME_ENTRY_free(ne);
    }
    
    if (buf)
    {
        free(buf);
    }
    output_name->name_oid = input_name_type;
    output_name->x509n = x509n;
    *output_name_P = output_name;
    return major_status ;
err:
    if (ne)
    {
        X509_NAME_ENTRY_free(ne);
    }
    if (x509n)
    {
        X509_NAME_free(x509n);
    }
    if (output_name)
    {
        free(output_name);
    }
    if (buf)
    {
        free(buf);
    }
    
    return major_status;
    
} /* gss_import_name */

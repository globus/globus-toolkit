
/**********************************************************************

inquire_cred.c:

Description:
	GSSAPI routine to inquire about the local credential
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
Function:   gss_inquire_cred()

Description:
	Get information about the current credential

	We will also allow the return of the proxy file name,
	if the minor_status is set to a value of 57056 0xdee0
	This is done since there is no way to pass back the delegated
	credential file name. 

	When 57056 is seen, this will cause a new copy of this
	credential to be written, and it is the user's responsibility
	to free the file when done. 
	The name will be a pointer to a char * of the file name
	which must be freeed. The minor_status will be set to 
	57057 0xdee1 to indicate this. 
	
	DEE - this is a kludge, till the GSSAPI get a better way 
	to return the name. 

	If the minor status is not changed from 57056 to 57057
	assume it is not this gssapi, and a gss name was returned. 

#ifdef CLASS_ADD
    We will also allow the return of the class add extensions
    if the minor_status is set to a value of 57060 0xdee2

    When 57060 is seen, the  name will return a
    pointer to an array of gss_buffer_desc one for each 
    proxy in the chain and the user certificate. A final 
    gss_buffer_desc will indicate the end of 
    the array by having a length of -1. 
    
    The caller is responsible for freeing the array and its 
    contents. 

    DEE - this is a kludge, and only be used for testing.   
    I would have added the class add checking under the
    GSSAPI, and have both the client and server supply 
    their sides via the channel bindings. 

    If the minor status is not changed from 57060 to 57061
    assume it is not this gssapi, and a gss name was returned. 
#endif

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_inquire_cred
(OM_uint32 *               minor_status ,
 const gss_cred_id_t       cred_handle_P ,
 gss_name_t *              name,
 OM_uint32 *               lifetime,
 gss_cred_usage_t *        cred_usage,
 gss_OID_set *             mechanisms
) 
{
	OM_uint32 major_status = 0;
	gss_cred_id_desc * cred_handle = (gss_cred_id_desc *)cred_handle_P;
	char * filename = NULL;
	int rc;
	int i,j,k;
#ifdef CLASS_ADD
    gss_buffer_desc * class_add_array = NULL;
    gss_buffer_desc * class_add_array_entry = NULL;
    X509 * cert;
    STACK_OF(X509_EXTENSION) *extensions;
    X509_EXTENSION *ex;
    ASN1_OBJECT *class_add_obj;
    ASN1_OCTET_STRING *class_add_oct;
#endif

#ifdef DEBUG
	fprintf(stderr,"inquire_cred:\n");
#endif /* DEBUG */

	if (cred_handle == GSS_C_NO_CREDENTIAL) {
	  major_status = GSS_S_NO_CRED;
	} else {

	  if (mechanisms != NULL) {
		*mechanisms = GSS_C_NO_OID_SET;
	  }

	  if (cred_usage != NULL) {
		*cred_usage = cred_handle->cred_usage;
	  }

		/* DEE? should look at end time 
	     * but we are not using this option for globus
	     */

	  if (lifetime != NULL) {
		*lifetime = 0;
	  }

	  if (name != NULL) {
		if (*minor_status == 0xdee0) {
			*minor_status = 0;
			rc = proxy_marshal_tmp(cred_handle->pcd->ucert,
					cred_handle->pcd->upkey,
					NULL,
					cred_handle->pcd->cert_chain,
					&filename);
			if (rc) {
				major_status = GSS_S_FAILURE;
				*minor_status = rc;
				if (filename) {
					free(filename);
				}
			} else {
				*name = filename;
				*minor_status = 0xdee1;
				/* DEE passback the char string */
				/* non standard, but then there is no standard */
			}
			
#ifdef CLASS_ADD
        } else if (*minor_status == 0xdee2) {

            if(!(class_add_obj = OBJ_nid2obj(OBJ_txt2nid("CLASSADD")))) {
                major_status = GSS_S_FAILURE;
                goto err;
            }
            if ((cred_handle->pcd->cert_chain)) {
                i = sk_num(cred_handle->pcd->cert_chain);
#ifdef DEBUG
            fprintf(stderr,"Collect Class adds from %d certs\n", i);
#endif
                class_add_array = malloc(sizeof(gss_buffer_desc)*(i+1));
                if (!class_add_array) {
                    major_status = GSS_S_FAILURE;
                    goto err;
                }

                class_add_array_entry = class_add_array;
                for (j=i-1;j>=0;j--) {
                    class_add_array_entry->length = 0;
                    class_add_array_entry->value = NULL;
                    cert = (X509 *)sk_value(cred_handle->pcd->cert_chain,j);
                    if ((extensions = cert->cert_info->extensions)) {
                        for (k=0;k<sk_X509_EXTENSION_num(extensions);
                            k++) {
                            ex = (X509_EXTENSION *)sk_X509_EXTENSION_value(extensions,k);
                            if (!OBJ_cmp(class_add_obj,
                                X509_EXTENSION_get_object(ex))) {
                                class_add_oct = X509_EXTENSION_get_data(ex);
                                class_add_array_entry->value = 
                                    malloc(class_add_oct->length);
                                if (class_add_array_entry->value == NULL) {
                                    major_status = GSS_S_FAILURE;
                                    goto err;
                                }
                                class_add_array_entry->length =
                                     class_add_oct->length;
                                memcpy(class_add_array_entry->value,
                                        class_add_oct->data,
                                        class_add_oct->length);
                                break;
                            }
                        }
                    }
#ifdef DEBUG
    if (class_add_array_entry->length)
        fprintf(stderr,"ClassAdd:%5d %*s\n",
                class_add_array_entry->length,
                class_add_array_entry->length,
                class_add_array_entry->value);
    else
        fprintf(stderr,"ClassAdd:null\n");
#endif
                    class_add_array_entry++;
                }
                class_add_array_entry->length = -1;
                class_add_array_entry->value = NULL;

                *name = class_add_array;
                *minor_status = 0xdee3;
            }
#endif

		} else {
			major_status = gss_copy_name_to_name(minor_status,
                                (gss_name_desc * * )name,
				cred_handle->globusid);
		}
	  }
	}
	
err:

	return major_status;
}

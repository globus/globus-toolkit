
/**********************************************************************

inquire_context.c:

Description:
        GSSAPI routine to inquire about the local context
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
Function:   gss_inquire_context()

Description:
        Get information about the current context

#ifdef CLASS_ADD
        We will also allow the return of the class add extensions
    if the minor_status is set to a value of 57056 0xdee0

    When 57056 is seen, the  targ_name_P will return a
    pointer to an array of gss_buffer_desc one for each 
        proxy in the chain and the user certificate. A final 
        gss_buffer_desc will indicate the end of 
        the array by having a length of -1. 
    
        The caller is responsible for freeing the aray and its 
        contents. 

    DEE - this is a kludge, and only be used for testing.       
        I would have added the class add checking under the
        GSSAPI, and have both the client and server supply 
        their sides via the channel bindings. 

    If the minor status is not changed from 57056 to 57057
    assume it is not this gssapi, and a gss name was returned. 
#endif


Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_inquire_context(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle_P,
    gss_name_t *                        src_name_P,
    gss_name_t *                        targ_name_P,
    OM_uint32 *                         lifetime_rec,
    gss_OID *                           mech_type,
    OM_uint32 *                         ctx_flags,
    int *                               locally_initiated,
    int *                               open) 
{
    OM_uint32                           major_status = 0;
    gss_ctx_id_desc *                   context = 
        (gss_ctx_id_desc *)context_handle_P;
    int                                 i;
    int                                 j;
    int                                 k;
    time_t                              time_now;
    ASN1_UTCTIME *                      asn1_time = NULL;
        
#ifdef CLASS_ADD
    gss_buffer_desc *                   class_add_array = NULL;
    gss_buffer_desc *                   class_add_array_entry = NULL;
    X509 *                              cert;   
    STACK_OF(X509_EXTENSION) *          extensions;
    X509_EXTENSION *                    ex;
    ASN1_OBJECT *                       class_add_obj;
    ASN1_OCTET_STRING *                 class_add_oct;
#endif

#ifdef DEBUG
    fprintf(stderr,"inquire_context:\n");
#endif /* DEBUG */

    if (context == GSS_C_NO_CONTEXT)
    {
        major_status = GSS_S_NO_CONTEXT;
        goto err;
    }

    if (src_name_P)
    {
        if (context->source_name)
        {
            major_status = gss_copy_name_to_name((gss_name_desc **)src_name_P,
                                                 context->source_name);
            if (major_status != GSS_S_COMPLETE)
            {
                *minor_status = gsi_generate_minor_status();
                goto err;
            }
        }
        else
        {
            *src_name_P = NULL;
        }
    }
        
    if (targ_name_P)
    {

#ifdef CLASS_ADD
        if (*minor_status == 0xdee0)
        {
            *minor_status = 0; 
            if(!(class_add_obj = OBJ_nid2obj(OBJ_txt2nid("CLASSADD"))))
            {
                *minor_status = gsi_generate_minor_status();
                major_status = GSS_S_FAILURE;
                goto err;
            }

            if ((context->pvd.cert_chain))
            {
                i = sk_num(context->pvd.cert_chain);
#ifdef DEBUG
                fprintf(stderr,"Collect Class adds from %d certs\n", i);
#endif
                class_add_array = malloc(sizeof(gss_buffer_desc)*(i+1));
                if (!class_add_array)
                {
                    GSSerr(GSSERR_F_INQUIRE_CONTEXT, GSS_R_OUT_OF_MEMORY);
                    *minor_status = gsi_generate_minor_status();
                    major_status = GSS_S_FAILURE;
                    goto err;
                }

                class_add_array_entry = class_add_array;
                for (j=i-1;j>=0;j--)
                {
                    class_add_array_entry->length = 0;
                    class_add_array_entry->value = NULL;
                    cert = (X509 *)sk_value(context->pvd.cert_chain,j);
                    if ((extensions = cert->cert_info->extensions))
                    {
                        for (k=0;k<sk_X509_EXTENSION_num(extensions);
                             k++)
                        {
                            ex = (X509_EXTENSION *)sk_X509_EXTENSION_value(extensions,k);
                            if (!OBJ_cmp(class_add_obj,
                                         X509_EXTENSION_get_object(ex)))
                            {
                                class_add_oct = X509_EXTENSION_get_data(ex);
                                class_add_array_entry->value = 
                                    malloc(class_add_oct->length);
                                if (class_add_array_entry->value == NULL)
                                {
                                    GSSerr(GSSERR_F_INQUIRE_CONTEXT,
                                           GSSERR_R_OUT_OF_MEMORY);
                                    *minor_status = gsi_generate_minor_status();
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
                    {
                        fprintf(stderr,"ClassAdd:%5d %*s\n",
                                class_add_array_entry->length,
                                class_add_array_entry->length,
                                class_add_array_entry->value);
                    }
                    else
                    {
                        fprintf(stderr,"ClassAdd:null\n");
                    }
#endif
                    class_add_array_entry++;
                }
                class_add_array_entry->length = -1;
                class_add_array_entry->value = NULL;

                *targ_name_P = class_add_array; 
                *minor_status = 0xdee1;
            }
        }
        else
#endif

            if (context->target_name)
            {
                major_status =
                    gss_copy_name_to_name((gss_name_desc **)targ_name_P,
                                          context->target_name);
                if (major_status != GSS_S_COMPLETE)
                {
                    *minor_status = gsi_generate_minor_status();
                    goto err;
                }
            }
            else
            {
                *targ_name_P = NULL;
            }
    }
        
    if (lifetime_rec)
    {
        asn1_time = ASN1_UTCTIME_new();
        if (!asn1_time)
        {
            major_status = GSS_S_FAILURE;
            *minor_status = gsi_generate_minor_status();
            goto err;
        }
        X509_gmtime_adj(asn1_time,0);
        time_now = ASN1_UTCTIME_mktime(asn1_time);
        *lifetime_rec = context->pvxd.goodtill - time_now;
        if ( context->pvxd.goodtill == 0)
        {
            *lifetime_rec = GSS_C_INDEFINITE;
        }
        else
        {
            *lifetime_rec = context->pvxd.goodtill - time_now;
        }
        ASN1_UTCTIME_free(asn1_time);
    }

    if (mech_type)
    {
        *mech_type = (gss_OID) gss_mech_globus_gssapi_ssleay;
    }

    if (ctx_flags)
    {
        if (context->gs_state == GS_CON_ST_DONE)
        {
            *ctx_flags = context->ret_flags;
        }
        else
        {
            *ctx_flags = context->req_flags;
        }
    }

    if (locally_initiated)
    {
        *locally_initiated = context->locally_initiated;
    }
                
    if (open)
    {
        if (context->gs_state == GS_CON_ST_DONE)
        {
            *open = 1;
        }
        else
        {
            *open = 0;
        }
    }

err:
    return major_status;
}

/**********************************************************************
Function:   gss_context_time()

Description:
        Get information about the current context

Returns:
**********************************************************************/

OM_uint32 
GSS_CALLCONV gss_context_time(
    OM_uint32 *                         minor_status,
    const gss_ctx_id_t                  context_handle,
    OM_uint32 *                         time_rec
    )
{
    return gss_inquire_context(minor_status,
                               context_handle,
                               NULL,
                               NULL,
                               time_rec,
                               NULL,
                               NULL,
                               NULL,
                               NULL);
}


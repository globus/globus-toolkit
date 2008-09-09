/*
 * Copyright 1999-2008 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



/*
gcc -g -I$GLOBUS_LOCATION/include -I$GLOBUS_LOCATION/include/gcc32dbg -L$GLOBUS_LOCATION/lib group_test.c -lglobus_gssapi_gsi_gcc32dbg -lglobus_gss_assist_gcc32dbg -lglobus_ssl_utils_gcc32dbg -lssl_gcc32dbg -lcrypto_gcc32dbg

*/

/* scenarios that need testing:
 *
 * - cert1 has trusted group, cert2 doesn't have any groups
 * - cert1 has untrusted group, cert2 doesn't have any groups
 * - cert1 has trusted group, cert2 has same trusted group
 * - cert1 has untrusted group, cert2 has same untrusted group
 * - cert1 has untrusted group, cert2 has same trusted group
 * - cert1 has trusted group, cert2 has same trusted group + trusted
 *   subgroup
 * - cert1 has trusted group, cert2 has same trusted group + untrusted
 *   subgroup
 * - get/set_group
 */


#include "gssapi.h"
#include "../source/library/gssapi_ssleay.h"

static int establish_context(
    gss_cred_id_t                       initiator_cred,
    gss_cred_id_t                       acceptor_cred);

static X509_EXTENSION * proxy_extension_create(
    const gss_OID                       extension_oid,
    const gss_buffer_t                  extension_data);

static int create_proxy(
    gss_cred_id_t                       cred,
    gss_cred_id_t *                     proxy_cred,
    gss_buffer_t                        group,
    gss_OID                             group_oid);

int main()
{
    gss_cred_id_t                       proxy_cred_trusted;
    gss_cred_id_t                       proxy_cred_trusted_trusted;
    gss_cred_id_t                       proxy_cred_trusted_untrusted;
    gss_cred_id_t                       proxy_cred_untrusted;
    gss_cred_id_t                       orig_cred;
    gss_name_t                          name;
    gss_buffer_set_t                    subgroups;
    gss_OID_set                         group_types;
    gss_buffer_set_t                    set_subgroups;
    gss_OID_set                         set_group_types;
    OM_uint32                           maj_stat;
    OM_uint32                           min_stat;
    gss_buffer_desc                     group;
    char *                              error_str;
    int                                 i;
    
    /* acquire the initial credential */

    maj_stat = gss_acquire_cred(&min_stat,
                                NULL,
                                GSS_C_INDEFINITE,
                                GSS_C_NO_OID_SET,
                                GSS_C_BOTH,
                                &orig_cred,
                                NULL,
                                NULL);

    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }

    group.value = (void *) "subgroup1";
    group.length = 10;

    ERR_load_prxyerr_strings(0);

    /* case 0 */

    printf("\n%s:%d:\n\tcert1 , cert2 don't have any groups\n\tSecurity context establishment should succeed\n",__FILE__,__LINE__);

    establish_context(orig_cred,
                      orig_cred);
    /* case 1 */

    printf("\n%s:%d:\n\tcert1 has trusted group, cert2 doesn't have any groups\n\tSecurity context establishment should succeed\n",__FILE__,__LINE__);
    
    create_proxy(orig_cred,
                 &proxy_cred_trusted,
                 &group,
                 (gss_OID) gss_trusted_group);

    establish_context(orig_cred,
                      proxy_cred_trusted);


    /* case 2 */

    printf("\n%s:%d:\n\tcert1 has untrusted group, cert2 doesn't have any groups\n\tSecurity context establishment should fail\n",__FILE__,__LINE__);
    
    create_proxy(orig_cred,
                 &proxy_cred_untrusted,
                 &group,
                 (gss_OID) gss_untrusted_group);

    establish_context(orig_cred,
                      proxy_cred_untrusted);

    /* case 3 */

    printf("\n%s:%d:\n\tcert1 has trusted group, cert2 has same trusted group\n\tSecurity context establishment should succeed\n",__FILE__,__LINE__);
    
    establish_context(proxy_cred_trusted,
                      proxy_cred_trusted);

    /* case 4 */

    printf("\n%s:%d:\n\tcert1 has untrusted group, cert2 has same untrusted group\n\tSecurity context establishment should succeed\n",__FILE__,__LINE__);
    
    establish_context(proxy_cred_untrusted,
                      proxy_cred_untrusted);

    /* case 5 */
    
    printf("\n%s:%d:\n\tcert1 has trusted group, cert2 has same untrusted group\n\tSecurity context establishment should fail\n",__FILE__,__LINE__);
    
    establish_context(proxy_cred_trusted,
                      proxy_cred_untrusted);

    /* case 6 */

    group.value = (void *) "subgroup2";
    
    printf("\n%s:%d:\n\tcert1 has trusted group, cert2 has same trusted group + trusted subgroup\n\tSecurity context establishment should succeed\n",__FILE__,__LINE__);
    
    create_proxy(proxy_cred_trusted,
                 &proxy_cred_trusted_trusted,
                 &group,
                 (gss_OID) gss_trusted_group);

    establish_context(proxy_cred_trusted,
                      proxy_cred_trusted_trusted);

    /* case 7 */

    printf("\n%s:%d:\n\tcert1 has trusted group, cert2 has same trusted group + untrusted subgroup\n\tSecurity context establishment should fail\n",__FILE__,__LINE__);
    
    create_proxy(proxy_cred_trusted,
                 &proxy_cred_trusted_untrusted,
                 &group,
                 (gss_OID) gss_untrusted_group);
    
    establish_context(proxy_cred_trusted,
                      proxy_cred_trusted_untrusted);

    /* test set/get group */

    maj_stat = gss_inquire_cred(&min_stat, 
                                proxy_cred_trusted_untrusted, 
                                &name, 
                                NULL,
                                NULL,
                                NULL);

    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }

    printf("\n%s:%d:\n\tTesting gss_get_group\n",
           __FILE__,__LINE__);
    
    maj_stat = gss_get_group(&min_stat, 
                             name,
                             &subgroups,
                             &group_types);

    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }

    for(i=0;i<subgroups->count;i++)
    {
        if(g_OID_equal((gss_OID) &group_types->elements[i],
                       gss_untrusted_group))
        {
            printf("\n%s:%d:\n\tCertificate contains untrusted group %s\n",
                   __FILE__,__LINE__,(char *) subgroups->elements[i].value);
        }
        else
        {
            printf("\n%s:%d:\n\tCertificate contains trusted group %s\n",
                   __FILE__,__LINE__,(char *) subgroups->elements[i].value);
        }   
    }


    printf("\n%s:%d:\n\tTesting gss_set_group\n",
           __FILE__,__LINE__);

    subgroups->elements[0].value = "subgroup3";
    
    maj_stat = gss_set_group(&min_stat, 
                             name,
                             subgroups,
                             group_types);

    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }

    maj_stat = gss_get_group(&min_stat, 
                             name,
                             &set_subgroups,
                             &set_group_types);

    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        exit(1);
    }

    for(i=0;i<set_subgroups->count;i++)
    {
        if(g_OID_equal((gss_OID) &set_group_types->elements[i],
                       gss_untrusted_group))
        {
            printf("\n%s:%d:\n\tCertificate contains untrusted group %s\n",
                   __FILE__,__LINE__,(char *) set_subgroups->elements[i].value);
        }
        else
        {
            printf("\n%s:%d:\n\tCertificate contains trusted group %s\n",
                   __FILE__,__LINE__,(char *) set_subgroups->elements[i].value);
        }   
    }
}


static int establish_context(
    gss_cred_id_t                       initiator_cred,
    gss_cred_id_t                       acceptor_cred)
{
    OM_uint32                           init_maj_stat;
    OM_uint32                           accept_maj_stat;
    OM_uint32                           maj_stat;
    OM_uint32                           min_stat;
    OM_uint32                           ret_flags;
    OM_uint32                           time_rec;
    gss_buffer_desc                     send_tok;
    gss_buffer_desc                     recv_tok;
    gss_buffer_desc *                   token_ptr;
    gss_OID                             mech_type;
    gss_name_t                          target_name;
    gss_ctx_id_t  			init_context;
    gss_ctx_id_t  			accept_context;
    gss_ctx_id_desc *                   init_context_handle;
    char *                              error_str;

    /* Initialize variables */
    
    token_ptr = GSS_C_NO_BUFFER;
    init_context = GSS_C_NO_CONTEXT;
    accept_context = GSS_C_NO_CONTEXT;
    accept_maj_stat = GSS_S_CONTINUE_NEEDED;
    ret_flags = 0;

    /* get the target name */

    maj_stat = gss_inquire_cred(&min_stat, 
                                initiator_cred, 
                                &target_name, 
                                NULL,
                                NULL,
                                NULL);

    if(maj_stat != GSS_S_COMPLETE)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        return 1;
    }

    
    /* set up the security context */
    
    init_maj_stat = gss_init_sec_context(&min_stat,
                                         initiator_cred,
                                         &init_context,
                                         target_name,
                                         GSS_C_NULL_OID,
                                         0,
                                         0,
                                         GSS_C_NO_CHANNEL_BINDINGS,
                                         token_ptr,
                                         NULL,
                                         &send_tok,
                                         NULL,
                                         NULL);


    if(init_maj_stat != GSS_S_CONTINUE_NEEDED)
    {
        globus_gss_assist_display_status_str(&error_str,
                                             NULL,
                                             init_maj_stat,
                                             min_stat,
                                             0);
        printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
        return 1;
    }

    while(1)
    {
        
        accept_maj_stat=gss_accept_sec_context(&min_stat,
                                               &accept_context,
                                               acceptor_cred,
                                               &send_tok,
                                               GSS_C_NO_CHANNEL_BINDINGS,
                                               GSS_C_NO_NAME,
                                               &mech_type,
                                               &recv_tok,
                                               &ret_flags,
                                               /* ignore time_rec */
                                               NULL, 
                                               GSS_C_NO_CREDENTIAL);

        if(accept_maj_stat != GSS_S_COMPLETE &&
           accept_maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 init_maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            return 1;
        }
        else if(accept_maj_stat == GSS_S_COMPLETE)
        {
            break;
        }

        init_maj_stat = gss_init_sec_context(&min_stat,
                                             initiator_cred,
                                             &init_context,
                                             target_name,
                                             GSS_C_NULL_OID,
                                             0,
                                             0,
                                             GSS_C_NO_CHANNEL_BINDINGS,
                                             &recv_tok,
                                             NULL,
                                             &send_tok,
                                             NULL,
                                             NULL);
        
        
        if(init_maj_stat != GSS_S_COMPLETE &&
           init_maj_stat != GSS_S_CONTINUE_NEEDED)
        {
            globus_gss_assist_display_status_str(&error_str,
                                                 NULL,
                                                 init_maj_stat,
                                                 min_stat,
                                                 0);
            printf("\nLINE %d ERROR: %s\n\n", __LINE__, error_str);
            return 1;
        }
    }

    printf("%s:%d:\n\tSuccessfully established security context\n",
           __FILE__,
           __LINE__);

    return 0;
}



static X509_EXTENSION *
proxy_extension_create(
    const gss_OID                       extension_oid,
    const gss_buffer_t                  extension_data)

{
    X509_EXTENSION *                    ex = NULL;
    ASN1_OBJECT *                       asn1_obj = NULL;
    ASN1_OCTET_STRING *                 asn1_oct_string = NULL;
    int                                 crit = 1;

    if(g_OID_equal(extension_oid, gss_restrictions_extension))
    {
        asn1_obj = OBJ_txt2obj("RESTRICTEDRIGHTS",0);   
    }
    else if(g_OID_equal(extension_oid, gss_trusted_group))
    {
        asn1_obj = OBJ_txt2obj("TRUSTEDGROUP",0);   
    }
    else if(g_OID_equal(extension_oid, gss_untrusted_group))
    {
        asn1_obj = OBJ_txt2obj("UNTRUSTEDGROUP",0);   
    }
    else
    {
        return ex;
    }
    
    if(!(asn1_oct_string = ASN1_OCTET_STRING_new()))
    {
        /* set some sort of error */
        goto err;
    }

    asn1_oct_string->data = extension_data->value;
    asn1_oct_string->length = extension_data->length;

    if (!(ex = X509_EXTENSION_create_by_OBJ(NULL, asn1_obj, 
                                            crit, asn1_oct_string)))
    {
        /* set some sort of error */
        goto err;
    }
    asn1_oct_string = NULL;

    return ex;

err:
    if (asn1_oct_string)
    {
        ASN1_OCTET_STRING_free(asn1_oct_string);
    }
    
    if (asn1_obj)
    {
        ASN1_OBJECT_free(asn1_obj);
    }
    
    return NULL;
}

static int create_proxy(
    gss_cred_id_t                       cred,
    gss_cred_id_t *                     proxy_cred,
    gss_buffer_t                        group,
    gss_OID                             group_oid)
{
    X509_REQ *                          req = NULL;
    EVP_PKEY *                          private_key = NULL;
    gss_cred_id_desc *                  cred_handle;
    X509_EXTENSION *                    ex = NULL;
    STACK_OF(X509_EXTENSION) *          extensions = NULL;
    X509 *                              new_cert = NULL;

    
    cred_handle = (gss_cred_id_desc *) cred;
    
    proxy_genreq(cred_handle->pcd->ucert,
                 &req,
                 &private_key,
                 0,
                 NULL,
                 cred_handle->pcd);

    extensions = sk_X509_EXTENSION_new_null();

    /* add the extensions here */

    if(group_oid != GSS_C_NO_OID)
    {
        ex = proxy_extension_create(group_oid,
                                    group);

        sk_X509_EXTENSION_push(extensions, ex);
    }

    proxy_sign(cred_handle->pcd->ucert,
               cred_handle->pcd->upkey,
               req,
               &new_cert,
               0,
               extensions,
               0);

    sk_X509_push(cred_handle->pcd->cert_chain,cred_handle->pcd->ucert);
    
    gss_create_and_fill_cred(proxy_cred,
                             GSS_C_BOTH,
                             new_cert,
                             private_key,
                             cred_handle->pcd->cert_chain,
                             NULL);
    
    sk_X509_pop(cred_handle->pcd->cert_chain);

    return 0;
}

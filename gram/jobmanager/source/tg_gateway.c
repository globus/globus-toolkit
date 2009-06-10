/*
 * Portions of this file Copyright 1999-2009 University of Chicago
 * Portions of this file Copyright 1999-2009 The University of Southern Californ
ia.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_common.h"
#include "gssapi.h"
#include "libxml/parser.h"
#include "libxml/xpath.h"
#include "libxml/xpathInternals.h"
#include "libxml/tree.h"
#include "openssl/x509.h"
#include "globus_gram_protocol.h"


static gss_OID_desc  globus_l_saml_oid_desc = 
        {11, (void *) "\x2B\x06\x01\x04\x01\x9B\x50\x01\x01\x01\x0C" };
gss_OID globus_saml_oid = &globus_l_saml_oid_desc;

globus_bool_t
globus_l_tg_saml_assertion_is_self_issued(
    gss_ctx_id_t                        ctx,
    const char *                        entity_id)
{
    /* TODO: Process trusted authorities entities map */
    return GLOBUS_TRUE;
}
/* globus_l_tg_saml_assertion_is_self_issued() */

int
globus_i_gram_get_tg_gateway_user(
    gss_ctx_id_t                        context,
    char **                             gateway_user)
{
    OM_uint32                           maj_stat, min_stat;
    gss_buffer_set_t                    data_set;
    ASN1_UTF8STRING *                   asn1_str;
    char *                              assertion_string;
    unsigned char *                     p;
    long                                pl;
    xmlDocPtr                           doc;
    xmlXPathContextPtr                  xpath_ctx;
    xmlXPathObjectPtr                   xresult;
    int                                 rc;

    *gateway_user = NULL;

    maj_stat =  gss_inquire_sec_context_by_oid(
            &min_stat,
            context,
            globus_saml_oid,
            &data_set);

    if (GSS_ERROR(maj_stat))
    {
        globus_gram_protocol_error_7_hack_replace_message(
                "Error extracting SAML assertion");

        rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION;

        goto inquire_failed;
    }

    /* We'll process only the first SAML assertion bound in the X.509 chain */
    if (data_set->count < 1)
    {
        rc = GLOBUS_SUCCESS;

        goto empty_data_set;
    }

    p = data_set->elements[0].value;
    pl = data_set->elements[0].length;

    /* Convert DER-Encoded string to UTF8 */
    asn1_str = d2i_ASN1_UTF8STRING(NULL, &p, pl);
    if (!asn1_str)
    {
        globus_gram_protocol_error_7_hack_replace_message(
                "Error decoding SAML assertion");
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION;

        goto utfstring_failed;
    }

    assertion_string = malloc(asn1_str->length + 1);
    if (assertion_string == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto assertion_string_malloc_failed;
    }
    memcpy(assertion_string, asn1_str->data, asn1_str->length);
    assertion_string[asn1_str->length] = 0;

    /* Parse SAML assertion */
    doc = xmlParseDoc(BAD_CAST assertion_string);
    if (doc == NULL)
    {
        globus_gram_protocol_error_7_hack_replace_message(
                "Error parsing SAML assertion");
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION;

        goto parse_assertion_failed;
    }

    xmlXPathInit();

    /* Use XPATH to extract Issuer */
    xpath_ctx = xmlXPathNewContext(doc);
    if (xpath_ctx == NULL)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto xpath_ctx_init_failed;
    }
    rc = xmlXPathRegisterNs(
            xpath_ctx,
            (xmlChar *) "s",
            (xmlChar *) "urn:oasis:names:tc:SAML:1.0:assertion");

    if (rc != 0)
    {
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_MALLOC_FAILED;

        goto xpath_register_ns_failed;
    }

    xresult = xmlXPathEvalExpression(
            (const xmlChar *) "string(/s:Assertion/@Issuer)",
            xpath_ctx);

    if (xresult == NULL)
    {
        globus_gram_protocol_error_7_hack_replace_message(
                "Error processing SAML assertion: no \"Issuer\" attribute");
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION;

        goto xpath_eval_issuer_failed;
    }

    if (! globus_l_tg_saml_assertion_is_self_issued(
                context,
                (const char *) xresult->stringval))
    {
        /* Ignore non-self issued assertions */
        rc = GLOBUS_SUCCESS;

        goto non_self_issued;
    }

    xmlXPathFreeObject(xresult);

    /* Use XPATH to extract the sender-vouches, self-issued, TG principal name
     * Subject attribute from the Assertion's AuthenticationStatement
     */
    xresult = xmlXPathEvalExpression(
            (const xmlChar *) "string(/s:Assertion/s:AuthenticationStatement/s:Subject[string(s:SubjectConfirmation/s:ConfirmationMethod) = 'urn:oasis:names:tc:SAML:1.0:cm:sender-vouches' and s:NameIdentifier/@Format = 'http://teragrid.org/names/nameid-format/principalname']/s:NameIdentifier[1])",
            xpath_ctx);

    if (xresult == NULL)
    {
        globus_gram_protocol_error_7_hack_replace_message(
                "Error processing SAML assertion: no teragrid principal");
        rc = GLOBUS_GRAM_PROTOCOL_ERROR_AUTHORIZATION;

        goto get_gateway_name_failed;
    }

    if (xresult != NULL &&
        xresult->stringval != NULL &&
        *(xresult->stringval) != 0)
    {
        *gateway_user = strdup((char *) xresult->stringval);
    }

get_gateway_name_failed:
non_self_issued:
    if (xresult != NULL)
    {
        xmlXPathFreeObject(xresult);
    }
xpath_eval_issuer_failed:
xpath_register_ns_failed:
    xmlXPathFreeContext(xpath_ctx);
xpath_ctx_init_failed:
    xmlFreeDoc(doc);
parse_assertion_failed:
    free(assertion_string);
assertion_string_malloc_failed:
    ASN1_UTF8STRING_free(asn1_str);
utfstring_failed:
    gss_release_buffer_set(&min_stat, &data_set);
empty_data_set:
inquire_failed:
    return rc;
}
/* globus_i_gram_get_tg_gateway_user() */

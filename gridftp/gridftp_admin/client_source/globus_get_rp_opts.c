#include "globus_get_rp.h"

static
globus_result_t
getrp_l_opts_debug(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_get_rp_info_t *              info;

    info = (globus_get_rp_info_t *) arg;

    *out_parms_used = 0;

    info->debug = GLOBUS_TRUE;

    return GLOBUS_SUCCESS;
}

static
globus_result_t
getrp_l_opts_epr(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_result_t                     result;
    globus_soap_message_handle_t        soap_handle;
    globus_get_rp_info_t *              info;
    xsd_QName                           element_name;

    info = (globus_get_rp_info_t *) arg;

    if(info->endpoint != NULL)
    {
        goto error;
    }

    element_name.Namespace = "http://docs.oasis-open.org/wsrf/2004/06/wsrf-WS-ServiceGroup-1.2-draft-01.xsd";
    element_name.local = "MemberServiceEPR";

    result = globus_soap_message_handle_init_from_file(
        &soap_handle,
        opt);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = wsa_EndpointReferenceType_init(&info->epr);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    result = wsa_EndpointReferenceType_deserialize(
        NULL,
        info->epr,
        soap_handle,
        0);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }
    globus_soap_message_handle_destroy(soap_handle);

    *out_parms_used = 1;
    return GLOBUS_SUCCESS;

error:

    return result;
}

static
globus_result_t
getrp_l_opts_sec(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_result_t                     result;
    globus_soap_message_auth_method_t   msg_sec;
    globus_get_rp_info_t *              info;

    info = (globus_get_rp_info_t *) arg;

    if(strcmp("msg", opt) == 0)
    {
        msg_sec = GLOBUS_SOAP_MESSAGE_AUTH_SECURE_MESSAGE;
    }
    else if(strcmp("conv", opt) == 0)
    {
        msg_sec = GLOBUS_SOAP_MESSAGE_AUTH_SECURE_CONVERSATION;
    }
    else if(strcmp("trans", opt) == 0)
    {
        msg_sec = GLOBUS_SOAP_MESSAGE_AUTH_SECURE;
    }
    else
    {
        goto error;
    }

    globus_soap_message_attr_set(
        info->attr,
        GLOBUS_SOAP_MESSAGE_AUTHENTICATION_METHOD_KEY,
        NULL,
        NULL,
        (void *) msg_sec);

    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
error:
    return result;
}

static
globus_result_t
getrp_l_opts_prot(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_result_t                     result;
    globus_get_rp_info_t *              info;

    info = (globus_get_rp_info_t *) arg;

    if(strcmp("sig", opt) == 0)
    {
        /* this is the default */
    }
    else if(strcmp("enc", opt) == 0)
    {
        globus_soap_message_attr_set(
            info->attr,
            GLOBUS_SOAP_MESSAGE_AUTH_PROTECTION_KEY,
            NULL,
            NULL,
            (void *) GLOBUS_SOAP_MESSAGE_AUTH_PROTECTION_PRIVACY);
    }
    else
    {
        /* error */
        goto error;
    }


    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
error:
    return result;
}

static
globus_result_t
getrp_l_opts_url(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    globus_result_t                     result;
    globus_get_rp_info_t *              info;

    info = (globus_get_rp_info_t *) arg;

    if(info->epr != NULL)
    {
        goto error;
    }
    info->endpoint = strdup(opt);

    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
error:

    return result;
}

static
globus_result_t
getrp_l_opts_auth(
    char *                              cmd,
    char *                              opt,
    void *                              arg,
    int *                               out_parms_used)
{
    int                                 value;
    globus_result_t                     result;
    globus_get_rp_info_t *              info;
    gss_buffer_desc                     send_tok;
    gss_name_t                          target_name;
    OM_uint32                           min_stat;
    OM_uint32                           maj_stat;

    info = (globus_get_rp_info_t *) arg;

    if(strcmp("self", opt) == 0)
    {
        value = GLOBUS_SOAP_MESSAGE_AUTHZ_SELF;
    }
    else if(strcmp("host", opt) == 0)
    {
        value = GLOBUS_SOAP_MESSAGE_AUTHZ_HOST;
    }
    else if(strcmp("none", opt) == 0)
    {
        value = GLOBUS_SOAP_MESSAGE_AUTHZ_NONE;
    }
    else
    {
        value = GLOBUS_SOAP_MESSAGE_AUTHZ_IDENTITY;

        send_tok.value = (void *)opt;
        send_tok.length = strlen(opt) + 1;

        maj_stat = gss_import_name(
            &min_stat,
            &send_tok,
            GSS_C_NT_USER_NAME,
            &target_name);
        if(maj_stat != GSS_S_COMPLETE)
        {
            result = globus_error_put(GLOBUS_ERROR_NO_INFO);
            goto error;
        }

        result = globus_soap_message_attr_set(
            info->attr,
            GLOBUS_SOAP_MESSAGE_AUTHZ_TARGET_NAME_KEY,
            NULL,
            NULL,
            (void *)target_name);
        if(result != GLOBUS_SUCCESS)
        {
            goto error;
        }
    }
    result = globus_soap_message_attr_set(
        info->attr,
        GLOBUS_SOAP_MESSAGE_AUTHZ_METHOD_KEY,
        NULL,
        NULL,
        (void *) value);
    if(result != GLOBUS_SUCCESS)
    {
        goto error;
    }

    *out_parms_used = 1;

    return GLOBUS_SUCCESS;
error:
    return result;
}

globus_options_entry_t                   getrp_i_opts_table[] =
{
    {"debug", "d", NULL, NULL, "Enables debug mode", 0, getrp_l_opts_debug},
    {"eprFile", "e", NULL, "<file>", "Loads EPR from file", 
        1, getrp_l_opts_epr},
    {"securityMech", "m", NULL, "<type>", 
        "Sets authentication mechanism: 'msg' (for GSI Secure Message), or 'conv' (for GSI Secure Conversation)", 1, getrp_l_opts_sec},
    {"protection", "p", NULL, "<type>", "sets protection level, can be 'sig' (for signature)  can be 'enc' (for encryption)", 1, getrp_l_opts_prot},
    {"service", "s", NULL, "<url>", "Service URL", 1, getrp_l_opts_url},
    {"z", "authorization", NULL, "<type>", "Sets authorization, can be 'self', 'host', 'hostSelf', 'none' or a string specifying the expected identity of the remote party.", 1, getrp_l_opts_auth},
    {NULL, NULL, NULL, NULL, NULL, 0, NULL}
};




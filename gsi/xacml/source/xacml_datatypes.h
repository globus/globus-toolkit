#ifndef XACML_DATATYPES_H
#define XACML_DATATYPES_H

#ifndef EXTERN_C_BEGIN
#    ifdef __cplusplus
#        define EXTERN_C_BEGIN extern "C" {
#        define EXTERN_C_END }
#    else
#        define EXTERN_C_BEGIN
#        define EXTERN_C_END
#    endif
#endif

EXTERN_C_BEGIN

typedef struct xacml_request_s * xacml_request_t;
typedef struct xacml_response_s * xacml_response_t;

typedef enum
{
    SAML_STATUS_Success,
    SAML_STATUS_Requester,
    SAML_STATUS_Responder,
    SAML_STATUS_VersionMismatch,
    SAML_STATUS_AuthnFailed,
    SAML_STATUS_InvalidAttrNameOrValue,
    SAML_STATUS_InvalidNameIDPolicy,
    SAML_STATUS_NoAuthnContext,
    SAML_STATUS_NoAvailableIDP,
    SAML_STATUS_NoPassive,
    SAML_STATUS_NoSupportedIDP,
    SAML_STATUS_PartialLogout,
    SAML_STATUS_ProxyCountExceeded,
    SAML_STATUS_RequestDenied,
    SAML_STATUS_RequestUnsupported,
    SAML_STATUS_RequestVersionDeprecated,
    SAML_STATUS_RequestVersionTooHigh,
    SAML_STATUS_RequestVersionTooLow,
    SAML_STATUS_ResourceNotRecognized,
    SAML_STATUS_TooManyResponses,
    SAML_STATUS_UnknownAttrProfile,
    SAML_STATUS_UnknownPrincipal,
    SAML_STATUS_UnsupportedBinding
}
saml_status_code_t;

extern const char *saml_status_code_strings[];

typedef enum
{
    XACML_STATUS_missing_attribute,
    XACML_STATUS_ok,
    XACML_STATUS_processing_error,
    XACML_STATUS_syntax_error
}
xacml_status_code_t;

extern const char *xacml_status_code_strings[];


typedef enum
{
    XACML_DECISION_Permit,
    XACML_DECISION_Deny,
    XACML_DECISION_Indeterminate,
    XACML_DECISION_NotApplicable
}
xacml_decision_t;

typedef enum
{
    XACML_EFFECT_Permit,
    XACML_EFFECT_Deny,
}
xacml_effect_t;

typedef int (*xacml_obligation_handler_t) (
    void *                              handler_arg,
    const xacml_response_t              response,
    const char *                        obligation_id,
    xacml_effect_t                      fulfill_on,
    const char *                        attribute_ids[],
    const char *                        datatypes[],
    const char *                        values[]);

typedef int (*xacml_authorization_handler_t) (
    void *                              handler_arg,
    const xacml_request_t               request,
    xacml_response_t                    response);

    
/* Set of Attribute Datatypes from Appendix B of xacml 2.0 core spec */
/* char * value */
#define XACML_DATATYPE_X500_NAME \
        "urn:oasis:names:tc:xacml:1.0:data-type:x500Name"
/* char * value */
#define XACML_DATATYPE_RFC822_NAME \
        "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name"
/* char * value */
#define XACML_DATATYPE_IP_ADDRESS \
        "urn:oasis:names:tc:xacml:2.0:data-type:ipAddress"
/* char * value */
#define XACML_DATATYPE_DNS_NAME \
        "urn:oasis:names:tc:xacml:2.0:data-type:dnsName"
/* char * value */
#define XACML_DATATYPE_STRING \
        "http://www.w3.org/2001/XMLSchema#string"
/* int * value */
#define XACML_DATATYPE_BOOLEAN \
        "http://www.w3.org/2001/XMLSchema#boolean"
/* int * value */
#define XACML_DATATYPE_INTEGER \
        "http://www.w3.org/2001/XMLSchema#integer"
/* double * value */
#define XACML_DATATYPE_DOUBLE \
        "http://www.w3.org/2001/XMLSchema#double"
/* time_t * value */
#define XACML_DATATYPE_TIME \
        "http://www.w3.org/2001/XMLSchema#time"
/* time_t * value */
#define XACML_DATATYPE_DATE \
        "http://www.w3.org/2001/XMLSchema#date"
/* time_t * value */
#define XACML_DATATYPE_DATE_TIME \
        "http://www.w3.org/2001/XMLSchema#dateTime"
/* char * value */
#define XACML_DATATYPE_ANY_URI \
        "http://www.w3.org/2001/XMLSchema#anyURI"
/* char * value */
#define XACML_DATATYPE_HEX_BINARY \
        "http://www.w3.org/2001/XMLSchema#hexBinary"
/* char * value */
#define XACML_DATATYPE_BASE64_BINARY \
        "http://www.w3.org/2001/XMLSchema#base64Binary"

/* Subject Categories */
#define XACML_SUBJECT_CATEGORY_ACCESS_SUBJECT \
        "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
#define XACML_SUBJECT_CATEGORY_RECIPIENT_SUBJECT \
        "urn:oasis:names:tc:xacml:1.0:subject-category:recipient-subject"
#define XACML_SUBJECT_CATEGORY_INTERMEDIARY_SUBJECT \
        "urn:oasis:names:tc:xacml:1.0:subject-category:intermediary-subject"
#define XACML_SUBJECT_CATEGORY_CODEBASE \
        "urn:oasis:names:tc:xacml:1.0:subject-category:codebase"
#define XACML_SUBJECT_CATEGORY_REQUESTING_MACHINE \
        "urn:oasis:names:tc:xacml:1.0:subject-category:requesting-machine"

/* Subject Attributes */
#define XACML_SUBJECT_ATTRIBUTE_SUBJECT_ID \
        "urn:oasis:names:tc:xacml:1.0:subject:subject-id"
#define XACML_SUBJECT_ATTRIBUTE_SUBJECT_CATEGORY \
        "urn:oasis:names:tc:xacml:1.0:subject-category"
#define XACML_SUBJECT_ATTRIBUTE_SUBJECT_ID_QUALIFIER \
        "urn:oasis:names:tc:xacml:1.0:subject:subject-id-qualifier"
#define XACML_SUBJECT_ATTRIBUTE_KEY_INFO \
        "urn:oasis:names:tc:xacml:1.0:subject:key-info"
#define XACML_SUBJECT_ATTRIBUTE_AUTHENTICATION_TIME \
        "urn:oasis:names:tc:xacml:1.0:subject:authentication-time"
#define XACML_SUBJECT_ATTRIBUTE_AUTHENTICATION_METHOD \
        "urn:oasis:names:tc:xacml:1.0:subject:authn-locality:authentication-method"
#define XACML_SUBJECT_ATTRIBUTE_REQUEST_TIME \
        "urn:oasis:names:tc:xacml:1.0:subject:request-time"
#define XACML_SUBJECT_ATTRIBUTE_SESSION_START_TIME \
        "urn:oasis:names:tc:xacml:1.0:subject:session-start-time"
#define XACML_SUBJECT_ATTRIBUTE_AUTHN_LOCALITY_IP_ADDRESS \
        "urn:oasis:names:tc:xacml:1.0:subject:authn-locality:ip-address"
#define XACML_SUBJECT_ATTRIBUTE_AUTHN_LOCALITY_DNS_NAME \
        "urn:oasis:names:tc:xacml:1.0:subject:authn-locality:dns-name"

/* Resource Attributes */
#define XACML_RESOURCE_ATTRIBUTE_RESOURCE_ID \
        "urn:oasis:names:tc:xacml:1.0:resource:resource-id"
#define XACML_RESOURCE_ATTRIBUTE_TARGETN_NAMESPACE \
        "urn:oasis:names:tc:xacml:2.0:resource:target-namespace"

/* Action Attributes */
#define XACML_ACTION_ATTRIBUTE_ACTION_ID \
        "urn:oasis:names:tc:xacml:1.0:action:action-id"
#define XACML_ACTION_ATTRIBUTE_IMPLIED_ACTION \
        "urn:oasis:names:tc:xacml:1.0:action:implied-action"
#define XACML_ACTION_ATTRIBUTE_ACTION_NAMESPACE \
        "urn:oasis:names:tc:xacml:1.0:action:action-namespace"

/* Environment Attributes */
#define XACML_ENVIRONMENT_ATTRIBUTE_CURRENT_TIME \
        "urn:oasis:names:tc:xacml:1.0:environment:current-time"
#define XACML_ENVIRONMENT_ATTRIBUTE_CURRENT_DATE \
        "urn:oasis:names:tc:xacml:1.0:environment:current-date"
#define XACML_ENVIRONMENT_ATTRIBUTE_CURRENT_DATE_TIME \
        "urn:oasis:names:tc:xacml:1.0:environment:current-dateTime"

/* SAML NameID formats */
#define SAML_NAME_ID_FORMAT_UNSPECIFIED \
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
#define SAML_NAME_ID_FORMAT_EMAIL_ADDRESS \
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
#define SAML_NAME_ID_FORMAT_X509_SUBJECT_NAME \
        "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
#define SAML_NAME_ID_FORMAT_WINDOWS_DOMAIN_QUALIFIED_NAME \
        "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
#define SAML_NAME_ID_FORMAT_KERBEROS \
        "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
#define SAML_NAME_ID_FORMAT_ENTITY \
        "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
#define SAML_NAME_ID_FORMAT_PERSISTENT \
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
#define SAML_NAME_ID_FORMAT_TRANSIENT \
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

EXTERN_C_END

#endif /* XACML_DATATYPES_H */

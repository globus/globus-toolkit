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

#include <stdlib.h>
#include <sys/socket.h>

#ifndef DONT_DOCUMENT_INTERNAL
EXTERN_C_BEGIN
#endif

#define XACML_IO_DESCRIPTOR "xacml_io_descriptor"

/**
 XACML Request Handle
 @ingroup xacml_common
 @see xacml_request_init(), xacml_request_destroy()
 */
typedef struct xacml_request_s * xacml_request_t;

/**
 XACML Resource Attribute
 @ingroup xacml_common
 @see xacml_resource_attribute_init(), xacml_resource_attribute_destroy()
 */
typedef struct xacml_resource_attribute_s * xacml_resource_attribute_t;

/**
 XACML Response Handle
 @ingroup xacml_common
 */
typedef struct xacml_response_s * xacml_response_t;

/**
 XACML Obligation Handle
 @ingroup xacml_common
 */
typedef struct xacml_obligation_s * xacml_obligation_t;

/**
 @defgroup xacml_io XACML I/O Callbacks
 */

typedef void* (*xacml_io_connect_t)(
    const char                         *endpoint,
    const char                         *host,
    int                                 port);

typedef int (*xacml_io_send_t)(
    void                               *arg,
    const char                         *data,
    size_t                              size);

typedef size_t (*xacml_io_recv_t)(
    void                               *arg,
    char                               *data,
    size_t                              size);

typedef int (*xacml_io_close_t)(
    void                               *arg);

typedef void * (*xacml_io_accept_t)(
    int                                 socket,
    struct sockaddr                    *addr,
    socklen_t                          *addr_len,
    int                                *sock_out);

typedef struct
{
    char *                              name;
    xacml_io_accept_t                   accept_func;
    xacml_io_connect_t                  connect_func;
    xacml_io_send_t                     send_func;
    xacml_io_recv_t                     recv_func;
    xacml_io_close_t                    close_func;
}
xacml_io_descriptor_t;

/**
 * SAML Status Codes
 * @ingroup xacml_common
 * These codes correspond to the values described in the section 3.2.2.2 of the
 * <a href="http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf">SAML 2.0 Core specification</a>
 */
typedef enum
{
    /** The request succeeded. */
    SAML_STATUS_Success,
    /**
     * The request could not be performed due to an error on the part of the
     * requester.
     */
    SAML_STATUS_Requester,
    /**
     * The request could not be performed due to an error on the part of the
     * SAML responder or SAML authority.
     */
    SAML_STATUS_Responder,
    /** 
     * The SAML responder could not process the request because the version of
     * the request message was incorrect. 
     */
    SAML_STATUS_VersionMismatch,
    /**
     * The responding provider was unable to successfully authenticate the
     * principal.
     */
    SAML_STATUS_AuthnFailed,
    /**
     * Unexpected or invalid content was encountered within a @a saml:Attribute
     * or @a saml:AttributeValue element.
     */
    SAML_STATUS_InvalidAttrNameOrValue,
    /**
     * The responding provider cannot or will not support the requested name
     * identifier policy. 
     */
    SAML_STATUS_InvalidNameIDPolicy,
    /**
     * The specified authentication context requirements cannot be met by the
     * responder. 
     */
    SAML_STATUS_NoAuthnContext,
    /**
     * Used by an intermediary to indicate that none of the supported identity
     * provider @a Loc elements in an @a IDPList can be resolved or that none
     * of the supported identity providers are available.
     */
    SAML_STATUS_NoAvailableIDP,
    /**
     * Indicates the responding provider cannot authenticate the principal
     * passively, as has been requested.
     */
    SAML_STATUS_NoPassive,
    /**
     * Used by an intermediary to indicate that none of the identity providers
     * in an @a IDPList are supported by the intermediary.
     */
    SAML_STATUS_NoSupportedIDP,
    /**
     * Used by a session authority to indicate to a session participant that it
     * was not able to propagate logout to all other session participants.
     */
    SAML_STATUS_PartialLogout,
    /**
     * Indicates that a responding provider cannot authenticate the principal
     * directly and is not permitted toproxy the request further. 
     */
    SAML_STATUS_ProxyCountExceeded,
    /**
     * The SAML responder or SAML authority is able to process the request but
     * has chosen not to respond. This status code MAY be used when there is
     * concern about the security context of the request message or the
     * sequence of request messages received from a particular requester.
     */
    SAML_STATUS_RequestDenied,
    /**
     * The SAML responder or SAML authority does not support the request.
     */
    SAML_STATUS_RequestUnsupported,
    /**
     * The SAML responder cannot process any requests with the protocol version
     * specified in the request. 
     */
    SAML_STATUS_RequestVersionDeprecated,
    /**
     * The SAML responder cannot process the request because the protocol
     * version specified in the request message is a major upgrade from the
     * highest protocol version supported by the responder.
     */
    SAML_STATUS_RequestVersionTooHigh,
    /**
     * The SAML responder cannot process the request because the protocol
     * version specified in the request message is too low.
     */
    SAML_STATUS_RequestVersionTooLow,
    /**
     * The resource value provided in the request message is invalid or
     * unrecognized. 
     */
    SAML_STATUS_ResourceNotRecognized,
    /**
     * The response message would contain more elements than the SAML responder
     * is able to return. 
     */
    SAML_STATUS_TooManyResponses,
    /**
     * An entity that has no knowledge of a particular attribute profile has
     * been presented with an attribute drawn from that profile.
     */
    SAML_STATUS_UnknownAttrProfile,
    /**
     * The responding provider does not recognize the principal specified or
     * implied by the request. 
     */
    SAML_STATUS_UnknownPrincipal,
    /**
     * The SAML responder cannot properly fulfill the request using the
     * protocol binding specified in the requerequest.
     */
    SAML_STATUS_UnsupportedBinding
}
saml_status_code_t;

/**
 * XCAML API Return Values
 * @ingroup xacml_common
 */
typedef enum
{
    /** Success */
    XACML_RESULT_SUCCESS,
    /** Invalid parameter */
    XACML_RESULT_INVALID_PARAMETER,
    /** Obligation could not be processed */
    XACML_RESULT_OBLIGATION_FAILED,
    /** Error processing message */
    XACML_RESULT_SOAP_ERROR,
    /** Invalid state */
    XACML_RESULT_INVALID_STATE
}
xacml_result_t;

/**
 SAML Status Code Strings
 @ingroup xacml_common
 The enumeration values in #saml_status_code_t can be used as indices into this
 string array.
 */
extern const char *saml_status_code_strings[];

/**
 * XACML Status Codes
 * @ingroup xacml_common
 * These codes correspond to the values described in the appendix B.9 of the
 * <a href="http://docs.oasis-open.org/xacml/2.0/access_control-xacml-2.0-core-spec-os.pdf">XACML 2.0 specification</a>
 */
typedef enum
{
    /**
     * This identifier indicates success.
     */
    XACML_STATUS_ok,
    /**
     * This identifier indicates that all the attributes necessary to make a
     * policy decision were not available.
     */
    XACML_STATUS_missing_attribute,
    /**
     * This identifier indicates that some attribute value contained a syntax
     * error, such as a letter in a numeric field.
     */
    XACML_STATUS_syntax_error,
    /**
     * This identifier indicates that an error occurred during policy
     * evaluation.  An example would be division by zero.
     */
    XACML_STATUS_processing_error
}
xacml_status_code_t;

/**
 XACML Status Code Strings
 @ingroup xacml_common
 The enumeration values in #xacml_status_code_t can be used as indices into this
 string array.
 */
extern const char *xacml_status_code_strings[];

/**
 * XACML Decisions
 * @ingroup xacml_common
 * These codes correspond to the values described in the section 6.11 of the
 * <a href="http://docs.oasis-open.org/xacml/2.0/access_control-xacml-2.0-core-spec-os.pdf">XACML 2.0 specification</a>
 */
typedef enum
{
    /**
     * The requested access is permitted.
     */
    XACML_DECISION_Permit,
    /**
     * The requested access is denied.
     */
    XACML_DECISION_Deny,
    /**
     * The PDP is unable to evaluate the requested access.  Reasons for such
     * inability include: missing attributes, network errors while retrieving
     * policies, division by zero during policy evaluation, syntax errors in
     * the decision request or in the policy, etc..
     */
    XACML_DECISION_Indeterminate,
    /**
     * The PDP does not have any policy that applies to this decision request.
     */
    XACML_DECISION_NotApplicable
}
xacml_decision_t;

/**
 XACML Effects
 @ingroup xacml_common
 */
typedef enum
{
    /**
     * The requested access is permitted.
     */
    XACML_EFFECT_Permit,
    /**
     * The requested access is denied.
     */
    XACML_EFFECT_Deny,
}
xacml_effect_t;

/**
 Obligation Handler Callback
 @ingroup xacml_client

 @param handler_arg
     Application-specification handler argument.
 @param response
     Server response value.
 @param obligation_id
     Name of the obligation contained in the response
 @param fulfill_on
     Effect indicating when the obligation applies.
 @param attribute_ids
     XACML attribute names associated with the obligation values
 @param datatypes
     XACML attribute datatypes associated with the obligation values
 @param values
     String representation of the obligation values
 */
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


/**
 * @defgroup xacml_common_datatypes Attribute Data Types
 * @ingroup xacml_common
 *
 * These macros define constants which can be used for XACML 2.0-compliant
 * subject category attributes. See Appendex B.3 of 
 * http://docs.oasis-open.org/xacml/2.0/access_control-xacml-2.0-core-spec-os.pdf
 * for details.
 */
/**
 * X.500 Name
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_X500_NAME \
        "urn:oasis:names:tc:xacml:1.0:data-type:x500Name"
/**
 * RFC 822 Name
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_RFC822_NAME \
        "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name"
/**
 * IP Address
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_IP_ADDRESS \
        "urn:oasis:names:tc:xacml:2.0:data-type:ipAddress"
/**
 * DNS Name
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_DNS_NAME \
        "urn:oasis:names:tc:xacml:2.0:data-type:dnsName"
/**
 * String
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_STRING \
        "http://www.w3.org/2001/XMLSchema#string"
/**
 * Boolean
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_BOOLEAN \
        "http://www.w3.org/2001/XMLSchema#boolean"
/**
 * Integer
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_INTEGER \
        "http://www.w3.org/2001/XMLSchema#integer"
/**
 * Double
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_DOUBLE \
        "http://www.w3.org/2001/XMLSchema#double"
/**
 * Time
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_TIME \
        "http://www.w3.org/2001/XMLSchema#time"
/**
 * Date
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_DATE \
        "http://www.w3.org/2001/XMLSchema#date"
/**
 * DateTime
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_DATE_TIME \
        "http://www.w3.org/2001/XMLSchema#dateTime"
/**
 * anyURI
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_ANY_URI \
        "http://www.w3.org/2001/XMLSchema#anyURI"
/**
 * hexBinary
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_HEX_BINARY \
        "http://www.w3.org/2001/XMLSchema#hexBinary"
/**
 * base64Binary
 * @ingroup xacml_common_datatypes
 */
#define XACML_DATATYPE_BASE64_BINARY \
        "http://www.w3.org/2001/XMLSchema#base64Binary"

/**
 * @defgroup xacml_common_subject_categories Access Subject Categories
 * @ingroup xacml_common
 * These macros define constants which can be used for XACML 2.0-compliant
 * subject category attributes. See Appendex B.2 of 
 * http://docs.oasis-open.org/xacml/2.0/access_control-xacml-2.0-core-spec-os.pdf
 * for details.
 *
 * @see xacml_request_add_subject_attribute()
 */ 
/**
 * Access Subject
 * @ingroup xacml_common_subject_categories
 */
#define XACML_SUBJECT_CATEGORY_ACCESS_SUBJECT \
        "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
/**
 * Recipient Subject
 * @ingroup xacml_common_subject_categories
 */
#define XACML_SUBJECT_CATEGORY_RECIPIENT_SUBJECT \
        "urn:oasis:names:tc:xacml:1.0:subject-category:recipient-subject"
/**
 * Intermediary Subject
 * @ingroup xacml_common_subject_categories
 */
#define XACML_SUBJECT_CATEGORY_INTERMEDIARY_SUBJECT \
        "urn:oasis:names:tc:xacml:1.0:subject-category:intermediary-subject"
/**
 * Codebase
 * @ingroup xacml_common_subject_categories
 */
#define XACML_SUBJECT_CATEGORY_CODEBASE \
        "urn:oasis:names:tc:xacml:1.0:subject-category:codebase"
/**
 * Requesting Machine
 * @ingroup xacml_common_subject_categories
 */
#define XACML_SUBJECT_CATEGORY_REQUESTING_MACHINE \
        "urn:oasis:names:tc:xacml:1.0:subject-category:requesting-machine"

/**
 * @defgroup xacml_common_subject_attributes Subject Attributes
 * @ingroup xacml_common
 *
 * These macros define constants which can be used for XACML 2.0-compliant
 * subject category attributes. See Appendex B.4 of 
 * http://docs.oasis-open.org/xacml/2.0/access_control-xacml-2.0-core-spec-os.pdf
 * for details.
 *
 * @see xacml_request_add_subject_attribute()
 */
/* Subject Attributes */

/**
 * Subject Identifier
 * @ingroup xacml_common_subject_attributes
 */
#define XACML_SUBJECT_ATTRIBUTE_SUBJECT_ID \
        "urn:oasis:names:tc:xacml:1.0:subject:subject-id"
/**
 * Subject Category
 * @ingroup xacml_common_subject_attributes
 */
#define XACML_SUBJECT_ATTRIBUTE_SUBJECT_CATEGORY \
        "urn:oasis:names:tc:xacml:1.0:subject-category"
/**
 * Subject Id Qualifier
 * @ingroup xacml_common_subject_attributes
 */
#define XACML_SUBJECT_ATTRIBUTE_SUBJECT_ID_QUALIFIER \
        "urn:oasis:names:tc:xacml:1.0:subject:subject-id-qualifier"
/**
 * Key Information
 * @ingroup xacml_common_subject_attributes
 */
#define XACML_SUBJECT_ATTRIBUTE_KEY_INFO \
        "urn:oasis:names:tc:xacml:1.0:subject:key-info"
/**
 * Authentication Time
 * @ingroup xacml_common_subject_attributes
 */
#define XACML_SUBJECT_ATTRIBUTE_AUTHENTICATION_TIME \
        "urn:oasis:names:tc:xacml:1.0:subject:authentication-time"
/**
 * Authentication Method
 * @ingroup xacml_common_subject_attributes
 */
#define XACML_SUBJECT_ATTRIBUTE_AUTHENTICATION_METHOD \
        "urn:oasis:names:tc:xacml:1.0:subject:authn-locality:authentication-method"
/**
 * Request Time
 * @ingroup xacml_common_subject_attributes
 */
#define XACML_SUBJECT_ATTRIBUTE_REQUEST_TIME \
        "urn:oasis:names:tc:xacml:1.0:subject:request-time"
/**
 * Session Start Time
 * @ingroup xacml_common_subject_attributes
 */
#define XACML_SUBJECT_ATTRIBUTE_SESSION_START_TIME \
        "urn:oasis:names:tc:xacml:1.0:subject:session-start-time"
/**
 * Authentication Locality IP Address
 * @ingroup xacml_common_subject_attributes
 */
#define XACML_SUBJECT_ATTRIBUTE_AUTHN_LOCALITY_IP_ADDRESS \
        "urn:oasis:names:tc:xacml:1.0:subject:authn-locality:ip-address"
/**
 * Authentication Locality DNS Name
 * @ingroup xacml_common_subject_attributes
 */
#define XACML_SUBJECT_ATTRIBUTE_AUTHN_LOCALITY_DNS_NAME \
        "urn:oasis:names:tc:xacml:1.0:subject:authn-locality:dns-name"

/**
 * @defgroup xacml_common_resource_attributes Resource Attributes
 * @ingroup xacml_common
 *
 * These macros define constants which can be used for XACML 2.0-compliant
 * subject category attributes. See Appendex B.6 of 
 * http://docs.oasis-open.org/xacml/2.0/access_control-xacml-2.0-core-spec-os.pdf
 * for details.
 *
 * @see xacml_request_add_resource_attribute()
 */

/**
 * Resource ID
 * @ingroup xacml_common_resource_attributes
 */
#define XACML_RESOURCE_ATTRIBUTE_RESOURCE_ID \
        "urn:oasis:names:tc:xacml:1.0:resource:resource-id"
/**
 * Target Namespace
 * @ingroup xacml_common_resource_attributes
 */
#define XACML_RESOURCE_ATTRIBUTE_TARGETN_NAMESPACE \
        "urn:oasis:names:tc:xacml:2.0:resource:target-namespace"
/*@}*/

/**
 * @defgroup xacml_common_action_attributes Action Attributes
 * @ingroup xacml_common
 *
 * These macros define constants which can be used for XACML 2.0-compliant
 * subject category attributes. See Appendex B.7 of 
 * http://docs.oasis-open.org/xacml/2.0/access_control-xacml-2.0-core-spec-os.pdf
 * for details.
 *
 * @see xacml_request_add_action_attribute()
 */
/**
 * Action ID
 * @ingroup xacml_common_action_attributes
 */
#define XACML_ACTION_ATTRIBUTE_ACTION_ID \
        "urn:oasis:names:tc:xacml:1.0:action:action-id"
/**
 * Implied Action
 * @ingroup xacml_common_action_attributes
 */
#define XACML_ACTION_ATTRIBUTE_IMPLIED_ACTION \
        "urn:oasis:names:tc:xacml:1.0:action:implied-action"
/**
 * Action Namespace
 * @ingroup xacml_common_action_attributes
 */
#define XACML_ACTION_ATTRIBUTE_ACTION_NAMESPACE \
        "urn:oasis:names:tc:xacml:1.0:action:action-namespace"

/* Environment Attributes */
/**
 * @defgroup xacml_common_environment_attributes Environment Attributes
 * @ingroup xacml_common
 *
 * These macros define constants which can be used for XACML 2.0-compliant
 * subject category attributes. See Appendex B.8 of 
 * http://docs.oasis-open.org/xacml/2.0/access_control-xacml-2.0-core-spec-os.pdf
 * for details.
 *
 * @see xacml_request_add_environment_attribute()
 */

/**
 * Current Time
 * @ingroup xacml_common_environment_attributes
 */
#define XACML_ENVIRONMENT_ATTRIBUTE_CURRENT_TIME \
        "urn:oasis:names:tc:xacml:1.0:environment:current-time"
/**
 * Current Date
 * @ingroup xacml_common_environment_attributes
 */
#define XACML_ENVIRONMENT_ATTRIBUTE_CURRENT_DATE \
        "urn:oasis:names:tc:xacml:1.0:environment:current-date"
/**
 * Current Date and Time
 * @ingroup xacml_common_environment_attributes
 */
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

#ifndef DONT_DOCUMENT_INTERNAL
EXTERN_C_END
#endif

#endif /* XACML_DATATYPES_H */

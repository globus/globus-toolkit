#include "xacml_datatypes.h"
#include "stdsoap2.h"

extern "C"
int
xacml_init(void)
{
    soap_ssl_init();
    return 0;
}

extern "C"
const char *saml_status_code_strings[] =
{
    "urn:oasis:names:tc:SAML:2.0:status:Success",
    "urn:oasis:names:tc:SAML:2.0:status:Requester",
    "urn:oasis:names:tc:SAML:2.0:status:Responder",
    "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch",
    "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
    "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue",
    "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy",
    "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext",
    "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP",
    "urn:oasis:names:tc:SAML:2.0:status:NoPassive",
    "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP",
    "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
    "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded",
    "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
    "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported",
    "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated",
    "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh",
    "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow",
    "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized",
    "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses",
    "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile",
    "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
    "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
};


extern "C"
const char *xacml_status_code_strings[] = 
{
    "urn:oasis:names:tc:xacml:1.0:status:missing-attribute",
    "urn:oasis:names:tc:xacml:1.0:status:ok",
    "urn:oasis:names:tc:xacml:1.0:status:processing-error",
    "urn:oasis:names:tc:xacml:1.0:status:syntax-error"
};

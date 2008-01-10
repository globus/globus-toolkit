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

#include "xacml_datatypes.h"
#include "stdsoap2.h"

/**
 * Initialize the XACML / SAML Library
 * @ingroup xacml_common
 * 
 * Applications must call this before calling any other functions in this
 * library.
 * 
 * @retval XACML_RESULT_SUCCESS
 * Library initialized successfully.
 */
extern "C"
xacml_result_t
xacml_init(void)
{
    return XACML_RESULT_SUCCESS;
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

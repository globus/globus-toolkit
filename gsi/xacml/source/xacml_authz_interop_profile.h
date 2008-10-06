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

#ifndef XACML_AUTHZ_INTEROP_PROFILE_H
#define XACML_AUTHZ_INTEROP_PROFILE_H

#include "xacml_datatypes.h"

#ifndef DONT_DOCUMENT_INTERNAL
EXTERN_C_BEGIN
#endif

/**
 * @defgroup xacml_authz_interop_profile Interop Profile Constants
 */

typedef enum
{
    XACML_INTEROP_SUBJECT_X509_ID,
    XACML_INTEROP_SUBJECT_CONDOR_CANONICAL_NAME_ID,
    XACML_INTEROP_SUBJECT_X509_ISSUER,
    XACML_INTEROP_VO,
    XACML_INTEROP_VOMS_SIGNING_SUBJECT,
    XACML_INTEROP_VOMS_SIGNING_ISSUER,
    XACML_INTEROP_VOMS_FQAN,
    XACML_INTEROP_VOMS_PRIMARY_FQAN,
    XACML_INTEROP_CERTIFICATE_SERIAL_NUMBER,
    XACML_INTEROP_CA_SERIAL_NUMBER,
    XACML_INTEROP_VOMS_DNS_PORT,
    XACML_INTEROP_CA_POLICY_OID,
    XACML_INTEROP_CERT_CHAIN
}
xacml_interop_profile_subject_attr_t;

extern const char *xacml_interop_profile_subject_attr_strings[];

typedef enum
{
    XACML_INTEROP_ACTION_RSL_STRING
}
xacml_interop_profile_action_attr_t;

extern const char *xacml_interop_profile_action_attr_strings[];

typedef enum
{
    XACML_INTEROP_ACTION_TYPE_QUEUE,
    XACML_INTEROP_ACTION_TYPE_EXECUTE_NOW,
    XACML_INTEROP_ACTION_TYPE_ACCESS
}
xacml_interop_profile_action_type_enum_t;

extern const char *xacml_interop_profile_action_type_enum_strings[];

typedef enum
{
    XACML_INTEROP_RESOURCE_DNS_HOST_NAME,
    XACML_INTEROP_RESOURCE_X509_ID,
    XACML_INTEROP_RESOURCE_X509_ISSUER
}
xacml_interop_profile_resource_attr_t;

extern const char *xacml_interop_profile_resource_attr_strings[];

typedef enum
{
    XACML_INTEROP_RESOURCE_TYPE_CE,
    XACML_INTEROP_RESOURCE_TYPE_SE,
    XACML_INTEROP_RESOURCE_TYPE_WN
}
xacml_interop_profile_resource_type_enum_t;

extern const char *xacml_interop_profile_resource_type_enum_strings[];

typedef enum
{
    XACML_INTEROP_ENV_PEP_OBLIG_SUPPORTED,
    XACML_INTEROP_ENV_PILOT_JOB_SUBJECT_X509_ID,
    XACML_INTEROP_ENV_PILOT_JOB_SUBJECT_CONDOR_CANONICAL_NAME_ID,
    XACML_INTEROP_ENV_PILOT_JOB_SUBJECT_X509_ISSUER,
    XACML_INTEROP_ENV_PILOT_JOB_VO,
    XACML_INTEROP_ENV_PILOT_JOB_VOMS_SIGNING_SUBJECT,
    XACML_INTEROP_ENV_PILOT_JOB_VOMS_SIGNING_ISSUER,
    XACML_INTEROP_ENV_PILOT_JOB_VOMS_FQAN,
    XACML_INTEROP_ENV_PILOT_JOB_VOMS_PRIMARY_FQAN
}
xacml_interop_profile_environment_attr_t;

extern const char *xacml_interop_profile_environment_attr_strings[];

typedef enum
{
    XACML_INTEROP_OBLIGATION_UIDGID,
    XACML_INTEROP_OBLIGATION_SECONDARY_GIDS,
    XACML_INTEROP_OBLIGATION_USERNAME,
    XACML_INTEROP_OBLIGATION_AFS_TOKEN,
    XACML_INTEROP_OBLIGATION_ROOT_AND_HOME_PATHS,
    XACML_INTEROP_OBLIGATION_STORAGE_ACCESS_PRIORITY,
    XACML_INTEROP_OBLIGATION_ACCESS_PERMISSIONS
}
xacml_interop_profile_obligation_t;

extern const char *xacml_interop_profile_obligation_strings[];

typedef enum
{
    XACML_INTEROP_OBLIGATION_ATTR_POSIX_UID,
    XACML_INTEROP_OBLIGATION_ATTR_POSIX_GID,
    XACML_INTEROP_OBLIGATION_ATTR_USERNAME,
    XACML_INTEROP_OBLIGATION_ATTR_AFS_TOKEN,
    XACML_INTEROP_OBLIGATION_ATTR_ROOTPATH,
    XACML_INTEROP_OBLIGATION_ATTR_HOMEPATH,
    XACML_INTEROP_OBLIGATION_ATTR_STORAGE_PRIORITY,
    XACML_INTEROP_OBLIGATION_ATTR_ACCESS_PERMISSIONS,
    
}
xacml_interop_profile_obligation_attrs_t;

extern const char *xacml_interop_profile_obligation_attr_strings[];

#ifndef DONT_DOCUMENT_INTERNAL
EXTERN_C_END
#endif

#endif /* XACML_AUTHZ_INTEROP_PROFILE_H */

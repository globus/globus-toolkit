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

#include "xacml_authz_interop_profile.h"

#define XACML_AUTHZ_INTEROP_PREFIX "http://authz-interop.org/xacml/"
#define XACML_AUTHZ_INTEROP_SUBJECT_PREFIX XACML_AUTHZ_INTEROP_PREFIX "subject/"
#define XACML_AUTHZ_INTEROP_ACTION_PREFIX XACML_AUTHZ_INTEROP_PREFIX "action/"
#define XACML_AUTHZ_INTEROP_ACTION_TYPE_PREFIX XACML_AUTHZ_INTEROP_ACTION_PREFIX "action-type/"
#define XACML_AUTHZ_INTEROP_RESOURCE_PREFIX XACML_AUTHZ_INTEROP_PREFIX "resource/"
#define XACML_AUTHZ_INTEROP_RESOURCE_TYPE_PREFIX XACML_AUTHZ_INTEROP_RESOURCE_PREFIX "resource-type/"
#define XACML_AUTHZ_INTEROP_ENV_PREFIX XACML_AUTHZ_INTEROP_PREFIX "environment/"
#define XACML_AUTHZ_INTEROP_PILOT_JOB_PREFIX XACML_AUTHZ_INTEROP_ENV_PREFIX "pilot-job/"
#define XACML_AUTHZ_INTEROP_OBLIGATION_PREFIX XACML_AUTHZ_INTEROP_PREFIX "obligation/"
#define XACML_AUTHZ_INTEROP_ATTRIBUTE_PREFIX XACML_AUTHZ_INTEROP_PREFIX "attribute/"

extern "C" const char *xacml_interop_profile_subject_attr_strings[] =
{
    XACML_AUTHZ_INTEROP_SUBJECT_PREFIX "subject-x509-id",
    XACML_AUTHZ_INTEROP_SUBJECT_PREFIX "subject-condor-canonical-name-id",
    XACML_AUTHZ_INTEROP_SUBJECT_PREFIX "subject-x509-issuer",
    XACML_AUTHZ_INTEROP_SUBJECT_PREFIX "vo",
    XACML_AUTHZ_INTEROP_SUBJECT_PREFIX "voms-signing-subject",
    XACML_AUTHZ_INTEROP_SUBJECT_PREFIX "voms-signing-issuer",
    XACML_AUTHZ_INTEROP_SUBJECT_PREFIX "voms-fqan",
    XACML_AUTHZ_INTEROP_SUBJECT_PREFIX "voms-primary-fqan",
    XACML_AUTHZ_INTEROP_SUBJECT_PREFIX "certificate-serial-number",
    XACML_AUTHZ_INTEROP_SUBJECT_PREFIX "ca-serial-number",
    XACML_AUTHZ_INTEROP_SUBJECT_PREFIX "voms-dns-port",
    XACML_AUTHZ_INTEROP_SUBJECT_PREFIX "ca-policy-oid",
    XACML_AUTHZ_INTEROP_SUBJECT_PREFIX "cert-chain"
};

extern "C" const char *xacml_interop_profile_action_attr_strings[] =
{
    XACML_AUTHZ_INTEROP_ACTION_PREFIX "rsl-string"
};

extern "C" const char *xacml_interop_profile_action_type_enum_strings[] =
{
    XACML_AUTHZ_INTEROP_ACTION_TYPE_PREFIX "queue",
    XACML_AUTHZ_INTEROP_ACTION_TYPE_PREFIX "execute-now",
    XACML_AUTHZ_INTEROP_ACTION_TYPE_PREFIX "access"
};

extern "C" const char *xacml_interop_profile_resource_attr_strings[] =
{
    XACML_AUTHZ_INTEROP_RESOURCE_PREFIX "dns-host-name",
    XACML_AUTHZ_INTEROP_RESOURCE_PREFIX "resource-x509-id",
    XACML_AUTHZ_INTEROP_RESOURCE_PREFIX "resource-x509-issuer"
};

extern "C" const char *xacml_interop_profile_resource_type_enum_strings[] =
{
    XACML_AUTHZ_INTEROP_RESOURCE_TYPE_PREFIX "ce",
    XACML_AUTHZ_INTEROP_RESOURCE_TYPE_PREFIX "se",
    XACML_AUTHZ_INTEROP_RESOURCE_TYPE_PREFIX "wn"
};

extern "C" const char *xacml_interop_profile_environment_attr_strings[] =
{
    XACML_AUTHZ_INTEROP_ENV_PREFIX "pep-oblig-supported",
    XACML_AUTHZ_INTEROP_PILOT_JOB_PREFIX "subject-x509_-id",
    XACML_AUTHZ_INTEROP_PILOT_JOB_PREFIX "subject-condor-canonical-name-id",
    XACML_AUTHZ_INTEROP_PILOT_JOB_PREFIX "subject-x509-issuer",
    XACML_AUTHZ_INTEROP_PILOT_JOB_PREFIX "vo",
    XACML_AUTHZ_INTEROP_PILOT_JOB_PREFIX "voms-signing-subject",
    XACML_AUTHZ_INTEROP_PILOT_JOB_PREFIX "voms-signing-issuer",
    XACML_AUTHZ_INTEROP_PILOT_JOB_PREFIX "voms-fqan",
    XACML_AUTHZ_INTEROP_PILOT_JOB_PREFIX "voms-primary-fqan"
};

extern "C" const char *xacml_interop_profile_obligation_strings[] =
{
    XACML_AUTHZ_INTEROP_OBLIGATION_PREFIX "uidgid",
    XACML_AUTHZ_INTEROP_OBLIGATION_PREFIX "secondary-gids",
    XACML_AUTHZ_INTEROP_OBLIGATION_PREFIX "username",
    XACML_AUTHZ_INTEROP_OBLIGATION_PREFIX "afs-token",
    XACML_AUTHZ_INTEROP_OBLIGATION_PREFIX "root-and-home-paths",
    XACML_AUTHZ_INTEROP_OBLIGATION_PREFIX "storage-access-priority",
    XACML_AUTHZ_INTEROP_OBLIGATION_PREFIX "access-permissions"
};

extern "C" const char *xacml_interop_profile_obligation_attr_strings[] =
{
    XACML_AUTHZ_INTEROP_ATTRIBUTE_PREFIX "posix-uid",
    XACML_AUTHZ_INTEROP_ATTRIBUTE_PREFIX "posix-gid",
    XACML_AUTHZ_INTEROP_ATTRIBUTE_PREFIX "username",
    XACML_AUTHZ_INTEROP_ATTRIBUTE_PREFIX "afs-token",
    XACML_AUTHZ_INTEROP_ATTRIBUTE_PREFIX "rootpath",
    XACML_AUTHZ_INTEROP_ATTRIBUTE_PREFIX "homepath",
    XACML_AUTHZ_INTEROP_ATTRIBUTE_PREFIX "storage-priority",
    XACML_AUTHZ_INTEROP_ATTRIBUTE_PREFIX "access-permissions"
};

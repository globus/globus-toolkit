/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_gsi_gssapi_constants.h
 * @author Sam Lang, Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#ifndef _GLOBUS_GSI_GSSAPI_CONSTANTS_H_
#define _GLOBUS_GSI_GSSAPI_CONSTANTS_H_

extern char *                globus_l_gsi_gssapi_error_strings[];

/**
 * @defgroup globus_gsi_gssapi_constants GSI GSS-API Constants
 */

/**
 * @name Error Codes
 * @ingroup globus_gsi_gssapi_constants
 */
typedef enum
{    
    GLOBUS_GSI_GSSAPI_ERROR_HANDSHAKE = 0,
    GLOBUS_GSI_GSSAPI_ERROR_NO_GLOBUSID = 1,
    GLOBUS_GSI_GSSAPI_ERROR_PROCESS_CERT = 2,
    GLOBUS_GSI_GSSAPI_ERROR_MUTUAL_AUTH = 3,
    GLOBUS_GSI_GSSAPI_ERROR_WRAP_BIO = 4,
    GLOBUS_GSI_GSSAPI_ERROR_PROXY_VIOLATION = 5,
    GLOBUS_GSI_GSSAPI_ERROR_PROXY_NOT_RECEIVED = 6,
    GLOBUS_GSI_GSSAPI_ERROR_BAD_ARGUMENT = 7,
    GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BIO_SSL = 8,
    GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_NO_CIPHER = 9,
    GLOBUS_GSI_GSSAPI_ERROR_IMPEXP_BAD_LEN = 10,
    GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CREDENTIAL = 11,
    GLOBUS_GSI_GSSAPI_ERROR_EXPORT_FAIL = 12,
    GLOBUS_GSI_GSSAPI_ERROR_IMPORT_FAIL = 13,
    GLOBUS_GSI_GSSAPI_ERROR_READ_BIO = 14,
    GLOBUS_GSI_GSSAPI_ERROR_WRITE_BIO = 15,
    GLOBUS_GSI_GSSAPI_ERROR_WITH_GSS_CONTEXT = 16,
    GLOBUS_GSI_GSSAPI_ERROR_UNEXPECTED_FORMAT = 17,
    GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_PROXY = 18,    
    GLOBUS_GSI_GSSAPI_ERROR_WITH_CALLBACK_DATA = 19,
    GLOBUS_GSI_GSSAPI_ERROR_BAD_DATE = 20,
    GLOBUS_GSI_GSSAPI_ERROR_BAD_MECH = 21,
    GLOBUS_GSI_GSSAPI_ERROR_ADD_EXT = 22,
    GLOBUS_GSI_GSSAPI_ERROR_REMOTE_CERT_VERIFY_FAILED = 23,
    GLOBUS_GSI_GSSAPI_ERROR_OUT_OF_MEMORY = 24,
    GLOBUS_GSI_GSSAPI_ERROR_BAD_NAME = 25,
    GLOBUS_GSI_GSSAPI_ERROR_UNORDERED_CHAIN = 26,
    GLOBUS_GSI_GSSAPI_ERROR_WITH_GSI_CREDENTIAL = 27,
    GLOBUS_GSI_GSSAPI_ERROR_WITH_OPENSSL = 28,
    GLOBUS_GSI_GSSAPI_ERROR_TOKEN_FAIL = 29,
    GLOBUS_GSI_GSSAPI_ERROR_WITH_DELEGATION = 30,
    GLOBUS_GSI_GSSAPI_ERROR_WITH_OID = 31,
    GLOBUS_GSI_GSSAPI_ERROR_EXPIRED_CREDENTIAL = 32,
    GLOBUS_GSI_GSSAPI_ERROR_WITH_MIC = 33,
    GLOBUS_GSI_GSSAPI_ERROR_ENCRYPTING_MESSAGE = 34,
    GLOBUS_GSI_GSSAPI_ERROR_WITH_BUFFER = 35,
    GLOBUS_GSI_GSSAPI_ERROR_GETTING_PEER_CRED = 36,
    GLOBUS_GSI_GSSAPI_ERROR_UNKNOWN_OPTION = 37,
    GLOBUS_GSI_GSSAPI_ERROR_CREATING_ERROR_OBJ = 38,
    GLOBUS_GSI_GSSAPI_ERROR_CANONICALIZING_HOST = 39,
    GLOBUS_GSI_GSSAPI_ERROR_UNSUPPORTED = 40,
    GLOBUS_GSI_GSSAPI_ERROR_AUTHZ_DENIED = 41,
    GLOBUS_GSI_GSSAPI_ERROR_LAST = 42
} globus_gsi_gssapi_error_t;

#define GLOBUS_GSI_GSSAPI_ERROR_BASE            100

#define GLOBUS_GSI_GSSAPI_ERROR_MINOR_STATUS(_ERROR_VALUE_) \
            _ERROR_VALUE_ + GLOBUS_GSI_GSSAPI_ERROR_BASE


/**
 * @name Cred Export/Import Type
 * @ingroup globus_gsi_gssapi_constants
 */
/* @{ */
typedef enum {
    GSS_IMPEXP_OPAQUE_FORM = 0,
    GSS_IMPEXP_MECH_SPECIFIC = 1
} gss_impexp_cred_type_t;
/* @} */

/**
 * @name Connection State Type
 * @ingroup globus_gsi_gssapi_constants
 */
/* @{ */
typedef enum {
    GSS_CON_ST_HANDSHAKE = 0,
    GSS_CON_ST_FLAGS,
    GSS_CON_ST_REQ,
    GSS_CON_ST_CERT,
    GSS_CON_ST_DONE
} gss_con_st_t;
/* @} */

/**
 * @name Delegation State Type
 * @ingroup globus_gsi_gssapi_constants
 */
/* @{ */
typedef enum
{
    GSS_DELEGATION_START,
    GSS_DELEGATION_DONE,
    GSS_DELEGATION_COMPLETE_CRED,
    GSS_DELEGATION_SIGN_CERT
} gss_delegation_state_t;
/* @} */

/**
 * @name Compare Name Type
 * @ingroup globus_gsi_gssapi_constants
 */
/* @{ */
typedef enum
{
    GSS_NAMES_NOT_EQUAL = 0,
    GSS_NAMES_EQUAL = 1
} gss_names_equal_t;
/* @} */

/**
 * @name Context Established State Type
 * @ingroup globus_gsi_gssapi_constants
 */
/* @{ */
typedef enum
{
    GSS_CTX_FULLY_ESTABLISHED = 1,
    GSS_CTX_TOKEN_EXPECTED_FROM_PEER = 0
} gss_ctx_state_t;
/* @} */

/**
 * @name Confidentiality State Type
 * @ingroup globus_gsi_gssapi_constants
 */
/* @{ */
typedef enum
{
    GSS_CONFIDENTIALITY = 1,
    GSS_INTEGRITY_ONLY = 0
} gss_conf_state_t;
/* @} */

#define GSS_SSL_MESSAGE_DIGEST_PADDING  12
#define GSS_SSL3_WRITE_SEQUENCE_SIZE    8

#endif

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file globus_xio_gsi.h
 * @author Sam Meder
 * 
 * $RCSfile$
 * $Revision$
 * $Date$
 */
#endif

#ifndef GLOBUS_XIO_GSI_DRIVER_INCLUDE
#define GLOBUS_XIO_GSI_DRIVER_INCLUDE

#include "gssapi.h"
#include "globus_common.h"

/**
 * @defgroup globus_xio_gsi_datatypes Datatypes
 */

/**
 * Globus XIO GSI cntl operation types
 * @ingroup globus_xio_gsi_datatypes
 */
typedef enum
{
    /** Set the credential to be used */
    /** if this is called with the handle_cntl, there must be no outstanding
     * operations on the handle.
     */
    GLOBUS_XIO_GSI_SET_CREDENTIAL,
    /** Get the credential to be used */
    GLOBUS_XIO_GSI_GET_CREDENTIAL,
    /** Set the GSSAPI req_flags to be used */
    GLOBUS_XIO_GSI_SET_GSSAPI_REQ_FLAGS,
    /** Get the GSSAPI req_flags to be used */
    GLOBUS_XIO_GSI_GET_GSSAPI_REQ_FLAGS,
    /** Set the proxy mode. See globus_xio_gsi_proxy_mode_t */
    GLOBUS_XIO_GSI_SET_PROXY_MODE,
    /** Get the proxy mode. See globus_xio_gsi_proxy_mode_t */
    GLOBUS_XIO_GSI_GET_PROXY_MODE,
    /** Set the delegation mode. See globus_xio_gsi_delegation_mode_t */
    GLOBUS_XIO_GSI_SET_DELEGATION_MODE,
    /** Get the delegation mode. See globus_xio_gsi_delegation_mode_t */
    GLOBUS_XIO_GSI_GET_DELEGATION_MODE,
    /** Make the on the wire protocol SSL compatible. This implies no wrapping
     * of security tokens and no delegation
     */ 
    GLOBUS_XIO_GSI_SET_SSL_COMPATIBLE,
    /** Do anonymous authentication */
    GLOBUS_XIO_GSI_SET_ANON,
    /** Wrap security tokens */
    GLOBUS_XIO_GSI_SET_WRAP_MODE,
    /** Get the wrapping mode */
    GLOBUS_XIO_GSI_GET_WRAP_MODE,
    /** Set the read buffer size */
    GLOBUS_XIO_GSI_SET_BUFFER_SIZE,
    /** Get the read buffer size */
    GLOBUS_XIO_GSI_GET_BUFFER_SIZE,
    /** Set the protection level. See globus_xio_gsi_protection_level_t */
    GLOBUS_XIO_GSI_SET_PROTECTION_LEVEL,
    /** Get the protection level See globus_xio_gsi_protection_level_t */
    GLOBUS_XIO_GSI_GET_PROTECTION_LEVEL,
    /** Set the expected peer name */
    GLOBUS_XIO_GSI_GET_TARGET_NAME,
    /** Get the expected peer name */
    GLOBUS_XIO_GSI_SET_TARGET_NAME,
    /** Get the GSS context */
    GLOBUS_XIO_GSI_GET_CONTEXT,
    /** Get the delegated credential */
    GLOBUS_XIO_GSI_GET_DELEGATED_CRED,
    /** Get the name of the peer */
    GLOBUS_XIO_GSI_GET_PEER_NAME,
    /** Get the name associated with the local credentials */
    GLOBUS_XIO_GSI_GET_LOCAL_NAME,
    /** Initialize delegation-at-any-time process */
    GLOBUS_XIO_GSI_INIT_DELEGATION,
    /** Initialize non-blocking delegation-at-any-time process */
    GLOBUS_XIO_GSI_REGISTER_INIT_DELEGATION,
    /** Accept delegation-at-any-time process */
    GLOBUS_XIO_GSI_ACCEPT_DELEGATION,
    /** Accept delegation-at-any-time process */
    GLOBUS_XIO_GSI_REGISTER_ACCEPT_DELEGATION,
    /** Set with target cntl. Behave as though this was a server
     * (accept delegation) */
    GLOBUS_XIO_GSI_FORCE_SERVER_MODE
} globus_xio_gsi_cmd_t;

/**
 * Globus XIO GSI protection levels
 * @ingroup globus_xio_gsi_datatypes
 */
typedef enum
{
    /** No security */
    GLOBUS_XIO_GSI_PROTECTION_LEVEL_NONE,
    /** Messages are signed */
    GLOBUS_XIO_GSI_PROTECTION_LEVEL_INTEGRITY,
    /** Messages are encrypted */
    GLOBUS_XIO_GSI_PROTECTION_LEVEL_PRIVACY
} globus_xio_gsi_protection_level_t;

/**
 * Globus XIO GSI delegation modes
 * @ingroup globus_xio_gsi_datatypes
 */
typedef enum
{
    /** No delegation */
    GLOBUS_XIO_GSI_DELEGATION_MODE_NONE,
    /** Delegate a limited proxy */
    GLOBUS_XIO_GSI_DELEGATION_MODE_LIMITED,
    /** Delegate a full proxy */
    GLOBUS_XIO_GSI_DELEGATION_MODE_FULL
} globus_xio_gsi_delegation_mode_t;

/**
 * Globus XIO GSI proxy modes
 * @ingroup globus_xio_gsi_datatypes
 */
typedef enum
{
    /** Accept only full proxies */
    GLOBUS_XIO_GSI_PROXY_MODE_FULL,
    /** Accept full proxies and limited proxies if they are
     *  the only limited proxy in the cert chain.
     */
    GLOBUS_XIO_GSI_PROXY_MODE_LIMITED,
    /** Accept both full and limited proxies unconditionally */
    GLOBUS_XIO_GSI_PROXY_MODE_MANY
} globus_xio_gsi_proxy_mode_t;

/**
 * Globus XIO GSI init delegation callback
 * @ingroup globus_xio_gsi_datatypes
 */
typedef void (* globus_xio_gsi_delegation_init_callback_t)(
    globus_result_t			result,
    void *				user_arg);

/**
 * Globus XIO GSI init delegation callback
 * @ingroup globus_xio_gsi_datatypes
 */
typedef void (* globus_xio_gsi_delegation_accept_callback_t)(
    globus_result_t			result,
    gss_cred_id_t                       delegated_cred,
    OM_uint32                           time_rec,
    void *				user_arg);


#endif

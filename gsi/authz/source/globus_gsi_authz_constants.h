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
 * @file globus_gsi_cred_constants.h
 * Globus GSI Authorization Library
 *
 */
#endif

#ifndef GLOBUS_GSI_AUTHZ_CONSTANTS_H
#define GLOBUS_GSI_AUTHZ_CONSTANTS_H

/**
 * @defgroup globus_gsi_authz_constants GSI Credential Constants
 */
/**
 * GSI Authz Error codes
 * @ingroup globus_gsi_authz_constants
 */
typedef enum
{
    GLOBUS_GSI_AUTHZ_ERROR_SUCCESS = 0,
    GLOBUS_GSI_AUTHZ_ERROR_ERRNO = 1,
    GLOBUS_GSI_AUTHZ_ERROR_BAD_PARAMETER = 2,
    GLOBUS_GSI_AUTHZ_ERROR_CALLOUT = 3,
    GLOBUS_GSI_AUTHZ_ERROR_LAST = 4
} globus_gsi_authz_error_t;

#endif


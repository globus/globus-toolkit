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
 * @file globus_i_error_gssapi.h
 * Globus Gssapi Error
 *
 * $RCSfile$
 * $Revision$
 * $Date $
 */

#include "globus_common.h"
#include "gssapi.h"
#include "globus_error_gssapi.h"

#ifndef GLOBUS_I_INCLUDE_GSSAPI_ERROR_H
#define GLOBUS_I_INCLUDE_GSSAPI_ERROR_H

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

EXTERN_C_BEGIN

/**
 * GSSAPI Error object instance data definition
 * @ingroup globus_gssapi_error_object
 * @internal
 *
 * This structure contains all of the data associated with a Globus
 * GSSAPI Error.
 *
 * @see globus_error_construct_gssapi_error(),
 *      globus_error_initialize_gssapi_error(),
 *      globus_l_error_free_gssapi()
 */

typedef struct globus_l_gssapi_error_data_s
{
    /** the major status */
    OM_uint32                           major_status;
    /** the minor status */
    OM_uint32                           minor_status;
    globus_bool_t                       is_globus_gsi;
}
globus_l_gssapi_error_data_t;

EXTERN_C_END

#endif /* GLOBUS_I_INCLUDE_GSSAPI_ERROR_H */

#endif /* GLOBUS_DONT_DOCUMENT_INTERNAL */

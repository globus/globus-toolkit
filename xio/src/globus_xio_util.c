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

#include "globus_xio_util.h"
#include "globus_xio_types.h"
#include "globus_common.h"

globus_bool_t
globus_xio_error_is_eof(
    globus_result_t                     res)
{
    return globus_error_match(
        globus_error_peek(res), GLOBUS_XIO_MODULE, GLOBUS_XIO_ERROR_EOF);
}

globus_bool_t
globus_xio_error_is_canceled(
    globus_result_t                     res)
{
    return globus_error_match(
        globus_error_peek(res), GLOBUS_XIO_MODULE, GLOBUS_XIO_ERROR_CANCELED);
}

globus_bool_t
globus_xio_error_match(
    globus_result_t                     result,
    int                                 type)
{
    return globus_error_match(
        globus_error_peek(result), GLOBUS_XIO_MODULE, type);
}

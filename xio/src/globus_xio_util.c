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

globus_result_t
globus_xio_contact_info_copy(
    globus_xio_contact_t **             dst,
    const globus_xio_contact_t *        src)
{
    globus_result_t                     result;
    globus_xio_contact_t *              ci;
    GlobusXIOName(globus_xio_contact_info_copy);

    if(dst == NULL)
    {
        result = GlobusXIOErrorParameter("dst");
        goto error;
    }
    if(src == NULL)
    {
        result = GlobusXIOErrorParameter("src");
        goto error;
    }

    ci = (globus_xio_contact_t *)
        globus_calloc(1, sizeof(globus_xio_contact_t));
    if(ci == NULL)
    {
        result = GlobusXIOErrorMemory("ci");
        goto error;
    }

    if(src->unparsed)
    {
        ci->unparsed = strdup(src->unparsed);
    }
    if(src->resource)
    {
        ci->resource = strdup(src->resource);
    }
    if(src->host)
    {
        ci->host = strdup(src->host);
    }
    if(src->port)
    {
        ci->port = strdup(src->port);
    }
    if(src->scheme)
    {
        ci->scheme = strdup(src->scheme);
    }
    if(src->user)
    {
        ci->user = strdup(src->user);
    }
    if(src->pass)
    {
        ci->pass = strdup(src->pass);
    }
    if(src->subject)
    {
        ci->subject = strdup(src->subject);
    }

    *dst = ci;

    return GLOBUS_SUCCESS;
error:
    return result;
}


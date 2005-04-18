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

#ifndef _TEST_DRIVERS_
#define _TEST_DRIVERS_

GlobusDebugDeclare(GLOBUS_XIO_TEST);

enum
{
    GLOBUS_XIO_TEST_DEBUG_TRACE = 1,
    GLOBUS_XIO_TEST_DEBUG_INTERNAL_TRACE = 2,
    GLOBUS_XIO_TEST_DEBUG_INFO_VERBOSE = 4,
    GLOBUS_XIO_TEST_DEBUG_STATE = 8
};

#define GlobusXIOTestDebugPrintf(level, message)                            \
    GlobusDebugPrintf(GLOBUS_XIO_TEST, level, message)
#define GlobusXIOTestDebugEnter()                                           \
    GlobusXIOTestDebugPrintf(                                               \
        GLOBUS_XIO_TEST_DEBUG_TRACE,                                        \
        ("[%s] Entering\n", _xio_name))

#define GlobusXIOTestDebugExit()                                            \
    GlobusXIOTestDebugPrintf(                                               \
        GLOBUS_XIO_TEST_DEBUG_TRACE,                                        \
        ("[%s] Exiting\n", _xio_name))

#define GlobusXIOTestDebugExitWithError()                                   \
    GlobusXIOTestDebugPrintf(                                               \
        GLOBUS_XIO_TEST_DEBUG_TRACE,                                        \
        ("[%s] Exiting with error\n", _xio_name))

#define GlobusXIOTestDebugInternalEnter()                                   \
    GlobusXIOTestDebugPrintf(                                               \
        GLOBUS_XIO_TEST_DEBUG_INTERNAL_TRACE,                               \
        ("[%s] I Entering\n", _xio_name))

#define GlobusXIOTestDebugInternalExit()                                    \
    GlobusXIOTestDebugPrintf(                                               \
        GLOBUS_XIO_TEST_DEBUG_INTERNAL_TRACE,                               \
        ("[%s] I Exiting\n", _xio_name))

#define GlobusXIOTestDebugInternalExitWithError()                           \
    GlobusXIOTestDebugPrintf(                                               \
        GLOBUS_XIO_TEST_DEBUG_INTERNAL_TRACE,                               \
        ("[%s] I Exiting with error\n", _xio_name))

#endif

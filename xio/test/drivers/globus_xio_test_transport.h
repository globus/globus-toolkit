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

#if !defined GLOBUS_XIO_TEST_TRANSPORT_H
#define GLOBUS_XIO_TEST_TRANSPORT_H 1

#include "globus_common.h"

typedef enum globus_xio_test_failure_e
{
    GLOBUS_XIO_TEST_FAIL_NONE,
    GLOBUS_XIO_TEST_FAIL_PASS_OPEN,
    GLOBUS_XIO_TEST_FAIL_FINISH_OPEN,
    GLOBUS_XIO_TEST_FAIL_PASS_CLOSE,
    GLOBUS_XIO_TEST_FAIL_FINISH_CLOSE,
    GLOBUS_XIO_TEST_FAIL_PASS_READ,
    GLOBUS_XIO_TEST_FAIL_FINISH_READ,
    GLOBUS_XIO_TEST_FAIL_PASS_WRITE,
    GLOBUS_XIO_TEST_FAIL_FINISH_WRITE,
    GLOBUS_XIO_TEST_FAIL_PASS_ACCEPT,
    GLOBUS_XIO_TEST_FAIL_FINISH_ACCEPT
} globus_xio_test_failure_t;

enum
{
    GLOBUS_XIO_TEST_SET_INLINE,
    GLOBUS_XIO_TEST_SET_FAILURES,
    GLOBUS_XIO_TEST_SET_USECS,
    GLOBUS_XIO_TEST_READ_EOF_BYTES,
    GLOBUS_XIO_TEST_CHUNK_SIZE,
    GLOBUS_XIO_TEST_RANDOM
};

#endif

/*
 * Copyright 1999-2006 University of Chicago
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

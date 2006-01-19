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

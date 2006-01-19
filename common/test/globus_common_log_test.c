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

#include "globus_common.h"
#ifdef WIN32
#include "globus_logging.h"
#endif

int 
main(
    int                                 argc, 
    char **                             argv)
{
    int                                 count;
    globus_result_t                     res;
    globus_reltime_t                    delay;
    globus_abstime_t                    abstime;
    globus_logging_handle_t             log_handle;

    globus_module_activate(GLOBUS_COMMON_MODULE);

    /*
     *   this should be all inline
     */
    res = globus_logging_init(
        &log_handle,
        NULL,
        1024,
        255,
        &globus_logging_stdio_module,
        stdout);
    globus_assert(res == GLOBUS_SUCCESS);

    count = 1;
    res = globus_logging_write(log_handle, 1, "first message: %d\n", count);
    globus_assert(res == GLOBUS_SUCCESS);

    count++;
    res = globus_logging_write(log_handle, 5, "message: %d\n", count);
    globus_assert(res == GLOBUS_SUCCESS);

    count++;
    res = globus_logging_write(log_handle, 31, "message: %d\n", count);
    globus_assert(res == GLOBUS_SUCCESS);
 
    res = globus_logging_destroy(log_handle); 
    globus_assert(res == GLOBUS_SUCCESS);

    GlobusTimeReltimeSet(delay, 5, 0);
    res = globus_logging_init(
        &log_handle,
        &delay,
        1024,
        255,
        &globus_logging_stdio_module,
        stdout);
    globus_assert(res == GLOBUS_SUCCESS);

    count++;
    res = globus_logging_write(log_handle, 1, "next set message: %d\n", count);
    globus_assert(res == GLOBUS_SUCCESS);

    count++;
    res = globus_logging_write(log_handle, 5, "message: %d\n", count);
    globus_assert(res == GLOBUS_SUCCESS);

    count++;
    res = globus_logging_write(log_handle, 31, "message: %d\n", count);
    globus_assert(res == GLOBUS_SUCCESS);

    fprintf(stdout, "3 should follow\n");
    res = globus_logging_flush(log_handle);
    globus_assert(res == GLOBUS_SUCCESS);

    count++;
    res = globus_logging_write(log_handle, 1, "next set message: %d\n", count);
    globus_assert(res == GLOBUS_SUCCESS);

    count++;
    res = globus_logging_write(log_handle, 5, "message: %d\n", count);
    globus_assert(res == GLOBUS_SUCCESS);

    count++;
    res = globus_logging_write(log_handle, 31, "message: %d\n", count);
    globus_assert(res == GLOBUS_SUCCESS);

    fprintf(stdout, "waiting for final set\n");
    GlobusTimeAbstimeSet(abstime, 6, 0);
    globus_callback_poll(&abstime);

    fprintf(stdout, "last is inline\n");
    count++;
    res = globus_logging_write(log_handle, 3 | GLOBUS_LOGGING_INLINE, 
            "message: %d\n", count);
    globus_assert(res == GLOBUS_SUCCESS);

    fprintf(stdout, "no more\n");
    res = globus_logging_destroy(log_handle); 
    globus_assert(res == GLOBUS_SUCCESS);

    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return 0;
}

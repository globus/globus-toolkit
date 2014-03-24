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

#include "globus_io.h"
#ifndef TARGET_ARCH_WIN32
#include <fcntl.h>
#endif

#include "globus_preload.h"

/*
 * Function:    main
 *
 * Description: 
 *              
 * Parameters:  
 *
 * Returns:     
 */
int
main(int argc, char **argv)
{
    int                                 rc;
    globus_result_t                     result;
    globus_object_t *                   error = NULL;
    char *                              errstring;
    globus_io_handle_t                  handle;
    globus_io_handle_t                  stdout_handle;
    globus_size_t                       bytes;
    globus_size_t                       i;
    globus_byte_t                       buf[1024];
    const char *                        path = getenv("DATA_FILE");

    LTDL_SET_PRELOADED_SYMBOLS();
    if (path == NULL && argc < 2)
    {
        fprintf(stderr, "# Usage: %s DATA_FILE\n", argv[0]);
        exit(99);
    }
    else if (path == NULL)
    {
        path = argv[1];
    }
    rc = globus_module_activate(GLOBUS_COMMON_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "# Error activating GLOBUS_COMMON_MODULE\n");
        exit(99);
    }
    rc = globus_module_activate(GLOBUS_IO_MODULE);
    if (rc != GLOBUS_SUCCESS)
    {
        fprintf(stderr, "# Error activating GLOBUS_COMMON_MODULE\n");
        exit(99);
    }
    result = globus_io_file_open(path,
				 O_RDONLY,
				 0600,
				 GLOBUS_NULL,
				 &handle);

    if(result != GLOBUS_SUCCESS)
    {
        error = globus_error_get(result);
        errstring = globus_object_printable_to_string(error);
        globus_libc_printf("test failed to open %s: %s\n", path, errstring);
        goto done;
    }
    
#ifndef TARGET_ARCH_WIN32
    result = globus_io_file_posix_convert(
        fileno(stdout),
        GLOBUS_NULL,
        &stdout_handle);
#else
    result = globus_io_file_windows_convert(
        GetStdHandle(STD_OUTPUT_HANDLE),
        GLOBUS_NULL,
        &stdout_handle);
#endif
    if(result != GLOBUS_SUCCESS)
    {
        error = globus_error_get(result);
        errstring = globus_object_printable_to_string(error);
        globus_libc_printf("test failed to convert stdout to io handle: %s\n",
                           errstring);
        goto done;
    }

    do
    {
        result = globus_io_read(&handle,
                                buf,
                                sizeof(buf),
                                sizeof(buf),
                                &bytes);
        if(result == GLOBUS_SUCCESS ||
           ((error = globus_error_get(result)) &&
            (globus_object_type_match(globus_object_get_type(error),
                                      GLOBUS_IO_ERROR_TYPE_EOF))))
        {
            globus_size_t           nbytes2;
            
	globus_io_write(&stdout_handle,
			buf,
			bytes,
			&nbytes2);
        }
        else
        {
            errstring = globus_object_printable_to_string(error);
            globus_libc_printf("test failed to read /etc/group: %s\n",
                               errstring);
            goto done;

        }
    }
    while(result == GLOBUS_SUCCESS);

 done:

    if(error)
    {
        globus_object_free(error);
    }
    
    globus_io_close(&handle);
    globus_io_close(&stdout_handle);

    globus_module_deactivate(GLOBUS_IO_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return 0;
}
/* main() */

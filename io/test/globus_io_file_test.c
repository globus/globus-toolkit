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

#include "globus_io.h"
#ifndef TARGET_ARCH_WIN32
#include <fcntl.h>
#endif
/* forward declaration */
void usage( char * executableName );

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
#ifdef TARGET_ARCH_WIN32
	HANDLE						outputFile;
    globus_io_handle_t			write_handle;

	if ( argc < 3 )
	{
		usage( argv[0] );
		return -1;
	}
#endif

    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_IO_MODULE);

#ifndef TARGET_ARCH_WIN32
    result = globus_io_file_open("/etc/group",
				 O_RDONLY,
				 0600,
				 GLOBUS_NULL,
				 &handle);
#else
    result = globus_io_file_open( argv[1],
				 O_RDONLY,
				 0600,
				 GLOBUS_NULL,
				 &handle);
#endif

    if(result != GLOBUS_SUCCESS)
    {
        error = globus_error_get(result);
        errstring = globus_object_printable_to_string(error);
#ifndef TARGET_ARCH_WIN32
        globus_libc_printf("test failed to open /etc/group: %s\n", errstring);
#else
        globus_libc_printf("test failed to open %s: %s\n", argv[1], errstring);
#endif
        goto done;
    }
    
#ifndef TARGET_ARCH_WIN32
    result = globus_io_file_posix_convert(
        fileno(stdout),
        GLOBUS_NULL,
        &stdout_handle);
#else
	outputFile= CreateFile( argv[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
	 FILE_FLAG_OVERLAPPED, NULL );
	if ( outputFile == INVALID_HANDLE_VALUE )
	{
		printf( "An error occurred while trying to create the output file (error is %d)...exiting\n",
		 GetLastError() );
		return -1;
	}
    result= globus_io_file_windows_convert(
		outputFile,
		GLOBUS_NULL,
		&write_handle);
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
            
#ifndef TARGET_ARCH_WIN32
	globus_io_write(&stdout_handle,
			buf,
			bytes,
			&nbytes2);
#else
		globus_io_write( &write_handle,
				buf,
				bytes,
				&nbytes2);
#endif
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
#ifndef TARGET_ARCH_WIN32
    globus_io_close(&stdout_handle);
#else
    globus_io_close( &write_handle);
#endif

    globus_module_deactivate(GLOBUS_IO_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    return 0;
}
/* main() */

void usage( char * executableName )
{
	printf( "Usage --\n" );
	printf( "%s <input file> <output file>\n", executableName );
}

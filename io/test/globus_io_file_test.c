#include "globus_io.h"
#ifndef TARGET_ARCH_WIN32
#include <fcntl.h>
#else
#include "globus_io_windows.h"
// forward declaration
void usage( char * executableName );
#endif

/*
 * Function:	main
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
    int					rc;
    globus_result_t			result;
    globus_io_handle_t			handle;
    globus_io_handle_t			stdout_handle;
#ifdef TARGET_ARCH_WIN32
	HANDLE						outputFile;
    globus_io_handle_t			write_handle;
#endif
    globus_size_t			bytes;
    globus_size_t			i;
    globus_byte_t			buf[11];
    
    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_IO_MODULE);

#ifndef TARGET_ARCH_WIN32
    result = globus_io_file_open("/etc/group",
				 O_RDONLY,
				 0600,
				 GLOBUS_NULL,
				 &handle);
#else
	if ( argc < 3 )
	{
		usage( argv[0] );
		return -1;
	}
    result = globus_io_file_open( argv[1],
				 O_RDONLY,
				 0,
				 GLOBUS_NULL,
				 &handle);
#endif
	if ( result != GLOBUS_SUCCESS )
	{
		printf( "An error occurred while trying to open the file...exiting\n" );
		return -1;
	}

#ifndef TARGET_ARCH_WIN32
    result = globus_io_file_posix_convert(
	fileno(stdout),
	GLOBUS_NULL,
	&stdout_handle);
#else
/*
    result = globus_io_file_windows_convert(
		GetStdHandle(STD_OUTPUT_HANDLE),
		GLOBUS_NULL,
		&stdout_handle);
*/
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
	if ( result != GLOBUS_SUCCESS )
	{
		printf( "Could not convert stdout to a Globus IO handle...exiting\n" );
		globus_io_close(&handle);
		return -1;
	}

    while(globus_io_read(&handle,
			 buf,
			 10,
			 1,
			 &bytes) == GLOBUS_SUCCESS)
    {
		globus_size_t		nbytes2;

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
    globus_io_close(&handle);
#ifndef TARGET_ARCH_WIN32
    globus_io_close(&stdout_handle);
#else
    globus_io_close( &write_handle);
#endif

    globus_module_deactivate(GLOBUS_IO_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
}
/* main() */

void usage( char * executableName )
{
	printf( "Usage --\n" );
	printf( "%s <input file> <output file>\n", executableName );
}

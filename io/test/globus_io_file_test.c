#include "globus_io.h"
#include <fcntl.h>

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
    globus_size_t			bytes;
    globus_size_t			i;
    globus_byte_t			buf[10];
    
    globus_module_activate(GLOBUS_COMMON_MODULE);
    globus_module_activate(GLOBUS_IO_MODULE);

    result = globus_io_file_open("/etc/group",
				 O_RDONLY,
				 0600,
				 GLOBUS_NULL,
				 &handle);

    result = globus_io_file_posix_convert(
	fileno(stdout),
	GLOBUS_NULL,
	&stdout_handle);

    while(globus_io_read(&handle,
			 buf,
			 10,
			 1,
			 &bytes) == GLOBUS_SUCCESS)
    {
	globus_size_t		nbytes2;

	globus_io_write(&stdout_handle,
			buf,
			bytes,
			&nbytes2);
    }
    globus_io_close(&handle);
    globus_io_close(&stdout_handle);

    globus_module_deactivate(GLOBUS_IO_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);
}
/* main() */

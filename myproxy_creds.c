/*
 * myproxy_creds.c
 *
 * Routines for storing and retrieving credentials.
 *
 * See myproxy_creds.h for documentation.
 */

#include "myproxy_creds.h"

#include "verror.h"

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/param.h>

/* Files should only be readable by me */
#define FILE_MODE		0600

/**********************************************************************
 *
 * Internal functions
 *
 */

/*
 * get_storage_locations()
 *
 * Given an user name return the path where the credentials for that
 * username should be stored and the path where data about the credentials
 * should be stored.
 *
 * Return 0 on success, -1 on error.
 */
static int
get_storage_locations(const char *username,
		      char *creds_path,
		      const int creds_path_len,
		      char *data_path,
		      const int data_path_len)
{
    return -1;
}

/*
 * copy_file()
 *
 * Copy source to destination, creating destination if needed.
 * Set permissions on destination to given mode.
 *
 * Returns 0 on success, -1 on error.
 */
static int
copy_file(const char *source,
	  const char *dest,
	  const mode_t mode)
{
    return -1;
}

/*
 * write_data_file()
 *
 * Write the data in the myproxy_creds() structure out the the
 * file name given, creating it if needed with the given mode.
 *
 * Returns 0 on success, -1 on error.
 */
static int
write_data_file(const struct myproxy_creds *creds,
		const char *data_file_path,
		const mode_t data_file_mode)
{
    int data_fd = -1;
    FILE *data_stream = NULL;
    int data_file_open_flags = O_WRONLY | O_CREAT | O_TRUNC;
    int return_code = -1;
    
    /*
     * Open with open() first to minimize any race condition with
     * file permissions.
     */
    data_fd = open(data_file_path, data_file_open_flags, data_file_mode);
    
    if (data_fd == -1)
    {
	verror_put_errno(errno);
	verror_put_string("opening storage file %s", data_file_path);
	goto error;
    }

    /* Now open as stream for easier IO */
    data_stream = fdopen(data_fd, "w");
    
    if (data_stream == NULL)
    {
	verror_put_errno(errno);
	verror_put_string("reopening storage file %s", data_file_path);
	goto error;
    }

    /* Write out all the extra data associated with these credentials */
    fprintf(data_stream, "OWNER=%s\n", creds->owner_name);
    fprintf(data_stream, "PASSPHRASE=%s\n", creds->pass_phrase);
    fprintf(data_stream, "LIFETIME=%d\n", creds->lifetime);
    fprintf(data_stream, "END_OPTIONS\n");

    /* Success */
    return_code = 0;
    
  error:
    if (data_fd != -1)
    {
	close(data_fd);
	
	if (return_code == -1)
	{
	    unlink(data_file_path);
	}
    }
    
    return return_code;
}

/*
 * read_data_file()
 *
 * Read the data contained in the given data file and fill in the
 * given creds structure.
 *
 * Returns 0 on success, -1 on error.
 */
static int
read_data_file(struct myproxy_creds *creds,
	       const char *datafile_path)
{
    return -1;
}



/**********************************************************************
 *
 * API routines
 *
 */

int
myproxy_creds_store(const struct myproxy_creds *creds)
{
    char creds_path[MAXPATHLEN] = "";
    char data_path[MAXPATHLEN] = "";
    mode_t data_file_mode = FILE_MODE;
    mode_t creds_file_mode = FILE_MODE;
    int return_code = -1;
    
    if ((creds == NULL) ||
	(creds->user_name == NULL) ||
	(creds->pass_phrase == NULL) ||
	(creds->owner_name == NULL) ||
	(creds->location == NULL) ||
	(creds->restrictions != NULL))
    {
	verror_put_errno(EINVAL);
	return -1;
    }
  
    if (get_storage_locations(creds->user_name,
			      creds_path, sizeof(creds_path),
			      data_path, sizeof(data_path)) == -1)
    {
	goto error;
    }

    if (write_data_file(creds, data_path, data_file_mode) == -1)
    {
	goto error;
    }

    if (copy_file(creds->location, creds_path, creds_file_mode) == -1)
    {
	goto error;
    }

    /* Success */
    return_code = 0;
    
  error:
    /* Remove files on error */
    if (return_code == -1)
    {
	myproxy_creds_delete(creds->user_name);
    }

    return return_code;
}

int
myproxy_creds_retrieve(const char *user_name,
		       struct myproxy_creds *creds)
{
    char creds_path[MAXPATHLEN];
    char data_path[MAXPATHLEN];
    int return_code = -1;

    
    if ((creds == NULL) ||
	(user_name == NULL))
    {
	verror_put_errno(EINVAL);
	return -1;
    }
  
    if (get_storage_locations(user_name,
			      creds_path, sizeof(creds_path),
			      data_path, sizeof(data_path)) == -1)
    {
	goto error;
    }

    if (read_data_file(creds, data_path) == -1)
    {
	goto error;
    }

    creds->location = strdup(creds_path);
    
    if (creds->location == NULL)
    {
	verror_put_errno(errno);
	goto error;
    }
    
    /* Success */
    return_code = 0;
    
  error:
    myproxy_creds_free_contents(creds);
    
    return return_code;
}


void
myproxy_creds_delete(const char *user_name)
{
    char creds_path[MAXPATHLEN];
    char data_path[MAXPATHLEN];
  
    if (get_storage_locations(user_name,
			      creds_path, sizeof(creds_path),
			      data_path, sizeof(data_path)) == -1)
    {
	/* Punt */
	return;
    }

    unlink(creds_path);
    unlink(data_path);
}

void myproxy_creds_free_contents(struct myproxy_creds *creds)
{
    if (creds == NULL)
    {
	return;
    }
    
    if (creds->user_name != NULL)
    {
	free(creds->user_name);
	creds->user_name = NULL;
    }

    if (creds->pass_phrase != NULL)
    {
	free(creds->pass_phrase);
	creds->pass_phrase = NULL;
    }

    if (creds->owner_name != NULL)
    {
	free(creds->owner_name);
	creds->owner_name = NULL;
    }
    
    if (creds->location != NULL)
    {
	free(creds->location);
	creds->location = NULL;
    }
}


	

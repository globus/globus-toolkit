/*
 * myproxy_creds.c
 *
 * Routines for storing and retrieving credentials.
 *
 * See myproxy_creds.h for documentation.
 */

#include "myproxy_common.h"	/* all needed headers included here */

/*
 * Doesn't always seem to be define in <unistd.h>
 */
//char * des_crypt(const char *key, const char *salt);

/* Files should only be readable by me */
#define FILE_MODE               0600

/**********************************************************************
 *
 * Internal variables
 *
 */

static char *storage_dir = NULL;

/**********************************************************************
 *
 * Internal functions
 *
 */

/*
 * mystrdup()
 *
 * Wrapper around strdup()
 */
static char *
mystrdup(const char *string)
{
    char *dup = NULL;
    
    assert(string != NULL);
    
    dup = strdup(string);
    
    if (dup == NULL)
    {
        verror_put_errno(errno);
    }
    
    return dup;
}


/*
 * file_exists()
 *
 * Check for existance of a file.
 *
 * Returns 1 if exists, 0 if not, -1 on error.
 */
static int
file_exists(const char *path)
{
    struct stat					statbuf;
    int						return_value = -1;

    if (path == NULL)
    {
	verror_put_errno(EINVAL);
	return -1;
    }
    
    if (stat(path, &statbuf) == -1)
    {
	switch (errno)
	{
	  case ENOENT:
	  case ENOTDIR:
	    /* File does not exist */
	    return_value = 0;
	    break;
	    
	  default:
	    /* Some error */
	    return_value = -1;
	    break;
	}
    }
    else
    {
	/* File exists */
	return_value = 1;
    }
    
    return return_value;
}

/*
 * check_storage_directory()
 *
 * Check for existance and permissions on storage directory.
 * Create storage directory if it doesn't exist.
 *
 * Returns 0 if ok, -1 on error.
 */
static int
check_storage_directory()
{
    struct stat statbuf;
    int return_code = -1;
    char *gl_storage_dir = NULL;

    if (storage_dir == NULL) { /* Choose a default storage directory */
	char *GL;
	GL = getenv("GLOBUS_LOCATION");
	if (stat("/var/myproxy", &statbuf) == 0) {
	    storage_dir = mystrdup("/var/myproxy");
	    if (!storage_dir) goto error;
	}
	/* if /var/myproxy doesn't exist, look for $GL/var/myproxy */
	if (storage_dir == NULL && GL != NULL) {
	    gl_storage_dir =
		(char *)malloc(strlen(GL)+strlen("/var/myproxy")+1);
	    if (!gl_storage_dir) {
		verror_put_errno(errno);
		verror_put_string("malloc() failed");
		goto error;
	    }
	    sprintf(gl_storage_dir, "%s/var/myproxy", GL);
	    if (stat(gl_storage_dir, &statbuf) == 0) {
		storage_dir = gl_storage_dir;
		gl_storage_dir = NULL;
	    }
	}
	/* if neither exist, try creating one */
	if (storage_dir == NULL) {
	    if (mkdir("/var/myproxy", 0700) == 0) {
		storage_dir = mystrdup("/var/myproxy");
		if (stat("/var/myproxy", &statbuf) == -1) {
		    verror_put_errno(errno);
		    verror_put_string("could not stat directory /var/myproxy");
		    goto error;
		}
	    } else if (gl_storage_dir) {
		sprintf(gl_storage_dir, "%s/var", GL);
		if (mkdir(gl_storage_dir, 0755) < 0 && errno != EEXIST) {
		    verror_put_errno(errno);
		    verror_put_string("mkdir(%s) failed", gl_storage_dir);
		    goto error;
		}
		sprintf(gl_storage_dir, "%s/var/myproxy", GL);
		if (mkdir(gl_storage_dir, 0700) < 0) {
		    verror_put_errno(errno);
		    verror_put_string("mkdir(%s) failed", gl_storage_dir);
		    goto error;
		}
		storage_dir = gl_storage_dir;
		gl_storage_dir = NULL;
		if (stat(storage_dir, &statbuf) == -1) {
		    verror_put_errno(errno);
		    verror_put_string("could not stat directory %s",
				      storage_dir);
		    goto error;
		}
	    }
	}
	if (storage_dir == NULL) {
	    verror_put_string("failed to find or create a storage directory");
	    if (!GL) verror_put_string("GLOBUS_LOCATION not set");
	    goto error;
	}
	myproxy_log("using storage directory %s", storage_dir);
    } else { /* storage directory already chosen; just check it */
	if (stat(storage_dir, &statbuf) == -1) {
	    verror_put_errno(errno);
	    verror_put_string("could not stat directory %s", storage_dir);
	    goto error;
	}
    }
    
    if (!S_ISDIR(statbuf.st_mode))
    {
        verror_put_string("%s is not a directory", storage_dir);
        goto error;
    }
    
    /* Make sure it's owned by me */
    if (statbuf.st_uid != geteuid())
    {
	struct passwd *pw;
	pw = getpwuid(geteuid());
	if (pw) {
	    verror_put_string("%s not owned by %s", storage_dir, pw->pw_name);
	} else {
	    verror_put_string("%s not owned by uid %d", storage_dir,
			      geteuid());
	}
        goto error;
    }
    
    /* Make sure it's not readable or writable by anyone else */
    if ((statbuf.st_mode & S_IRWXG) ||
        (statbuf.st_mode & S_IRWXO))
    {
        verror_put_string("permissions on %s must be 0700", storage_dir);
        goto error;
    }
    
    /* Success */
    return_code = 0;
    
  error:
    if (gl_storage_dir) free(gl_storage_dir);
    return return_code;
}


/*
 * sterilize_string
 *
 * Walk through a string and make sure that is it acceptable for using
 * as part of a path.
 */
void
sterilize_string(char *string)
{
    /* Characters to be removed */
    char *bad_chars = "/";
    /* Character to replace any of above characters */
    char replacement_char = '-';
    
    assert(string != NULL);
    
    /* No '.' as first character */
    if (*string == '.')
    {
        *string = replacement_char;
    }
    
    /* Replace any bad characters with replacement_char */
    while (*string != '\0')
    {
        if (strchr(bad_chars, *string) != NULL)
        {
            *string = replacement_char;
        }

        string++;
    }

    return;
}

static char *
strmd5(const char *s, unsigned char *digest)
{
    MD5_CTX md5;
    unsigned char   d[16];
    int     i;
    char mbuf[33];

    MD5_Init(&md5);
    MD5_Update(&md5,s,strlen(s));
    MD5_Final(d,&md5);

    if (digest) 
       memcpy(digest,d,sizeof(d));
    for (i=0; i<16; i++) {
       int     dd = d[i] & 0x0f;
       mbuf[2*i+1] = dd<10 ? dd+'0' : dd-10+'a';
       dd = d[i] >> 4;
       mbuf[2*i] = dd<10 ? dd+'0' : dd-10+'a';
    }
    mbuf[32] = 0;
    return mystrdup(mbuf);
}
        
    
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
                      const int data_path_len,
		      char *lock_path,
		      const int lock_path_len,
		      const char *credname)
{
    int return_code = -1;
    char *sterile_username = NULL;
    char *sterile_credname = NULL;
    const char *creds_suffix = ".creds";
    const char *data_suffix = ".data";
    const char *lock_suffix = ".lock";
    
    assert(username != NULL);
    assert(creds_path != NULL);
    assert(data_path != NULL);
    assert(lock_path != NULL);

    if (check_storage_directory() == -1) {
        goto error;
    }

    if (strchr(username, '/')) {
       sterile_username = strmd5(username, NULL);
       if (sterile_username == NULL)
	  goto error;
    } else {
       sterile_username = mystrdup(username);

       if (sterile_username == NULL) {
	   goto error;
       }
       
       sterilize_string(sterile_username);
    }

    creds_path[0] = '\0';
    data_path[0] = '\0';
    lock_path[0] = '\0';
   
    if (!credname) {
    	if (concatenate_strings(creds_path, creds_path_len, storage_dir,
				"/", sterile_username, creds_suffix,
				NULL) == -1) {
	    verror_put_string("Internal error: creds_path too small: "
			      "%s line %s", __FILE__, __LINE__);
	    goto error;
    	}
    	if (concatenate_strings(data_path, data_path_len, storage_dir,
				"/", sterile_username, data_suffix,
				NULL) == -1) {
	    verror_put_string("Internal error: data_path too small: "
			      "%s line %s", __FILE__, __LINE__);
	    goto error;
    	}
    	if (concatenate_strings(lock_path, lock_path_len, storage_dir,
				"/", sterile_username, lock_suffix,
				NULL) == -1) {
	    verror_put_string("Internal error: lock_path too small: "
			      "%s line %s", __FILE__, __LINE__);
	    goto error;
    	}
    } else {
	sterile_credname = mystrdup(credname);
	if (sterile_credname == NULL) {
	    goto error;
	}
	sterilize_string(sterile_credname);
    
    	if (concatenate_strings(creds_path, creds_path_len, storage_dir,
				"/", sterile_username, "-",
				sterile_credname, creds_suffix, NULL) == -1) {
         verror_put_string("Internal error: creds_path too small: %s line %s",
			   __FILE__, __LINE__);
       	 goto error;
    	}
    	if (concatenate_strings(data_path, data_path_len, storage_dir,
				"/", sterile_username, "-",
				sterile_credname, data_suffix, NULL) == -1)
    	{
       	 verror_put_string("Internal error: data_path too small: %s line %s",
       	                   __FILE__, __LINE__);
       	 goto error;
    	}
    	if (concatenate_strings(lock_path, lock_path_len, storage_dir,
				"/", sterile_username, "-",
				sterile_credname, lock_suffix, NULL) == -1)
    	{
       	 verror_put_string("Internal error: lock_path too small: %s line %s",
       	                   __FILE__, __LINE__);
       	 goto error;
    	}
    }

    /* Success */
    return_code = 0;

  error:
    if (sterile_username != NULL) {
        free(sterile_username);
    }
    if (sterile_credname != NULL) {
        free(sterile_credname);
    }
    
    return return_code;
}


/*
 * write_data_file()
 *
 * Write the data in the myproxy_creds structure to the
 * file name given, creating the file if needed with the given mode.
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
    char *tmp1;

    /* Write out all the extra data associated with these credentials 
     * support for crypt() added btemko /6/16/00
     * Please, don't try to free tmp1 - crypt() uses one 
     * static string space, a la getenv()
     */
    tmp1=(char *)des_crypt(creds->passphrase, 
	&creds->owner_name[strlen(creds->owner_name)-3]);
 
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

    fprintf (data_stream, "OWNER=%s\n",creds->owner_name);
    fprintf (data_stream, "PASSPHRASE=%s\n", tmp1);
    fprintf (data_stream, "LIFETIME=%d\n", creds->lifetime);

    if (creds->credname != NULL)
	fprintf (data_stream, "NAME=%s\n", creds->credname);

    if (creds->creddesc != NULL)
	fprintf (data_stream, "DESCRIPTION=%s\n", creds->creddesc);

    if (creds->retrievers != NULL)
	fprintf (data_stream, "RETRIEVERS=%s\n", creds->retrievers);
    if (creds->renewers != NULL)
	fprintf (data_stream, "RENEWERS=%s\n", creds->renewers);

    fprintf (data_stream, "END_OPTIONS\n");


    fflush(data_stream);
    
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

    if (data_stream != NULL)
    {
        fclose(data_stream);
    }
    
    return return_code;
}

/*
 * read_data_file()
 *
 * Read the data contained in the given data file and fills in the
 * given creds structure.
 *
 * Returns 0 on success, -1 on error.
 */
static int
read_data_file(struct myproxy_creds *creds,
               const char *datafile_path)
{
    FILE *data_stream = NULL;
    char *data_stream_mode = "r";
    int done = 0;
    int line_number = 0;
    int return_code = -1;

    assert(creds != NULL);
    assert(datafile_path != NULL);
    
    myproxy_creds_free_contents(creds);	/* initialize creds structure */

    data_stream = fopen(datafile_path, data_stream_mode);
    
    if (data_stream == NULL)
    {
        verror_put_errno(errno);
        verror_put_string("opening %s for reading", datafile_path);
        goto error;
    }

    while (!done)
    {
        char buffer[512];
        char *variable;
        char *value;
        int len;
        
        if (fgets(buffer, sizeof(buffer), data_stream) == NULL)
        {
            int errno_save = errno;
            
            if (feof(data_stream))
            {
                verror_put_string("unexpected EOF reading %s", datafile_path);
                goto error;
            }
            else
            {
                verror_put_errno(errno_save);
                verror_put_string("reading %s", datafile_path);
                goto error;
            }
            /* Not reached */
        }

        /* Remove carriage return from credentials */
        len = strlen(buffer);
        
        if (buffer[len - 1] == '\n')
        {
            buffer[len - 1] = '\0';
        }

        line_number++;
        
        variable = buffer;
        
        value = strchr(buffer, '=');
        
        if (value != NULL)
        {
            /* NUL-terminate variable name */
            *value = '\0';

            /* ...and advance value to point at value */
            value++;
        }

        if (strcmp(variable, "END_OPTIONS") == 0) 
        {
            done = 1;
            break;
        }
        
        /* Everything else requires values to be non-NULL */
        if (value == NULL)
        {
            verror_put_string("malformed line: %s line %d",
                              datafile_path, line_number);
            goto error;
        }
        
        if (strcmp(variable, "OWNER") == 0)
        {
            creds->owner_name = mystrdup(value);
            
            if (creds->owner_name == NULL)
            {
                goto error;
            }
            continue;
        }

        if (strcmp(variable, "PASSPHRASE") == 0)
        {
            creds->passphrase = mystrdup(value);
            
            if (creds->passphrase == NULL)
            {
                goto error;
            }
            continue;
        }
       
        if (strcmp(variable, "RETRIEVERS") == 0)
        {
            creds->retrievers = mystrdup(value);
            
            if (creds->retrievers == NULL)
            {
                goto error;
            }
            continue;
        }
        
        if (strcmp(variable, "RENEWERS") == 0)
        {
            creds->renewers = mystrdup(value);
            
            if (creds->renewers == NULL)
            {
                goto error;
            }
            continue;
        }
        
        if (strcmp(variable, "NAME") == 0)
        {
            creds->credname = mystrdup(value);
            
            if (creds->credname == NULL)
            {
                goto error;
            }
            continue;
        }
        
        if (strcmp(variable, "DESCRIPTION") == 0)
        {
            creds->creddesc= mystrdup(value);
            
            if (creds->creddesc == NULL)
            {
                goto error;
            }
            continue;
        }
        
        if (strcmp(variable, "LIFETIME") == 0)
        {
            creds->lifetime = (int) strtol(value, NULL, 10);
            
            continue;
        }
        
        /* Unrecognized varibale */
        verror_put_string("unrecognized line: %s line %d",
                          datafile_path, line_number);
        goto error;
    }

    /* Success */
    return_code = 0;
    
  error:
    if (data_stream != NULL)
    {
        fclose(data_stream);
    }
    
    return return_code;
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
    char lock_path[MAXPATHLEN] = "";
    mode_t data_file_mode = FILE_MODE;
    mode_t creds_file_mode = FILE_MODE;
    int return_code = -1;
   
    if ((creds == NULL) ||
        (creds->username == NULL) ||
        (creds->passphrase == NULL) ||
        (creds->owner_name == NULL) ||
        (creds->location == NULL)) {
        verror_put_errno(EINVAL);
	goto error;
    }

    if (get_storage_locations(creds->username,
                              creds_path, sizeof(creds_path),
                              data_path, sizeof(data_path),
			      lock_path, sizeof(lock_path),
			      creds->credname) == -1) {
        goto error;
    }

    /* info about credential */
    if (write_data_file(creds, data_path, data_file_mode) == -1) {
	verror_put_string ("Error writing data file");
	goto clean_up;
    }

    /* credential */
    if (copy_file(creds->location, creds_path, creds_file_mode) == -1) {
	verror_put_string ("Error writing credential file");
	goto clean_up;
    }

    /* administrative locks */
    if (creds->lockmsg) {
	FILE *lockfile;
	lockfile = fopen(lock_path, "w");
	if (!lockfile) {
	    verror_put_string("Error writing lockfile");
	    goto clean_up;
	}
	fprintf(lockfile, creds->lockmsg);
	fclose(lockfile);
    } else {
	unlink(lock_path);
    }
	
    /* Success */
    return_code = 0;

clean_up:
    /* XXX */
    /* Remove files on error */
    if (return_code == -1)
    {
        unlink(data_path);
        ssl_proxy_file_destroy(creds_path);
    }

error:
    return return_code;
}

int
myproxy_creds_retrieve(struct myproxy_creds *creds)
{
    char creds_path[MAXPATHLEN] = "";
    char data_path[MAXPATHLEN] = "";
    char lock_path[MAXPATHLEN] = "";
    char *username = NULL;
    FILE *lockfile;
    
    
    if ((creds == NULL) || (creds->username == NULL)) {
        verror_put_errno(EINVAL);
        return -1;
    }

    /* stash username */
    username = mystrdup(creds->username);

    if (get_storage_locations(username,
                              creds_path, sizeof(creds_path),
                              data_path, sizeof(data_path),
			      lock_path, sizeof(lock_path),
			      creds->credname) == -1) {
	return -1;
    }

    if (read_data_file(creds, data_path) == -1) {
	if (verror_get_errno() == ENOENT) {
	    verror_clear();
	    verror_put_string("Credentials do not exist");
	} else {
	    verror_put_string("Can't read credentials");
	}
	return -1;
    }

    /* read lockmsg in lockfile if it exists */
    if (creds->lockmsg) {
	free(creds->lockmsg);
	creds->lockmsg = NULL;
    }
    if ((lockfile = fopen(lock_path, "r")) != NULL) {
	long len;
	fseek(lockfile, 0, SEEK_END);
	len = ftell(lockfile);
	rewind(lockfile);
	if (len < 0) {
	    verror_put_string("Failed to access %s", lock_path);
	    fclose(lockfile);
	    return -1;
	}
	len++;
	creds->lockmsg = malloc(len);
	fgets(creds->lockmsg, len, lockfile);
	fclose(lockfile);
    }

    /* reset username from stashed value */
    creds->username = username;
    creds->location = mystrdup(creds_path);
    ssl_get_times(creds_path, &creds->start_time, &creds->end_time);

    /* Success */
    return 0;
}


int myproxy_creds_retrieve_all(struct myproxy_creds *creds)
{
    char *username = NULL, *h_username = NULL, *owner_name = NULL;
    size_t h_username_len;
    struct myproxy_creds *cur_cred = NULL, *new_cred = NULL;
    DIR *dir;
    struct dirent *de;
    int return_code = -1;

    /*
     * cur_cred always points to the last valid credential in the list.
     * If cur_cred is NULL, we haven't found any credentials yet.
     * The first cred in the list is the one passed in.  Other creds
     *    in the list are ones we allocated and added.
     */

    if ((creds == NULL) || (creds->username == NULL)) {
        verror_put_errno(EINVAL);
        goto error;
    }

    /* stash username and owner_name so we can test each credential */
    username = strdup(creds->username);
    if (strchr(creds->username, '/')) {
	h_username = strmd5(username, NULL);
    } else {
	h_username = strdup(creds->username);
    }
    h_username_len = strlen(h_username);
    owner_name = strdup(creds->owner_name);

    new_cred = creds; /* new_cred is what we're filling in */

    /* first, try to get the default credential */
    if (new_cred->credname) {
	free(new_cred->credname); new_cred->credname = NULL;
    }
    if (myproxy_creds_retrieve(new_cred) == 0) {
	if (strcmp(owner_name, new_cred->owner_name) == 0) {
	    cur_cred = creds;
	    new_cred = malloc(sizeof(struct myproxy_creds));
	    memset(new_cred, 0, sizeof(struct myproxy_creds));
	} else {
	    /* owned by someone else; re-initialize cred structure */
	    myproxy_creds_free_contents(new_cred);
	}
    }

    if ((dir = opendir(storage_dir)) == NULL) {
	verror_put_string("failed to open credential storage directory");
	goto error;
    }
    while ((de = readdir(dir)) != NULL) {
	if (!strncmp(de->d_name, h_username, h_username_len) &&
	    de->d_name[h_username_len] == '-' &&
	    !strncmp(de->d_name+strlen(de->d_name)-5, ".data", 5)) {
	    char *credname, *dot;
	    credname = strdup(de->d_name+h_username_len+1);
	    dot = strchr(credname, '.');
	    *dot = '\0';
	    if (new_cred->username) free(new_cred->username);
	    if (new_cred->credname) free(new_cred->credname);
	    new_cred->username = strdup(username);
	    new_cred->credname = strdup(credname);
	    if (myproxy_creds_retrieve(new_cred) == 0) {
		if (strcmp(owner_name, new_cred->owner_name) == 0) {
		    if (cur_cred) cur_cred->next = new_cred;
		    cur_cred = new_cred;
		    new_cred = malloc(sizeof(struct myproxy_creds));
		    memset(new_cred, 0, sizeof(struct myproxy_creds));
		} else {
		    /* owned by someone else; re-initialize cred structure */
		    myproxy_creds_free_contents(new_cred);
		}
	    }
	}
    }
    closedir(dir);

    if (!cur_cred) {
	verror_put_string("no credentials found for user %s, owner \"%s\"",
			  username, owner_name);
	goto error;
    }

    return_code = 0;

 error:
    if (username) free(username);
    if (h_username) free(h_username);
    if (owner_name) free(owner_name);
    if (cur_cred && new_cred) {
	myproxy_creds_free_contents(new_cred);
	free(new_cred);
    }
    return return_code;
}

/* Retrieves info about all credentials. Verifies username and
   remaining lifetime if specified.
   If query is username or lifetime based, username should be
   specified in creds->username
   and remaining lifetime in creds->end_time
*/
int myproxy_admin_retrieve_all(struct myproxy_creds *creds)
{
    struct myproxy_creds *cur_cred = NULL, *new_cred = NULL;
    DIR *dir;
    struct dirent *de;
    int return_code = -1, numcreds=0;
    char *username = NULL, *credname = NULL;
    time_t end_time = 0, start_time = 0, now;

    now = time(0);

    if (check_storage_directory() == -1) {
        goto error;
    }

    /*
     * cur_cred always points to the last valid credential in the list.
     * If cur_cred is NULL, we haven't found any credentials yet.
     * The first cred in the list is the one passed in.  Other creds
     *    in the list are ones we allocated and added.
     */

    if (creds == NULL) {
        verror_put_errno(EINVAL);
        goto error;
    }

    new_cred = creds; /* new_cred is what we're filling in */

    if (creds->username) {
	username = creds->username;
	creds->username = NULL;
    }

    if (creds->credname) {
	credname = creds->credname;
	creds->credname = NULL;
    }

    if (creds->start_time) {
	start_time = creds->start_time;
	creds->start_time = 0;
    }

    if (creds->end_time) {
	end_time = creds->end_time;
	creds->end_time = 0;
    }

    if ((dir = opendir(storage_dir)) == NULL) {
	verror_put_string("failed to open credential storage directory");
	goto error;
    }

    /* Credential data file names are of the form   "<username>-<credname>.data" where <credname> is "" for 
       default credentials */

    while ((de = readdir(dir)) != NULL) {
	if (!strncmp(de->d_name+strlen(de->d_name)-5, ".data", 5)) {
	    char *cname = NULL, *dot, *dash;

	    dash = strchr (de->d_name, '-');	/*Get a pointer to '-' */

	    dot = strchr(de->d_name, '.');
	    *dot = '\0';

	    if (dash) /*Credential with a name */
	    	cname = dash+1;

	    if (new_cred->username) free(new_cred->username);
	    if (new_cred->credname) free(new_cred->credname);

	    if (dash != NULL)	/*Stash '-' and beyond in de->d_name (Gives username) */
		*dash = '\0';

	    new_cred->username = strdup(de->d_name);

	    if (cname)
	    	new_cred->credname = strdup(cname);
	    else
		new_cred->credname = NULL;

	    if (username)	/* use username to query if specified */
		if (strcmp(username, new_cred->username))
			continue;

	    if (credname)
		if ((new_cred->credname == NULL && credname[0] != '\0') ||
		    (new_cred->credname != NULL &&
		     strcmp(credname, new_cred->credname)))
			continue;

	    if (myproxy_creds_retrieve(new_cred) == 0) {
		if ((start_time == 0 || start_time < new_cred->end_time) &&
		    (end_time == 0 || end_time >= new_cred->end_time)) {
			if (cur_cred) cur_cred->next = new_cred;
			cur_cred = new_cred;
			new_cred = malloc(sizeof(struct myproxy_creds));
			memset(new_cred, 0, sizeof(struct myproxy_creds));
			numcreds++;
		} else {
			myproxy_creds_free_contents(new_cred);
		}
	    }
	}
    }
    closedir(dir);

    return_code = numcreds;

 error:
    if (username) free(username);
    if (cur_cred && new_cred) {
	myproxy_creds_free_contents(new_cred);
	free(new_cred);
    }
    return return_code;
}

int
myproxy_creds_exist(const char *username, const char *credname)
{
    char creds_path[MAXPATHLEN] = "";
    char data_path[MAXPATHLEN] = "";
    char lock_path[MAXPATHLEN] = "";
    int rc;

    if (username == NULL)
    {
	verror_put_errno(EINVAL);
	return -1;
    }

    if (get_storage_locations(username,
                              creds_path, sizeof(creds_path),
                              data_path, sizeof(data_path),
			      lock_path, sizeof(lock_path),
			      credname) == -1) {
	return -1;
    }

    rc = file_exists(creds_path);
    
    switch(rc)
    {
      case 0:
	/* File does not exist */
	return 0;

      case 1:
	/* File exists, keep checking */
	break;
	
      case -1:
	/* Error */
	return -1;

      default:
	/* Should not be here */
	verror_put_string("file_exists(%s) return unknown value (%d)",
			  creds_path, rc);
	return -1;
    }

    rc = file_exists(data_path);
    
    switch(rc)
    {
      case 0:
	/* File does not exist */
	return 0;

      case 1:
	/* File exists, keep checking */
	break;
	
      case -1:
	/* Error */
	return -1;

      default:
	/* Should not be here */
	verror_put_string("file_exists(%s) return unknown value (%d)",
			  data_path, rc);
	return -1;
    }
    
    /* Everything seems to exist */
    
    /* XXX Should check for expiration? */

    return 1;
}

int
myproxy_creds_is_owner(const char		*username, 
			const char 		*credname, 
			const char		*client_name)
{
    char creds_path[MAXPATHLEN];
    char data_path[MAXPATHLEN];
    char lock_path[MAXPATHLEN];
    struct myproxy_creds retrieved_creds = {0}; /* initialize with 0s */
    int return_code = -1;

    assert(username != NULL);
    assert(client_name != NULL);
    
    if (get_storage_locations(username,
                              creds_path, sizeof(creds_path),
                              data_path, sizeof(data_path),
			      lock_path, sizeof(lock_path),
			      credname ) == -1)
    {
        goto error;
    }

    if (read_data_file(&retrieved_creds, data_path) == -1)
    {
        goto error;
    }

    if (strcmp(retrieved_creds.owner_name, client_name) == 0)
    {
	/* Is owner */
	return_code = 1;
    }
    else
    {
	/* Is not owner */
	return_code = 0;
    }
    
  error:
    myproxy_creds_free_contents(&retrieved_creds);
    
    return return_code;
}

int
myproxy_creds_delete(const struct myproxy_creds *creds)
{
    char creds_path[MAXPATHLEN];
    char data_path[MAXPATHLEN];
    char lock_path[MAXPATHLEN];
    int return_code = -1;
    
    if ((creds == NULL) || (creds->username == NULL)) {
        verror_put_errno(EINVAL);
        return -1;
    }
    
    if (get_storage_locations(creds->username,
                              creds_path, sizeof(creds_path),
                              data_path, sizeof(data_path),
			      lock_path, sizeof(lock_path),
			      creds->credname) == -1) {
        goto error;
    }

    if (unlink(data_path) == -1) {
        verror_put_errno(errno);
        verror_put_string("deleting credentials data file %s", data_path);
        goto error;
    }

    if (ssl_proxy_file_destroy(creds_path) != SSL_SUCCESS) {
	verror_put_string("deleting credentials file %s", creds_path);
        goto error;
    }
    
    unlink(lock_path);		/* may not exist */

    /* Success */
    return_code = 0;
    
  error:
    return return_code;
}

int
myproxy_creds_lock(const struct myproxy_creds *creds, const char *reason)
{
    char creds_path[MAXPATHLEN];
    char data_path[MAXPATHLEN];
    char lock_path[MAXPATHLEN];
    int return_code = -1;
    FILE *lockfile;
    
    if ((creds == NULL) || (creds->username == NULL) || (reason == NULL)) {
        verror_put_errno(EINVAL);
        return -1;
    }
    
    if (get_storage_locations(creds->username,
                              creds_path, sizeof(creds_path),
                              data_path, sizeof(data_path),
			      lock_path, sizeof(lock_path),
			      creds->credname) == -1) {
        goto error;
    }

    lockfile = fopen(lock_path, "w");
    if (!lockfile) {
	verror_put_errno(errno);
	verror_put_string("Error opening lockfile for writing");
	goto error;
    }
    fprintf(lockfile, "%s", reason);
    fclose(lockfile);

    /* Success */
    return_code = 0;
    
  error:
    return return_code;
}

int
myproxy_creds_unlock(const struct myproxy_creds *creds)
{
    char creds_path[MAXPATHLEN];
    char data_path[MAXPATHLEN];
    char lock_path[MAXPATHLEN];
    int return_code = -1;
    
    if ((creds == NULL) || (creds->username == NULL)) {
        verror_put_errno(EINVAL);
        return -1;
    }
    
    if (get_storage_locations(creds->username,
                              creds_path, sizeof(creds_path),
                              data_path, sizeof(data_path),
			      lock_path, sizeof(lock_path),
			      creds->credname) == -1) {
        goto error;
    }

    unlink(lock_path);

    /* Success */
    return_code = 0;
    
  error:
    return return_code;
}

/* Server password change function - called from myproxy_server.
   Checks existing password before changing it */ 
int
myproxy_creds_change_passphrase(const struct myproxy_creds *creds,
				const char *new_passphrase)
{
    char creds_path[MAXPATHLEN];
    char data_path[MAXPATHLEN];
    char lock_path[MAXPATHLEN];
    mode_t data_file_mode = FILE_MODE;
    struct myproxy_creds tmp_creds = {0}; /* initialize with 0s */
    int return_code = -1;
    SSL_CREDENTIALS *ssl_creds;
    
    if ((creds == NULL) || (creds->username == NULL) ||
	(creds->passphrase == NULL)) {
	verror_put_errno(EINVAL);
	goto error;
    }
    
    if (get_storage_locations(creds->username,
                              creds_path, sizeof(creds_path),
                              data_path, sizeof(data_path),
			      lock_path, sizeof(lock_path),
			      creds->credname) == -1) {
        goto error;
    }

    if ((ssl_creds = ssl_credentials_new()) == NULL) {
	goto error;
    }

    if (ssl_proxy_load_from_file(ssl_creds, creds_path, creds->passphrase) !=
	SSL_SUCCESS) {
	goto error;
    }

    if (read_data_file(&tmp_creds, data_path) == -1) {
        goto error;
    }
   
    /* Remove and rewrite with modified password.  Crude but works */ 
    if (unlink(data_path) == -1) {
        verror_put_errno(errno);
        verror_put_string("deleting credentials data file %s", data_path);
        goto error;
    }
    if (ssl_proxy_file_destroy(creds_path) == SSL_ERROR) {
        verror_put_string("deleting credentials data file %s", creds_path);
        goto error;
    }

    /* overwrite old passphrase with new */
    tmp_creds.passphrase = strdup(new_passphrase);

    if (write_data_file(&tmp_creds, data_path, data_file_mode) == -1) {
	verror_put_string ("Error writing data file");
       	goto error;
    }
    if (ssl_proxy_store_to_file(ssl_creds, creds_path, new_passphrase) !=
	SSL_SUCCESS) {
	goto error;
    }

    /* Success */
    return_code = 0;
    
  error:
    myproxy_creds_free_contents(&tmp_creds);
    ssl_credentials_destroy(ssl_creds);

    return return_code;
}

void myproxy_creds_free_contents(struct myproxy_creds *creds)
{
    if (creds == NULL) return;
    if (creds->next) myproxy_creds_free_contents(creds->next);
    if (creds->username != NULL)	free(creds->username);
    if (creds->passphrase != NULL)	free(creds->passphrase);
    if (creds->owner_name != NULL)	free(creds->owner_name);
    if (creds->location != NULL)	free(creds->location);
    if (creds->retrievers != NULL)	free(creds->retrievers);
    if (creds->renewers != NULL)	free(creds->renewers);
    if (creds->credname != NULL)	free(creds->credname);
    if (creds->creddesc != NULL)	free(creds->creddesc);
    memset(creds, 0, sizeof(struct myproxy_creds));
}

int myproxy_set_storage_dir(const char *dir)
{
    if (storage_dir) {
	free(storage_dir);
	storage_dir = NULL;
    }
    storage_dir=strdup(dir);
    if (!storage_dir) {
	verror_put_errno(errno);
	verror_put_string("strdup() failed");
	return -1;
    }
    return 0;
}

int myproxy_check_storage_dir()
{
    return check_storage_directory();
}

int
myproxy_print_cred_info(myproxy_creds_t *creds, FILE *out)
{
    if (!creds) return -1;
    for (; creds; creds = creds->next) {
	time_t time_diff = 0, now = 0;
	float days = 0.0;
	if (creds->owner_name) printf("owner: %s\n", creds->owner_name);
	if (creds->username)   printf("username: %s\n", creds->username);
        if (creds->credname)   printf("  name: %s\n", creds->credname);
	if (creds->creddesc)   printf("  description: %s\n", creds->creddesc);
	if (creds->retrievers) printf("  retrieval policy: %s\n",
				      creds->retrievers);
	if (creds->renewers)   printf("  renewal policy: %s\n",
				      creds->renewers);
	if (creds->lockmsg)    printf("  locked: %s\n", creds->lockmsg);
	now = time(0);
	if (creds->end_time > now) {
	    time_diff = creds->end_time - now;
	    days = time_diff / 86400.0;
	}
	printf("  timeleft: %ld:%02ld:%02ld", 
	       (long)(time_diff / 3600),
	       (long)(time_diff % 3600) / 60,
	       (long)time_diff % 60 );
	if (days > 1.0) {
	    printf("  (%.1f days)\n", days);
	} else {
	    printf("\n");
	}
    }
    return 0;
}

/******************************************************************************
globus_gass_cache.c
 
Description:
    The GASS cache management API is part of the Globus module called "GASS",
    (Global Access to Secondary Storage)
    The GASS cache management API defines calls for manipulating a local file
    cache.  

    Each cache entry can be locked during addition and deletion to allow for
    atomic handling of the cache file contents.

    Each cache entry also has an associated timestamp.  This timestamp is
    independent of the local cache file's  modification time. Rather, the
    cache entry timestamp is maintained by the user.  It can, for example, be
    used to keep track of the timestamp of a remote file that is associated
    with the cache entry. 

    Note: all timestamps are as seconds since the epoch.
    (01 Jan 1970, 00:00 GMT)

    The following functions are part of the API:
    
      globus_gass_cache_open()
      globus_gass_cache_close()
      globus_gass_cache_add()
      globus_gass_cache_add_done()
      globus_gass_cache_delete_start()
      globus_gass_cache_delete()
      globus_gass_cache_cleanup_tag()
      globus_gass_cache_cleanup_file()
      globus_gass_cache_list()
      globus_gass_cache_list_free()

CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
		    
******************************************************************************/

/******************************************************************************
                             Include header files
******************************************************************************/
#include "globus_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>

#include "globus_i_gass_cache.h"
#include "globus_gass_cache.h"
#include "version.h"

/*
 * UNICOS has four quota errno values: EQUSR, EQGRP, EQACT, EOFQUOTA
 * #define EQUSR           60      (User file/inode quota limit reached)
 * #define EQGRP           61      (Group file/inode quota limit reached)
 * #define EQACT           62      (Account file/inode quota limit reached)
 * #define EOFQUOTA        363     (File offline, retrieval would 
 *                                  exceed disk space quota)
 */
#ifdef EDQUOT
#define IS_QUOTA_ERROR(err) ((err) == EDQUOT)
#elif defined(EQUSR) && defined(EQGRP) && defined(EQACT) && defined(EOFQUOTA)
#define IS_QUOTA_ERROR(err) ((err) == EQUSR || \
                             (err) == EQGRP || \
                             (err) == EQACT || \
                             (err) == EOFQUOTA)
#else
#define IS_QUOTA_ERROR(err) (GLOBUS_FALSE)
#endif

static globus_bool_t globus_l_gass_cache_link_works = GLOBUS_TRUE;

static int
globus_l_gass_cache_module_activate(void);

globus_module_descriptor_t globus_i_gass_cache_module =
{
    "globus_gass_cache",
    globus_l_gass_cache_module_activate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/******************************************************************************
                          Module specific variables
******************************************************************************/

/* variables not used by them-self, but pointed by the field "init" of the
   cache_handle structures, to indicate if the cache has been initialised 
   simple methode to help the user: it is his responsbility to open the cache
   before using it. A list of handlers could be used...*/
static char globus_l_gass_cache_is_init;
static char globus_l_gass_cache_is_not_init;
static int globus_l_gass_cache_pid;
static int globus_l_gass_cache_fn_fudge;

/* it is fine to declare those macro here, together with the var. they uses  */
#define CHECK_CACHE_IS_INIT() if (cache_handle->init != &globus_l_gass_cache_is_init) return(GLOBUS_GASS_CACHE_ERROR_CACHE_NOT_OPENED)
#define CHECK_CACHE_IS_NOT_INIT() if (cache_handle->init == &globus_l_gass_cache_is_init) return(GLOBUS_GASS_CACHE_ERROR_CACHE_ALREADY_OPENED)
									   
/* this is not in the globus_gass_cache specs, but we can see if we want to
   add it. It is a list of error message corresponding to each error codes
   returned by globus_gass_cache functions. The user does not have direct
   access to this variable, but thrue the function
   globus_gass_cache_error_string()*/
static
char *
globus_gass_cache_error_strings[] =
{
    "success",
    "your home directory could not be determined",
    "the GASS cache directory or status file could not be created",
    "the pathname of the internal cache files is too long for the system to handle",
    "the GASS cache lock file could not be created or read",
    "the GASS cache lock file was broken due to a time out",
    "the GASS cache state file could not be opened for reading",
    "the GASS cache state file is corrupt",
    "a memory allocation failed",
    "the local file for an URL could not be created",
    "the URL was not found in the GASS cache",
    "an old lock file could not be removed",
    "the cache entry was locked using a different tag",
    "the cache entry was not locked",
    "the cache state could not be written",
    "the cache state file could not be read",
    "the local file for an URL was not being used, but could not be removed",
    "the cache handle was invalid",
    "the cache handle was already opened",
    "the cache_directory_path parameter is not supported",
    "the cache library and the cache state file have an incompatible versions",
    "the cache file system is full",
    "your quota is exceeded in your home filesystem"
};


/******************************************************************************
                          Module specific prototypes
******************************************************************************/
#ifdef GLOBUS_L_GASS_CACHE_LOG
static
void
globus_l_gass_cache_log(
    FILE*                               f,
    char *                              str,...);

#endif

#ifdef DEBUG
static
void
globus_l_gass_cache_trace(
    char*                              source_file,
    int                                line,
    char *                             str, ...);
#endif

static
void
globus_l_gass_cache_entry_free(
    globus_gass_cache_entry_t**         entry,
    globus_bool_t                       itself);
static
int
globus_l_gass_cache_read_nb_entries(
    globus_gass_cache_t* cache_handle);
static
int
globus_l_gass_cache_write_nb_entries(
    int                                 fd,
    int                                 nb_entries);
static
int
globus_l_gass_cache_lookfor_url(
    globus_gass_cache_entry_t**         return_entry,
    char *                              searched_url,
    globus_gass_cache_t *               cache_handle);
static
int
globus_l_gass_cache_write_state_file(
    globus_gass_cache_entry_t *         entry,
    globus_gass_cache_t *               cache_handle);
static
int
globus_l_gass_cache_write_one_str(
    char*                               buff_pt,
    int                                 fd);
static
int
globus_l_gass_cache_write_one_entry(
    int                                 fd,
    globus_gass_cache_entry_t *         entry);
static
int
globus_l_gass_cache_read_one_str(
    char**                              buff_pt,
    int                                 fd);
static
int
globus_l_gass_cache_read_one_entry(
    int                                 fd,
    globus_gass_cache_entry_t**         entry);

static
int
globus_l_gass_cache_lock_file(
    char *                              file,
    char *                              temp_file);
static
int
globus_l_gass_cache_unlock_file(
    char*                               file);
static
int
globus_l_gass_cache_lock_open(
    globus_gass_cache_t*                cache_handle);
static
int
globus_l_gass_cache_unlock_close(
    globus_gass_cache_t *               cache_handle,
    globus_bool_t                       abort);

static int
globus_l_gass_cache_module_activate(void)
{
#ifdef TARGET_ARCH_CYGWIN

/* 
 * Have to do this check at runtime, as the same executable can run
 * on both Win9x and WinNT, and it seems like stat() -> st_nlink is
 * broken on only one of them.
 */

    char         file1[PATH_MAX];
    char         file2[PATH_MAX];
    int          fd;
    int          rc;
    struct stat  stx;
    
    tmpnam(file1);
    tmpnam(file2);

    remove(file1);
    remove(file2);
    
    fd = open(file1, 
	      O_RDWR|O_CREAT,
	      GLOBUS_L_GASS_CACHE_STATE_MODE);

    if (fd < 0)
	goto real_exit;

    close(fd);
    
    rc = stat(file1, &stx);
    if ((rc!=0) || (stx.st_nlink != 1))
	globus_l_gass_cache_link_works = GLOBUS_FALSE;
    else if (link(file1,file2))
	globus_l_gass_cache_link_works = GLOBUS_FALSE;
    else
    {
	rc = stat(file1, &stx);
	if ((rc!=0) || (stx.st_nlink != 2))
	    globus_l_gass_cache_link_works = GLOBUS_FALSE;
    }

    remove(file2);
    remove(file1);
 real_exit:
#endif
    globus_l_gass_cache_pid = globus_libc_getpid();
    globus_l_gass_cache_fn_fudge = 0;
    return GLOBUS_SUCCESS;
}



void
globus_l_gass_cache_name_lock_file(char * lock_file,
				   char * file_to_be_locked);
void
globus_l_gass_cache_name_uniq_lock_file(char * uniq_lock_file,
					char * file_to_be_locked);

#ifdef GLOBUS_L_GASS_CACHE_LOG
/*
 * globus_l_gass_cache_log()
 *
 * Write in the file [first param] the message passed as a
 * "printf-like" argument list, prepended by the date, the hostname and
 * the PID of the caller process.
 * 
 * Parameters: 
 *      f - file to write in.
 *
 * Returns:
 * none */
static
void 
globus_l_gass_cache_log(
    FILE*      f,
    char*      str,
    ...)
{
    va_list    args;
    char hname[MAXHOSTNAMELEN];
    char time_buff[26];
    time_t ttime;
    long mytid;

    /* Note : I use the local time to log. This might not be the best        */
    time(&ttime);

    globus_libc_ctime_r(&ttime,time_buff,sizeof(time_buff));
    
    /* remove the \n */
    time_buff[24]='\0';
    globus_libc_gethostname(hname,sizeof(hname));
    mytid = (long) globus_thread_self();

    globus_libc_fprintf(f,"%s %s PID:%ld TID:%ld : ",
	    time_buff,
	    hname,
	    (long)getpid(),
	    mytid);

    va_start(args, str);
    globus_libc_vfprintf(f, str, args);
    va_end(args);
    globus_libc_fprintf(f,"\n");
    globus_libc_lock();
    fflush(f);
    globus_libc_unlock();
}
/* globus_gass_cache_log() */
#endif

#ifdef DEBUG
/*
 * globus_l_gass_cache_trace()
 *
 * Writes on the standard error the message passed as a
 * "printf-like" argument list [3rd arg], prepended by the file name of
 * the source code and the line number passed as 2 first arguments.
 * This function should be called this way:
 * globus_l_gass_cache_trace(__FILE__,__LINE," printf-like format string",
 * args...);
 *    
 * Parameters:
 *     source_file - File name of the source code
 *     line        - line number in the source code
 *
 *Returns:
 *               none 
 */         
static
void 
globus_l_gass_cache_trace(
    char*                        source_file,
    int                          line,
    char                         *str,
    ...)
{
    va_list    args;
    static FILE *fp = GLOBUS_NULL;
    
    globus_libc_lock();
    if(fp == GLOBUS_NULL)
    {
#if 0
	fp = fopen("/tmp/cache_trace.out", 
	           "a+");
#else
        fp = stderr;
#endif
    }
    globus_libc_unlock();

    va_start(args,str);
    
    globus_libc_fprintf(fp,"%s %d : ",source_file,  line);
    globus_libc_vfprintf(fp, str, args);
    va_end(args);
    
    globus_libc_fprintf(fp,"\n");

    globus_libc_lock();
    fflush(fp);
    globus_libc_unlock();
    
}
/* globus_l_gass_cache_trace() */
#endif

/*
 * globus_l_gass_cache_name_lock_file()
 *
 */
void
globus_l_gass_cache_name_lock_file(char * lock_file,
				   char * file_to_be_locked)
{
    strcpy(lock_file, file_to_be_locked);
    strcat(lock_file, GLOBUS_L_GASS_CACHE_LOCK_EXT);    
} /* globus_l_gass_cache_name_lock_file() */

/*
 * globus_l_gass_cache_name_uniq_lock_file()
 *
 */
void
globus_l_gass_cache_name_uniq_lock_file(char * uniq_lock_file,
					char * file_to_be_locked)
{
    char   hname[MAXHOSTNAMELEN];
    /* !!! need to handle multi threaded !!! */
    globus_libc_gethostname(hname,sizeof(hname));

    globus_libc_sprintf(uniq_lock_file,"%s%s_%s_%ld_%ld",
			file_to_be_locked,
			GLOBUS_L_GASS_CACHE_LOCK_EXT,
			hname,
			(long) globus_libc_getpid(),
			(long) globus_thread_self());

} /* globus_l_gass_cache_name_uniq_lock_file() */

/*
 * globus_l_gass_cache_write_comment()
 *
 * Write the first line of the file containning the version of
 * the format of the stat file and a comment.
 *   
 * Parameters:
 *
 *     cache_handle - handler to the chache directory to use.
 *     fd - File descriptor where to write the comment  
 * 
 * Returns: 
 *     GLOBUS_SUCCESS or
 *     GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE if the data could not be writen.
 */
static
int
globus_l_gass_cache_write_comment(
    globus_gass_cache_t*             cache_handle,
    int                              fd)
{
    /* In future version, We should take care of backward compatibility,
       and eventually write an other version number, but for now
       we do not care */
    globus_libc_sprintf(
	cache_handle->comment,
	"%s%5u%-65s",
	"-Version ",
	GLOBUS_GASS_CACHE_STATE_FILE_FORMAT_VERSION,
	" # Gass_cache state file - DO NOT MODIFY ! ");
    cache_handle->comment[sizeof(cache_handle->comment)-1] = '\n';
    
    while (write(fd,
		 cache_handle->comment,sizeof(cache_handle->comment))
	   != sizeof(cache_handle->comment))
    {
	if (errno != EINTR)
	{
	    if (errno == ENOSPC)
            {
                return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
            }
            else if (IS_QUOTA_ERROR(errno))
            {
                return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
            }
            else
            {
	        CACHE_TRACE("Error writing state file");
	        return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
            }
	}
    }
    return(GLOBUS_SUCCESS);

}
/* globus_l_gass_cache_write_comment() */

/*
 * globus_l_gass_cache_write_one_str()
 * 
 * Write one string of variable length (buff_pt*) into the file fd,
 * by writing first its length (in ascii coded decimal format) and then
 * the string itself.
 *    
 * Parameters:
 *
 *     buff_pt - pointer to the string of variable length to be writen.
 *
 *     fd - descriptor of the file to write in.
 *
 * Returns: 
 *     GLOBUS_SUCCESS or
 *     GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE if the data could not be writen.
 */
static
int
globus_l_gass_cache_write_one_str(
    char*                           buff_pt,
    int                             fd)
{
    /* ascii coded size of the next data to read */
    char size_s[GLOBUS_L_GASS_CACHE_L_LENGHT+1];
    /* size of the data to write             */
    unsigned int size;  

    
    /* write buffer length, including \n */
    size = strlen(buff_pt) +1;	/* include the terminating null char     */
    globus_libc_sprintf(size_s,"%40u",size);
    /* 40 is for GLOBUS_L_GASS_CACHE_L_LENGHT !!!    */
    size_s[sizeof(size_s)-1] = '\n';

    while ( write(fd, size_s,sizeof(size_s)) != sizeof(size_s) )
    {
	if (errno != EINTR)
	{
	    if (errno == ENOSPC)
            {
                return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
            }
            else if (IS_QUOTA_ERROR(errno))
            {
                return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
            }
            else
            {
	        CACHE_TRACE("Error writing state file");
	        return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
            }
	}
    }
    /* write buffer */
    while ( write(fd, buff_pt, size-1 ) != size-1 )
    {
	if (errno != EINTR)
	{
	    if (errno == ENOSPC)
            {
                return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
            }
            else if (IS_QUOTA_ERROR(errno))
            {
                return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
            }
            else
            {
	        CACHE_TRACE("Error writing state file");
	        return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
            }
	}
    }
    while ( write(fd, "\n", 1 ) != 1 ) /* replace 0 with \n                  */
    {
	if (errno != EINTR)
	{
	    if (errno == ENOSPC)
            {
                return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
            }
            else if (IS_QUOTA_ERROR(errno))
            {
                return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
            }
            else
            {
	        CACHE_TRACE("Error writing state file");
	        return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
            }
	}
    }
    return(GLOBUS_SUCCESS);

}
/* globus_l_gass_cache_write_one_str() */

/*
 * globus_l_gass_cache_read_one_str()
 * 
 * Read one string of variable length from the file fd.
 *     Read first the string length from the file (ascii coded decimal), then
 *     allocate the memory for the string and at last, read the string
 *     and return the address of this buffer.
 *     
 *     fd must be positioned in the file at a place where a "variable-length"
 *     followed by the string itself are expected.
 *    
 * Parameters: 
 * 	       
 *     fd - descriptor of the file to read from.
 * 	       
 *     buff_pt - pointer to the string read. 	  
 * 	       
 * Returns: 
 * 	       
 *     GLOBUS_SUCCESS or
 *     GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT if the string could not be read
 *     GLOBUS_GASS_CACHE_ERROR_NO_MEMORY
 */
static
int
globus_l_gass_cache_read_one_str(
    char**                        buff_pt,
    int                           fd)
{
    /* ascii coded size of the next data to read */
    char size_s[GLOBUS_L_GASS_CACHE_L_LENGHT+1];
    /* size of the next data to read             */
    size_t size;  

    
    /* read buffer length, including \n */
    while ( read(fd, size_s,sizeof(size_s)) != sizeof(size_s) )
    {
	if (errno != EINTR)
	{
	    return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
	}
    }
    size_s[GLOBUS_L_GASS_CACHE_L_LENGHT]='\0';
    /* replace \n with  0 (end of string) */
    
    size = atoi(size_s);
    
    if (!size)
    {
	CACHE_TRACE("Error reading state file");
	return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
    }
    *buff_pt=(char *) globus_malloc(size);
    if (*buff_pt == NULL)
    {
    	CACHE_TRACE("No more memory");
	return(GLOBUS_GASS_CACHE_ERROR_NO_MEMORY);
    }   
    while ( read(fd,*buff_pt , size) != size )
    {
	if (errno != EINTR)
	{
	    CACHE_TRACE("Error reading state file");
	    return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
	}
    }
    /* replace \n with  0 (end of string) */
    (*buff_pt)[size-1]='\0';  
    
    return(GLOBUS_SUCCESS);
}
/* globus_l_gass_cache_read_one_str() */

/*
 * globus_l_gass_cache_read_nb_entries()
 * 
 * Read from the cache state file the number of globus_gass_cache_entry
 * it contains. This number is always the last information storred in the
 * file; The file pointer must be correctly positionned in the file before
 * this function is called.
 *     
 * Parameters:
 *     
 *    cache_handle - contains the file desciptor of the cache file
 * 	                      to read (cache_handle->state_file_fd)
 *     
 *    cache_handle - this function update the field
 * 	                      cache_handle->nb_entries whith the values read.
 * 			      
 * Returns: 
 *     
 *     GLOBUS_SUCCESS or
 *     GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT if the data could not be read.
 */
static int
globus_l_gass_cache_read_nb_entries(
    globus_gass_cache_t*  cache_handle)
{
    /* ascii coded size of the next data to read */
    char size_s[GLOBUS_L_GASS_CACHE_L_LENGHT+1];

    /* read buffer length, including \n */
    while ( read(cache_handle->state_file_fd,
	      size_s,sizeof(size_s)) != sizeof(size_s) )
    {
	if (errno != EINTR)
	{
	    CACHE_TRACE("Error reading state file");
	    return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
	}
    }
    size_s[GLOBUS_L_GASS_CACHE_L_LENGHT]='\0';
    /* replace \n with  0 (end of string) */
    
    cache_handle->nb_entries = atoi(size_s);

    return(GLOBUS_SUCCESS);
}
/* globus_l_gass_cache_read_nb_entries() */

/*
 * globus_l_gass_cache_write_nb_entries()
 * 
 * Write into the cache state file the number of globus_gass_cache_entry
 * it contains. This number is always the last information storred in the
 * file; The file pointer must be correctly positionned in the file before
 * this function is called.
 *     
 * Parameters:
 *      fd - contains the file desciptor of the cache file to write in.
 * 	(in the current implementation, it is cache_handle->state_file_temp_fd)
 *
 * 	nb_entries - number of entries to write.
 * 	(it should be cache_handle->nb_entries)
 *     
 *      cache_handle - this function update the field
 *	cache_handle->nb_entries whith the values read.
 *     		      
 * Returns: 
 *      GLOBUS_SUCCESS or
 *      GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE if the data could not be writen. 
 */
static
int
globus_l_gass_cache_write_nb_entries(
    int                               fd,
    int                               nb_entries)
{
    /* ascii coded size of the next data to read */
    char size_s[GLOBUS_L_GASS_CACHE_L_LENGHT+1];

    
    /* first lets write an entry separator to tell that there is one more    */
    while ( write(fd, "*\n",2) != 2 )
    {
	if (errno != EINTR)
	{
	    if (errno == ENOSPC)
            {
                return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
            }
            else if (IS_QUOTA_ERROR(errno))
            {
                return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
            }
            else
            {
	        CACHE_TRACE("Error writing state file");
	        return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
            }
	}
    }

    globus_libc_sprintf(size_s,"%40u",nb_entries);
    /* 40 is for GLOBUS_L_GASS_CACHE_L_LENGHT !*/
    size_s[sizeof(size_s)-1] = '\n';

    while (write(fd,
	      size_s,sizeof(size_s))  != sizeof(size_s) )
    {
	if (errno != EINTR)
	{
	    if (errno == ENOSPC)
            {
                return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
            }
            else if (IS_QUOTA_ERROR(errno))
            {
                return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
            }
            else
            {
	        CACHE_TRACE("Error writing state file");
	        return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
            }
	}
    }

    return(GLOBUS_SUCCESS);
}
/* globus_l_gass_cache_write_nb_entries() */


/*
 * globus_l_gass_cache_write_one_entry()
 *
 * Write one globus_gass_cache_entry_t structure in a file ,
 *   mapping the data to text as desribed below:
 *   - Eache data is ascii coded, on one line (terminated by \n)
 *   - Eache entry is preceded by a "header" : #
 *   - numerical values are ascii coded into a fixed number of char:
 *     GLOBUS_L_GASS_CACHE_L_LENGHT
 *   - Eache string (url, filename,...) is preceded by is length, coded as
 *     described above
 *    
 * Parameters:
 *
 *     fd - file descriptor of the open file to write in at the
 *     current position.
 *
 *     entry - address of the globus_gass_cache_entry_t to write in the file
 *
 * Returns:
 *     GLOBUS_SUCCESS or
 *     GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE
 */        
static
int
globus_l_gass_cache_write_one_entry(
    int                               fd,
    globus_gass_cache_entry_t*        entry)
{
    /* ascii coded size of the next data to read         */
    char size_s[GLOBUS_L_GASS_CACHE_L_LENGHT+1];
    /* size of the next data to read                     */
    /* to loop in the tags array                         */
    unsigned int i;

    
    /* first lets write an entry separator to tell that there is one more    */
    while ( write(fd, "#\n",2) != 2 )
    {
	if (errno != EINTR)
	{
	    if (errno == ENOSPC)
            {
                return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
            }
            else if (IS_QUOTA_ERROR(errno))
            {
                return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
            }
            else
            {
	        CACHE_TRACE("Error writing state file");
	        return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
            }
	}
    }
    /* write url */
    if (globus_l_gass_cache_write_one_str(entry->url, fd))
    {
	CACHE_TRACE("Error writing state file");
	return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
    }

     /* write filename  */
    if (globus_l_gass_cache_write_one_str(entry->filename, fd))
    {
	CACHE_TRACE("Error writing state file");
	return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
    }

    /* write timestamp */
    /* 40 is for GLOBUS_L_GASS_CACHE_L_LENGHT !!!*/
    globus_libc_sprintf(size_s,"%40lu",entry->timestamp);
    size_s[sizeof(size_s)-1] = '\n';
                             
    while ( write(fd, size_s,sizeof(size_s)) != sizeof(size_s) )
    {
	if (errno != EINTR)
	{
	    if (errno == ENOSPC)
            {
                return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
            }
            else if (IS_QUOTA_ERROR(errno))
            {
                return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
            }
            else
            {
	        CACHE_TRACE("Error writing state file");
	        return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
            }
	}
    }

    /* status */
    if (entry->lock_tag != GLOBUS_NULL)
    {
	/* write it is locked  */
	while (write(fd, "L\n", 2) != 2 )        
	{
	    if (errno != EINTR)
	    {
	        if (errno == ENOSPC)
                {
                    return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
                }
                else if (IS_QUOTA_ERROR(errno))
                {
                    return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
                }
                else
                {
	            CACHE_TRACE("Error writing state file");
	            return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
                }
	    }
	}
        /* write the tag_lock */
	if (globus_l_gass_cache_write_one_str(entry->lock_tag, fd))
	{
	    CACHE_TRACE("Error writing state file");
	    return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
	}
    }
    else
    {
	/* write it is NOT locked  */
	while (write(fd, "R\n", 2) != 2 )        
	{
	    if (errno != EINTR)
	    {
	        if (errno == ENOSPC)
                {
                    return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
                }
                else if (IS_QUOTA_ERROR(errno))
                {
                    return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
                }
                else
                {
	            CACHE_TRACE("Error writing state file");
	            return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
                }
	    }
	}
    }


    /* write the number of existing tag enties */
    /* Changed in 1.1
       Here is a hack because the Pending flag did not exist in version 1.0
       of globus_gass_cache. I added it in this line to preserve backward
       compatibility; The hack is that I moved the "num_tag" 2 char to the left
       and add a \0 in the string to make atoi (below) not read the 3 last char
       I use this 2 last char to put the Pending flag and the \n.
       It reduce the number of tag possible, but the 38 digits left should be
       enought... */
    globus_libc_sprintf(size_s,"%38lu",entry->num_tags);
    size_s[sizeof(size_s)-3] = '\0';
    if (entry->pending != 'F' && entry->pending != 'P')
    {
	globus_libc_printf("Error Pending flag not set when writing\n");
    }
    size_s[sizeof(size_s)-2] = entry->pending;
    size_s[sizeof(size_s)-1] = '\n';
    
    while ( write(fd, size_s,sizeof(size_s)) != sizeof(size_s) )
    {
	if (errno != EINTR)
	{
	    if (errno == ENOSPC)
            {
                return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
            }
            else if (IS_QUOTA_ERROR(errno))
            {
                return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
            }
            else
            {
	        CACHE_TRACE("Error writing state file");
	        return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
            }
	}
    }

    /* write each tag */
    /* I use num_tags+1 to be sure to get the last one if I have deleted one */
    /* not that if I have created one, I will not point outside of the       */
    /* allocated array because I alocate num_tags+2 when I read the entry    */
    
    for (i=0; i<entry->num_tags+1; i++)
    {
	/* if this tag has not been deleted */
	if ((entry->tags+i)->tag != GLOBUS_NULL)
	{
	    /* write each tag   */
	    if (globus_l_gass_cache_write_one_str((entry->tags+i)->tag, fd))
	    {
		CACHE_TRACE("Error writing state file");
		return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
	    }
	
	    /* write the count */
	    /* 40 is for GLOBUS_L_GASS_CACHE_L_LENGHT  !!!     */
	    globus_libc_sprintf(size_s,"%40u",(entry->tags+i)->count);
	    size_s[sizeof(size_s)-1] = '\n';

	    while ( write(fd, size_s,sizeof(size_s)) != sizeof(size_s) )
	    {
		if (errno != EINTR)
		{
	            if (errno == ENOSPC)
                    {
                        return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
                    }
                    else if (IS_QUOTA_ERROR(errno))
                    {
                        return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
                    }
                    else
                    {
	                CACHE_TRACE("Error writing state file");
	                return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
                    }
		}
	    }
	} /* this tag has not been deleted */
    }
    return(GLOBUS_SUCCESS);
} /*  globus_l_gass_cache_write_one_entry() */


/*
 * globus_l_gass_cache_read_one_entry()
 *
 * Read one globus_gass_cache_entry_t structure from a file.
 * The entry must have been writen following the format described and used in
 * globus_l_gass_cache_write_one_entry(). All the memory necessary to store
 * this structure is allocated: The function globus_l_gass_cache_entry_free()
 * must be called subsequently.
 * 
 * Parameters:
 *      fd - file descriptor of the open file to read from at the
 *      current position.  
 * 	   
 * 	entry - Pointer to the  globus_gass_cache_entry_t read
 * 	from the file.
 * 
 * Returns:
 *      GLOBUS_SUCCESS or
 *      GLOBUS_GASS_CACHE_ERROR_NO_MEMORY or
 * 	GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT if not all the
 *      expected structure fields could be read.	    
 */         
static int
globus_l_gass_cache_read_one_entry(
    int                                fd,
    globus_gass_cache_entry_t**        entry)
{
    /* ascii coded size of the next data to read */
    char size_s[GLOBUS_L_GASS_CACHE_L_LENGHT+1];
    int i;              /* tag array index                           */

    if (*entry == NULL)
    {
	/* allocate the memory for one entry */
	*entry = (globus_gass_cache_entry_t *)globus_malloc(sizeof(globus_gass_cache_entry_t));
	if (entry == NULL)
	{
	    CACHE_TRACE("No more memory");
	    return(GLOBUS_GASS_CACHE_ERROR_NO_MEMORY);
	}
    }
    /* init some fields */
    (*entry)->num_tags=0;
    (*entry)->tags= GLOBUS_NULL;
    (*entry)->pending= 'F';
    /* read url */
    if (globus_l_gass_cache_read_one_str(&((**entry).url), fd))
    {
	CACHE_TRACE("Error reading state file");
	globus_l_gass_cache_entry_free(entry,GLOBUS_TRUE);
	return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
    }
   
    /* read file name */
    if (globus_l_gass_cache_read_one_str(&((**entry).filename), fd))
    {
	CACHE_TRACE("Error reading state file");
	globus_l_gass_cache_entry_free(entry,GLOBUS_TRUE);
	return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
    }

    /* read timestamp */
    while ( read(fd, size_s,sizeof(size_s)) != sizeof(size_s) )
    {
	if (errno != EINTR)
	{
	    CACHE_TRACE("Error reading state file");
	    globus_l_gass_cache_entry_free(entry,GLOBUS_TRUE);
	    return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
	}
    }
    size_s[GLOBUS_L_GASS_CACHE_L_LENGHT]='\0'; /* replace \n with  0 (end of string) */
    (**entry).timestamp = atol(size_s);
    
    /* read status */
    while (read(fd, &size_s[0], 2) != 2 )           
    {
	if (errno != EINTR)
	{
	    CACHE_TRACE("Error reading state file");
	    globus_l_gass_cache_entry_free(entry,GLOBUS_TRUE);
	    return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
	}
    }
    if (size_s[0] == 'L')
    { /* File locked, let read the lock_tag */
	    /* read file name, including \n */
	if (globus_l_gass_cache_read_one_str(&((**entry).lock_tag), fd))
	{
	    CACHE_TRACE("Error reading state file");
	    globus_l_gass_cache_entry_free(entry,GLOBUS_TRUE);
	    return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
	}
    }
    else
    {
	/* file not locked */
	(**entry).lock_tag = GLOBUS_NULL;
    }

    /* read Tags */

    /* first the number of tags */
    while ( read(fd, size_s,sizeof(size_s)) != sizeof(size_s) )
    {
	if (errno != EINTR)
	{
	    CACHE_TRACE("Error reading state file");
	    globus_l_gass_cache_entry_free(entry,GLOBUS_TRUE);
	    return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
	}
    }
    size_s[GLOBUS_L_GASS_CACHE_L_LENGHT]='\0'; /* replace \n with  0 (end of string) */

    /* Changed in 1.1
       Here is a hack because the Pending flag did not exist in version 1.0
       of globus_gass_cache. I added it in this line to preserve backward
       compatibility; The hack is that I moved the "num_tag" 2 char to the left
       and add a \0 in the string to make atoi (below) not read the 3 last char
       I use this 2 last char to put the Pending flag and the \n.
       It reduce the number of tag possible, but the 38 digits left should be
       enought... */

    if (size_s[sizeof(size_s)-3] == '\0' )
    {
	(**entry).pending = size_s[sizeof(size_s)-2];
	if ((**entry).pending != 'P' &&
	    (**entry).pending != 'F')
	{
	    CACHE_TRACE("Error reading state file");
	    globus_l_gass_cache_entry_free(entry,GLOBUS_TRUE);
	    return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);	    
	}
    }

    (**entry).num_tags= atoi(size_s);
    /* allocate 2 too much : one spare for add  and one for the last (NULL) */
    (**entry).tags=(globus_gass_cache_tag_t *)
	globus_malloc(((**entry).num_tags+2)* sizeof(globus_gass_cache_tag_t)); 
    if ((**entry).tags == GLOBUS_NULL)
    {
    	CACHE_TRACE("No more memory");
	(*entry)->num_tags=0;
	globus_l_gass_cache_entry_free(entry,GLOBUS_TRUE);
	return(GLOBUS_GASS_CACHE_ERROR_NO_MEMORY);
    }

    /* read each tag */
    for (i=0; i<(**entry).num_tags; i++)
    {
	/* read each tag */
	if (globus_l_gass_cache_read_one_str(&((**entry).tags[i].tag), fd))
	{
	    CACHE_TRACE("Error reading state file");
	    globus_l_gass_cache_entry_free(entry,GLOBUS_TRUE);
	    return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
	}

	/* read the tag count */
	while ( read(fd, size_s,sizeof(size_s)) != sizeof(size_s) )
	{
	    if (errno != EINTR)
	    {
		CACHE_TRACE("Error reading state file");
		globus_l_gass_cache_entry_free(entry,GLOBUS_TRUE);
		return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
	    }
	}
	size_s[GLOBUS_L_GASS_CACHE_L_LENGHT]='\0';/* replace \n with 0(end of string)*/
	(**entry).tags[i].count = atoi(size_s);
    }
    /* initialize the 2 extra entries with NULL */
    (**entry).tags[(**entry).num_tags].tag=GLOBUS_NULL;
    (**entry).tags[(**entry).num_tags+1].tag=GLOBUS_NULL;
    return(GLOBUS_SUCCESS);
    
}
/* globus_l_gass_cache_read_one_entry() */


/*
 * globus_l_gass_cache_entry_free()
 *
 * Free the memory allocated by globus_l_gass_cache_read_one_entry().
 * 
 * Parameters: 
 *      entry - address to the "entry pointer" pointing to
 *	the globus_gass_cache_entry_t structure to free.
 *
 *      itself - indicate if the pointer "entry" itself should be freed, or
 *      if only the entries should be freed
 * Returns: 
 *      none
 */
static void
globus_l_gass_cache_entry_free(
    globus_gass_cache_entry_t**           entry,
    globus_bool_t                         itself)
{
    int i;
    if (*entry != GLOBUS_NULL)
    {

	globus_free((*entry)->url);
	(*entry)->url = GLOBUS_NULL;
	globus_free((*entry)->filename);
	(*entry)->filename = GLOBUS_NULL;
	globus_free((*entry)->lock_tag);
	(*entry)->lock_tag = GLOBUS_NULL;
	if ((*entry)->tags != GLOBUS_NULL)
	{
	    for (i=0; i<(*entry)->num_tags+1; i++)
	    {
		globus_free(((*entry)->tags+i)->tag);
		((*entry)->tags+i)->tag = GLOBUS_NULL;
	    }
	}
	globus_free((*entry)->tags);
	(*entry)->tags = GLOBUS_NULL;
	if (itself == GLOBUS_TRUE)
	{
	    globus_free(*entry);
	    *entry=GLOBUS_NULL;
	}	
    }
}
/* globus_l_gass_cache_entry_free() */

/*
 * globus_l_gass_cache_write_state_file()
 *
 * Call globus_l_gass_cache_write_one_entry() to write one
 * globus_gass_cache_entry_t structure in the state file. In this function, we
 * define in which file we want the entry to be writen.
 * (globus_l_gass_cache_write_one_entry() is independant of this choice)
 * For the current implementation, we use a temporary file.
 * => cache_handle->temp_file_fd.
 *  
 * 
 * Parameters:
 *
 *     entry : address of the globus_gass_cache_entry_t to write in the file
 *
 *     cache_handle : contains the name/file descriptor of the file
 *     to write to.
 *
 * Returns:
 *     GLOBUS_SUCCESS or
 *     error code returned by globus_l_gass_cache_write_one_entry().
 */
static
int
globus_l_gass_cache_write_state_file(
    globus_gass_cache_entry_t *            entry,
    globus_gass_cache_t *                  cache_handle)
{
    int      rc; /* general purpose return code */

    if (entry != NULL)
    {
	rc = globus_l_gass_cache_write_one_entry(cache_handle->temp_file_fd,
					entry);
	globus_l_gass_cache_entry_free(&entry,GLOBUS_TRUE);
	if (rc != GLOBUS_SUCCESS)
	{
	    return (rc);
	}
    }
    return(GLOBUS_SUCCESS);
}
/* globus_l_gass_cache_write_state_file() */

/*
 * globus_l_gass_cache_lookfor_url()
 *
 * Search [read] in the cache state file for an existing entry
 *    with an url identic to the url (searched_url).
 *    When an entry is read, if it does not correspond to the searched url, the
 *    entry is writen back in the state file (actually to the temporary state
 *    file in the current implementation)
 *    
 *    If the entry read correspond to the searched url, it is returned 
 *    in an allocated  globus_gass_cache_entry_t structure.
 *    
 *    if none are found, NULL pointer is returned.
 * 
 *    Note that the whole file is scaned, self the url has been found before
 *    the last entry.
 *  
 * Parameters:
 *
 *       searched_url - url to look for in the file
 *
 *       cache_handle - cache handler used to get the
 *       file names /descriptor to read/write.
 *      
 *       return_entry - pointer to the entry found; NULL if none found
 *
 * Returns:
 *
 *    GLOBUS_SUCCESS or
 *    GLOBUS_GASS_CACHE_ERROR_OPEN_STATE
 *    GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE
 *    GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT
 *    error code returned by globus_l_gass_cache_read_one_entry()
 *    error code returned by globus_l_gass_cache_write_one_entry()
 */
static int
globus_l_gass_cache_lookfor_url(
    globus_gass_cache_entry_t **       return_entry,
    char *                             searched_url,
    globus_gass_cache_t *              cache_handle)
{
    globus_gass_cache_entry_t* globus_gass_cache_entry_pt=NULL;
				/* for general usage            */

    int rc;			/* return code                  */
    char entry_separator[2];	/* eache entry is preceded by   */
				/* a line containing #\n        */
  
    /* Write the  comment */
    rc = globus_l_gass_cache_write_comment(cache_handle,
					   cache_handle->temp_file_fd);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }
    
    *return_entry = NULL;   /* initialised to "not found" */
    /* scann the file */
    /* I do not "rewind" because I should have just opened the file         */

    
    while ( read( cache_handle->state_file_fd,
		  entry_separator,
		  sizeof(entry_separator))
	    == sizeof(entry_separator) && entry_separator[0] == '#' )
   
    {   /* If I manage to read an entry separator, I should have an entry */
	rc = globus_l_gass_cache_read_one_entry(cache_handle->state_file_fd,
				       &globus_gass_cache_entry_pt);
	if (rc != GLOBUS_SUCCESS)
	{
	    return (rc);
	}

	if ( strcmp(globus_gass_cache_entry_pt->url,searched_url))
	{
	    /* not the same url */
	    rc = globus_l_gass_cache_write_one_entry(cache_handle->temp_file_fd,
					    globus_gass_cache_entry_pt);
	    if (rc != GLOBUS_SUCCESS)
	    {
		globus_l_gass_cache_entry_free(&globus_gass_cache_entry_pt,
					       GLOBUS_TRUE);
		return (rc);
	    }
	    globus_l_gass_cache_entry_free(&globus_gass_cache_entry_pt,
					   GLOBUS_TRUE);
	}
	else
	{
	    /* the same url */
	    GLOBUS_L_GASS_CACHE_LG("URL found ");
	    *return_entry=globus_gass_cache_entry_pt;
	    globus_gass_cache_entry_pt=GLOBUS_NULL;
	}
    }

    if (entry_separator[0] != '*')
    {
	CACHE_TRACE("Error reading state file");
	return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
    }
    else
    {
	return(globus_l_gass_cache_read_nb_entries(cache_handle));
    }
}
/* globus_l_gass_cache_lookfor_url() */


/*
 * globus_l_gass_cache_lock_file()
 *
 * Create an advisory lock on a file. To methode have been
 * implemented: using hard link (if NEW_LOCK is not defined) and
 *  using open(... O_CREAT|O_EXCL) which return an error if file exist.
 *  ->hard links do not exist on AFS
 *  -> open(... O_CREAT|O_EXCL) do not work on all version of unix (But
 *  all the new versions/POSIX [IEEE 1988]
 *  Note : If compilled with LOCK_TOUT defined, the lock will timeout after
 *  LOCK_TOUT try to get the lock, if the file to lock is older than
 *  LOCK_TOUT*LOOP_TIME
 *
 * Parameters:
 *
 *     file_to_be_locked : path to the file to lock
 *
 * Returns: 
 *
 *     GLOBUS_SUCCESS or
 *     GLOBUS_GASS_CACHE_ERROR_LOCK_ERROR or
 *     GLOBUS_GASS_CACHE_ERROR_LOCK_TIME_OUT
 */	    
static
int
globus_l_gass_cache_lock_file(
    char *                       file_to_be_locked,
    char *                       temp_file)
{
    char   lock_file[PATH_MAX+1];
    int    temp_file_fd;
    char   uniq_lock_file[PATH_MAX+1];
    int    uniq_lock_file_fd;
    struct stat file_stat, tmp_file_stat;
    int    return_code=GLOBUS_SUCCESS;

#   ifdef LOCK_TOUT
	int    lock_tout=0;
	struct timeval tv;
#   endif

    /* build the name of the file used to lock "file_to_be_locked" */
    globus_l_gass_cache_name_lock_file(lock_file, file_to_be_locked);
    globus_l_gass_cache_name_uniq_lock_file(uniq_lock_file, file_to_be_locked);

    
    while ( (uniq_lock_file_fd = creat(uniq_lock_file,
				       GLOBUS_L_GASS_CACHE_STATE_MODE)) < 0 )
    {
	if (errno != EINTR)
	{
	    if (errno == ENOSPC)
            {
                return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
            }
            else if (IS_QUOTA_ERROR(errno))
            {
                return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
            }
            else
            {
	        CACHE_TRACE("Error writing state file");
	        return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
            }
	}
    }
    
    /* write its own name in the file, so it could be read in the "common"
       lock file */
    /* NOT USED 
    while ( write(uniq_lock_file_fd, uniq_lock_file, strlen(uniq_lock_file) )
	    != strlen(uniq_lock_file))
    {
	if (errno != EINTR)
	{
	    if (errno == ENOSPC)
            {
                return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
            }
            else if (IS_QUOTA_ERROR(errno))
            {
                return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
            }
            else
            {
	        CACHE_TRACE("Error writing state file");
	        return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
            }
	}
    }*/
    
    while (close(uniq_lock_file_fd) < 0 )
    {
	if (errno != EINTR)
	{
	    CACHE_TRACE2("could not close uniq lock file %s",uniq_lock_file);
	    return(GLOBUS_GASS_CACHE_ERROR_LOCK_ERROR);
	}
    }
    
    do
    {
	while ( link(uniq_lock_file, lock_file) < 0)
	{
            /* ENOTEMPTY: I try to ignore it for problems on DFS from a      */
	    /* Solaris machine                                               */
	    /* EEXIST : the file is locked by an other process               */
	    /* EINTR : system call interrupted: retry                        */
	    if (errno != EEXIST && errno != EINTR  && errno != ENOTEMPTY  )
	    {
		CACHE_TRACE3("Lock: Could not link files %s and %s\n",uniq_lock_file, lock_file);
		CACHE_TRACE2("Lock: Errno :%d\n",errno);
		return(GLOBUS_GASS_CACHE_ERROR_LOCK_ERROR);
	    }

#           ifdef LOCK_TOUT
	    {
		lock_tout++;
		if (lock_tout> LOCK_TOUT)
		{
		    /* check the age of the file to lock */
		    while ( stat(lock_file ,&file_stat) != 0)
		    {
			if (errno != EINTR)
			{
			    CACHE_TRACE2("could not get stat of file %s",
					 lock_file);
			    return(GLOBUS_GASS_CACHE_ERROR_LOCK_ERROR);
			}
		    }
		    while ( stat(temp_file,&tmp_file_stat) != 0)
		    {
			if (errno != EINTR)
			{
			    CACHE_TRACE2("could not get stat of file %s",
					 temp_file);
			    /*
			      If this has occurred, then either :
			      1/ The lock file has either been broken by
			      another process/thread
			      2/ the lock has been has been released, 
			      3/ the locking process crashed just when the
			      temp file was not here (before creation or after 
			      rename/deletion) but when the lock was 
			      already/still there.	
			      In case 1 and 2 I should try again to acquire
			      the lock. In case 3 the lock will never be 
			      released if I do not do some thing. I will create
			      an empty "temp" file (no trunc) so next time I 
			      timeout.
			      I could see that this file is old (or not)
			      */
			    while ((temp_file_fd =
				    open(temp_file,
					 O_WRONLY |O_CREAT,
					 GLOBUS_L_GASS_CACHE_STATE_MODE))
				   == -1)
			    {
	                        if (errno == ENOSPC)
                                {
                                    return(GLOBUS_GASS_CACHE_ERROR_NO_SPACE);
                                }
                                else if (IS_QUOTA_ERROR(errno))
                                {
                                    return(GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED);
                                }
				else if (errno != EINTR )
				{
	                            return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE);
                                }
			    }
			    while (close (temp_file_fd) == -1)
			    {
				if (errno != EINTR )
				{
				    return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
				}
			    }
  
			    
			    /* let's wait again */
			    lock_tout = 0;
			    
			    goto end_of_while;
			}
		    }
		    /* get system time */
		    gettimeofday(&tv, 0);
		    
		    if ( ( file_stat.st_ctime + (LOOP_TIME*LOCK_TOUT)/1000000 < tv.tv_sec) &&
			 ( tmp_file_stat.st_ctime + (LOOP_TIME*LOCK_TOUT)/1000000 < tv.tv_sec) )
			
		    {
			/* the file has not been accessed for long,
			 *
			 * BREAK THE LOCK !!!!!!!!
			 *
			 * This is very dangerous, can not be done without
			 * taking a chance (risk of corruption of the cache)
			 */
			/*
			  CACHE_TRACE2("Lock on %s too old: I BREAK IT !!\n",
			  file_to_be_locked);
			  */
			while ( unlink(temp_file) != 0 )
			{
			    if (errno != EINTR && errno != ENOENT )
			    {
				CACHE_TRACE2("Could not remove lock file %s",
					     temp_file);
				return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_DEL_LOCK);
			    }
			    if (errno == ENOENT )
			    {
				break;
			    }
			}
			
			while (unlink(lock_file) != 0 )
			{
			    if (errno != EINTR && errno != ENOENT )
			    {
				CACHE_TRACE2("Could not remove lock file %s",lock_file);
				return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_DEL_LOCK);
			    }
			    if (errno == ENOENT )
			    {
				break;
			    }
			}
			return_code=GLOBUS_GASS_CACHE_ERROR_LOCK_TIME_OUT
			    ;
		    }
		    
		    lock_tout=0;
		}
		else
		{
		    globus_libc_usleep(LOOP_TIME);
		}
	    }
#           else
	    {	
		globus_libc_usleep(LOOP_TIME);
	    }
#           endif
	    /* try again to lock the file */

            end_of_while:
	    ;
	}

	while ( stat(uniq_lock_file ,&file_stat) != 0)
	{
	    if (errno != EINTR)
	    {
		CACHE_TRACE("could not get stat of files");
		return(GLOBUS_GASS_CACHE_ERROR_LOCK_ERROR);
	    }
	}
	
	if  ( file_stat.st_nlink != 2)
	{
	    if (!globus_l_gass_cache_link_works)
		break;

	    /* we manage to create the file, but it is not a hard link
	       to the uniq_file, for some wird reasons. let try again */
	    while (unlink(lock_file) != 0 )
	    {
		if (errno != EINTR && errno != ENOENT )
		{
		    CACHE_TRACE2("Could not remove lock file %s",lock_file);
		    return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_DEL_LOCK);
		}
		if (errno == ENOENT )
		{
		    break;
		}
	    }
	}
	else
	{
	    /* we aquired the lock correctly, lets continue */
	    break;
	}
	globus_libc_usleep(LOOP_TIME);
	
	/* try again to lock the file */
    } while ( 1 );
    
    return(return_code);
}
/* globus_l_gass_cache_lock_file() */


/*
 * globus_l_gass_cache_unlock_file()
 *
 * Remove the lock previously created by globus_l_gass_cache_lock_file()
 *
 * Parameters:
 *
 *     file_to_be_locked - path to the file to lock
 *
 * Returns: 
 *     GLOBUS_SUCCESS or
 *     GLOBUS_GASS_CACHE_ERROR_CAN_NOT_DEL_LOCK
 */  
static
int
globus_l_gass_cache_unlock_file(
    char *                        file_to_be_locked)
{
    char   lock_file[PATH_MAX+1];

    char   uniq_lock_file[PATH_MAX+1];
 
    /* build the name of the file used to lock "file_to_be_locked" */
    globus_l_gass_cache_name_lock_file(lock_file, file_to_be_locked);
    globus_l_gass_cache_name_uniq_lock_file(uniq_lock_file, file_to_be_locked);
 
    /* remove the lock */
    while (unlink(lock_file) != 0 )
    {
	if (errno != EINTR && errno != ENOENT )
	{
	    CACHE_TRACE("Could not remove lock file");
	    return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_DEL_LOCK);
	}
	if (errno == ENOENT )
	{
	    break;
	}
    }
    while ( unlink(uniq_lock_file) != 0 )
    {
	if (errno != EINTR && errno != ENOENT)
	{
	    /* it strangely happens that the file is not here any more */
	    /* well, all my  test seems to show it work like this......*/
	    break;
	}
	if (errno == ENOENT )
	{
	    break;
	}
    }
    
    return(GLOBUS_SUCCESS); 
}
/* globus_l_gass_cache_unlock_file() */

/*
 * globus_l_gass_cache_lock_open()
 *
 * Check if the cache state file is locked; wait it is unlocked
 * using a simple sleep loop and lock it.
 * The lock is implemented using a hard link on the file to lock.
 *
 * Open the cache state file when locked.
 *  
 * It also initialise the file if it is empty (first use) (this is done in
 * this function because we need the file to be locked before it can be
 * modified)
 *  
 * Parameters:
 *
 *      cache_handle - handler to the chache directory to use.
 *      cache_handle->state_file_path  and
 *      cache_handle->state_file_lock_path
 *	
 *      cache_handle->state_file_fd - file descriptor of the open
 *      cache state file
 *	    
 *      cache_handle->temp_file_fd - file descriptor of an open
 *      temporary cache state file into which every modification
 *      made to the cache state file is stored. Used to prevent
 *      cache state file corruption in case of proglobus_gramm
 *      crash.
 *      the temporary file will "atomically" overwrite the
 *      cache state file by the function
 *      globus_l_gass_cache_unlock_close()
 *	   
 *      cache_handle->nb_entries  - If the cache state file was empty,
 *      this variable is initialised to 0 (zero).
 *	    
 * Returns:
 *      GLOBUS_SUCCESS or error code:
 *      GLOBUS_GASS_CACHE_ERROR_LOCK_ERROR or
 *      GLOBUS_GASS_CACHE_ERROR_OPEN_STATE or
 *      GLOBUS_GASS_CACHE_ERROR_LOCK_TIME_OUT (Not implemented in this version)
 */ 
static
int
globus_l_gass_cache_lock_open(
    globus_gass_cache_t*             cache_handle)
{
    int rc;

    rc =globus_l_gass_cache_lock_file(cache_handle->state_file_path,
				      cache_handle->temp_file_path);
    if ( rc != GLOBUS_SUCCESS && rc !=GLOBUS_GASS_CACHE_ERROR_LOCK_TIME_OUT)
    {
	return(rc);
    }

    GLOBUS_L_GASS_CACHE_LG2("State file %s LOCKED", cache_handle->state_file_path );

    while ((cache_handle->state_file_fd =
	    open(cache_handle->state_file_path,
		 O_RDWR,GLOBUS_L_GASS_CACHE_STATE_MODE))
	   == -1)
    {
	if ( errno != EINTR )
	{
	    /* well, if we can not open the state file,there is probably
	       a serious problem. but any way, lets try to unlock it before
	       we return an error */
	    globus_l_gass_cache_unlock_file(cache_handle->state_file_path);
	    GLOBUS_L_GASS_CACHE_LG("Could not open the state file");
	    return(GLOBUS_GASS_CACHE_ERROR_OPEN_STATE);
	}
    }
    
    do
    {
	rc = read( cache_handle->state_file_fd,
		    cache_handle->comment,
		    sizeof(cache_handle->comment));
    
        if (rc!=sizeof(cache_handle->comment))
	{
	    
	    if (rc == -1 &&errno == EINTR)
	    {
		continue;
	    }
	    if (rc == 0)
	    {
		/* file is probably empty */
		/* initialise the number of entries */
		cache_handle->nb_entries=0;
		/* Write the  comment */
		rc = globus_l_gass_cache_write_comment(
		    cache_handle,
		    cache_handle->state_file_fd);
		if (rc != GLOBUS_SUCCESS)
		{
		    globus_l_gass_cache_unlock_close(
			cache_handle,
			GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		    return(rc);
		}
		/* write the number of entry, 0 */
		rc = globus_l_gass_cache_write_nb_entries(
		    cache_handle->state_file_fd,
		    0);
		if (rc != GLOBUS_SUCCESS)
		{
		    globus_l_gass_cache_unlock_close(
			cache_handle,
			GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		    return(rc);
		}
		lseek(cache_handle->state_file_fd, 0,SEEK_SET);
		/*
		rc=sizeof(cache_handle->comment);
		*/
		continue;
		
	    }
	    else
	    {
		CACHE_TRACE("Error reading  state file");
		globus_l_gass_cache_unlock_close(
		    cache_handle,
		    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_READ);
	    }
	}
	else
	{
	    /* comment read correctly */
	    cache_handle->comment[sizeof(cache_handle->comment)-1]='\0';
	    /* verify the version number */
	    if (strncmp(cache_handle->comment,"# Gass_cache state file",23))
	    {
		int nbfield_scanned;

		nbfield_scanned = sscanf(cache_handle->comment,
					 "-Version %5u",
					 &cache_handle->version);
		if (nbfield_scanned != 1)
		{
		    globus_l_gass_cache_unlock_close(
			cache_handle,
			GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		    return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
		}
		
		if (cache_handle->version >
		    GLOBUS_GASS_CACHE_STATE_FILE_FORMAT_VERSION)
		{
		    globus_l_gass_cache_unlock_close(
			cache_handle,
			GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		    return(GLOBUS_GASS_CACHE_ERROR_INVALID_VERSION);
		}
		
	    }
	    else /* version beta has no version number and is equivalent to */
		 /* version 1 */               
	    {
		cache_handle->version = 1;
	    }
	    
	}
    } while (rc!=sizeof(cache_handle->comment)); /* just to handle the EINTR */
    
    GLOBUS_L_GASS_CACHE_LG("State file opened");
    while ((cache_handle->temp_file_fd =
	    open(cache_handle->temp_file_path,
		 O_WRONLY |O_CREAT|O_TRUNC,
		 GLOBUS_L_GASS_CACHE_STATE_MODE ))
	   == -1)
    {
	if (errno != EINTR )
	{
	    GLOBUS_L_GASS_CACHE_LG(
		"Could not open/create the temporary state file");
	    globus_l_gass_cache_unlock_close(
		cache_handle,
		GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	    return(GLOBUS_GASS_CACHE_ERROR_OPEN_STATE);
	}
    }

    GLOBUS_L_GASS_CACHE_LG("Temporary State file opened");
    
    return (GLOBUS_SUCCESS);
}
/* globus_l_gass_cache_lock_open() */

/*
 * globus_l_gass_cache_unlock_close()
 *
 * Close the state file of the cache and remove its lock.
 * Actually, because of the choice of using a temporary state file
 * to avoid file corruption, some more is done:
 * 
 *      - the number of entries is writen at the end of the temp file,
 *      - the temporary state file and the state are closed, 
 *      - if the function is called with the parameter "commit",
 *        the temporary state file "atomically" overwrite the state
 *        file (using a rename system call), and therefor, the changes are
 *        commited.
 *      - if the function is called with the parameter "abort",
 *        the temporary file is just abandonned, and the changes are
 *        therefor discarded.
 *
 *      - The lock is removed
 *    
 * Parameters:
 *
 *      cache_handle - handler to the chache directory to use.
 *      cache_handle->state_file_path  and
 *	cache_handle->temp_file_fd     and
 *	cache_handle->state_file_lock_path are used to access
 *	the corresponding files.
 *
 * Returns:
 *      BLOBUS_SUCCESS or error code:
 *      GLOBUS_GASS_CACHE_ERROR_LOCK_ERROR if the lock could not be removed,
 *      error code returned by globus_l_gass_cache_write_nb_entries()
 */ 
static
int
globus_l_gass_cache_unlock_close(
    globus_gass_cache_t *           cache_handle,
    globus_bool_t                   abort)
{
    /* return code                  */
    int                 rc;                  
    struct stat         lock_stat;   
    char   uniq_lock_file[PATH_MAX+1];

    /* before I close, I want to write the number of entries */
    if (!abort)
    {
	    rc = globus_l_gass_cache_write_nb_entries(
		cache_handle->temp_file_fd,
		cache_handle->nb_entries);
	    
	    if ( rc!= GLOBUS_SUCCESS )
	    {
		globus_l_gass_cache_unlock_close(cache_handle,
						 GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		return(rc);
	    }
    }
    if (cache_handle->state_file_fd >0 )
    {
	if (close(cache_handle->state_file_fd) <0)
	{
	    GLOBUS_L_GASS_CACHE_LG("Error closing the state file");
	    /* do not return: we want to [try to] unlock it any way */
	}
	cache_handle->state_file_fd = -1;
    }
    if (cache_handle->temp_file_fd>0 )
    {
	if (close(cache_handle->temp_file_fd) <0)
	{
	    GLOBUS_L_GASS_CACHE_LG("Error closing the temporary state file");
	    /* do not return: we want to [try to] unlock it any way */
	}
	cache_handle->temp_file_fd = -1;
    }

    /* for test purpose: add this so you can remove manually the lock...
       sleep(10);
       */
    
    /* if I still have the lock
     */    
    globus_l_gass_cache_name_uniq_lock_file(uniq_lock_file,
					    cache_handle->state_file_path);
    while ((rc =  stat(uniq_lock_file,
		      &lock_stat)) != 0)
    {
	if (errno != EINTR )
	{
	    break;
	}
    }

    if ((rc==0) && (!globus_l_gass_cache_link_works || lock_stat.st_nlink==2))
    {
	/* I still have the lock */

	if (!abort)                    /* if (abort=GLOBUS_SUCCESS) */
	{
	    if (rename(cache_handle->temp_file_path,cache_handle->state_file_path))
	    {
		/* that is too bad... and should not happen... lets test it...   */
		GLOBUS_L_GASS_CACHE_LG("Error renaming the temporary state file/state file");
	    }
	}
	else
	{
	    if (unlink(cache_handle->temp_file_path))
	    {
		GLOBUS_L_GASS_CACHE_LG("Error unlinking the temporary state file");
	    }
	}
	
	/* release the lock */
	rc = globus_l_gass_cache_unlock_file(cache_handle->state_file_path);
	if ( rc != GLOBUS_SUCCESS)
	{
	    return(rc);
	}

    
    }
    else
    {
	/* if I lost the lock, I just leave every thing in place
	 * and do nothing: I do not want to take a chance of corrupting the
	 * cache if someone "stole" the lock 
	 */
	return(GLOBUS_GASS_CACHE_ERROR_LOCK_ERROR);
    }
    GLOBUS_L_GASS_CACHE_LG("State file UNlocked");
    
    return (GLOBUS_SUCCESS);
} /*  globus_l_gass_cache_unlock_close() */



/******************************************************************************

  PUBLIC FUNCTIONS
  
******************************************************************************/

/*
 * globus_gass_cache_open()
 *
 * Open the cache specified by the cache_directory_path argument, and return
 * a cache handle that can be used in subsequent cache calls. 
 *
 * If cache_directory_path is NULL, then use the value contained in the
 * GLOBUS_GASS_CACHE_DEFAULT environment variable if it is defined,
 * otherwise use ~/.globus_gass_cache.
 *
 * The cache_directory_path must be a directory. If it is a file, this call
 * will fail with a non-0 return value.
 *
 * If the specified directory does not exist, then this call will create the
 * directory.
 *
 * Parameters:     
 *
 *     cache_directory_path : Path to the cache directory to open.
 *     Can be NULL (see above)
 *
 *     cache_handle->is_init: checked and return an error if 
 *     cache_handle has already been used.
 *	    
 *     cache_handle: Structure containning all the necessary
 *     information to access the cache (file names, descriptor,...)
 *     (see globus_gass_gache.h) Some files are also opened:
 *     globus_gass_cache_close() must be called subsequently to close those
 *     files.
 *     This parameter is modified by the globus_gass_cache_open()
 *	
 * Returns:    
 *     BLOBUS_SUCCESS or error code:	
 *     GLOBUS_GASS_CACHE_ERROR_CACHE_ALREADY_OPENED
 *     GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG if the cache directory path is
 *     too long
 *     GLOBUS_GASS_CACHE_ERROR_NO_HOME if cache_directory_path is NULL and
 *     the env. variable GLOBUS_GASS_CACHE_DEFAULT is empty and
 *     the env. variable $HOME is not defined !
 *     GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE if the cache directory or any
 *     necessary file can not be created.
 *	 
 */
int 
globus_gass_cache_open(char                *cache_directory_path,
		       globus_gass_cache_t *cache_handle)

{
    int         rc;		/* general purpose returned code           */
    char *      pt;		/* general purpose returned pointer        */

    int         f_name_length;	/* too verify the length of the file names */
    char        f_name[PATH_MAX+1];/* path name of the 3 files we */
				     /* will open */
#   if defined GLOBUS_L_GASS_CACHE_LOG
    char        log_f_name[PATH_MAX+1]; /* log file file name           */
#   endif
    int         state_f_fd;	/* to open/create the state file          */
    struct stat cache_dir_stat;   

    char        homedir[PATH_MAX];

    CHECK_CACHE_IS_NOT_INIT();

    cache_handle->state_file_fd = -1;
    cache_handle->temp_file_fd = -1;
    
    /* look for the correct directory path */

    /* if cache_directory_path empty (""), behave as if NULL */
    if ( cache_directory_path != GLOBUS_NULL) 
    {	
	f_name_length=strlen(cache_directory_path);
	if ( f_name_length == 0 )
	{
	    cache_directory_path = GLOBUS_NULL;

	    CACHE_TRACE("Error: cache_directory_path empty");

	}
    }

    /* if cache_directory_path empty, read it from GLOBUS_GASS_CACHE_DEFAULT */
    if ( cache_directory_path == GLOBUS_NULL )
    {
      	pt = globus_libc_getenv(GLOBUS_L_GASS_CACHE_DEFAULT_DIR_ENV_VAR);

	/* if GLOBUS_GASS_CACHE_DEFAUL empty (""), behave as if not defined */
	if ( pt != GLOBUS_NULL)
	{
	    f_name_length=strlen(pt);
	    if ( f_name_length == 0)
	    {
		pt = GLOBUS_NULL;
	    }
	}

	if ( pt == GLOBUS_NULL )
	{
	    GLOBUS_L_GASS_CACHE_LG("GLOBUS_GASS_CACHE_DEFAULT_DIR_ENV_VAR is empty");
	    /* cache directory still not defined; use the defaults */
	    /*   "$HOME/.globus_gass_cache" */

	    if ( globus_libc_gethomedir(homedir,PATH_MAX) == GLOBUS_SUCCESS)
	    {
		f_name_length=strlen(homedir);
		if ( f_name_length > 0)
		    pt = homedir;
	    }
	    
	    if (pt == GLOBUS_NULL)
	    {
		/* $HOME not defined or null ! this should not happen */
		CACHE_TRACE("HOME not defined or empty");
		return ( GLOBUS_GASS_CACHE_ERROR_NO_HOME );
	    }
	    
	    if ((f_name_length +
		 strlen(GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME))>=PATH_MAX)
	    {
		CACHE_TRACE("ENAMETOOLONG");
                printf("NAMETOOLONG: f_name_length: %d, default_name_length: %d, filename_max: %d\n",
                       f_name_length,
                       strlen(GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME),
                       PATH_MAX);
		return ( GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG);
	    }
	    strcpy(cache_handle->cache_directory_path,
		   pt);

	    /* before going on, verify the .globus directory exist 
               and create it if not */ 
	    strcat(cache_handle->cache_directory_path,
		   GLOBUS_L_DOT_GLOBUS_DIR_NAME);
	    rc =  stat(cache_handle->cache_directory_path,
		       &cache_dir_stat);
	    if (rc == 0)
	    {
		
		if ( (cache_dir_stat.st_mode & S_IFMT) != S_IFDIR )
		{
		    CACHE_TRACE("The .globus directory exist and is not a directory");
		    return (GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE);
		}
	    }
	    if (rc != 0)
	    {
		/* I assume the error is "directory not existing"    */
		/* but it could occur if it is not accessible; the   */
		/* creation call would the fail also, and the error  */
		/* code send back would be a little erroneous        */
		/* ok for now.                                       */
		rc = mkdir(cache_handle->cache_directory_path,
			   GLOBUS_L_GASS_CACHE_DIR_MODE);
		if ( rc != 0 )
		{
		    CACHE_TRACE("could not create the .globus directory");
		    return (GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE);
		}
	    }
	    /* here the .globus existe and is a directory */
	    strcat(cache_handle->cache_directory_path,
		   GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME);
	}
	else /* *pt is not null or empty */
	{
	    if (f_name_length >= PATH_MAX)
	    {
		CACHE_TRACE("ENAMETOOLONG");
		return ( GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG);
	    }
	    strcpy(cache_handle->cache_directory_path, pt);
	}
    }
    else			/* cache_directory_path is valid */
    {
	/* for the version which will accept a cache directory not null  */
	if (f_name_length >= PATH_MAX)
	{
	    CACHE_TRACE("ENAMETOOLONG");
	    return ( GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG);
	}
	strcpy(cache_handle->cache_directory_path,
	       cache_directory_path);
    }
    GLOBUS_L_GASS_CACHE_LG2(" cache directory :%s ",
		 cache_handle->cache_directory_path );

    /* here, *cache_handle.cache_directory_path should be defined */
    /* let see if it exists, and create it if it does not */
    rc =  stat(cache_handle->cache_directory_path,
	       &cache_dir_stat);
    if (rc == 0)
    {
	
	if ( (cache_dir_stat.st_mode & S_IFMT) != S_IFDIR )
	{
	    CACHE_TRACE("The cache directory exist and is not a directory");
	    return (GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE);
	}
    }
    if (rc != 0)
    {
        /* I assume the error is "directory not existing"    */
	/* but it could occur if it is not accessible; the   */
	/* creation call would the fail also, and the error  */
	/* code send back would be a little erroneous        */
	/* ok for now.                                       */
	
	rc = mkdir(cache_handle->cache_directory_path,
		   GLOBUS_L_GASS_CACHE_DIR_MODE);
        if ( rc != 0 )
	{
	    CACHE_TRACE("could not create the cache directory");
	    return (GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE);
	}
    }

    /* here I suppose cache_directory_path existe and is a directory */
    if ((f_name_length + LONGER_NAME_USED )>=PATH_MAX)
    {
	CACHE_TRACE("ENAMETOOLONG");
	return ( GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG);
    }
    strcpy(f_name,cache_handle->cache_directory_path);
    strcat(f_name,GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME);
    
    /* open the log file and log the some informations */
#   if defined GLOBUS_L_GASS_CACHE_LOG
    {
	strcpy(log_f_name,cache_handle->cache_directory_path);
	strcat(log_f_name,GLOBUS_L_GASS_CACHE_LOG_F_NAME);
	cache_handle->log_FILE = fopen( log_f_name,"a");
	if (cache_handle->log_FILE == GLOBUS_NULL)
	{
	    CACHE_TRACE("Could NOT open or create the log file");
	}
    }
#   endif

    /* Prepare a lock file name */
    strcpy(cache_handle->state_file_lock_path,
	   cache_handle->cache_directory_path);
    strcat(cache_handle->state_file_lock_path,
	   GLOBUS_L_GASS_CACHE_STATE_F_LOCK);
    
    /* open or create the state file */
    strcpy(cache_handle->state_file_path,cache_handle->cache_directory_path);
    strcat(cache_handle->state_file_path,GLOBUS_L_GASS_CACHE_STATE_F_NAME );
    GLOBUS_L_GASS_CACHE_LG(cache_handle->state_file_path);

    while ((state_f_fd = open(cache_handle->state_file_path,
			      O_RDWR|O_CREAT,
			      GLOBUS_L_GASS_CACHE_STATE_MODE))
	   == -1)
    {
	if (errno != EINTR )
	{
	    GLOBUS_L_GASS_CACHE_LG("Could NOT open or create the state file");
#           if defined GLOBUS_L_GASS_CACHE_LOG
	    {
		fclose(cache_handle->log_FILE);
	    }
#           endif
	    return ( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE );
	}
    }
    
    while (close (state_f_fd) == -1)
    {
	if (errno != EINTR )
	{
	    return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE);
	}
    }
     
    /* just prepare a temporary file name */
    strcpy(cache_handle->temp_file_path,
	   cache_handle->cache_directory_path);
    strcat(cache_handle->temp_file_path,
	   GLOBUS_L_GASS_CACHE_STATE_F_TEMP);

    GLOBUS_L_GASS_CACHE_LG("Cache Opened");
    /* to simply check if the cache has been open, in any other function */
    cache_handle->init = &globus_l_gass_cache_is_init;

    /* just to check the version number */
    rc = globus_l_gass_cache_lock_open(cache_handle);
    if (rc != GLOBUS_SUCCESS)
    {
	globus_l_gass_cache_unlock_close(cache_handle,
					 GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	/* mark this handle as not opened */
	cache_handle->init=&globus_l_gass_cache_is_not_init;
	
	return(rc);
    }
    return(globus_l_gass_cache_unlock_close(cache_handle,
					    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT));
    
}
/*  globus_gass_cache_open() */

/*
 * globus_gass_cache_close()
 *
 *
 * Close (NOT delete) a previously opened cache:
 * - close the opened files and 
 * - free the memory allocated for the cache_handle.
 * - mark the handle as "not initialized".
 *
 * Parameters: 
 *     cache_handle: Handler to the opened cahe directory to use.    
 *	    
 *     cache_handle->is_init set to "not initialized" and all the
 *     files opened bu globus_gass_cache_open are closed . 
 *
 * Returns:
 *     GLOBUS_SUCCESS or error code:
 *     GLOBUS_GASS_CACHE_ERROR_CACHE_NOT_OPENED
 * 
 */
int
globus_gass_cache_close(
    globus_gass_cache_t *          cache_handle)
{
    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT();

    /* marque this handle as not opened */
    cache_handle->init=&globus_l_gass_cache_is_not_init;
#   if defined GLOBUS_L_GASS_CACHE_LOG
    {
	fclose(cache_handle->log_FILE);
    }
#   endif
    
    GLOBUS_L_GASS_CACHE_LG("Cache Closed");
    return(GLOBUS_SUCCESS);
}
/*  globus_gass_cache_close() */

/*
 * globus_gass_cache_add()
 *
 * Create a new cache file or add a tag on it.
 *
 * If the URL is already in the cache but is locked, then this call will block
 * until the cache entry is unlocked, then will proceed with the subsequent
 * operations.
 *
 * If the URL is already in the cache and unlocked, then add the tag to the
 * cache entry's tag list, return the local cache filename in *local_filename,
 * return the entry's current timestamp in *timestamp, lock the cache entry,
 * and return GLOBUS_GASS_CACHE_ADD_EXISTS.
 *
 * If the URL is not in the cache, and create==GLOBUS_TRUE, then create a new
 * unique empty local cache file, add it to the cache with the specified tag,
 * return the filename in *local_filename, return *timestamp set to
 * GLOBUS_GASS_CACHE_TIMESTAMP_UNKNOWN, lock the cache entry, and
 * return GLOBUS_GASS_CACHE_ADD_NEW.
 *
 * If the URL is not in the cache, and create==GLOBUS_FALSE, then do not
 * add it to the cache, and return GLOBUS_GASS_CACHE_URL_NOT_FOUND. 
 *
 * If this function returns GLOBUS_GASS_CACHE_ADD_EXISTS or
 * GLOBUS_GASS_CACHE_ADD_NEW, then globus_gass_cache_add_done() or
 * globus_gass_cache_delete() must be subsequently
 * called to unlock the cache entry. 
 *
 * Subsequent calls to globus_gass_cache_add() and
 * globus_gass_cache_delete_start() on the same cache and url, made either
 * from this process or another, will block until the cache entry is unlocked.
 *
 * If tag==NULL, then a tag with the value "null" will be added to the cache
 * entry's tag list.
 *
 * The same tag can be used multiple times, in which case this tag will be
 * added to the entry's tag list multiple times.
 *
 * Note: It is recommended that proglobus_grams started via GLOBUS_GRAM
 * pass a tag value
 * of getenv("GLOBUS_GRAM_JOB_CONTACT"), since upon completion of a
 * job GLOBUS_GRAM will automatically cleanup entries with this tag.
 *
 * Important Note: the local_filename MUST be free by the user in a
 * subsequent operation, using globus_free()
 *  
 * Parameters:
 *
 *     cache_handle - Handler to the opened cahe directory to use.
 *
 *     url - url of the file to be cached. It is used as the main
 *     key to the cache entries.
 *
 *     tag - tag specifying which job is/are using the cache. This
 *     is usually the GLOBUS_GRAM_JOB_CONTACT. Can be NULL or empty; the
 *     tag "null" is then used.
 *     create - Tells if the cache entry should be created if it is
 *     not already existing.
 *
 *     timestamp - time stamp of the cached file, set by
 *     globus_gass_cache_done(), (or globus_gass_cache_delete() ).
 *
 *     local_filename - Path the the local file caching the file
 *     specified by "url". NULL if "url" not yet cached and
 *     creation not requested (create false). 
 *
 * Returns:    
 *     GLOBUS_GASS_CACHE_URL_NOT_FOUND
 *     GLOBUS_GASS_CACHE_ADD_NEW
 *     GLOBUS_GASS_CACHE_ADD_EXISTS
 *     or any of the defined gass error code.
 *
 */
int
globus_gass_cache_add(
    globus_gass_cache_t *      cache_handle,
    char*                      url,
    char *                     tag,
    globus_bool_t              create,
    unsigned long *            timestamp,
    char **                    local_filename)
{
    int                        rc;   /* general purpose return code */
    globus_gass_cache_entry_t *entry_found_pt;
    globus_gass_cache_entry_t *new_entry_pt;
    globus_gass_cache_tag_t   *tag_pt; /* to scan thrue the tag arrays */
    char                       notready_file_path[PATH_MAX+1];
    struct stat                file_stat;
    int                        tmp_fd;
    
    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT();
    
   /* if no tag supplied, we map it to the tag
      GLOBUS_L_GASS_CACHE_NULL_TAG ("null") */
   if (tag == GLOBUS_NULL)
   {
       tag=GLOBUS_L_GASS_CACHE_NULL_TAG;
   }
   
   /* I want to do every thing again and again until the data file 
      is ready */
   while (GLOBUS_TRUE)
   {
       rc = globus_l_gass_cache_lock_open(cache_handle);
       if (rc != GLOBUS_SUCCESS)
       {
	   *local_filename=GLOBUS_NULL;
	   return(rc);
       }
       
       rc = globus_l_gass_cache_lookfor_url(&entry_found_pt,
					    url,
					    cache_handle);
       if (rc != GLOBUS_SUCCESS)
       {
	   globus_l_gass_cache_unlock_close(cache_handle,
					    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	   return(rc);
       }
       
       if (entry_found_pt == GLOBUS_NULL)   /* url not found */
       {
	   GLOBUS_L_GASS_CACHE_LG("URL not found");

	   if (create == GLOBUS_FALSE)
	   {
	       globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	       return(GLOBUS_GASS_CACHE_URL_NOT_FOUND);
       }
	   
	   /* create requested: I have to add the entry */
	   
	   cache_handle->nb_entries++;
	   
	   /* create a new file name */
	   *local_filename=(char *) globus_malloc(PATH_MAX+1);
	   GLOBUS_L_GASS_CACHE_FILENAME(*local_filename);
	   globus_libc_lock();
	   while (stat(*local_filename,&file_stat) != -1)
	   {
	       GLOBUS_L_GASS_CACHE_FILENAME(*local_filename);
	   }
	   globus_libc_unlock();

	   GLOBUS_L_GASS_CACHE_LG(*local_filename);

	   if ((tmp_fd = creat(*local_filename, 
                               GLOBUS_L_GASS_CACHE_STATE_MODE)) == -1 )
	   {
	       CACHE_TRACE("Could not create new data file");
	       globus_l_gass_cache_unlock_close(cache_handle, 
                                                GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	       return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE_DATA_F);
	   }
           close(tmp_fd);
	   
	   /* set the file as not ready */
	   strcpy(notready_file_path,*local_filename);
	   strcat(notready_file_path,GLOBUS_L_GASS_CACHE_EXT_NOTREADY);
	   if ((tmp_fd = creat(notready_file_path, 
			       GLOBUS_L_GASS_CACHE_STATE_MODE)) == -1 )
	   {
	       CACHE_TRACE("Could not create new data filei lock");
	       globus_l_gass_cache_unlock_close(cache_handle,
                                                GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	       return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE_DATA_F);
	   }
           close(tmp_fd);
	   
	   /* create a new stat entry and initialise it */
	   new_entry_pt = (globus_gass_cache_entry_t *)
	       globus_malloc(sizeof(globus_gass_cache_entry_t));
	   
	   if (new_entry_pt == GLOBUS_NULL)
	   {
	       CACHE_TRACE("No more memory");
	       globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	       return(GLOBUS_GASS_CACHE_ERROR_NO_MEMORY);
	   }
	   
	   /* url */
	   new_entry_pt->url = (char *) globus_malloc(strlen(url)+1);
	   if (new_entry_pt->url == GLOBUS_NULL)
	   {
	       CACHE_TRACE("No more memory");
	       globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	       return(GLOBUS_GASS_CACHE_ERROR_NO_MEMORY);
	   }
	   strcpy(new_entry_pt->url,url);
	   
	   /* file name */
	   new_entry_pt->filename=(char *)
	       globus_malloc(strlen(*local_filename)+1);
	   if (new_entry_pt->filename == GLOBUS_NULL)
	   {
	       CACHE_TRACE("No more memory");
	       globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	       return(GLOBUS_GASS_CACHE_ERROR_NO_MEMORY);
	   }
	   strcpy(new_entry_pt->filename,*local_filename);
	   
	   /* status */
	   /* we could point directly in the tag area, but it is not
	   very clean confusing problems could occur when unlocked and
	   locked on an other tag...  */
	   
	   /* status */
	   /* lets lock the file on the new tag */
	   new_entry_pt->lock_tag = (char *) globus_malloc(strlen(tag)+1);
	   
	   if ( new_entry_pt->lock_tag == GLOBUS_NULL)
	   {
	       CACHE_TRACE("No more memory");
	       globus_l_gass_cache_entry_free(&new_entry_pt,
					      GLOBUS_TRUE);
	       globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	       return(GLOBUS_GASS_CACHE_ERROR_NO_MEMORY);
	   }
	   strcpy( new_entry_pt->lock_tag, tag);
	   
	   
	   /* timestamp */
	   /* for the time being */
	   new_entry_pt->timestamp = GLOBUS_GASS_CACHE_TIMESTAMP_UNKNOWN;
	   *timestamp = GLOBUS_GASS_CACHE_TIMESTAMP_UNKNOWN;
	   
	   /* tags */
	   /* allocate an array of 2 tags (one real, and one "end" indicator */
	   new_entry_pt->tags = (globus_gass_cache_tag_t *)
	       globus_malloc(2*sizeof(globus_gass_cache_tag_t));
	   
	   if (new_entry_pt->tags == GLOBUS_NULL)
	   {
	       CACHE_TRACE("No more memory");
	       globus_l_gass_cache_entry_free(&new_entry_pt,
					      GLOBUS_TRUE);
	       globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	       return(GLOBUS_GASS_CACHE_ERROR_NO_MEMORY);
	   }
	   
	   (*(new_entry_pt->tags)).tag= (char *) globus_malloc(strlen(tag)+1);
	   if ( (*(new_entry_pt->tags)).tag == GLOBUS_NULL)
	   {
	       CACHE_TRACE("No more memory");
	       globus_l_gass_cache_entry_free(&new_entry_pt,
					      GLOBUS_TRUE);
	       globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	       return(GLOBUS_GASS_CACHE_ERROR_NO_MEMORY);
	   }
	   strcpy( (*(new_entry_pt->tags)).tag,tag);
	   (*(new_entry_pt->tags)).count=1;
	   (*(new_entry_pt->tags+1)).tag = GLOBUS_NULL;
	   (*(new_entry_pt->tags+1)).count=0;
	   new_entry_pt->num_tags=1;
	   new_entry_pt->pending='F';
	       
	   /* ok now lets write this new entry */
	   rc= globus_l_gass_cache_write_state_file(new_entry_pt,
						    cache_handle);
	   if (rc != GLOBUS_SUCCESS)
	   {
	       globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	       return(rc);
	   }
	   rc = globus_l_gass_cache_unlock_close(cache_handle,
						 GLOBUS_L_GASS_CACHE_COMMIT);
	   if (rc != GLOBUS_SUCCESS)
	   {
	       return(rc);
	   }
	   
	   GLOBUS_L_GASS_CACHE_LG3( "Url %s tag %s CREATED",
				    url,
				    tag);
	   return(GLOBUS_GASS_CACHE_ADD_NEW);
       } 
       else /* url found */
       {
	   GLOBUS_L_GASS_CACHE_LG("URL found");

	   if (entry_found_pt->lock_tag != GLOBUS_NULL) /* data file not ready */
	   {
	       GLOBUS_L_GASS_CACHE_LG("Data file not ready: wait");

	       /* new with 1.1 */
	       entry_found_pt->pending='P';
	       
	       strcpy(notready_file_path,
		      entry_found_pt->filename);
	       strcat(notready_file_path,
		      GLOBUS_L_GASS_CACHE_EXT_NOTREADY);
	       
	       /* just check coherence between state file and blocking file */
	       if ( stat(notready_file_path, &file_stat) == -1 )
	       {
		   GLOBUS_L_GASS_CACHE_LG(
		       "State file and bloking file are not coherent");
		   globus_l_gass_cache_unlock_close(cache_handle,
						    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
		   
	       }
	       
	       rc = globus_l_gass_cache_write_state_file(entry_found_pt,
							 cache_handle);
	       if (rc != GLOBUS_SUCCESS)
	       {
		   globus_l_gass_cache_unlock_close(cache_handle,
						    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return(rc);
	       }
	       rc = globus_l_gass_cache_unlock_close(
		   cache_handle,
		   GLOBUS_L_GASS_CACHE_COMMIT);
	       
	       if (rc != GLOBUS_SUCCESS)
	       {
		   return(rc);
	       }
	       
	       /* wait */
	       rc = stat(notready_file_path,
			 &file_stat);
	       while ( rc != -1 )
	       {
		   globus_libc_usleep(LOOP_TIME);
		   rc = stat(notready_file_path,
			     &file_stat);
	       }
	       
	       GLOBUS_L_GASS_CACHE_LG("Data file now ready: continue");

	       continue;
	   }
	   else  /* file ready */
	   {
	       GLOBUS_L_GASS_CACHE_LG("Data file ready...");
	   
	       /* new with 1.1 */
	       entry_found_pt->pending='F';

	       /* return the file name and the timestamp */
	       /* create a new file name */
	       *local_filename = (char *) globus_malloc(PATH_MAX+1);
	       strcpy(*local_filename,
		      entry_found_pt->filename);
	       *timestamp = entry_found_pt->timestamp;
	       
	       /* add a tag */
	       tag_pt = entry_found_pt->tags;
	       while (tag_pt->tag != GLOBUS_NULL)
	       {
		   if ( !strcmp(tag_pt->tag,
				tag))
		   {
		       /* tag found */
		       tag_pt->count++;
		       break;
		   }
		   tag_pt++;
	       }
	       if (tag_pt->tag == GLOBUS_NULL)
	       {
		   GLOBUS_L_GASS_CACHE_LG("Tag Not found");

		   /* the tag was not found. Now, we are pointing one
		   the first empty tag entry allocated for tag
		   creation. Lets create it */
		   tag_pt->tag = (char *) globus_malloc(strlen(tag) +1);
		   if (tag_pt->tag == GLOBUS_NULL)
		   {
		       CACHE_TRACE("No more memory");
		       globus_l_gass_cache_unlock_close(
			   cache_handle,
			   GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		       
		       return(GLOBUS_GASS_CACHE_ERROR_NO_MEMORY);
		   }
		   strcpy(tag_pt->tag, tag);
		   tag_pt->count=1;
		   entry_found_pt->num_tags++;
		   
	       } /* tag not found */
	       
	       /* tag added; now lock the cache entry */
	       entry_found_pt->lock_tag= (char *) globus_malloc(strlen(tag)+1);
	       if ( entry_found_pt->lock_tag == GLOBUS_NULL)
	       {
		   CACHE_TRACE("No more memory");
		   globus_l_gass_cache_entry_free(&entry_found_pt,
						  GLOBUS_TRUE);
		   globus_l_gass_cache_unlock_close(cache_handle,
						    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return(GLOBUS_GASS_CACHE_ERROR_NO_MEMORY);
	       }
	       strcpy( entry_found_pt->lock_tag, tag);
	       
	       /* prepare to lock the datafile */
	       /* do it before I write the state file */
	       /* wich also free entry_found_pt */
	       strcpy(notready_file_path,
		      entry_found_pt->filename);
	       
	       strcat(notready_file_path,
		      GLOBUS_L_GASS_CACHE_EXT_NOTREADY);
	       
	       /* Write this url entry  */
	       rc = globus_l_gass_cache_write_state_file(entry_found_pt,
							 cache_handle);
	       if (rc != GLOBUS_SUCCESS)
	       {
		   globus_l_gass_cache_unlock_close(cache_handle,
						    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return(rc);
	       }
	       
	       /* New tag added, therefor */
	       /* lock the cache entry (set the file as not ready ) */
	       if ((tmp_fd = creat(notready_file_path, 
                                   GLOBUS_L_GASS_CACHE_STATE_MODE)) == -1 )
	       {
		   CACHE_TRACE("Could not create new data file lock");
		   globus_l_gass_cache_unlock_close(cache_handle,
                                                    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE_DATA_F);
	       }
               close(tmp_fd);
	       
	       /* release lock */
	       rc = globus_l_gass_cache_unlock_close(
		   cache_handle,
		   GLOBUS_L_GASS_CACHE_COMMIT);
	       if (rc != GLOBUS_SUCCESS)
	       {
		   return(rc);
	       }
	       
	       /* and return */
	       GLOBUS_L_GASS_CACHE_LG3("Url %s with tag %s ADDed",url, tag);
	       return(GLOBUS_GASS_CACHE_ADD_EXISTS);
	       
	   } /* file ready */
       } /* url found */
   } /* while recurs */
}
/*  globus_gass_cache_add() */

    
/*
 * globus_gass_cache_add_done()
 *
 * globus_gass_cache_add_done() MUST be called after globus_gass_cache_add(),
 * to set the timestamp in the cache entry for the URL, and then unlock the
 * cache entry. (The only case it does not need to be called is if
 * globus_gass_cache_add() has returned GLOBUS_GASS_CACHE_URL_NOT_FOUND, of
 * course.
 * 
 * Parameters:    
 *     cache_handle - Handler to the opened cahe directory to use.
 *
 *     url - url of the cached file to set as "done" (unlock)
 *     tag - tag specifying which job has locked the cache and must
 *     therfor be unlocked.It is an error to call this function
 *     with a tag which does not currently own the cache lock.
 *     timestamp: time stamp of the cached file.
 *	
 *
 * Returns:
 *     GLOBUS_SUCCESS or error code:
 *     or any of the defined gass error code.
 */
int
globus_gass_cache_add_done(
    globus_gass_cache_t *cache_handle,
    char                *url,
    char                *tag,
    unsigned long        timestamp)
{
    int                        rc;   /* general purpose return code */
    char                       notready_file_path[PATH_MAX+1];
    globus_gass_cache_entry_t *entry_found_pt;


    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT();
    
    rc = globus_l_gass_cache_lock_open(cache_handle);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }  
    rc = globus_l_gass_cache_lookfor_url(&entry_found_pt,
					 url,
					 cache_handle);
    if (rc != GLOBUS_SUCCESS)
    {
	globus_l_gass_cache_unlock_close(cache_handle,
					 GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	return(rc);
    }
    
    if (entry_found_pt == GLOBUS_NULL)   /* url not found */
    {
	GLOBUS_L_GASS_CACHE_LG("Function globus_gass_cache_add_done() "
			       "called with URL not in cache state file");
	globus_l_gass_cache_unlock_close(cache_handle,
					 GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	return(GLOBUS_GASS_CACHE_ERROR_URL_NOT_FOUND);
    }
    else
    { /* URL found */
	
	if ( entry_found_pt->lock_tag == GLOBUS_NULL)
	{
	    GLOBUS_L_GASS_CACHE_LG("Cache file already Done");
	    globus_l_gass_cache_unlock_close(cache_handle,
					     GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	    return(GLOBUS_GASS_CACHE_ERROR_ALREADY_DONE);
	}
	if (tag == GLOBUS_NULL)
	{
	    tag=GLOBUS_L_GASS_CACHE_NULL_TAG;
	}
	if ( strcmp(entry_found_pt->lock_tag,tag))
	{
	    /* wrong tag */
	    GLOBUS_L_GASS_CACHE_LG("Function globus_gass_cache_add_done() called with wrong tag");
	   globus_l_gass_cache_unlock_close(cache_handle,
					    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	   return(GLOBUS_GASS_CACHE_ERROR_WRONG_TAG);
	}
	
	/* set the file as ready and copy the timestamp *//* ??? */
	globus_free(entry_found_pt->lock_tag);
	entry_found_pt->lock_tag= GLOBUS_NULL; 
	entry_found_pt->timestamp=timestamp;


	/* prepare to unlock the datafile */
	/* do it before I write the state file */
	/* wich also free entry_found_pt */
	strcpy(notready_file_path,
	       entry_found_pt->filename);
        strcat(notready_file_path,
	       GLOBUS_L_GASS_CACHE_EXT_NOTREADY);
	
	/* update the state file */
	rc= globus_l_gass_cache_write_state_file(entry_found_pt,
						 cache_handle);
	if (rc != GLOBUS_SUCCESS)
	{
	    globus_l_gass_cache_unlock_close(cache_handle,
					     GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	    return(rc);
	}
	
	/* then unlock the process waiting on the data file to be ready      */
        if ( unlink(notready_file_path) )
	{
	    CACHE_TRACE("Could not delete data file lock");
	    globus_l_gass_cache_unlock_close(cache_handle,
					     GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	    return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_DEL_LOCK);
	}
	
	/* and realease the data file */
	rc = globus_l_gass_cache_unlock_close(cache_handle,
					      GLOBUS_L_GASS_CACHE_COMMIT);
	return(rc);
    }
}
/* globus_gass_cache_add_done() */


/*
 * globus_gass_cache_delete_start()
 *
 *
 * Lock the cache entry for the URL, and return the cache entry's current
 * timestamp in *timestamp.
 * This function will block if the data file is already locked, until it is
 * unlocked.
 *
 * Parameters:     
 *
 *     cache_handle - Handler to the opened cahe directory to use.
 *
 *     url - url of the cached file to set as "done" (unlock)
 *
 *     tag - tag specifying which job has locked the cache and must
 *     therfor be unlocked.It is an error to call this function
 *     with a tag which does not currently own the cache lock.
 *	
 *     timestamp - time stamp of the cached file, set by
 *     globus_gass_cache_done(), (or globus_gass_cache_delete() ).
 *
 * Returns:
 *     GLOBUS_SUCCESS or error code:
 *     or any of the defined gass error code.
 *
 */
int
globus_gass_cache_delete_start(globus_gass_cache_t *cache_handle,
			       char                *url,
			       char                *tag,
			       unsigned long       *timestamp)
{
    int                        rc; /* general purpose return code */
    globus_gass_cache_entry_t *entry_found_pt;
    char                       notready_file_path[PATH_MAX+1];
    struct stat                file_stat;
    globus_gass_cache_tag_t   *tag_pt;
    int                        tmp_fd;
    int count =0;
        
    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT();

    /* if no tag supplied, we map it to the tag
       GLOBUS_L_GASS_CACHE_NULL_TAG ("null")*/
    if (tag == GLOBUS_NULL)
    {
       tag=GLOBUS_L_GASS_CACHE_NULL_TAG;
    }
    
    /* I want to do every thing again and again until the data file is
       ready */
   while (GLOBUS_TRUE)
   {
       rc = globus_l_gass_cache_lock_open(cache_handle);
       if (rc != GLOBUS_SUCCESS)
       {
	   return(rc);
       }
       
       rc = globus_l_gass_cache_lookfor_url(&entry_found_pt,
					    url,
					    cache_handle);
       if (rc != GLOBUS_SUCCESS)
       {
	   globus_l_gass_cache_unlock_close(cache_handle,
					    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	   return(rc);
       }
       
       if (entry_found_pt == GLOBUS_NULL)   /* url not found */
       {
	   GLOBUS_L_GASS_CACHE_LG("Function "
				  "globus_gass_cache_delete_start() "
				  "called with URL not in cache state file");
	   globus_l_gass_cache_unlock_close(cache_handle,
					    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	   return(GLOBUS_GASS_CACHE_ERROR_URL_NOT_FOUND);
       }
       else
       { /* URL found */
	   GLOBUS_L_GASS_CACHE_LG("URL found");

	   /* new with 1.1 */      
	   if (entry_found_pt->pending == 'P' &&
	       count < 10  &&
	       entry_found_pt->lock_tag == GLOBUS_NULL)
	   {
	       /*  I wait               */
	       GLOBUS_L_GASS_CACHE_LG("Some add Pending on this url: wait");
	       
	       rc = globus_l_gass_cache_write_state_file(entry_found_pt,
							 cache_handle);
	       if (rc != GLOBUS_SUCCESS)
	       {
		   globus_l_gass_cache_unlock_close(cache_handle,
						    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return(rc);
	       }
	       rc = globus_l_gass_cache_unlock_close(cache_handle,
						     GLOBUS_L_GASS_CACHE_COMMIT);
	       if (rc != GLOBUS_SUCCESS)
	       {
		   return(rc);
	       }
	       
	       count++;
	       globus_libc_usleep(LOOP_TIME);
	       continue;
	       
	   }
	   
	   if (entry_found_pt->lock_tag != GLOBUS_NULL)   
	   {			/* data file not ready */

	       GLOBUS_L_GASS_CACHE_LG("Data file not ready: wait");
	       
	       strcpy(notready_file_path,
		      entry_found_pt->filename);
	       strcat(notready_file_path,
		      GLOBUS_L_GASS_CACHE_EXT_NOTREADY);
	       
	       /* just check coherence between state file and blocking file */
	       if ( stat(notready_file_path, &file_stat) == -1 )
	       {
		   GLOBUS_L_GASS_CACHE_LG("State file and bloking file "
					  "are not coherent");
		   globus_l_gass_cache_unlock_close(cache_handle,
						    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
		
	       }
	       
	       rc = globus_l_gass_cache_write_state_file(entry_found_pt,
							 cache_handle);
	       if (rc != GLOBUS_SUCCESS)
	       {
		   globus_l_gass_cache_unlock_close(cache_handle,
						    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return(rc);
	       }
	       rc = globus_l_gass_cache_unlock_close(
		   cache_handle,
		   GLOBUS_L_GASS_CACHE_COMMIT);
	       
	       if (rc != GLOBUS_SUCCESS)
	       {
		   return(rc);
	       }

	       /* wait */
	       rc = stat(notready_file_path, &file_stat);
	       while ( rc != -1 )
	       {
		   globus_libc_usleep(LOOP_TIME);
		   rc = stat(notready_file_path, &file_stat);
	       }
	       GLOBUS_L_GASS_CACHE_LG("Data file now ready: continue/call recursivelly");
	       continue;
	   }
	   else  /* file ready */
	   {
	       GLOBUS_L_GASS_CACHE_LG("Data file ready...");
	       
	       /* return the timestamp */
	       *timestamp=entry_found_pt->timestamp;
	       
	       /* look for the tag */
	       tag_pt = entry_found_pt->tags;
	       while (tag_pt->tag != GLOBUS_NULL)
	       {
		   if ( !strcmp(tag_pt->tag, tag))
		   {
		       /* tag found */
		       break;
		   }
		   tag_pt++;
	       }
	       if (tag_pt->tag == GLOBUS_NULL)
	       {
		   GLOBUS_L_GASS_CACHE_LG("Function "
					  "globus_gass_cache_delete_start() "
					  "called with unknown tag");
		   globus_l_gass_cache_unlock_close(cache_handle,
						    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return( GLOBUS_GASS_CACHE_ERROR_WRONG_TAG);
	       } /* tag not found */
	       
	       /* tag found; now lock the cache entry */
	       entry_found_pt->lock_tag= (char *) globus_malloc(strlen(tag)+1);
	       if ( entry_found_pt->lock_tag == GLOBUS_NULL)
	       {
		   CACHE_TRACE("No more memory");
		   globus_l_gass_cache_entry_free(&entry_found_pt,
						  GLOBUS_TRUE);
		   globus_l_gass_cache_unlock_close(cache_handle,
						    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return(GLOBUS_GASS_CACHE_ERROR_NO_MEMORY);
	       }
	       strcpy( entry_found_pt->lock_tag, tag);
	       
	       /* prepare to unlock the datafile */
	       /* do it before I write the state file */
	       /* wich also free entry_found_pt */
	       strcpy(notready_file_path,
		      entry_found_pt->filename);
	       strcat(notready_file_path,
		      GLOBUS_L_GASS_CACHE_EXT_NOTREADY);
	       
	       /* Write this url entry  */
	       rc = globus_l_gass_cache_write_state_file(entry_found_pt,
							 cache_handle);
	       if (rc != GLOBUS_SUCCESS)
	       {
		   globus_l_gass_cache_unlock_close(cache_handle,
						    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return(rc);
	       }
	       
	       /* lock the cache entry */
	       if ((tmp_fd = creat(notready_file_path, 
                                   GLOBUS_L_GASS_CACHE_STATE_MODE)) == -1 )
	       {
		   CACHE_TRACE("Could not create new data file lock");
		   globus_l_gass_cache_unlock_close(cache_handle,
						    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE_DATA_F);
	       }   
               close(tmp_fd);

	       /* release lock */
	       rc = globus_l_gass_cache_unlock_close(
		   cache_handle,
		   GLOBUS_L_GASS_CACHE_COMMIT);
	       /* and return */
	       return(rc);
	   }
       } /* file ready */
   } /* while recurs */    
}
/* globus_gass_cache_delete_start() */
/*
 * globus_gass_cache_delete()
 *
 * Remove one instance of the tag from the cache entry's tag list.
 *
 * If there are no more tags in the tag list, then remove this cache
 * entry and delete the associated local cache file.
 *
 * Otherwise, update the timestamp to the passed value.
 *    
 * This call will leave the cache entry unlocked.
 *
 * If is_locked==GLOBUS_TRUE, then this cache entry was locked during a
 * previous call to globus_gass_cache_add() or
 * globus_gass_cache_delete_start(). The cache
 * file should be locked by the corresponding url/tag, or an error is
 * returned. If it is locked by the corresponding url/tag, then the normal
 * operation occur, whithout blocking (remove one instance from the tag
 * update the timestamp and unlock the cache).
 *
 * If is_locked==GLOBUS_FALSE, eventually wait the cache is not locked any
 * more, and then proceed with the normal operations.(remove one instance
 * from the tag list and update the timestamp).
 *
 * Parameters:  
 *      cache_handle - Handler to the opened cahe directory to use.
 *
 *	url - url of the file to be cached. It is used as the main
 *	key to the cache entries.
 *
 *	tag - tag specifying which job is/are using the cache. This
 *      is usually the GLOBUS_GRAM_JOB_CONTACT. Can be NULL or empty; the
 *	tag "null" is then used.
 *
 *	timestamp - time stamp of the cached file.
 *
 *      is_locked - indicate if this cache entry was locked during a
 *	previous call to globus_gass_cache_add() or
 *	globus_gass_cache_delete_start().
 * 
 *		
 * Returns:
 *      GLOBUS_SUCCESS or error code:
 *      or any of the defined gass error code.   
 */
int
globus_gass_cache_delete(
    globus_gass_cache_t *cache_handle,
    char                *url,
    char                *tag,
    unsigned long        timestamp,
    globus_bool_t        is_locked)
{ 
    int                        rc; /* general purpose return code */
    globus_gass_cache_entry_t *entry_found_pt;
    char                       notready_file_path[PATH_MAX+1];
    struct stat                file_stat;
    globus_gass_cache_tag_t   *tag_pt;
    int                        same_tag;
    int count =0;

    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT();

    /* if no tag supplied, we map it to the tag GLOBUS_L_GASS_CACHE_NULL_TAG ("null")*/
    if (tag == GLOBUS_NULL)
    {
	tag=GLOBUS_L_GASS_CACHE_NULL_TAG;
    }
    
/* I want to do every thing again and again until the data file */
/* is ready */
   while (GLOBUS_TRUE)
   {
       rc = globus_l_gass_cache_lock_open(cache_handle);
       if (rc != GLOBUS_SUCCESS)
       {
	   return(rc);
       }
    
       rc = globus_l_gass_cache_lookfor_url(&entry_found_pt,
					    url,
					    cache_handle);
       if (rc != GLOBUS_SUCCESS)
       {
	   globus_l_gass_cache_unlock_close(cache_handle,
					    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	   return(rc);
       }
    
       if (entry_found_pt == GLOBUS_NULL)   /* url not found */
       {
	   GLOBUS_L_GASS_CACHE_LG("Function globus_gass_cache_delete() "
				  "called with  URL not in cache state file");
	   globus_l_gass_cache_unlock_close(cache_handle,
					    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	   return(GLOBUS_GASS_CACHE_ERROR_URL_NOT_FOUND);
       }
    
       /* URL found */
       GLOBUS_L_GASS_CACHE_LG("URL found");
    
       /* new with 1.1 */      
       if (entry_found_pt->pending == 'P' &&
	   count < 10  &&
	   entry_found_pt->lock_tag == GLOBUS_NULL)
       {
	   /*  I wait               */
	   GLOBUS_L_GASS_CACHE_LG("Some add Pending on this url: wait");

	   rc = globus_l_gass_cache_write_state_file(entry_found_pt,
						     cache_handle);
	   if (rc != GLOBUS_SUCCESS)
	   {
	       globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	       return(rc);
	   }
	   rc = globus_l_gass_cache_unlock_close(cache_handle,
						 GLOBUS_L_GASS_CACHE_COMMIT);
	   if (rc != GLOBUS_SUCCESS)
	   {
	       return(rc);
	   }
	   

	   count++;
	   globus_libc_usleep(LOOP_TIME);
	   continue;
	   
       } 
       
       
       if ((entry_found_pt->lock_tag != GLOBUS_NULL) )
       {			/* if file locked and */
	   same_tag = !strcmp(entry_found_pt->lock_tag, tag);
	   if ( !same_tag ||	/* Not by me (tag !=) or */
		( same_tag && !is_locked) /* might be me (tag ==)  */
				/* but I did not do it   */
	       )
	   {			/*  I wait               */
	       GLOBUS_L_GASS_CACHE_LG("Data file not ready: wait");
	    
	       strcpy(notready_file_path,
		      entry_found_pt->filename);
	       strcat(notready_file_path,
		      GLOBUS_L_GASS_CACHE_EXT_NOTREADY);
	    
	       /* just check coherence between state file and blocking file */
	       if ( stat(notready_file_path, &file_stat) == -1 )
	       {
		   GLOBUS_L_GASS_CACHE_LG("State file and blocking file "
					  "are not coherent");
		   globus_l_gass_cache_unlock_close(cache_handle,
						    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
		
	       }
	    
	       rc = globus_l_gass_cache_write_state_file(entry_found_pt,
							 cache_handle);
	       if (rc != GLOBUS_SUCCESS)
	       {
		   globus_l_gass_cache_unlock_close(cache_handle,
						    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		   return(rc);
	       }
	       rc = globus_l_gass_cache_unlock_close(cache_handle,
						     GLOBUS_L_GASS_CACHE_COMMIT);
	       if (rc != GLOBUS_SUCCESS)
	       {
		   return(rc);
	       }
	    

	       /* wait */
	       rc = stat(notready_file_path,
			 &file_stat);
	       while ( rc != -1 )
	       {
		   globus_libc_usleep(LOOP_TIME);
		   rc = stat(notready_file_path,
			     &file_stat);
	       }
	       GLOBUS_L_GASS_CACHE_LG("Data file now ready: continue/call recursivelly");
	       continue;
	   } 
       }       /* file ready or I did lockit*/
    
       /* look for the tag */
       tag_pt = entry_found_pt->tags;
       while (tag_pt->tag != GLOBUS_NULL)
       {
	   if ( !strcmp(tag_pt->tag, tag))
	   {
	       /* tag found */
	       break;
	   }
	   tag_pt++;
       }
       if (tag_pt->tag == GLOBUS_NULL)
       {
	   GLOBUS_L_GASS_CACHE_LG("Function globus_gass_cache_delete() "
				  "called with unknown tag");
	   globus_l_gass_cache_unlock_close(cache_handle,
					    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	   return( GLOBUS_GASS_CACHE_ERROR_WRONG_TAG);
       } /* tag not found */
    
       /* tag found; Here, either it is not locked, or it was locked
	  with the same tag : Unlock the file and Remove the tag
	  set the file as ready and copy the timestamp */
       
       if (entry_found_pt->lock_tag != GLOBUS_NULL)
       {
	   globus_free(entry_found_pt->lock_tag);
	   entry_found_pt->lock_tag= GLOBUS_NULL; 
	   /* Unlock the cache entry */
	   strcpy(notready_file_path,
		  entry_found_pt->filename);
	   
	   strcat(notready_file_path,
		  GLOBUS_L_GASS_CACHE_EXT_NOTREADY);
	   
	   if ( unlink(notready_file_path) )
	   {
	       CACHE_TRACE("Could not delete data file lock");
	       globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	       return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_DEL_LOCK);
	   }
       }
    
       entry_found_pt->timestamp=timestamp;
    
       /* remove the tag */
       tag_pt->count--;
       if (!tag_pt->count)   /* no tag left */ 
       {
	   globus_free(tag_pt->tag);
	   tag_pt->tag= GLOBUS_NULL;
	   entry_found_pt->num_tags--;
       }
    
       if (entry_found_pt->num_tags)    /* some more tag */
       {
	   /* I do write the last entry */
	   rc = globus_l_gass_cache_write_state_file(entry_found_pt,
						     cache_handle);
	   if (rc != GLOBUS_SUCCESS)
	   {
	       globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	       return(rc);
	   }
       }
       else
       {
	   cache_handle->nb_entries--;
	   /* else, if no more tag at all, I do not write this entry */
	   /* and I remove the data file */
	   if ( unlink(entry_found_pt->filename) )
	   {
	       CACHE_TRACE("Could not delete data file");
	       /* remove the entry anyway... we might have a zomby */
	       /* data file */
	       globus_l_gass_cache_entry_free(&entry_found_pt,
					      GLOBUS_TRUE);
	       globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_COMMIT);
	       return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_DEL_LOCK);
	   }
	   /* since we do not write it, lets free the entry here */
	   globus_l_gass_cache_entry_free(&entry_found_pt,
					  GLOBUS_TRUE);
       }
    
       /* release lock */
       rc = globus_l_gass_cache_unlock_close(cache_handle,
					     GLOBUS_L_GASS_CACHE_COMMIT);
       /* and return */
       return(rc);
   } /* while recurs */
}
/* globus_gass_cache_delete() */

/*
 * globus_gass_cache_cleanup_tag()
 *
 * Remove all instances of the tag from the cache entry's tag list.
 * If there are no more tags in the tag list, then remove this cache entry
 * and delete the associated local cache file.
 * If the cache entry is locked with the same tag as is passed to this
 * function, then the entry is unlocked after removing the tags.
 * Otherwise, the cache entry's lock is left untouched.
 *
 * This function does not block on a locked reference. 
 *
 * Note: The GLOBUS_GRAM job manager will automatically call this function
 * with a tag of getenv("GLOBUS_GRAM_JOB_CONTACT") upon completion of a job.
 *
 * Parameters:
 *
 *     cache_handle - Handler to the opened cahe directory to use.
 *
 *     url - url of the file to be cached. It is used as the main
 *     key to the cache entries.
 *
 *     tag - tag specifying which job is/are using the cache. This
 *     is usually the GLOBUS_GRAM_JOB_CONTACT. Can be NULL or empty; the
 *     tag "null" is then used.
 *
 *
 * Returns:
 *     GLOBUS_SUCCESS or error code:
 *     or any of the defined gass error code.   
 */
int
globus_gass_cache_cleanup_tag(
    globus_gass_cache_t *cache_handle,
    char                *url,
    char                *tag)
{
    int                        rc; /* general purpose return code */
    globus_gass_cache_entry_t *entry_found_pt;
    char                       notready_file_path[PATH_MAX+1];
    globus_gass_cache_tag_t   *tag_pt;
    int                        same_tag;

    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT();

    /* if no tag supplied, we map it to the tag
       GLOBUS_L_GASS_CACHE_NULL_TAG ("null")*/
   if (tag == GLOBUS_NULL)
   {
       tag=GLOBUS_L_GASS_CACHE_NULL_TAG;
   }
   
   rc = globus_l_gass_cache_lock_open(cache_handle);
   if (rc != GLOBUS_SUCCESS)
   {
       return(rc);
   }

   rc = globus_l_gass_cache_lookfor_url(&entry_found_pt,
					url,
					cache_handle);
   if (rc != GLOBUS_SUCCESS)
   {
       globus_l_gass_cache_unlock_close(cache_handle,
					GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
       return(rc);
   }

   if (entry_found_pt == GLOBUS_NULL)   /* url not found */
   {
       GLOBUS_L_GASS_CACHE_LG("Function globus_gass_cache_cleanup_tag() called with  URL not in cache state file");
       globus_l_gass_cache_unlock_close(cache_handle,
					GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
       return(GLOBUS_GASS_CACHE_ERROR_URL_NOT_FOUND);
   }
   /* URL found */
   GLOBUS_L_GASS_CACHE_LG("URL found");

   /* look for the tag */
   tag_pt = entry_found_pt->tags;
   while (tag_pt->tag != GLOBUS_NULL)  /* Note : Here I can use while        */
   /* because I know there is no hole in the tag array (just read from file) */
   {
       if ( !strcmp(tag_pt->tag, tag))
       {
	   /* tag found */
	   globus_free(tag_pt->tag);
	   tag_pt->tag= GLOBUS_NULL;
	   tag_pt->count=0;
	   entry_found_pt->num_tags--;
	   break;
       }
       tag_pt++;
   }

   /* no check if tag was not existing... */

   

   if ( entry_found_pt->lock_tag != GLOBUS_NULL ) /* file locked */
   {
       same_tag = !strcmp(entry_found_pt->lock_tag, tag);
       /* if locked with the same tag or if there is no more tag left
       at all Note that it should not happen that the file is locked
       with a not existing tag. But then we clean every thing any way */
       if (same_tag || !entry_found_pt->num_tags) 
       {
	   /* locked with the tag to be cleaned up : remove lock */
	   globus_free(entry_found_pt->lock_tag);
	   entry_found_pt->lock_tag= GLOBUS_NULL; 
	   /* Unlock the cache entry */
           strcpy(notready_file_path,entry_found_pt->filename);
           strcat(notready_file_path,GLOBUS_L_GASS_CACHE_EXT_NOTREADY);
           if ( unlink(notready_file_path) )
	   {
	       CACHE_TRACE("Could not delete data file lock, "
			   "but continue cleanup");
	       /* weel, since this is a clean up, lets try to clean up
		  any way and not abort/return an error here... */
	   }
       } /* same tag */
   } /* file locked */

   if (entry_found_pt->num_tags) /* some other tag */
   {
       /* I do write the last entry */
       rc = globus_l_gass_cache_write_state_file(entry_found_pt,
						 cache_handle);
       if (rc != GLOBUS_SUCCESS)
       {
	   globus_l_gass_cache_unlock_close(cache_handle,
					    GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	   return(rc);
       } 
   }
   else
   {
       cache_handle->nb_entries--;
       /* else, if no more tag at all, I do not write this entry */
       /* and I remove the data file */
       if ( unlink(entry_found_pt->filename) )
       {
	   CACHE_TRACE("Could not delete data file, clean up anyway...");
	   globus_l_gass_cache_unlock_close(cache_handle,
					    GLOBUS_L_GASS_CACHE_COMMIT);
	   return(GLOBUS_GASS_CACHE_ERROR_CAN_NOT_DELETE_DATA_F);
       }
       /* since we did not write it, lets free the entry here */
       globus_l_gass_cache_entry_free(&entry_found_pt,
				      GLOBUS_TRUE);
   } /* no more tag at all */
   
   /* release lock */
   rc = globus_l_gass_cache_unlock_close(cache_handle,
					 GLOBUS_L_GASS_CACHE_COMMIT);
   /* and return */
   return(rc);
    
}
/*globus_gass_cache_add_cleanup_tag() */


/*
 * Function: globus_gass_cache_cleanup_file()
 * 
 * Description:
 * Remove the cache entry and delete the associated local cache file,
 * regardless of the tags in tag list, and regardless of whether or not
 * the cache entry is locked.
 * 
 * This function does not block on a locked reference.
 *     
 * Parameters:   
 *      cache_handle - Handler to the opened cahe directory to use.
 *
 * 	url - url of the file to be cached. It is used as the main
 * 	key to the cache entries.
 *  		
 * Returns:
 *      GLOBUS_SUCCESS or error code:
 *      or any of the defined gass error code.   
 */
int
globus_gass_cache_cleanup_file(
    globus_gass_cache_t *cache_handle,
    char                *url)
{
    int                        rc; /* general purpose return code */
    globus_gass_cache_entry_t *entry_found_pt;
    char                       notready_file_path[PATH_MAX+1];

    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT();

    rc = globus_l_gass_cache_lock_open(cache_handle);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }
    
    rc = globus_l_gass_cache_lookfor_url(&entry_found_pt,
					 url,
					 cache_handle);
    if (rc != GLOBUS_SUCCESS)
    {
	globus_l_gass_cache_unlock_close(cache_handle,
					 GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	return(rc);
    }
    
    if (entry_found_pt == GLOBUS_NULL)   /* url not found */
    {
	GLOBUS_L_GASS_CACHE_LG("Function globus_gass_cache_cleanup_file() "
			       "called with  URL not in cache state file");
	globus_l_gass_cache_unlock_close(cache_handle,
					 GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	return(GLOBUS_GASS_CACHE_ERROR_URL_NOT_FOUND);
    }
    /* URL found */
    GLOBUS_L_GASS_CACHE_LG("URL found");
    
    
    /* delete the cache file */
    if ( unlink(entry_found_pt->filename) )
    {
       CACHE_TRACE("Could not delete data file, but continue cleanup");
    }
    /* decrease the number of entries */
    cache_handle->nb_entries--;
    
    /* remove the lock */
    if (entry_found_pt->lock_tag != NULL)
    {
        strcpy(notready_file_path,
	       entry_found_pt->filename);
        strcat(notready_file_path,
	       GLOBUS_L_GASS_CACHE_EXT_NOTREADY);
        if ( unlink(notready_file_path) )
	{
	    CACHE_TRACE("Could not delete data file lock, "
			"but continue cleanup");
	}
   }
    
    /* do not write the last entry, in order to delete it */
    /* since we do not write it, lets free the entry here */
    globus_l_gass_cache_entry_free(&entry_found_pt,
				   GLOBUS_TRUE);
    /* release lock */
    rc = globus_l_gass_cache_unlock_close(cache_handle,
					  GLOBUS_L_GASS_CACHE_COMMIT);
    /* and return */
    return(rc);
    
}
/*globus_gass_cache_add_cleanup_file() */

/*
 * globus_gass_cache_add_list()
 *
 * Return the entries of the cache in *entries as an array of
 * globus_gass_cache_entry_t structures, and return the number of elements in
 * this array in *size.
 *
 * The function globus_gass_cache_list_free() must be called subsequently to
 * free the entrie array allocated by globus_gass_cache_list();
 *
 * Parameters:
 *
 *     cache_handle - Handler to the opened cahe directory to use.
 *
 *     entries - array of globus_gass_cache_entry_t structure describing
 *     eache cache entry.
 *		
 *     size - size of the "entries" array, (nb of entries)
 *		
 * Returns:
 *		
 *      GLOBUS_SUCCESS 
 *	or any of the defined gass error code.      
 */
int
globus_gass_cache_list(
    globus_gass_cache_t        *cache_handle,
    globus_gass_cache_entry_t **entries,
    int                        *size)
{
    int      rc;		/* general purpose return code */
    char     size_s[GLOBUS_L_GASS_CACHE_L_LENGHT+1];
    char     entry_separator[2]; /* eache entry is preceded by   */
				 /* a line containing #\n or *\n */
    int      i;
    
    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT();

    
    rc = globus_l_gass_cache_lock_open(cache_handle);
    if (rc != GLOBUS_SUCCESS)
    {
	return(rc);
    }

    /* lets read the number of entries at the end of the file I must
    rewind LENGHT_LENGH for the nb_entries, +1 for the \n and + 2 for
    the "*\n" preceding the nb_entries, = LENGHT_LENGH+3 */
    lseek(cache_handle->state_file_fd,
	  -(GLOBUS_L_GASS_CACHE_L_LENGHT+3),
	  SEEK_END);
    
    while (read( cache_handle->state_file_fd,
		  entry_separator,
		  sizeof(entry_separator))
	    != sizeof(entry_separator))
    {
	/* file empty, probably */
	if (errno == EINTR)
	{
	    continue;
	}
	*entries = NULL;
	*size = 0;
	return(globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT));
    }
    if (entry_separator[0] != '*')
    {
	CACHE_TRACE("Error reading state file");
	globus_l_gass_cache_unlock_close(cache_handle,
					 GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
    }
    while ( read(cache_handle->state_file_fd,
		 size_s,sizeof(size_s)) != sizeof(size_s) )
    {
	if (errno != EINTR)
	{
	    CACHE_TRACE("Error reading state file");
	    globus_l_gass_cache_unlock_close(cache_handle,
					     GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	    return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
	}
    }
    size_s[GLOBUS_L_GASS_CACHE_L_LENGHT]='\0'; /* replace \n with \0 */
    *size = atoi(size_s);

    if ( *size == 0)
    {
	/* No entries, job finished */
	*entries =GLOBUS_NULL;
	return(globus_l_gass_cache_unlock_close(cache_handle,
						GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT));
    }
    
    *entries = (globus_gass_cache_entry_t *)
	globus_malloc( (*size) *  sizeof(globus_gass_cache_entry_t));
    if (*entries == GLOBUS_NULL)
    {
	CACHE_TRACE("No more memory");
	globus_l_gass_cache_unlock_close(cache_handle,
					 GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	return(GLOBUS_GASS_CACHE_ERROR_NO_MEMORY);
    }

    /* scan the file */
    lseek(cache_handle->state_file_fd,
	  COMMENT_LENGHT,
	  SEEK_SET);

    for (i=0; i<*size; i++)
    {
	globus_gass_cache_entry_t * entry_pt;

	while ( read( cache_handle->state_file_fd,
			    entry_separator,
			    sizeof(entry_separator))
		      != sizeof(entry_separator) )
	{
	    if (errno != EINTR)
		{
		    CACHE_TRACE("Error reading state file");
		    globus_l_gass_cache_unlock_close(
			cache_handle,
			GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
		    return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
		}
	}
	if (entry_separator[0] != '#' ) 
	{
	    CACHE_TRACE("Error reading state file");
	    globus_l_gass_cache_unlock_close(cache_handle,
					     GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	    return(GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT);
	}
	entry_pt =  *entries+i;
	rc = globus_l_gass_cache_read_one_entry(cache_handle->state_file_fd,
						&entry_pt);
	if (rc != GLOBUS_SUCCESS)
	{
	    globus_l_gass_cache_unlock_close(cache_handle,
					     GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
	    return (rc);
	}
    }
    /* here I could verify the number of entries... */
    
    /* release lock; But I do NOT want to update the file */

    /* I do not free the memory allocated by each read: the user must */
    /* call gass-cache_list_free() */
    rc = globus_l_gass_cache_unlock_close(cache_handle,
					  GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT);
    /* and return */
    return(rc);
    
}
/* globus_gass_cache_list() */

/*
 * globus_gass_cache_list_free()
 *
 * Free the cache entries previously returned by globus_gass_cache_list().
 *
 * Parameters:
 *
 *     entries - array of globus_gass_cache_entry_t structure describing
 *     eache cache entry.
 *
 *     size - size of the "entries" array, (nb of entries)
 *
 * Returns:
 *     GLOBUS_SUCCESS
 *
 */
int 
globus_gass_cache_list_free(
    globus_gass_cache_entry_t *entries,
    int                        size)
{
    int i;
    globus_gass_cache_entry_t *an_entry_pt;
    
    for (i=size-1; i>=0 ; i--)
    {
	an_entry_pt=entries+i;
	
        globus_l_gass_cache_entry_free(&an_entry_pt,GLOBUS_FALSE);
    }
    globus_free(entries);

    return(GLOBUS_SUCCESS);
} /* globus_gass_cache_add_list_free() */


/*
 * globus_gass_cache_error_string()
 *
 * Return a pointer on an error description string.
 *
 *Parameters: 
 *     error_code: error code returned by a previously called
 *     globus_gass_cache function.
 *	    
 * Returns:
 *     Pointer to an error message, or NULL if invalide error code.
 */
const
char *
globus_gass_cache_error_string(
    int error_code)
{
    if (error_code > 0 ||
	-error_code >=
	(sizeof(globus_gass_cache_error_strings) /
	 sizeof(globus_gass_cache_error_strings[0])))
    {
        return("Invalid error code");
    }
    return(globus_gass_cache_error_strings[-error_code]);
}
/* globus_gass_cache_error_string() */


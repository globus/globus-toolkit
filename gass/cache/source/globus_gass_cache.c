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
#include <utime.h>
#include <sys/types.h>
#include <ctype.h>

#include "openssl/md5.h"

/* #define DEBUG				0 */
/* #define GLOBUS_L_GASS_CACHE_LOG 	0 */
#include "globus_i_gass_cache.h"
#include "globus_gass_cache.h"
#include "version.h"

/* Lock existing files when returning ADD_EXISTS? */
#define LOCK_ADD_EXISTS			1

/* RedHat 6.2 (2.2.19 kernel) appears to have a bug in rename */
/* See the code for more details */
#define GLOBUS_L_GASS_CACHE_RENAMEBUG	1

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

/* Local error to return; never returned to the application */
#define GLOBUS_L_EOTHER		-100	/* Unknown error */
#define GLOBUS_L_ENOENT		-101	/* Does not exist */
#define GLOBUS_L_EEXISTS	-102	/* Does exist */
#define GLOBUS_L_ENODATA	-103	/* No data file */
#define GLOBUS_L_ENOTDIR	-104	/* Not a directory */
#define GLOBUS_L_ENOTUNIQ	-105	/* Not the first */
#define GLOBUS_L_UNLINK_LAST	-106	/* Last file unlinked */
#define GLOBUS_L_READY_MYPROC	-107	/* Data prev. ready for this PID */
#define GLOBUS_L_READY_OTHER	-108	/* Data ready from another process */
#define GLOBUS_L_ETIMEOUT	-109	/* Time out waiting for ready */

/* Prototype the mangling functions. */
static
int
globus_l_gass_cache_mangle_html(const char	*string,
				char		*mangled,
				int		*length );
static
int
globus_l_gass_cache_mangle_md5(const char	*string,
			       char		*mangled,
			       int		*length );

/* Other prototypes */
static
int
globus_l_gass_cache_make_dirtree( const char *filepath );


/* Structure for storing directory paths & other info */
typedef struct cache_names_s
{
    /* Mangled URL & tag */
    char	*mangled_url;
    char	*mangled_tag;

    /* The directories that we use */
    char	*global_dir;
    char	*local_dir;
    char	*local_base_dir;

    /* The data file names are built if the URL (& tag for local) are spec. */
    char	*global_data_file;
    char	*global_url_file;
    char	*local_data_file;
    char	*local_tag_file;
    char	*local_tag_link;

    /* The "uniq" name that we use */
    char	*uniq;

    /* Other names that can be stored here.. */
    /* There aren't allocated/filled automatically */

    /* Items in the "local" directory */
    char	*local_uniq_file;
    char	*localdir_lock_file;

    /* Items in the "global" directory */
    char	*global_uniq_file;
    char	*globaldir_lock_file;	/* Only used in RH62 */

    /* These *never* get freed up 'cause they're aliases to stuff in
       the cache_handle */
    const char	*global_root;
    const char	*local_root;
    const char	*tmp_root;
    const char	*log_root;

    /* These *never* get freed up 'cause they're aliases to the
       original tag & URL */
    const char	*tag;
    const char	*url;
} cache_names;

/* Size of an MD5ed URL / tag */
#define MD5_SIZE	(32 + 3)

/* Free a pointer if it's not NULL */
#define FREE_PTR(_ptr_) \
 if ( GLOBUS_NULL != (_ptr_) ) { globus_free(_ptr_); (_ptr_) = GLOBUS_NULL; }

/* Array of mangling functions.. */
#define MANGLING_OPTION_HTML	0x0001
#define MANGLING_OPTION_MD5	0x0002
#define MANGLING_OPTION_ALL	(MANGLING_OPTION_HTML | MANGLING_OPTION_MD5)
#define MANGLING_OPTION_DEFAULT	(MANGLING_OPTION_MD5)
typedef struct cache_mangling_option_s
{
    unsigned	flagbits;
    char	*prefix;
    int (* function) (const char *, char *, int * );
} cache_mangling_option;
static cache_mangling_option cache_mangling_list [] =
{
    { MANGLING_OPTION_HTML, "html/", globus_l_gass_cache_mangle_html },
    { MANGLING_OPTION_MD5, "md5/", globus_l_gass_cache_mangle_md5 },
    { 0x0000, GLOBUS_NULL, GLOBUS_NULL }
};

/* Structures for listing URLs */
typedef struct url_list_elem_s
{
    struct url_list_elem_s	*next;		/* Next in the linked list */
    char			*mangled;	/* Full path to the dir */
    int				data_count;	/* How many data files */
} url_list_elem;
typedef struct
{
    url_list_elem	*head;		/* Head of the list */
    int			count;		/* Size of the list */
} url_list_head;

static globus_bool_t globus_l_gass_cache_link_works = GLOBUS_TRUE;

static int
globus_l_gass_cache_module_activate(void);

/* NRLs Debugging stuff */
static double TODOGetTime(void)
{
    struct timeval tv;
    gettimeofday( &tv, NULL );
    return ( tv.tv_sec + ( tv.tv_usec * 0.000001 ) );
}

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
#define CHECK_CACHE_IS_INIT(_handle_) if (_handle_->init != &globus_l_gass_cache_is_init) return(GLOBUS_GASS_CACHE_ERROR_CACHE_NOT_OPENED)
#define CHECK_CACHE_IS_NOT_INIT(_handle_) if (_handle_->init == &globus_l_gass_cache_is_init) return(GLOBUS_GASS_CACHE_ERROR_CACHE_ALREADY_OPENED)
									   
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
    const char *                        str,...);

#endif

#ifdef DEBUG
static
void
globus_l_gass_cache_trace(
    const char*                        source_file,
    int                                line,
    const char *                       str, ...);
#endif

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
	      GLOBUS_L_FILE_MODE);

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
				   const char * file_to_be_locked);
void
globus_l_gass_cache_name_uniq_lock_file(char * uniq_lock_file,
					const char * file_to_be_locked);

#ifdef GLOBUS_L_GASS_CACHE_LOG
#define CACHE_ERROR_MSGSIZE	255
typedef struct
{
    int		SrcLine;
    int		ErrNo;
    int		rc;
    char	msgbuf[CACHE_ERROR_MSGSIZE + 1];
} CACHE_ERROR;
#define MAX_ERRORS	20
static struct
{
    int		NumErrors;
    CACHE_ERROR	Errors[MAX_ERRORS];
} cache_errors;
void error_return(int line, int ErrNo, int rc, const char *msg )
{
    int		num = cache_errors.NumErrors;
    if ( num < ( MAX_ERRORS - 1 ) )
    {
	CACHE_ERROR	*error = &cache_errors.Errors[num];
	error->SrcLine = line;
	error->ErrNo = ErrNo;
	error->rc = rc;
	if ( GLOBUS_NULL != msg )
	{
	    strncpy( error->msgbuf, msg, CACHE_ERROR_MSGSIZE );
	    error->msgbuf[CACHE_ERROR_MSGSIZE] = '\0';
	}
	else
	{
	    error->msgbuf[0] = '\0';
	}
	cache_errors.NumErrors++;
    }
}
void error_backtrace(FILE *fp)
{
    int		num;
    if ( cache_errors.NumErrors )
    {
	globus_l_gass_cache_log( fp, "Backtrace:\n" );
	for ( num = (cache_errors.NumErrors - 1) ; num >= 0;  num-- )
	{
	    CACHE_ERROR	*error = &cache_errors.Errors[num];
	    if ( '\0' == error->msgbuf[0] )
	    {
		globus_l_gass_cache_log(
		    fp,
		    "  Line=%d, errno=%d, Rc=%d\n",
		    error->SrcLine, error->ErrNo, error->rc );
	    }
	    else
	    {
		globus_l_gass_cache_log(
		    fp,
		    "  Line=%d, errno=%d, Rc=%d, msg='%s'\n",
		    error->SrcLine, error->ErrNo, error->rc, error->msgbuf );
	    }
	}
    }
}
#define CLR_ERROR	cache_errors.NumErrors = 0
#define MARK_ERROR(_rc_)		\
	error_return(__LINE__, errno, (_rc_), GLOBUS_NULL);
#define MARK_ERRORMSG(_rc_,_msg_)	\
	error_return(__LINE__, errno, (_rc_), (_msg_) );
#define RET_ERROR(_rc_)			\
	error_return(__LINE__, errno, (_rc_), GLOBUS_NULL); return (_rc_)
#define RET_ERRORMSG(_rc_,_msg_)	\
	error_return(__LINE__, errno, (_rc_), (_msg_) ); return (_rc_)
#define LOG_ERROR(_x_) \
    globus_l_gass_cache_log(cache_handle->log_FILE,\
	"ERROR: Line %d, errno %d; rc=%d\n",\
        __LINE__, errno, _x_ );\
    error_backtrace(cache_handle->log_FILE)
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
    FILE*       f,
    const char* str,
    ...)
{
    va_list    args;
    char hname[MAXHOSTNAMELEN];
    char time_buff[26];
    time_t ttime;
    long mytid;

    /* Note : I use the local time to log. This might not be the best */
    time(&ttime);

    globus_libc_ctime_r(&ttime,time_buff,sizeof(time_buff));

    /* If the log file hasn't been opened yet (i.e. we're logging from open) */
    /* log *somewhere* */
    if ( GLOBUS_NULL == f )
	f = stderr;

    /* remove the \n */
    time_buff[24]='\0';
    globus_libc_gethostname(hname,sizeof(hname));
    mytid = (long) globus_thread_self();

    globus_libc_fprintf(f,"GASSCACHE: %s %s PID:%ld TID:%ld : ",
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
#else
#define CLR_ERROR
#define LOG_ERROR(_x_)
#define RET_ERROR(_rc_)			return(_rc_)
#define RET_ERRORMSG(_rc_,_msg_)	return(_rc_)
#define MARK_ERROR(_rc_)
#define MARK_ERRORMSG(_rc_,_msg_)
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
    const char*                  source_file,
    int                          line,
    const char                   *format,
    ...)
{
    va_list    		args;
    struct timeval	tv;
    static FILE		*fp = GLOBUS_NULL;
    static globus_bool_t enabled = GLOBUS_FALSE;

    globus_libc_lock();
    if( fp == GLOBUS_NULL )
    {
	char	*env = getenv( GLOBUS_L_GASS_CACHE_DEBUG );
	if ( GLOBUS_NULL == env )
	{
	    enabled = GLOBUS_FALSE;
	}
	else
	{
	    enabled = GLOBUS_TRUE;
	    if (  ( '\0' == *env ) || ( ! strcmp ( env, "stderr" ) )  )
	    {
		fp = stderr;
	    }
	    else if  ( ! strcmp ( env, "stdout" ) )
	    {
		fp = stdout;
	    }
	    else
	    {
		fp = fopen( env, "a+" );
	    }
	}
    }
    globus_libc_unlock();

    /* Are we enabled? */
    if ( GLOBUS_FALSE == enabled )
    {
	return;
    }

    gettimeofday( & tv, NULL );

    va_start(args,format);
    
    globus_libc_fprintf(fp,"GC %ld.%06ld: %s %d : ", 
			tv.tv_sec, tv.tv_usec, source_file, line);
    globus_libc_vfprintf(fp, format, args);
    va_end(args);

    globus_libc_fprintf(fp,"\n");

    globus_libc_lock();
    fflush(fp);
    globus_libc_unlock();
    
}
/* globus_l_gass_cache_trace() */
#endif

/*
 * globus_l_gass_cache_build_filename()
 *
 * Build a cache filename by concatenating a file name onto a
 * directory name.  If no file name is provided, the directory name
 * alone is copied into the output path buffer.
 *  
 * Parameters:
 *	dir	- Incoming directory name
 *	file	- Optional file name
 *	path	- Outgoing full file path
 *
 * Returns: VOID
 *
 */
static
int
globus_l_gass_cache_build_filename(const char	*dir,
				   const char	*file,
				   const char	*uniq,
				   int		overwrite,
				   char		**path )
{
    int		len = strlen( dir ) + 1;	/* String + \0 */

    /* Did we already do this? */
    if ( GLOBUS_NULL != *path )
    {
	/* If we're supposed to overwrite, free up the buffer */
	if ( overwrite )
	{
	    globus_free( *path );
	}
	/* Otherwise, we're done! */
	else
	{
	    return GLOBUS_SUCCESS;
	}
    }

    /* Compute the lengths */
    if ( file )
    {
	len += strlen( file ) + 1;		/* slash + string */
    }
    if ( uniq )
    {
	len += strlen( uniq ) + 1;		/* (no slash) string */
    }

    /* Allocate the buffer */
    *path = globus_malloc( len );
    if ( GLOBUS_NULL == *path )
    {
	RET_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );
    }

    /* Fill it */
    strcpy( *path, dir );
    if ( file )
    {
	strcat( *path, "/" );
	strcat( *path, file );
    }
    if ( uniq )
    {
	strcat( *path, uniq );
    }

    /* All done, good */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_build_filename() */

/*
 * globus_l_gass_cache_mangle_html()
 *  
 * Parameters:
 *	string - The string to mangle
 *	mangled - Pointer to the buffer to mangle into (or GLOBUS_NULL)
 *	length - Pointer to the length of the mangled output (or GLOBUS_NULL)
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_mangle_html(const char	*string,
				char		*mangled,
				int		*length )
{
    /* These are "safe" characters */
    const char	*safe = "$-_.+";
    const char	*extra = "!*'(),";
    int		mangle_slash = 0;	/* Bool: Mangle extra slashes? */
    int		len = 0;
    int		c;

    /* Copy & clean.. */
    while( ( c = *string++ ) != '\0' )
    {
	int	mangle = 0;

	/* Alpha-numerics get copied directly */
	if ( isalnum( c ) )
	{
	    /* Do nothing */
	}

	/* Safe chars get copied directly */
	else if ( strchr( safe, c ) != NULL )
	{
	    /* Do nothing */
	}

	/* Extra chars get copied directly */
	else if ( strchr( extra, c ) != NULL )
	{
	    /* Do nothing */
	}

	/* Copy slashes (/) directly... */
	else if (  ( '/' == c ) && ( ! mangle_slash )  )
	{
	    /* Do nothing */
	}

	/* Everything else gets mangled */
	else
	{
	    mangle = 1;
	}

	/* Copy directly.. */
	if ( ! mangle )
	{
	    mangle_slash = ( '/' == c );
	    len++;
	    if ( mangled )
	    {
		*mangled++ = c;
	    }
	}
	/* Mangle the byte here */
	else
	{
	    len += 3;
	    if ( mangled )
	    {
		sprintf( mangled, "%%%02x", c );
		mangled += 3;
	    }

	    /* If this isn't a slash, force off / mangling for the next one */
	    if ( '/' != c )
	    {
		mangle_slash = 0;
	    }
	}
    }

    /* Terminate the string */
    if ( mangled )
    {
	*mangled = '\0';
    }

    /* Store off the length (add one for \0) */
    if ( length )
    {
	*length = ++len;
    }

    /* All ok! */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_mangle_html() */

/*
 * globus_l_gass_cache_mangle_md5()
 *  
 * Parameters:
 *	string - The string to mangle
 *	mangled - Pointer to the buffer to mangle into (or GLOBUS_NULL)
 *	length - Pointer to the length of the mangled output (or GLOBUS_NULL)
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_mangle_md5(const char	*string,
			       char		*mangled,
			       int		*length )
{
    /* Length is fixed */
    if ( GLOBUS_NULL != length )
    {
	/* +1 for \0, +3 for added slashes, +3 for .00 extension */
	*length = ( MD5_DIGEST_LENGTH * 2 ) + 1 + 3 + 3;
    }

    /* Do the mangling? */
    if ( GLOBUS_NULL != mangled )
    {
	unsigned char	md5[MD5_DIGEST_LENGTH], *md5ptr = &md5[0];
	int		i;

	/* Do the real work. */
	MD5( string, strlen(string), md5 );

	/* Convert it to string format */
	for ( i=0;  i<MD5_DIGEST_LENGTH;  i++ )
	{
	    sprintf( mangled, "%02x", *md5ptr );
	    mangled += 2;
	    md5ptr++;
	    if ( i <= 2 )
	    {
		*mangled++ = '/';
	    }
	}
	*mangled = '\0';
    }

    /* All ok! */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_mangle_md5() */

/*
 * globus_l_gass_cache_mangle()
 *
 * Mangles the given string (typically URL or tag) into a chunk
 * suitable for using as a file / path name.
 *  
 * Parameters:
 *	string - The incoming string to mangle (\0 terminated)
 *
 *	mangling_options - Flag bits defining the mangling options to
 *	try.
 *	
 *	max_mangled_len - Max allowable length of the mangled string
 *
 *	mangled - Pointer to the output string; a buffer for the real
 *	string is malloc()ed for the application.  If mangled is NULL,
 *	then no such buffer is allocated, and no mangled string is
 *	created.  This can be useful to just get the length of the
 *	mangled string.
 *
 *	Length - The length of the resulting string.  If NULL, this is
 *	not assigned to.
 *
 * Returns:
 *	GLOBUS_SUCCESS
 *	GLOBUS_GASS_CACHE_ERROR_NO_MEMORY
 *
 */
int
globus_l_gass_cache_mangle( const char	*string,
			    unsigned	mangling_options,
			    int		max_mangled_len,
			    char	**mangled,
			    int		*length )
{
    int				rc;
    int				len;
    int				option_no;
    cache_mangling_option	*option;

    /* Get the mangled length */
    for ( option_no = 0, option = &cache_mangling_list[0];
	  option->flagbits;
	  option_no++, option++ )
    {
	if ( mangling_options & option->flagbits )
	{
	    rc = option->function( string, GLOBUS_NULL, &len );
	    if ( GLOBUS_SUCCESS != rc )
	    {
		RET_ERROR( rc );
	    }
	    len += strlen( option-> prefix );
	    if (  ( max_mangled_len > 0 ) && ( len <= max_mangled_len )  )
	    {
		break;
	    }
	}
    }

    /* Valid option found? */
    if ( ! option->flagbits )
    {
	RET_ERROR( GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG );
    }

    /* Store the length */
    if ( length )
    {
	*length = len;
    }

    /* Allocate a buffer for it & mangle into it */
    if ( mangled )
    {
	char	*mptr;
	mptr = *mangled = globus_malloc( len );
	if ( GLOBUS_NULL == mptr )
	{
	    return GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
	}
	strcpy( mptr, option->prefix );
	mptr += strlen( mptr );
	rc = option->function( string, mptr, GLOBUS_NULL );
	if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( rc );
	}
    }

    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_mangle() */

/*
 * globus_l_gass_cache_build_dirname()
 *
 * Build a cache filename; can be used to generate either the global
 * or local file names.  Pass tag=NULL for global.
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_build_dirname( const char	*root,
				   const char	*mangled_tag,
				   const char	*mangled_url,
				   char		**path,
				   int		*path_len )
{
    int		len = strlen( root ) + 1;		/* root + '\0' */

    /* NULL out the passed in parameters in case of error */
    *path = GLOBUS_NULL;

    /* Add in for the tag, if relevant. */
    if ( mangled_tag )
    {
	len += ( strlen( mangled_tag ) + 1 );		/* + slash */
    }

    /* Add in the mangled */
    if ( GLOBUS_NULL != mangled_url )
    {
	len += ( strlen( mangled_url ) + 1 );		/* + slash */
    }

    /* Allocate the buffer.. */
    *path = globus_malloc( len );
    if ( GLOBUS_NULL == *path )
    {
	return GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
    }

    /* Store off the length.. */
    if ( path_len )
    {
	*path_len = len;
    }

    /* Build it */
    strcpy( *path, root );
    if ( mangled_tag )
    {
	strcat( *path, "/" );
	strcat( *path, mangled_tag );
    }
    if ( mangled_url )
    {
	strcat( *path, "/" );
	strcat( *path, mangled_url );
    }

    /* Ok */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_build_dirname() */

/*
 * globus_l_gass_cache_build_uniqname()
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_build_uniqname( char **uniq )
{
    char	hostname[MAXHOSTNAMELEN];
    char	uniq_string[UNIQ_NAME_MAX];

    /* !!! need to handle multi threaded !!! */
    globus_libc_gethostname( hostname, sizeof(hostname) );

    globus_libc_sprintf(uniq_string,
			UNIQ_NAME_FORMAT,
			hostname,
			(long) globus_libc_getpid(),
			(long) globus_thread_self() );

    /* Assign to the uniq passed in.. */
    *uniq = strdup( uniq_string );
    if ( GLOBUS_NULL == *uniq )
    {
	RET_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );
    }

    /* Outa here */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_build_uniqname() */

/*
 * globus_l_gass_cache_names_free()
 *
 * Free all allocated names
 *  
 * Parameters:
 *	names - Pointer to the "names" structure
 *
 * Returns:
 *	GLOBUS_SUCCESS
 */
static
int
globus_l_gass_cache_names_free( cache_names	*names )
{

    /* Free the mangled URL & tag */
    FREE_PTR( names->mangled_url );
    FREE_PTR( names->mangled_tag );

    /* Free the global... */
    FREE_PTR( names->global_dir );

    /* Free the local dir.. */
    FREE_PTR( names->local_dir );
    FREE_PTR( names->local_base_dir );

    /* The Uniq string */
    FREE_PTR( names->uniq );

    /* Optional names. */

    /* The local names. */
    FREE_PTR( names->local_data_file );
    FREE_PTR( names->local_tag_file );
    FREE_PTR( names->local_tag_link );
    FREE_PTR( names->local_uniq_file );
    FREE_PTR( names->localdir_lock_file );

    /* The global names. */
    FREE_PTR( names->global_data_file );
    FREE_PTR( names->global_url_file );
    FREE_PTR( names->global_uniq_file );
    FREE_PTR( names->globaldir_lock_file );


    /* Finally, zero out the PATHs */
    memset( names, 0, sizeof( cache_names ) );

    /* Here, all is good.  Return ok. */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_names_free() */

/*
 * globus_l_gass_cache_names_fill_global()
 *
 * Fill the global portion of the names structure
 *  
 * Parameters:
 *	names - The names structure to fill
 *
 * Returns:
 *	GLOBUS_SUCCESS
 *	GLOBUS_GASS_CACHE_ERROR_NO_MEMORY
 *
 */
static
int
globus_l_gass_cache_names_fill_global( cache_names *names )
{
    int		rc = GLOBUS_SUCCESS;

    /* Assemble the global... */
    if ( GLOBUS_NULL == names->mangled_url )
    {
	return GLOBUS_SUCCESS;
    }

    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_dirname( 
	    names->global_root,
	    GLOBUS_NULL,
	    names->mangled_url,
	    &names->global_dir,
	    GLOBUS_NULL );
    }

    /* Build the global data file name; *everything* uses it anyway */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_filename( 
	    names->global_dir, DATA_FILE, GLOBUS_NULL, GLOBUS_FALSE,
	    &names->global_data_file );
    }
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_filename( 
	    names->global_dir, URL_FILE, GLOBUS_NULL, GLOBUS_FALSE,
	    &names->global_url_file );
    }

    /* Done; */
    if ( GLOBUS_SUCCESS == rc )
    {
	return GLOBUS_SUCCESS;
    }
    else
    {
	RET_ERROR( rc );
    }

} /* globus_l_gass_cache_names_fill_global() */

/*
 * globus_l_gass_cache_names_fill_local()
 *
 * Fill the local portion of the names structure
 *  
 * Parameters:
 *	names - The names structure to fill
 *
 * Returns:
 *	GLOBUS_SUCCESS
 *	GLOBUS_GASS_CACHE_ERROR_NO_MEMORY
 *
 */
static
int
globus_l_gass_cache_names_fill_local( cache_names *names )
{
    int		rc = GLOBUS_SUCCESS;

    /* Valid tag? */
    if ( GLOBUS_NULL == names->mangled_tag )
    {
	return GLOBUS_SUCCESS;
    }

    /* Create the base local directory name (we don't need the URL for it) */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_dirname( 
	    names->local_root,
	    names->mangled_tag,
	    GLOBUS_NULL,
	    &names->local_base_dir,
	    GLOBUS_NULL );
	if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( rc );
	}
    }

    /* And, the local tag file */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_filename( 
	    names->local_base_dir, TAG_FILE, GLOBUS_NULL, GLOBUS_FALSE,
	    &names->local_tag_file );
    }

    /* For everything else, we need a valid URL, too */
    if ( GLOBUS_NULL == names->mangled_url )
    {
	return GLOBUS_SUCCESS;
    }

    /* Create the local directory name. */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_dirname( 
	    names->local_root,
	    names->mangled_tag,
	    names->mangled_url,
	    &names->local_dir,
	    GLOBUS_NULL );
    }

    /* Build the local data file name; *everything* uses it anyway */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_filename( 
	    names->local_dir, DATA_FILE, GLOBUS_NULL, GLOBUS_FALSE,
	    &names->local_data_file );
    }
    /* The local tag "link" name */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_filename( 
	    names->local_dir, TAG_FILE, GLOBUS_NULL, GLOBUS_FALSE,
	    &names->local_tag_link );
    }

    /* Done; */
    if ( GLOBUS_SUCCESS == rc )
    {
	return GLOBUS_SUCCESS;
    }
    else
    {
	RET_ERROR( rc );
    }

} /* globus_l_gass_cache_names_fill_local() */

/*
 * globus_l_gass_cache_names_init()
 *
 * Initialize the common names structure
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_names_init( const globus_gass_cache_t	*cache,
				const char			*url,
				const char			*tag,
				cache_names			*names )
{
    int		rc = GLOBUS_SUCCESS;

    /* Zero out the PATHs first... */
    memset( names, 0, sizeof( cache_names ) );

    /* Create the links to the root dirs */
    names->global_root = cache->global_directory_path;
    names->local_root = cache->local_directory_path;
    names->tmp_root = cache->tmp_directory_path;
    names->log_root = cache->tmp_directory_path;

    /* if no tag supplied, we map it to the tag
       GLOBUS_L_GASS_CACHE_NULL_TAG ("null") */
    if ( GLOBUS_NULL == tag )
    {
	tag = GLOBUS_L_GASS_CACHE_NULL_TAG;
    }

    /* Create the URL & tag aliases */
    names->url = url;
    names->tag = tag;

    /* Mangle the URL */
    if (  ( GLOBUS_SUCCESS == rc ) && ( GLOBUS_NULL != url )  )
    {
	rc = globus_l_gass_cache_mangle( url,
					 cache->mangling_options,
					 cache->max_mangled_url,
					 &names->mangled_url,
					 GLOBUS_NULL );
    }

    /* And, the tag */
    if (  ( GLOBUS_SUCCESS == rc ) && ( GLOBUS_NULL != tag )  )
    {
	rc = globus_l_gass_cache_mangle( tag,
					 cache->mangling_options,
					 cache->max_mangled_tag,
					 &names->mangled_tag, 
					 GLOBUS_NULL );
    }

    /* Assemble the global dir & related names */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_names_fill_global( names );
    }

    /* Assemble the local dir.. */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_names_fill_local( names );
    }

    /* Uniq string */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_uniqname( &names->uniq );
    }

    /* If we've had failures, free up all allocated memory */
    if ( GLOBUS_SUCCESS != rc )
    {
	globus_l_gass_cache_names_free( names );
	RET_ERROR( rc );
    }

    /* Here, all is good.  Return ok. */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_names_init() */

/*
 * globus_l_gass_cache_names_new_murl()
 *
 * Set a new mangled URL in the names structure.  This is for use
 * primarily for cleanup_tag_all().
 *
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_names_new_murl( const char	*mangled_url,
				    cache_names	*names )
{
    int		rc = GLOBUS_SUCCESS;

    /* We don't know the unmangled URL here... */
    names->url = GLOBUS_NULL;

    /* Is it really different? */
    if ( GLOBUS_NULL != names->mangled_url )
    {
	if ( ! strcmp( names->mangled_url, mangled_url )  )
	{
	    return GLOBUS_SUCCESS;
	}
	else
	{
	    globus_free( names->mangled_url );
	}
    }

    /* Copy it */
    names->mangled_url = strdup( mangled_url );
    if ( GLOBUS_NULL == names->mangled_url )
    {
	RET_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );
    }

    /* Free up existing local & global directories */
    FREE_PTR( names->global_dir );
    FREE_PTR( names->local_dir );
    FREE_PTR( names->local_base_dir );

    /* And, anything else that might be affected. */
    FREE_PTR( names->local_data_file );
    FREE_PTR( names->local_uniq_file );
    FREE_PTR( names->local_tag_file );
    FREE_PTR( names->local_tag_link );
    FREE_PTR( names->localdir_lock_file );

    /* The global names. */
    FREE_PTR( names->global_data_file );
    FREE_PTR( names->global_url_file );
    FREE_PTR( names->global_uniq_file );
    FREE_PTR( names->globaldir_lock_file );


    /* Assemble the global dir & related names */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_names_fill_global( names );
    }

    /* Assemble the local dir.. */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_names_fill_local( names );
    }
    
    /* If we've had failures, free up all allocated memory */
    if ( GLOBUS_SUCCESS != rc )
    {
	globus_l_gass_cache_names_free( names );
	RET_ERROR( rc );
    }

    /* Here, all is good.  Return ok. */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_names_new_murl() */

/*
 * globus_l_gass_cache_stat()
 *
 * Build a cache filename; can be used to generate either the global
 * or local file names.  Pass tag=NULL for global.
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_stat ( const char	*filepath,
			   struct stat	*statptr )
{
    struct stat	statbuf;
    int		rc;

    /* Check for null statptr.. */
    if ( GLOBUS_NULL == statptr )
    {
	statptr = &statbuf;
    }

    /* Run stat 'til we get an answer.. */
    while( 1 )
    {
	rc = stat( filepath, statptr );
	if ( 0 == rc )
	{
	    return GLOBUS_SUCCESS;
	}
	if ( ENOENT == errno )
	{
	    RET_ERRORMSG( GLOBUS_L_ENOENT, filepath );
	}
	if ( EINTR != errno )
	{
	    RET_ERROR( GLOBUS_L_EOTHER );
	}
    }
} /* globus_l_gass_cache_stat() */

#if defined( DEBUGxxxx )
static void TODOgu( const char *g, const char *u, const char *msg )
{
    static char	uniq_name[1024], data_name[1024];
    struct stat	statbuf;
    int		uniq_inode = -1, data_inode = -1;

    if ( g )
    {
	sprintf( data_name, "%s/%s", g, DATA_FILE );
	CACHE_TRACE3( "%d: Data name is '%s'", getpid(), data_name );
	if ( u )
	{
	    sprintf( uniq_name, "%s/%s%s", g, UDATA_FILE, u );
	    CACHE_TRACE3( "%d: Uniq name is '%s'", getpid(), uniq_name );
	}
    }

    if ( msg )
    {
	if ( globus_l_gass_cache_stat( data_name, &statbuf ) == 0 )
	    data_inode = statbuf.st_ino;
	if ( globus_l_gass_cache_stat( uniq_name, &statbuf ) == 0 )
	    uniq_inode = statbuf.st_ino;
	CACHE_TRACE5( "%d/%s: data/uniq %d/%d",
		      getpid(), msg, data_inode, uniq_inode );
    }
   
}
#else
# define TODOgu(_g_,_u_,_m_)
#endif

/*
 * globus_l_gass_cache_create()
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_create( const char	*filepath,
			    const char	*dir,
			    int		mode,
			    const char	*buf,
			    int		buflen )
{
    int		fd;
    int		mkdir_try = 0;

    /* Try to create the file... */
    while ( ( fd = creat( filepath, mode ) ) < 0 )
    {
	/* Interrupted? Go try again */
	if ( EINTR == errno )
	{
	    continue;
	}

	/* ENOENT?  Directory went away.. */
	if ( ENOENT == errno )
	{
	    /* If the app gave us a directory, try again... */
	    if (  ( GLOBUS_NULL != dir ) && 
		  ( ++mkdir_try < CREATE_MAX_TRIES ) )
	    {
		int	rc = globus_l_gass_cache_make_dirtree( dir );
		if ( GLOBUS_SUCCESS != rc )
		{
		    RET_ERROR( rc );
		}
		continue;	/* Try again.. */
	    }
	    /* No dir specified or time to give up */
	    else
	    {
		RET_ERROR( GLOBUS_L_ENOENT );
	    }
	}

	/* Handle other errors */
	if ( ENOSPC == errno)
	{
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_SPACE );
	}
	else if (IS_QUOTA_ERROR(errno))
	{
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED );
	}
	else
	{
	    CACHE_TRACE2("Error creat()ing '%s'", filepath );
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE );
	}
    }

    /* Write a buffer to it.. */
    if (  ( GLOBUS_NULL != buf ) && ( 0 != buflen )  )
    {
	int	written;

	while( buflen > 0)
	{
	    written = write( fd, buf, buflen );
	    if ( written < 0 )
	    {
		if ( errno != EINTR )
		{
		    CACHE_TRACE2( "creat: Error writing to '%s'; unlinking\n",
				  filepath );
		    unlink( filepath );
		    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE );
		}
	    }
	    else if ( written > 0 )
	    {
		buf += written;
		buflen -= written;
	    }
	}
    }

    /* Close it */
    while ( close( fd ) < 0 )
    {
	if (errno != EINTR)
	{
	    CACHE_TRACE2( "creat: Error closing '%s'; unlinking\n", filepath );
	    unlink( filepath );
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE );
	}
    }

    /* Done */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_create() */

/*
 * globus_l_gass_cache_link()
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_link( const char *oldfile,
			  const char *newfile )
{
    int		link_retry = 0;		/* How many link() retries? */

    /* Loop til link fails w/o EINTR or 'til link succeeds */
    while ( link( oldfile, newfile ) < 0 )
    {
	if ( EINTR == errno )
	{
	    continue;
	}
	else if (errno == ENOSPC)
	{
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_SPACE );
	}
	else if ( EEXIST == errno )
	{
	    RET_ERROR( GLOBUS_L_EEXISTS );
	}
	/*else if (  ( ENOENT == errno ) || ( EINVAL == errno )  ) */
	else if ( ENOENT == errno )
	{
	    int		rc;

	    /* RedHat 6.2 seems to return ENOENT sometimes even though
	     * it *does* exist & stat says so.  So, we'll stat it, and, if
	     * it does exist, sleep a bit & try again. 
	     */
	    if ( ++link_retry < LINKBUG_MAX_RETRY )
	    {
		rc = globus_l_gass_cache_stat( oldfile, GLOBUS_NULL );
		if ( GLOBUS_SUCCESS == rc )
		{
		    CACHE_TRACE3( 
			"LINK: link bug encountered; try %d, errno %d",
			link_retry, errno );
		    globus_libc_usleep( LINKBUG_SLEEP_USEC );
		    continue;
		}
		RET_ERROR( GLOBUS_L_ENOENT );
	    }
	    /* Give up! */
	    else
	    {
		RET_ERROR( GLOBUS_L_ENOENT );
	    }
	}
	else if ( IS_QUOTA_ERROR(errno) )
	{
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED );
	}
	else
	{
	    MARK_ERRORMSG( GLOBUS_L_EOTHER, oldfile );
	    MARK_ERRORMSG( GLOBUS_L_EOTHER, newfile );
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE );
	}
    }

    /* Return ok */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_link() */

/*
 * globus_l_gass_cache_rename()
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_rename( const char *oldfile,
			    const char *newfile )
{
    int		rename_retry = 0;	/* How many rename() retries? */

    /* Loop til link fails w/o EINTR or 'til link succeeds */
    while ( rename( oldfile, newfile ) < 0 )
    {
	if ( EINTR == errno )
	{
	    continue;
	}
	else if (errno == ENOSPC)
	{
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_SPACE );
	}
	else if ( EEXIST == errno )
	{
	    RET_ERROR( GLOBUS_L_EEXISTS );
	}
	else if ( ENOENT == errno )
	{
	    int		rc;

	    /* RedHat 6.2 seems to return ENOENT sometimes even though
	     * it *does* exist & stat says so.  So, we'll stat it, and, if
	     * it does exist, sleep a bit & try again. 
	     */
	    if ( ++rename_retry < LINKBUG_MAX_RETRY )
	    {
		rc = globus_l_gass_cache_stat( oldfile, GLOBUS_NULL );
		if ( GLOBUS_SUCCESS == rc )
		{
		    CACHE_TRACE3( "RENAME/%d: rename bug encountered; try %d",
				  getpid(), rename_retry );
		    globus_libc_usleep( LINKBUG_SLEEP_USEC );
		    continue;
		}
		RET_ERROR( GLOBUS_L_ENOENT );
	    }
	    /* Give up! */
	    else
	    {
		RET_ERROR( GLOBUS_L_ENOENT );
	    }
	}
	else if ( IS_QUOTA_ERROR(errno) )
	{
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED );
	}
	else
	{
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE );
	}
    }

    /* Return ok */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_link() */

/*
 * globus_l_gass_cache_unlink()
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_unlink( const char *filepath )
{
    int		tries = 0;

    /* Loop til unlink fails w/o EINTR or 'til link succeeds */
    while ( unlink( filepath ) < 0 )
    {
	/* EINTR; just try again */
	if ( EINTR == errno )
	{
	    if ( ++tries > UNLINK_MAX_TRIES )
	    {
		RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE );
	    }
	    continue;
	}

	/* If it's already gone, then we'll consider it a success */
	if ( ENOENT == errno )
	{
	    return GLOBUS_SUCCESS;
	}

	/* If it's "busy" wait a bit & try again.. */
	else if ( EBUSY == errno )
	{
	    if ( ++tries > UNLINK_MAX_TRIES )
	    {
		RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE );
	    }
	    globus_libc_usleep( EBUSY_SLEEP_USEC );
	    continue;
	}

	/* Otherwise, something bad happened. */
	RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE );
    }

    /* Return ok */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_unlink() */

/*
 * globus_l_gass_cache_scandir_free()
 *
 * Free the list from scandir()
 *
 * Parameters:
 *
 * Returns:
 *
 */
static
void
globus_l_gass_cache_scandir_free( struct dirent **list,
				  int		count )
{
    int		i;

    /* IF the list is empty, do nothing! */
    if ( GLOBUS_NULL == list )
    {
	return;
    }

    /* Loop til unlink fails w/o EINTR or 'til link succeeds */
    for( i = 0;  i < count;  i++ )
    {
	globus_free( list[i] );
    }
    globus_free( list );

} /* globus_l_gass_cache_scandir_free() */

/*
 * globus_l_gass_cache_scandir()
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_scandir( const char		*directory,
			     struct dirent	***list,
			     int		*list_count,
			     int (*selectfn)(const struct dirent *) )
{
    DIR			*dirptr;
    struct dirent	*dir_entry = GLOBUS_NULL;
    struct dirent	**newlist;
    int			newlist_size = 2;
    int			count = 0;
    int			rc = GLOBUS_SUCCESS;

    /* Initialize the count */
    *list_count = 0;

    /* Open the directory for reading.. */
    if (  ( dirptr = globus_libc_opendir( directory ) ) == NULL )
    {
	if ( ENOENT == errno )
	{
	    RET_ERROR( GLOBUS_L_ENOENT );
	}
	else if ( EINTR != errno )
	{
	    RET_ERROR( GLOBUS_L_EOTHER );
	}
    }

    /* Allocate & fill our "head" node */
    newlist = globus_malloc( newlist_size * sizeof( struct dirent * ) );
    if ( GLOBUS_NULL == newlist )
    {
	closedir( dirptr );
	RET_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );
    }

    /* Read the whole directory... */
    for( globus_libc_readdir_r( dirptr, &dir_entry );
	 ( dir_entry != GLOBUS_NULL ) && ( GLOBUS_SUCCESS == rc );
	 globus_libc_readdir_r( dirptr, &dir_entry ) )
    {

	int	keep = GLOBUS_FALSE;

	/* Invoke the select function... */
	if (  ( GLOBUS_NULL == selectfn ) || ( selectfn( dir_entry ) )  )
	{
	    keep = GLOBUS_TRUE;
	}

	/* If we should keep this entry.. */
	if ( GLOBUS_TRUE == keep )
	{
	    /* Did we exceed the size of our list? */
	    if ( count >= newlist_size )
	    {
		struct dirent	**tmp;

		/* Grow our list... */
		newlist_size *= 2;
		tmp = globus_realloc( 
		    newlist,
		    newlist_size * sizeof( struct dirent *) );
		if ( GLOBUS_NULL == tmp )
		{
		    globus_l_gass_cache_scandir_free( newlist, count );
		    closedir( dirptr );
		    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );
		}
		newlist = tmp;
	    }

	    /* The globus readdir_r() function malloc()s the dir_entry,
	     * so, I can just use it as is */
	    newlist[count++] = dir_entry;
	}

	/* Not keeping it;  because readdir_r() malloc()ed dir_entry,
	 * I must free it */
	else
	{
	    globus_free( dir_entry );
	}
    }

    /* Done */
    *list = newlist;
    *list_count = count;
    closedir( dirptr );
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_scandir() */

/*
 * globus_l_gass_cache_set_timestamp()
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_set_timestamp( const char	*filepath,
				   unsigned long timestamp )
{
    struct utimbuf	timebuf;
    int			rc;

    /* Copy the timestamp into the utime structure */
    timebuf.actime = (time_t) timestamp;
    timebuf.modtime = (time_t) timestamp;

    /* Loop til we succeed or fail */
    while( 1 )
    {
	rc = utime( filepath, &timebuf );
	if ( 0 == rc )
	{
	    return GLOBUS_SUCCESS;
	}
	else if ( ENOENT == errno )
	{
	    RET_ERROR( GLOBUS_L_ENOENT );
	}
	else if ( EINTR != errno )
	{
	    RET_ERROR( GLOBUS_L_EOTHER );
	}
	else
	{
	    continue;
	}
    }

    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_set_timestamp() */

/*
 * globus_l_gass_cache_calc_timeskew()
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_calc_timeskew( const char		*tmp_file,
				   struct timeval	*skew )
{
    int			rc;
    struct timeval	start, end;
    double		mean;
    struct stat		statbuf;
    double		mtime;
    double		diff;

    /* Get start time */
    gettimeofday( & start, NULL );

    /* Create the file. */
    rc = globus_l_gass_cache_create(
	tmp_file, GLOBUS_NULL, GLOBUS_L_GASS_CACHE_SKEWFILE_MODE,
	GLOBUS_NULL, 0 );
    if ( rc != GLOBUS_SUCCESS )
    {
	RET_ERROR( rc );
    }

    /* Get the end time. */
    gettimeofday( & end, NULL );

    /* Go get it's time stamp. */
    rc = globus_l_gass_cache_stat( tmp_file, &statbuf );
    if ( rc != GLOBUS_SUCCESS )
    {
	RET_ERROR( rc );
    }

    /* Perform the calculations... */
    mean = 0.5 * ( ( end.tv_sec + ( 1e-6 * end.tv_usec ) ) +
		   ( start.tv_sec + ( 1e-6 * start.tv_usec ) )  );
    mtime = statbuf.st_mtime;
    diff = mtime - mean;
    skew->tv_sec = ( long ) diff;
    skew->tv_usec = ( long ) ( ( diff - skew->tv_sec ) * 1e6 );

    /* Done with the file */
    (void) globus_l_gass_cache_unlink( tmp_file );

    /* Done */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_calc_timeskew() */

/*
 * globus_l_gass_cache_calc_timeskew()
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_calc_file_age( const char	*tmp_file,
				   time_t	cur_time,
				   time_t	mtime )
{
    static time_t	next_skewcalc = -1;
    static int		cur_skew = 0;
    static const  char	*file = GLOBUS_NULL;
    struct timeval	skew;
    int			tmp_skew;
    int			rc;
    int			age;

    /* Do we need the tmp file? */
    if (  ( GLOBUS_NULL == file ) && ( GLOBUS_NULL != tmp_file ) )
    {
	file = strdup( tmp_file );
	if ( GLOBUS_NULL == file )
	{
	    file = tmp_file;
	}
    }

    /* Do we need to recalculate? */
    if (  ( GLOBUS_NULL != file ) &&
	  ( ( next_skewcalc < 0 ) || ( cur_time > next_skewcalc ) )  )
    {
	next_skewcalc = cur_time + SKEWCALC_SECONDS;
	rc = globus_l_gass_cache_calc_timeskew( file, & skew );
	if ( GLOBUS_SUCCESS == rc )
	{
	    tmp_skew = skew.tv_sec;
	    if (  ( skew.tv_usec > 500000 ) && ( cur_skew >= 0 )  )
	    {
		tmp_skew++;
	    }
	    else if (  ( skew.tv_usec >= 500000 ) && ( cur_skew < 0 )  )
	    {
		tmp_skew--;
	    }

	    /* Update in one (should be atomic) operation. */
	    cur_skew = tmp_skew;
	}

	/* If we're using the tmp file, reset to NULL */
	if ( file == tmp_file )
	{
	    file = GLOBUS_NULL;
	}
    }

    /* Perform the calc.. */
    age = ( cur_time - mtime ) + cur_skew;
    return age;

} /* globus_l_gass_cache_calc_file_age() */

/*
 * globus_l_gass_cache_make_dirtree()
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_make_dirtree( const char *filepath )
{
    char	*temppath = (char *) globus_malloc( strlen( filepath ) + 1 );
    const char	*pos;
    int		offset = 0;
    int		rc;
    unsigned	length = strlen( filepath );
    struct stat	statbuf;
    int		tries = 0;

    /* Check that malloc() dien't fail */
    if ( NULL == temppath )
    {
	RET_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );
    }


    /* Loop through each component of the path... */
    while( *(filepath + offset) != '\0' )
    {
	pos = strchr( filepath + offset, '/' );
	if ( NULL == pos )
	{
	    pos = filepath + strlen( filepath );
	}

	/* Calculate the offset of the current "/" in the path */
	offset = ( pos - filepath );

	/* Copy the up to this "/" into the temp buffer */
	if ( 0 == offset )
	{
	    strcpy( temppath, "/" );
	}
	else
	{
	    strncpy( temppath, filepath, offset );
	    *(temppath + offset) = '\0';
	}


	/* Does it exist?  Is it a directory? */
	rc = globus_l_gass_cache_stat( temppath, &statbuf );

	/* If it exists, make sure its a directory! */
	if ( GLOBUS_SUCCESS == rc )
	{
	    if ( ! S_ISDIR( statbuf.st_mode ) )
	    {
		free( temppath );
		RET_ERROR( GLOBUS_L_ENOTDIR );
	    }
	}
	/* If it doesn't exist, create it */
	else if ( GLOBUS_L_ENOENT == rc )
	{
	    CLR_ERROR;
	    if ( mkdir( temppath, GLOBUS_L_GASS_CACHE_DIR_MODE ) < 0 )
	    {
		/* Check if somebody else beat me to it */
		if ( EEXIST == errno )
		{
		    /* If we keep failing something else must be wrong */
		    if ( ++tries > MAKE_DIRTREE_MAX_TRIES )
		    {
			free( temppath );
			RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE );
		    }
		    continue;
		}
		/* Somebody else deleted the base out from under us... */
		else if ( ENOENT == errno )
		{
		    /* If we keep failing something else must be wrong */
		    if ( ++tries > MAKE_DIRTREE_MAX_TRIES )
		    {
			free( temppath );
			RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE );
		    }

		    /* Start the whole process over */
		    offset = 0;
		    continue;
		}
		/* Something else went wrong; give up. */
		else
		{
		    free( temppath );
		    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE );
		}
	    }
	}
	/* Otherwise, something else is wrong.. */
	else
	{
	    free( temppath );
	    RET_ERROR( rc );
	}

	/* Are we done? */
	if ( length <= strlen( temppath ) )
	{
	    break;
	}

	/* Move the offset past the "/" for next time */
	offset++;
    }

    /* Done */
    free( temppath );
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_make_dirtree() */

/*
 * globus_l_gass_cache_remove_dirtree()
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_remove_dirtree( const char *base,
				    const char *tree )
{
    char	*fullpath = GLOBUS_NULL;
    char	*pos;
    struct stat	statbuf;
    int		rc;
    unsigned	length = strlen( base );

    /* Make a local copy of hte full path.. */
    fullpath = strdup( tree );
    if ( GLOBUS_NULL == fullpath )
    {
	RET_ERROR( -1 );
    }

    /* Loop through each component of the path... */
    while( strlen( fullpath ) > length )
    {
	/* Does it exist?  Is it a directory? */
	rc = globus_l_gass_cache_stat( fullpath, &statbuf );
	if ( GLOBUS_SUCCESS == rc )
	{
	    /* Bomb out if it's not a directory! */
	    if ( ! S_ISDIR( statbuf.st_mode ) )
	    {
		globus_free( fullpath );
		RET_ERROR( -1 );
	    }
	    /* If rmdir fails for any reason, we're hosed */
	    while ( rmdir( fullpath ) < 0 )
	    {
		/* Not empty (Solaris returns EEXIST - go figure) */
		if (  ( ENOTEMPTY == errno ) || ( EEXIST == errno ) )
		{
		    globus_free( fullpath );
		    return 1;
		}
		else if ( EINTR == errno )
		{
		    continue;
		}
		else if ( ENOENT == errno )
		{
		    break;	/* Somebody else beat me to it! */
		}
		globus_free( fullpath );
		RET_ERROR( -1 );
	    }
	}
	else if ( GLOBUS_L_ENOENT == rc )
	{
	    /* Nothing to do */
	}
	else
	{
	    globus_free( fullpath );
	    return rc;
	}

	/* Back up one level... */
	pos = strrchr( fullpath, '/' );
	*pos = '\0';
    }

    /* Done */
    globus_free( fullpath );
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_remove_dirtree() */

/*
 * globus_l_gass_cache_scandir_select_uniq()
 *
 * Select only files which match any file name.  Passed as the third
 * paramter to scandir()
 *  
 * Parameters:
 *
 * Returns:
 *	- 0: Don't include in the dirlist
 *	- <>0: Include in dirlist
 */
static
int
globus_l_gass_cache_scandir_select_uniq(const struct dirent *entry )
{
    const char	*pattern = UDATA_FILE_PAT;

    /* All uniq files should start with our "data" pattern */
    return ( ! strncmp( entry->d_name, pattern, UDATA_FILE_PAT_LEN )  );

} /* globus_l_gass_cache_scandir_select_uniq() */

/*
 * globus_l_gass_cache_scandir_select_data()
 *
 * Select only files which match any *data* file name.  Passed as the
 * third paramter to scandir()
 *  
 * Parameters:
 *
 * Returns:
 *	- 0: Don't include in the dirlist
 *	- <>0: Include in dirlist
 */
static
int
globus_l_gass_cache_scandir_select_data(const struct dirent *entry )
{
    const char	*pattern = DATA_FILE_PAT;

    /* All uniq files should start with our "data" pattern */
    return ( ! strncmp( entry->d_name, pattern, DATA_FILE_PAT_LEN )  );

} /* globus_l_gass_cache_scandir_select_data() */

/*
 * globus_l_gass_cache_scandir_select_all()
 *
 * Select only files which match all patterns.  Passed as the third
 * paramter to scandir()
 *  
 * Parameters:
 *
 * Returns:
 *	- 0: Don't include in the dirlist
 *	- <>0: Include in dirlist
 */
static
int
globus_l_gass_cache_scandir_select_all(const struct dirent *entry )
{
    (void) entry;
    return 1;

} /* globus_l_gass_cache_scandir_select_all() */

/*
 * globus_l_gass_cache_check_global_file()
 *
 * Check for the existence of a global file
 *  
 * Parameters:
 *
 * Returns:
 *	- GLOBUS_SUCCESS
 *	- GLOBUS_L_ENODATA		- No data files
 */
static
int
globus_l_gass_cache_check_global_file( const cache_names	*names,
				       int			*num_data,
				       int			*num_uniq )
{
    int			rc;
    struct dirent 	**data_list = NULL;
    int			data_list_count;
    int			data_num;
    struct stat		statbuf;
    int			data_count = 0;
    int			uniq_count = 0;

    /* Init the ptrs */
    if ( GLOBUS_NULL != num_data )
    {
	*num_data = 0;
    }
    if ( GLOBUS_NULL != num_uniq )
    {
	*num_uniq = 0;
    }

    /* Stat the data directory */
    rc = globus_l_gass_cache_stat( names->global_dir, &statbuf );

    /* There are no errors that I can handle here... */
    if ( GLOBUS_L_ENOENT == rc )
    {
	return GLOBUS_L_ENODATA;
    }
    else if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* Verify that it's a directory.. */
    if ( ! S_ISDIR( statbuf.st_mode ) )
    {
	RET_ERROR( GLOBUS_L_EOTHER );
    }

    /* Scan the directory; we're looking at *all* of the "data" files */
    rc = globus_l_gass_cache_scandir( 
	names->global_dir,
	&data_list,
	&data_list_count,
	globus_l_gass_cache_scandir_select_data );

    /* ENOENT means the directory somehow got smoked on us... */
    if ( ( GLOBUS_L_ENOENT == rc ) || ( 0 == data_list_count ) )
    {
	globus_l_gass_cache_scandir_free( data_list, data_list_count );
	return GLOBUS_L_ENODATA;
    }
    /* Something else bad happenned */
    else if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( GLOBUS_L_EOTHER );
    }

    /* Here, there's one or more entries ( count in rc ).. */
    for ( data_num = 0;  data_num < data_list_count; data_num++ )
    {
	/* Is it *the* data file? */
	if ( ! strcmp( DATA_FILE_PAT, data_list[data_num]->d_name ) )
	{
	    data_count++;
	}
	else
	{
	    uniq_count++;
	}
    }
    globus_l_gass_cache_scandir_free( data_list, data_list_count );

    /* Copy out the counts... */
    if ( GLOBUS_NULL != num_data )
    {
	*num_data = data_count;
    }
    if ( GLOBUS_NULL != num_uniq )
    {
	*num_uniq = uniq_count;
    }

    /* Done */
    RET_ERROR( GLOBUS_SUCCESS );

} /* globus_l_gass_cache_check_global_file() */

/*
 * globus_l_gass_cache_create_uniq_global_file()
 *
 * Build a cache filename; can be used to generate either the global
 * or local file names.  Pass tag=NULL for global.
 *  
 * Parameters:
 *
 * Returns:
 *	- GLOBUS_SUCCESS
 *	- GLOBUS_L_ENOTUNIQ		- We ddin't win the race
 *	- Returned failures from globus_l_gass_cache_creat()
 *	- Returned failures from globus_l_gass_cache_link()
 *	- Returned failures from globus_l_gass_cache_unlink()
 */
static
int
globus_l_gass_cache_create_uniq_global_file( const cache_names	*names )
{
    int			rc;
    int			uniq_count;
    struct dirent 	**uniq_list = NULL;
    struct stat		statbuf;
    int			uniq_num;
    ino_t		uniq_inode;
    int			lower_inode_found = GLOBUS_FALSE;
    const char		*TODOname = NULL;
    ino_t		TODOinode;

    /* Create my uniq file */
    rc = globus_l_gass_cache_create( 
	names->global_uniq_file, names->global_dir,
	GLOBUS_L_GASS_CACHE_UNIQFILE_MODE,
	GLOBUS_NULL, 0 );

    /* Other error */
    if ( rc < 0 )
    {
	RET_ERROR( rc );
    }

    /* Stat *my* file */
    rc = globus_l_gass_cache_stat( names->global_uniq_file, &statbuf );

    /* There are no errors that I can handle here... */
    if ( rc < 0 )
    {
	(void) globus_l_gass_cache_unlink( names->global_uniq_file );
	RET_ERROR( rc );
    }
    uniq_inode = statbuf.st_ino;

    /* Scan the directory; we're looking at *all* of the "uniq" files */
    rc = globus_l_gass_cache_scandir( 
	names->global_dir,
	&uniq_list,
	&uniq_count,
	globus_l_gass_cache_scandir_select_uniq );

    /* ENOENT means the directory somehow got smoked on us... */
    if ( GLOBUS_L_ENOENT == rc )
    {
	(void) globus_l_gass_cache_scandir_free( uniq_list, uniq_count );
	RET_ERROR( rc );
    }
    /* Something else bad happenned */
    else if ( GLOBUS_SUCCESS != rc )
    {
	(void) globus_l_gass_cache_unlink( names->global_uniq_file );
	RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE );
    }
    /* No matches...  Something's wrong.. */
    else if ( 0 == uniq_count )
    {
	(void) globus_l_gass_cache_scandir_free( uniq_list, uniq_count );
	(void) globus_l_gass_cache_unlink( names->global_uniq_file );
	RET_ERROR( GLOBUS_L_ENOENT );
    }
    /* 1 should mean just *my* file (hopefully) */
    else if ( 1 == uniq_count )
    {
	globus_l_gass_cache_scandir_free( uniq_list, 1 );
	return GLOBUS_SUCCESS;
    }

    /* More than one "uniq" file.  Look at them all, find the lowest inode */
    /* If we're the lowest, return SUCCESS, else ENOTUNIQ */
    for ( uniq_num = 0;  uniq_num < uniq_count; uniq_num++ )
    {
	/* Don't need to stat my uniq; I already did that above. */
	if ( ! strcmp( names->uniq, uniq_list[uniq_num]->d_name ) )
	{
	    /* If it's indoe # is lower than mine, it wins, we lose */
	    if ( uniq_list[uniq_num]->d_ino < uniq_inode )
	    {
		lower_inode_found = GLOBUS_TRUE;
		TODOname = strdup( uniq_list[uniq_num]->d_name );
		TODOinode = uniq_list[uniq_num]->d_ino;
		break;		/* Don't need to look any further */
	    }
	}
    }

    /* Free up the list that scandir() built so we don't leak memory */
    globus_l_gass_cache_scandir_free( uniq_list, uniq_count );

    /* Found a lower inode; it wins, we lose */
    if ( GLOBUS_TRUE == lower_inode_found )
    {
	CACHE_TRACE5( "INODE %d '%s' < %d '%s'; we lose",
		      TODOinode, TODOname, uniq_inode, 
		      names->global_uniq_file );
	free( (void *) TODOname );
	rc = globus_l_gass_cache_unlink( names->global_uniq_file );
	if (  ( GLOBUS_L_ENOENT != rc ) && ( rc < 0 )  )
	{
	    RET_ERROR( rc );
	}
	RET_ERROR( GLOBUS_L_ENOTUNIQ );
    }
    else
    {
	return GLOBUS_SUCCESS;
    }

} /* globus_l_gass_cache_create_uniq_global_file() */

/*
 * globus_l_gass_cache_create_global_url_file()
 *
 * Create the global "URL" file
 * Note: Currently we're not checking the URL for match
 *  
 * Parameters:
 *
 * Returns:
 *	GLOBUS_SUCCESS
 *	Errors returned by _build_filename(), _create(), _link()
 */
static
int
globus_l_gass_cache_create_global_url_file( cache_names	*names )
{
    int		rc = GLOBUS_SUCCESS;
    char	*uniq_filename = GLOBUS_NULL;

    /* Build "uniq" file name */
    rc = globus_l_gass_cache_build_filename( 
	names->global_dir,
	URL_FILE,
	names->uniq,
	GLOBUS_FALSE,
	&uniq_filename );
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* Write the file */
    rc = globus_l_gass_cache_create( 
	uniq_filename, names->global_dir, GLOBUS_L_GASS_CACHE_URLFILE_MODE,
	names->url, strlen( names->url )  );
    if ( GLOBUS_SUCCESS != rc )
    {
	globus_free( uniq_filename );
	RET_ERROR( rc );
    }

    /* Link it to the real URL file */
    rc = globus_l_gass_cache_link( uniq_filename, names->global_url_file );
    (void) globus_l_gass_cache_unlink( uniq_filename );
    globus_free( uniq_filename );
    if ( GLOBUS_L_EEXISTS == rc )
    {
	/* Probably, here, we should verify that the URLs match... */
	return GLOBUS_SUCCESS;
    }
    else if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* All ok! */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_create_global_url_file() */

/*
 * globus_l_gass_cache_create_global_file()
 *
 * Build a cache filename; can be used to generate either the global
 * or local file names.  Pass tag=NULL for global.
 *  
 * Parameters:
 *
 * Returns:
 *	- GLOBUS_SUCCESS
 *	- Returned failures from globus_l_gass_cache_creat()
 *	- Returned failures from globus_l_gass_cache_link()
 *	- Returned failures from globus_l_gass_cache_unlink()
 */
static
int
globus_l_gass_cache_create_global_file( cache_names	*names,
					globus_bool_t	force )
{
    int			rc = GLOBUS_SUCCESS;
    int			uniq_count;
    struct dirent 	**uniq_list;

    /* Build file name */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_filename( 
	    names->global_dir,
	    UDATA_FILE,
	    names->uniq,
	    GLOBUS_FALSE,
	    &names->global_uniq_file );
    }

    /* Scan the directory */
    rc = globus_l_gass_cache_scandir( 
	names->global_dir,
	&uniq_list,
	&uniq_count,
	globus_l_gass_cache_scandir_select_uniq );

    /* Check for errors */
    if ( GLOBUS_L_ENOENT == rc )
    {
	return GLOBUS_L_ENOENT;
    }
    else if ( GLOBUS_SUCCESS != rc )
    {
	return GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE;
    }
    else if ( ( uniq_count > 0 ) && ( GLOBUS_FALSE == force ) )
    {
	globus_l_gass_cache_scandir_free( uniq_list, uniq_count );
	return GLOBUS_L_ENOTUNIQ;
    }

    /* Here, either the count is zero, or we're in force mode.. */
    globus_l_gass_cache_scandir_free( uniq_list, uniq_count );

    /* Create my uniq file */
    rc = globus_l_gass_cache_create_uniq_global_file( names );
    if ( rc < 0 )
    {
	RET_ERROR( rc );
    }

    /* Create my "URL" file */
    rc = globus_l_gass_cache_create_global_url_file( names );
    if ( rc < 0 )
    {
	RET_ERROR( rc );
    }

    /* Done; all ok */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_create_global_file() */

/*
 * globus_l_gass_cache_make_ready()
 *
 * Make the global file "ready".
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_make_ready( cache_names	*names,
				unsigned long	timestamp )
{
    struct stat		statbuf;
    int			rc = GLOBUS_SUCCESS;

    /* Build the file names */
    /* Note that these will be freed by the top level call to names_free() */

    /* Build the uniq file name */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_filename( 
	    names->global_dir, UDATA_FILE, names->uniq, GLOBUS_FALSE,
	    &names->global_uniq_file );
    }

    /* Handle errors */
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* Does the uniq file exist?  If so, something's wrong! */
    while ( 1 )
    {
	rc = globus_l_gass_cache_stat( names->global_uniq_file, &statbuf );
	if ( GLOBUS_L_ENOENT == rc )
	{
	    /* If uniq doesn't exist & data does, it's already ready! */
	    rc = globus_l_gass_cache_stat( names->global_data_file,
					   GLOBUS_NULL );
	    if ( GLOBUS_SUCCESS == rc )
	    {
		RET_ERROR( GLOBUS_L_READY_MYPROC );
	    }
	    else
	    {
		RET_ERROR( GLOBUS_L_ENODATA );
	    }
	}
	else if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( rc );
	}
	if ( S_ISDIR( statbuf.st_mode ) )
	{
	    RET_ERROR( GLOBUS_L_EOTHER );
	}

	/* Set the uniq file's timestamp */
	rc = globus_l_gass_cache_set_timestamp(
	    names->global_uniq_file, timestamp );
	if ( GLOBUS_L_ENOENT == rc )
	{
	    continue;	/* Do nothing, loop back to top, should fail stat() */
	}
	else if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE );
	}

	/* Create a link between uniq and data */
	rc = globus_l_gass_cache_link( names->global_uniq_file,
				       names->global_data_file );

	/* If successful, exit the loop */
	if ( GLOBUS_SUCCESS == rc )
	{
	    break;
	}

	/* Handle errors from link() */
	if ( GLOBUS_L_EEXISTS == rc )
	{
	    /* Other process beat us to it; no harm done, though... */
	    CACHE_TRACE2( "MAKE_READY: Lost, unlinking '%s'",
			  names->global_uniq_file );
	    globus_l_gass_cache_unlink( names->global_uniq_file );
	    RET_ERROR( GLOBUS_L_READY_OTHER );
	}
	else if ( GLOBUS_L_ENOENT == rc )
	{
	    /* Do nothing, loop back to top, should fail stat() */
	}
	else
	{
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE );
	}
    }

    /* And, unlink the "uniq" version, leaving behind only the global */
    rc = globus_l_gass_cache_unlink( names->global_uniq_file );
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* Done. */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_make_ready() */

/*
 * globus_l_gass_cache_make_unready()
 *
 * Build a cache filename; can be used to generate either the global
 * or local file names.  Pass tag=NULL for global.
 *  
 * Parameters:
 *
 * Returns:
 *	GLOBUS_L_CACHE_UNLINK_LAST
 *
 */
static
int
globus_l_gass_cache_make_unready( cache_names	*names )
{
# if GLOBUS_L_GASS_CACHE_RENAMEBUG
    struct stat	statbuf;
    int		lock_age;
    time_t	cur_time;
# endif
    int		rc = GLOBUS_SUCCESS;

    /* Build the name of the uniq file... */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_filename( 
	    names->global_dir, UDATA_FILE, names->uniq, GLOBUS_FALSE,
	    &names->global_uniq_file );
    }
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }


    /* The RedHat 6.2 kernel (2.2.19) seems to have a race bug in which
     * rename() allows two processes to "win".  i.e.:
     * process a: a=rename("x", "a");
     * process b: b=rename("x", "b");
     * Results: a==0, b==0, file "x" gone, but "a" and "b" are hard
     * links to each other.  This is a work-around for this bug
     */
# if GLOBUS_L_GASS_CACHE_RENAMEBUG

    /*
     * 1. Link data -> lock
     * 2a. Fail: Check lock age, break lock if old, start over
     * 2b. Fail, lock not old: return ENODATA
     * 2c. Ok: Rename 'data' -> data.uniq
     */

    /* Create lock file name */
    rc = globus_l_gass_cache_build_filename(
	names->global_dir, LOCK_FILE, GLOBUS_NULL, GLOBUS_FALSE, 
	&names->globaldir_lock_file );
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* Loop 'til we get the lock ok, lock taken, or failure */
    while( 1 )
    {

	/* Link it to the lock file */
	rc = globus_l_gass_cache_link( names->global_data_file,
				       names->globaldir_lock_file );

	/* If ok, we win! */
	if ( GLOBUS_SUCCESS == rc )
	{
	    break;
	}
	/* Some other process killed our temp file! */
	else if ( GLOBUS_L_ENOENT == rc )
	{
	    CACHE_TRACE( "Unready; data file (@link) gone!" );
	    RET_ERROR( GLOBUS_L_ENODATA );
	}

	/* Some other error from link().  Bomb out */
	else if ( GLOBUS_L_EEXISTS != rc )
	{
	    MARK_ERRORMSG( rc, names->global_data_file );
	    MARK_ERRORMSG( rc, names->globaldir_lock_file );
	    RET_ERRORMSG( rc, "Unready: unknown link error" );
	}

	/* Lock file already exists */
	/* ( GLOBUS_L_EEXISTS == rc ) */
	CACHE_TRACE( "Unready; didn't get lock (EEXISTS)" );

	/* Check the lock file's status. */
	rc = globus_l_gass_cache_stat( names->globaldir_lock_file, &statbuf );
	if ( GLOBUS_L_ENOENT == rc )
	{
	    /* It went away; go try again */
	    CACHE_TRACE( "Unready: Link failed, but ENOENT" );
	    continue;
	}
	else if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( rc );
	}

	/* Make sure it's still valid */
	cur_time = time( NULL );
	lock_age = globus_l_gass_cache_calc_file_age( GLOBUS_NULL,
						      cur_time,
						      statbuf.st_mtime );
	/* If it's too old, invalidate it */
	if ( lock_age > LOCK_MAX_SECONDS )
	{
	    CACHE_TRACE3( "Killing global lock file %s; age = %d sec",
			  names->globaldir_lock_file, lock_age );
	    (void) globus_l_gass_cache_unlink( names->globaldir_lock_file );
	    /* Go back to the top and try again! */
	    continue;
	}

	/* Here, we lost the race.  Return ENODATA to the caller. */
	globus_libc_usleep( LOCK_SLEEP_USEC );
	rc = GLOBUS_L_ENODATA;
	break;
    }

# endif

    /* Do the rename if all is ok */
    if ( GLOBUS_SUCCESS == rc )
    {
	int	tmp_rc = GLOBUS_SUCCESS;
	rc = globus_l_gass_cache_rename( names->global_data_file,
					 names->global_uniq_file );

	/* Unlock the file (if required) */
#     if GLOBUS_L_GASS_CACHE_RENAMEBUG
	tmp_rc = globus_l_gass_cache_unlink( names->globaldir_lock_file );
#     endif

	/* Just call rename.. */
	if ( ( GLOBUS_SUCCESS == rc ) && ( GLOBUS_SUCCESS == tmp_rc )  )
	{
	    return GLOBUS_SUCCESS;
	}
	else if ( GLOBUS_L_ENOENT == rc )
	{
	    RET_ERROR( GLOBUS_L_ENODATA );
	}
	else
	{
	    RET_ERROR( GLOBUS_L_EOTHER );
	}
    }

    /* Failed to get the lock */

    /* Return the error */
    RET_ERROR( rc );

} /* globus_l_gass_cache_make_unready() */

/*
 * globus_l_gass_cache_wait_ready()
 *
 * Wait for the global file to become ready.
 *  
 * Parameters:
 *
 * Returns:
 *  GLOBUS_SUCCESS
 *  GLOBUS_L_ENODATA - *Data* file does not exist
 *  Retuned failures from globus_l_gass_cache_stat()
 *  Retuned failures from globus_l_gass_cache_unlink()
 *
 */
static
int
globus_l_gass_cache_wait_ready( const cache_names	*names,
				unsigned long		*timestamp )
{
    int			rc;
    struct stat		statbuf;
    time_t		checktime;	/* When should we do a lock check? */
    int			uniq_count;
    struct dirent 	**uniq_list = GLOBUS_NULL;
    int			uniq_num;
    int			uniq_num_recent;
    time_t		cur_time;
    time_t		dir_age = 0;
    time_t		TODOmin_age = 9999999;
    int			global_dir_len;
    int			cur_statpath_size = 0;
    char		*cur_statpath;

    /* Default to check right away, then we'll wait before further checks */
    checktime = ( time(NULL) + 0 );

    /* Run til we're done */
    while( 1 )
    {

	/* Stat the global directory.. */
	rc = globus_l_gass_cache_stat( names->global_dir, &statbuf );
	if ( GLOBUS_L_ENOENT == rc )
	{
	    RET_ERROR( GLOBUS_L_ENODATA );
	}
	else if ( GLOBUS_SUCCESS == rc )
	{
	    dir_age = globus_l_gass_cache_calc_file_age( 
		GLOBUS_NULL, cur_time, statbuf.st_mtime );
	}
	else
	{
	    RET_ERROR( rc );
	}
	CLR_ERROR;

	/* Stat the global data file.  If it's there, we're done. */
	rc = globus_l_gass_cache_stat( names->global_data_file, &statbuf );
	if ( GLOBUS_SUCCESS == rc )
	{
	    if ( GLOBUS_NULL != timestamp )
	    {
		*timestamp = (unsigned long) statbuf.st_mtime;
	    }
	    return GLOBUS_SUCCESS;
	}
	/* If it's not ENOENT, bad... */
	else if ( GLOBUS_L_ENOENT != rc )
	{
	    RET_ERROR( rc );
	}
	CLR_ERROR;

	/* Time to check the transfer stats? */
	if ( time(NULL) < checktime )
	{
	    sleep( 1 );
	    continue;
	}
	/* Update for next time.. */
	checktime = ( time(NULL) + NOTREADY_CHECK_SECONDS );

	/* Scan the directory; we're looking at *all* of the "uniq" files */
	rc = globus_l_gass_cache_scandir( 
	    names->global_dir,
	    &uniq_list,
	    &uniq_count,
	    globus_l_gass_cache_scandir_select_uniq );

	/* ENOENT means the directory somehow got smoked on us... */
	if ( GLOBUS_L_ENOENT == rc )
	{
	    RET_ERROR( GLOBUS_L_ENODATA );
	}
	/* Something else bad happenned */
	else if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE );
	}
	/* rc == 0 means no matches...  Something's wrong.. */
	else if ( 0 == uniq_count )
	{
	    globus_l_gass_cache_scandir_free( uniq_list, uniq_count );
	    RET_ERRORMSG( GLOBUS_L_ENODATA, names->global_dir );
	}

	/* Stat them all, check their mtime's */
	global_dir_len = strlen( names->global_dir );
	uniq_num_recent = 0;
	cur_time = time( NULL );
	cur_statpath = GLOBUS_NULL;
	for ( uniq_num = 0;  uniq_num < uniq_count; uniq_num++ )
	{
	    time_t	age;		/* Age (seconds) of the file */
	    int		min_size;	/* Min file name buffer size */
	    int		request_size;	/* Buffer size to request */

	    /* Compute the required file name buffer size. */
	    min_size =
		strlen( uniq_list[uniq_num]->d_name ) + global_dir_len + 2;
	    request_size = min_size + 50;

	    /* Allocate (or reallocate if our buffer is too small) a file name
	       buffer to use with stat() */
	    if ( GLOBUS_NULL == cur_statpath )
	    {
		cur_statpath = globus_libc_malloc( request_size );
		if ( GLOBUS_NULL == cur_statpath )
		{
		    globus_l_gass_cache_scandir_free( uniq_list, uniq_count );
		    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );
		}
		cur_statpath_size = request_size;
	    }
	    else if ( min_size > cur_statpath_size )
	    {
		char	*new;
		new = globus_libc_realloc( cur_statpath,
						    request_size );
		if ( GLOBUS_NULL == new )
		{
		    globus_libc_free( cur_statpath );
		    globus_l_gass_cache_scandir_free( uniq_list, uniq_count );
		    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );
		}
		cur_statpath = new;
		cur_statpath_size = request_size;
	    }

	    /* Fill in the file name buffer */
	    strcpy( cur_statpath, names->global_dir );
	    strcat( cur_statpath, "/" );
	    strcat( cur_statpath, uniq_list[uniq_num]->d_name );

	    /* Now, go stat() the file and learn all about it */
	    rc = globus_l_gass_cache_stat( cur_statpath, & statbuf);

	    /* If it's gone away, ignore it.. */
	    if ( GLOBUS_L_ENOENT == rc )
	    {
		CLR_ERROR;
		continue;
	    }
	    else if ( GLOBUS_SUCCESS != rc )
	    {
		/* BAD */
		globus_free( uniq_list );
		RET_ERROR( rc );
	    }

	    /* Now, if the file's been modified recently, update our oount */
	    age = globus_l_gass_cache_calc_file_age( GLOBUS_NULL,
						     cur_time,
						     statbuf.st_mtime );
	    if ( age <  NOTREADY_MAX_SECONDS )
	    {
		uniq_num_recent++;
	    }
	    if ( age < TODOmin_age )
	    {
		TODOmin_age = age;
	    }
	}

	/* Free our stat file name buffer */
	if ( GLOBUS_NULL != cur_statpath )
	{
	    globus_libc_free( cur_statpath );
	}

	/* Done with the list! */
	globus_l_gass_cache_scandir_free( uniq_list, uniq_count );

	/*
	 * If there are none, it means we should give up waiting, and
	 * take over the download process oursleves.
	 */
	if ( ( 0 == uniq_num_recent ) && ( dir_age > NOTREADY_MAX_SECONDS ) )
	{
	    CACHE_TRACE4( "WREADY: %d files, none recent, min age = %d"
			  ", dir age = %d", uniq_count, TODOmin_age, dir_age );
	    RET_ERROR( GLOBUS_L_ETIMEOUT );
	}

	/* Otherwise, just sleep a bit, then go try the whole thing over.. */
	sleep( 1 );
	continue;
    }

} /* globus_l_gass_cache_wait_ready() */

/*
 * globus_l_gass_cache_find_uniq()
 *
 * Find a uniq file
 *  
 * Parameters:
 *
 * Returns:
 *  GLOBUS_SUCCESS
 *  GLOBUS_L_ENODATA - *Data* file does not exist
 *  Retuned failures from globus_l_gass_cache_stat()
 *  Retuned failures from globus_l_gass_cache_unlink()
 *
 */
static
int
globus_l_gass_cache_find_uniq( const char	*dir,
			       char		**uniq_file,
			       int		*uniq_count )
{
    int			rc;
    struct dirent 	**uniq_list = GLOBUS_NULL;

    /* Scan the directory; we're looking at *all* of the "uniq" files */
    *uniq_count = 0;
    rc = globus_l_gass_cache_scandir( 
	dir,
	&uniq_list,
	uniq_count,
	globus_l_gass_cache_scandir_select_uniq );

    /* Something else bad happenned */
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }
    /* Count == 0 means no matches...  Something's wrong.. */
    else if ( 0 == *uniq_count )
    {
	globus_l_gass_cache_scandir_free( uniq_list, *uniq_count );
	RET_ERROR( GLOBUS_L_ENOENT );
    }

    /* Copy out the name of the first one.. */
    *uniq_file = strdup( uniq_list[0]->d_name );

    /* Free the list */
    globus_l_gass_cache_scandir_free( uniq_list, *uniq_count );

    /* Done */
    return (  ( GLOBUS_NULL == uniq_file ) ? 
	      GLOBUS_GASS_CACHE_ERROR_NO_MEMORY : GLOBUS_SUCCESS );

} /* globus_l_gass_cache_find_uniq() */

/*
 * globus_l_gass_cache_lock_delay()
 *
 * Sleep for LOOP_LOCK_TIME uSeconds, but backs off based on the value of
 * tryno, and also has a random factor built in.
 *
 * Parameters:
 *
 *	tryno : Attempt number
 *
 * Returns: 
 *
 *     # Of uSec acutal slept
 */
static
long
globus_l_gass_cache_lock_delay( int tryno )
{
    long	usec;

    usec = LOCK_SLEEP_USEC + ( random() % LOCK_SLEEP_USEC );
    if ( tryno > 5 )
	usec >>= 1;
    if ( tryno > 10 )
	usec >>= 1;
    if ( tryno > 100 )
	usec >>= 1;
    if ( tryno > 1000 )
	usec >>= 1;
    if ( 0 != usec )
    {
	globus_libc_usleep( usec );
    }
    return usec;
}
/* globus_l_gass_cache_lock_delay() */

/*
 * globus_l_gass_cache_lock_local_dir()
 *
 * Lock the local directory
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_lock_local_dir( cache_names	*names,
				    const char	*existing_file )
{
    int			rc;
    struct stat		statbuf;
    time_t		cur_time;
    int			tryno = 0;
    int			lock_age;

    /* Build the lock file name */
    rc = globus_l_gass_cache_build_filename(
	names->local_dir, LOCK_FILE, GLOBUS_NULL,
	GLOBUS_FALSE, &names->localdir_lock_file );
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* Run til we're done */
    while( 1 )
    {
	/* Link to the lock file.  If it works, we're done */
	rc = globus_l_gass_cache_link( existing_file, 
				       names->localdir_lock_file );
	if ( GLOBUS_SUCCESS == rc )
	{
	    return GLOBUS_SUCCESS;
	}
	/* If it's not EEXISTS, bad... */
	else if ( GLOBUS_L_EEXISTS != rc )
	{
	    RET_ERROR( rc );
	}
	CLR_ERROR;

	/* EEXISTS; check the lock file time stamp */
	rc = globus_l_gass_cache_stat( names->localdir_lock_file, &statbuf );
	if ( GLOBUS_L_ENOENT == rc )
	{
	    CLR_ERROR;
	    continue;
	}
	else if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( rc );
	}

	/* Has the file been modified recently?  If not, then probably
	   the process which is downloading it died */
	cur_time = time( NULL );
	lock_age = globus_l_gass_cache_calc_file_age( GLOBUS_NULL,
						      cur_time,
						      statbuf.st_mtime );
	if ( lock_age > LOCK_MAX_SECONDS )
	{
	    /* Kill the file and start over */
	    CACHE_TRACE3( "Breaking lock on tag '%s'; local dir = %s",
			  names->tag, names->local_dir );
	    rc = globus_l_gass_cache_unlink( names->localdir_lock_file );
	    if ( GLOBUS_SUCCESS != rc )
	    {
		RET_ERROR( rc );
	    }
	    continue;
	}

	/* Sleep for a bit, then go back and try again.. */
	globus_l_gass_cache_lock_delay( tryno++ );
    }

} /* globus_l_gass_cache_lock_local_dir() */

/*
 * globus_l_gass_cache_unlock_local_dir()
 *
 * Unlock the local directory
 *
 * Parameters:
 *	names - The standard "names" structure of various file/dir names
 *
 *	target_name - Unlock can rename the existing lock file to a
 *	target name.  Specify GLOBUS_NULL to not do this.
 *
 * Returns:
 *	GLOBUS_SUCESS
 *	Values returned from _build_filename(), _unlink(), and _rename()
 *
 * Notes:
 */

static
int
globus_l_gass_cache_unlock_local_dir( cache_names	*names,
				      const char	*target_name )
{
    int		rc = GLOBUS_SUCCESS;

    /* Build the lock file name (should be valid already, but doesn't hurt */
    rc = globus_l_gass_cache_build_filename(
	names->local_dir, LOCK_FILE, GLOBUS_NULL,
	GLOBUS_FALSE, &names->localdir_lock_file );
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* If the target name is valid, rename to it.. */
    if ( GLOBUS_NULL != target_name )
    {
	int	tmp_rc;

	/* rename(a,b) doesn't always work as you would expect.  If a
	 * & b are _hard links_ to each other, it is valid for
	 * rename(a,b) to return 0 (success), and do _nothing_
	 * (i.e. leave a and b).  For this reason, you see the
	 * _unlink() followed by _rename() * logic below. */

	/* Kill the target file, if it exists */
	tmp_rc = globus_l_gass_cache_stat( target_name, GLOBUS_NULL );
	if ( GLOBUS_SUCCESS == tmp_rc )
	{
	    (void) globus_l_gass_cache_unlink( target_name );
	}
	CLR_ERROR;	/* This is ok! */

	/* Now, we should be safe to rename to it (we still have the
	 * "dir lock".  This will also _release_ this lock. */
	rc = globus_l_gass_cache_rename( names->localdir_lock_file,
					 target_name );
	if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( rc );
	}
    }
    /* Otherwise, just kill the lock file */
    else
    {
	rc = globus_l_gass_cache_unlink( names->localdir_lock_file );
	if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( rc );
	}
    }

    /* All ok */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_unlock_local_dir() */

/*
 * globus_l_gass_cache_create_local_tag_file()
 *
 * Create the local "Tag" file
 * Note: Currently we're not checking the tag for match
 *  
 * Parameters:
 *
 * Returns:
 *	GLOBUS_SUCCESS
 *	Errors returned by _build_filename(), _create(), _link()
 */
static
int
globus_l_gass_cache_create_local_tag_file( cache_names	*names )
{
    int		rc = GLOBUS_SUCCESS;
    char	*uniq_filename = GLOBUS_NULL;

    /* Build "uniq" file name */
    rc = globus_l_gass_cache_build_filename( 
	names->tmp_root,
	TAG_FILE,
	names->uniq,
	GLOBUS_FALSE,
	&uniq_filename );
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* Write the file */
    rc = globus_l_gass_cache_create( 
	uniq_filename, names->local_dir, GLOBUS_L_GASS_CACHE_TAGFILE_MODE,
	names->tag, strlen( names->tag )  );
    if ( GLOBUS_SUCCESS != rc )
    {
	globus_free( uniq_filename );
	RET_ERROR( rc );
    }

    /* Create the real tag file by linking to this temp one.. */
    rc = globus_l_gass_cache_link( uniq_filename, names->local_tag_file );
    (void) globus_l_gass_cache_unlink( uniq_filename );
    globus_free( uniq_filename );
    if ( ( GLOBUS_SUCCESS != rc ) && ( GLOBUS_L_EEXISTS != rc )  )
    {
	RET_ERROR( rc );
    }

    /* Link it to the "tag link" file, which is down in the URL subdir */
    rc = globus_l_gass_cache_link( names->local_tag_file,
				   names->local_tag_link );
    if ( ( GLOBUS_SUCCESS != rc ) && ( GLOBUS_L_EEXISTS != rc )  )
    {
	RET_ERROR( rc );
    }

    /* All ok! */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_create_local_tag_file() */

/*
 * globus_l_gass_cache_make_local_file()
 *
 * Build a cache filename; can be used to generate either the global
 * or local file names.  Pass tag=NULL for global.
 *  
 * Parameters:
 *
 * Returns:
 *
 */
static
int
globus_l_gass_cache_make_local_file( cache_names	*names,
				     const char		*global_name,
				     const char		*global_uniq )
{
    int		rc = GLOBUS_SUCCESS;
    char	*global_file = GLOBUS_NULL;

    /* Build the uniq file name */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_filename(
	    names->local_dir, UDATA_FILE, names->uniq,
	    GLOBUS_FALSE, &names->local_uniq_file );
    }

    /* Make sure the local directory exists. */
    rc = globus_l_gass_cache_make_dirtree( names->local_dir );
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* Create the "tag" file... */
    rc = globus_l_gass_cache_create_local_tag_file( names );
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* Build the name of the global file..
     * Note: We're using our own "global_file" here, and it must
     *  be freed up before returning */
    rc = globus_l_gass_cache_build_filename(
	names->global_dir, global_name, global_uniq, GLOBUS_TRUE,
	&global_file );
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* Link the global file to the local file. */
    rc = globus_l_gass_cache_link( global_file, names->local_data_file );
    
    /* We're done with the gloal file buffer, so free it right away. */
    globus_free( global_file );

    /* Now, check the return status of the _link() call above */
    if ( GLOBUS_L_ENOENT == rc )
    {
	RET_ERROR( GLOBUS_L_ENODATA );
    }
    else if ( GLOBUS_SUCCESS == rc )
    {
	/* Create the tag file */
	if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( rc );
	}
    }
    else if ( GLOBUS_L_EEXISTS == rc )
    {
	CLR_ERROR;	/* This is ok! */
    }
    else
    {	
	/* Badness 10000 */
	RET_ERROR( rc );
    }

    /* Get a lock on the local directory (use data to link from; its easy) */
    rc = globus_l_gass_cache_lock_local_dir( names, names->local_data_file );
    if ( GLOBUS_SUCCESS != rc )
    {
	/* Failed to get lock for some reason.  Bail out. */
	RET_ERROR( rc );
    }

    /* Release the lock & create a uniq "link count" file in one op */
    rc = globus_l_gass_cache_unlock_local_dir( names,
					       names->local_uniq_file );
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }
    return rc;

} /* globus_l_gass_cache_make_local_file() */

/*
 * globus_l_gass_cache_unlink_local()
 *
 * Build a cache filename; can be used to generate either the global
 * or local file names.  Pass tag=NULL for global.
 *  
 * Parameters:
 *
 * Returns:
 *	GLOBUS_L_CACHE_UNLINK_LAST
 *
 */
static
int
globus_l_gass_cache_unlink_local( cache_names	*names )
{
    char	*uniq_file = GLOBUS_NULL;
    int		uniq_count;
    int		rc = GLOBUS_SUCCESS;

    /* Lock the target tag directory */
    rc = globus_l_gass_cache_lock_local_dir( names, names->local_data_file );
    if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* Find a uniq file to kill... */
    rc = globus_l_gass_cache_find_uniq( names->local_dir,
					&uniq_file, 
					&uniq_count );
    if ( GLOBUS_SUCCESS != rc )
    {
	(void) globus_l_gass_cache_unlock_local_dir( names, GLOBUS_NULL );
	RET_ERROR( rc );
    }

    /* Kill the uniq file */
    if ( uniq_count > 0 )
    {
	char	*uniq_filepath = GLOBUS_NULL;
	rc = globus_l_gass_cache_build_filename(
	    names->local_dir, uniq_file, GLOBUS_NULL, GLOBUS_FALSE,
	    &uniq_filepath );
	globus_free( uniq_file );	/* We're done with this */
	uniq_file = GLOBUS_NULL;
	if ( GLOBUS_SUCCESS != rc )
	{
	    (void) globus_l_gass_cache_unlock_local_dir( names, GLOBUS_NULL );
	    RET_ERROR( rc );
	}
	rc = globus_l_gass_cache_unlink( uniq_filepath );
	globus_free( uniq_filepath );	/* We're done with this now */
	if ( GLOBUS_SUCCESS != rc )
	{
	    (void) globus_l_gass_cache_unlock_local_dir( names, GLOBUS_NULL );
	    RET_ERROR( rc );
	}
    }

    /* Free up the buffer for the uniq file. */
    if ( GLOBUS_NULL != uniq_file )
    {
	globus_free( uniq_file );
    }

    /* If this is the last one, we can do some bigger cleanups... */
    if ( 1 == uniq_count )
    {
	rc = globus_l_gass_cache_unlink( names->local_data_file );
	if (  ( GLOBUS_SUCCESS != rc ) && 
	      ( GLOBUS_L_ENOENT != rc ) )
	{
	    (void) globus_l_gass_cache_unlock_local_dir( names, GLOBUS_NULL );
	    RET_ERROR( rc );
	}
	CLR_ERROR;
    }

    /* Release the lock */
    rc = globus_l_gass_cache_unlock_local_dir( names, GLOBUS_NULL );
    if (  ( GLOBUS_SUCCESS != rc ) && ( GLOBUS_L_ENOENT != rc ) )
    {
	RET_ERROR( rc );
    }
    CLR_ERROR;

    /* Finally, cleanup the directory tree... */
    if ( 1 == uniq_count )
    {
	struct stat	statbuf;

	/* Kill the local data file */
	rc = globus_l_gass_cache_unlink( names->local_data_file );
	if (  ( GLOBUS_SUCCESS != rc ) && 
	      ( GLOBUS_L_ENOENT != rc ) )
	{
	    RET_ERROR( rc );
	}

	/* Kill the URL under the local tag dir (if empty) */
	rc = globus_l_gass_cache_remove_dirtree( names->local_root,
						 names->local_dir );

	/* >0 is ok: remove_dirtree() is oportunistic... */
	if ( rc < 0 )
	{
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_DELETE_DATA_F );
	}

	/* Kill the tag *link* file */
	/* It's ok if somebody else beat us to it */
	(void) globus_l_gass_cache_unlink( names->local_tag_link );

	/* Now, stat the *main* tag file, see how many links it has */
	/* It's ok if somebody else killed it before us! */
	rc = globus_l_gass_cache_stat( names->local_tag_file, &statbuf );
	if ( GLOBUS_SUCCESS == rc )
	{
	    if ( 1 == statbuf.st_nlink )
	    {
		(void) globus_l_gass_cache_unlink( names->local_tag_file );
	    }
	}

	/* Finally, try to kill the rest of the tree... */
	rc = globus_l_gass_cache_remove_dirtree( names->local_root,
						 names->local_dir );

	/* >0 is ok: remove_dirtree() is oportunistic... */
	if ( rc < 0 )
	{
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_CAN_NOT_DELETE_DATA_F );
	}

	/* Tell the caller that we've removed the last one.. */
	return GLOBUS_L_UNLINK_LAST;
    }

    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_unlink_local() */

/*
 * globus_l_gass_cache_unlink_global()
 *
 * Unlink the global data & URL file, remove the global directory if empty.
 *  
 * Parameters:
 *	names - File & dir name
 *
 * Returns:
 *	GLOBUS_SUCCESS
 *	GLOBUS_L_CACHE_UNLINK_LAST
 *	Errors returned by _stat(), _unlink(), _remove_dirtree()
 *
 */
static
int
globus_l_gass_cache_unlink_global( cache_names		*names,
				   globus_bool_t	is_locked )
{
    struct stat	statbuf;
    const char	*global_file;
    int		rc = GLOBUS_SUCCESS;

    /* Stat the global file (or uniq file if _we_ have it locked) */
    if ( is_locked )
    {
	/* Make sure that the uniq file name is valid */
	rc = globus_l_gass_cache_build_filename( 
	    names->global_dir,
	    UDATA_FILE,
	    names->uniq,
	    GLOBUS_FALSE,
	    &names->global_uniq_file );
	if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( rc );
	}
	global_file = names->global_uniq_file;
    }
    else
    {
	global_file = names->global_data_file;
    }
    rc = globus_l_gass_cache_stat( global_file, &statbuf );

    /* ENOENT here means that it was killed by another process, ok */
    if ( GLOBUS_L_ENOENT == rc )
    {
	/* Other proc's shoulded kill _our_ uniq file!! */
	if ( is_locked )
	{
	    RET_ERROR( GLOBUS_L_ENOENT );
	}
	/* But, it's ok to kill the _global_ (shared) data file */
	else
	{
	    return GLOBUS_SUCCESS;
	}
    }
    /* Something else went wrong! */
    else if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* If it's still in use, nothing to do! */
    if ( statbuf.st_nlink > 1 )
    {
	return GLOBUS_SUCCESS;
    }

    /* Kill it */
    (void) globus_l_gass_cache_unlink( names->global_url_file );
    rc = globus_l_gass_cache_unlink( global_file );
    if ( ( GLOBUS_SUCCESS != rc ) && ( GLOBUS_L_ENOENT != rc ) )
    {
	RET_ERROR( rc );
    }

    /* And, clean up the dirtree.. */
    rc = globus_l_gass_cache_remove_dirtree( names->global_root, 
					     names->global_dir );
    if ( rc < 0 )
    {
	RET_ERROR( rc );
    }

    /* Tell the caller that we've removed the last one.. */
    return GLOBUS_L_UNLINK_LAST;

} /* globus_l_gass_cache_unlink_global() */

/*
 * globus_l_gass_cache_list_all_urls()
 *
 * Build a cache filename; can be used to generate either the global
 * or local file names.  Pass tag=NULL for global.
 *  
 * Parameters:
 *
 * Returns:
 *	- GLOBUS_SUCCESS
 *	- GLOBUS_L_ENOTUNIQ		- We ddin't win the race
 *	- Returned failures from globus_l_gass_cache_creat()
 *	- Returned failures from globus_l_gass_cache_link()
 *	- Returned failures from globus_l_gass_cache_unlink()
 */
static
int
globus_l_gass_cache_list_all_urls( const char		*search_dir,
				   const char		*base_mangled,
				   url_list_head	*url_list )
{
    int			rc;
    int			dirent_count;
    int			dirent_num;
    struct dirent 	**dirent_list = NULL;
    struct stat		statbuf;
    int			data_count = 0;

    /* Scan the directory; we're looking at *all* of the "uniq" files */
    rc = globus_l_gass_cache_scandir( 
	search_dir,
	&dirent_list,
	&dirent_count,
	globus_l_gass_cache_scandir_select_all );

    /* Something bad happenned */
    if ( rc < 0 )
    {
	CACHE_TRACE2( "SCAN: Error scanning '%s'", search_dir );
	RET_ERROR( rc );
    }
    /* rc == 0 means no matches.  Hmmmm..  Skip it for now  */
    else if ( 0 == dirent_count )
    {
	globus_l_gass_cache_scandir_free( dirent_list, dirent_count );
	RET_ERROR( GLOBUS_L_ENOENT );
    }
    /* Just . & .. ? */
    else if ( dirent_count <= 2 )
    {
	globus_l_gass_cache_scandir_free( dirent_list, dirent_count );
	return GLOBUS_SUCCESS;
    }

    /* Walk through the matches... */
    for ( dirent_num = 0;  dirent_num < dirent_count; dirent_num++ )
    {
	const char	*name = dirent_list[dirent_num]->d_name;
	char		name_path[ PATH_MAX + 1 ];

	/* Build it's full path */
	strcpy( name_path, search_dir );
	strcat( name_path, "/" );
	strcat( name_path, name );

	/* Stat it to find out what it is... */
	rc = globus_l_gass_cache_stat( name_path, &statbuf );

	/* Errors?! */
	if ( GLOBUS_SUCCESS != rc )
	{
	    globus_l_gass_cache_scandir_free( dirent_list, dirent_count );
	    CACHE_TRACE2( "SCAN: Can't stat '%s'", name_path );
	    RET_ERROR( rc );
	}

	/* If it's a file, this must be a URL; mark it & go on */
	if ( ! S_ISDIR( statbuf.st_mode ) )
	{
	    /* If it's a "uniq" data file ("data.*"), count it */
	    if ( ! strncmp( name, UDATA_FILE_PAT, UDATA_FILE_PAT_LEN ) )
	    {
		data_count++;
	    }
	    /* Otherwise, ignore it (probably a URL or tag file) */
	}
	/* Ignore "." and "..", but process all other dirs */
	else if (  ( strcmp ( name, "." ) ) && ( strcmp( name, ".." ) )  )
	{
	    char	new_mangled[ PATH_MAX + 1 ];

	    strcpy( new_mangled, base_mangled );
	    if ( new_mangled[0] != '\0' )
	    {
		strcat( new_mangled, "/" );
	    }
	    strcat( new_mangled, name );
	    rc = globus_l_gass_cache_list_all_urls( name_path,
						    new_mangled,
						    url_list );
	}
    }

    /* Free up the dirent list */
    globus_l_gass_cache_scandir_free( dirent_list, dirent_count );

    /* Add myself to the list */
    if ( data_count )
    {
	url_list_elem	*new_url_elem = 
	    globus_malloc( sizeof( url_list_elem ) );
	if ( GLOBUS_NULL == new_url_elem )
	{
	    CACHE_TRACE( "list_all_files: malloc failed" );
	    RET_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );
	}
	else
	{
	    new_url_elem->mangled = strdup( base_mangled );
	    new_url_elem->data_count = data_count;
	    new_url_elem->next = url_list->head;
	    url_list->head = new_url_elem;
	    url_list->count++;
	}
    }
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_list_all_urls() */

/*
 * globus_l_gass_cache_delete()
 *
 * Build a cache filename; can be used to generate either the global
 * or local file names.  Pass tag=NULL for global.
 *  
 * Parameters:
 *
 * Returns:
 *	- GLOBUS_SUCCESS
 *	- GLOBUS_L_ENOTUNIQ		- We ddin't win the race
 *	- Returned failures from globus_l_gass_cache_creat()
 *	- Returned failures from globus_l_gass_cache_link()
 *	- Returned failures from globus_l_gass_cache_unlink()
 */
static
int
globus_l_gass_cache_delete( cache_names		*names,
			    const unsigned long	*timestamp,
			    globus_bool_t	is_locked )
{
    int		rc = GLOBUS_SUCCESS;		/* Temp return code */

    /* Wait for the file to become "ready" */
    if ( ! is_locked )
    {
	rc = globus_l_gass_cache_wait_ready( names, GLOBUS_NULL );

	/* It got blown away by somebody else */
	if ( ( GLOBUS_L_ENODATA == rc ) || ( GLOBUS_L_ENOENT == rc ) )
	{
	    return GLOBUS_SUCCESS;	    /* Nothing to do */
	}
	else if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( rc );
	}
    }

    /* Cleanup the local */
    rc = globus_l_gass_cache_unlink_local( names );
    if ( GLOBUS_L_UNLINK_LAST == rc )
    {
	rc = globus_l_gass_cache_unlink_global( names, is_locked );
	if ( GLOBUS_L_UNLINK_LAST == rc )
	{
	    /* Do nothing */
	}
	else if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( rc );
	}
    }
    /* Set the file's timestamp (if the we're passed one) */
    else if ( ( GLOBUS_SUCCESS == rc ) && ( GLOBUS_NULL != timestamp ) )
    {
	rc = globus_l_gass_cache_set_timestamp( 
	    names->global_data_file, *timestamp );
	if ( GLOBUS_SUCCESS != rc )
	{
	    RET_ERROR( rc );
	}
    }
    /* Log errors from unlink_local */
    else if ( GLOBUS_SUCCESS != rc )
    {
	RET_ERROR( rc );
    }

    /* Done */
    return GLOBUS_SUCCESS;

} /* globus_l_gass_cache_delete() */


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
globus_gass_cache_open(const char		*cache_directory_path,
		       globus_gass_cache_t	*cache_handle)

{
    int         rc;			/* general purpose returned code */
    char *      pt;			/* general purpose returned pointer */
    int		f_name_length;		/* to verify len of the file names */
    char	f_name[PATH_MAX+1];	/* path name of the 3 files to open */
#  if defined GLOBUS_L_GASS_CACHE_LOG
    char        log_f_name[PATH_MAX+1]; /* log file file name */
#  endif
    char	*uniq;
    char        homedir[PATH_MAX];

    CHECK_CACHE_IS_NOT_INIT(cache_handle);
    memset( cache_handle, 0, sizeof( globus_gass_cache_t ) );
    CLR_ERROR;

    /* Random initialize */
    {
	struct timeval tv;
	gettimeofday( &tv, NULL );
	srandom( tv.tv_usec );
    }
    
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

	/* if GLOBUS_GASS_CACHE_DEFAULT empty (""),
	   behave as if not defined */
	if ( GLOBUS_NULL != pt )
	{
	    f_name_length = strlen(pt);
	    if ( 0 == f_name_length )
	    {
		pt = GLOBUS_NULL;
	    }
	}

	if ( GLOBUS_NULL == pt )
	{
	    GLOBUS_L_GASS_CACHE_LG2( "'%s' is empty", 
				     GLOBUS_L_GASS_CACHE_DEFAULT_DIR_ENV_VAR );
	    /* cache directory still not defined; use the defaults */
	    /*   "$HOME/.globus_gass_cache" */
	    if ( globus_libc_gethomedir(homedir,PATH_MAX) == GLOBUS_SUCCESS)
	    {
		f_name_length=strlen(homedir);
		if ( f_name_length > 0)
		    pt = homedir;
	    }
	    
	    if ( GLOBUS_NULL == pt )
	    {
		/* $HOME not defined or null ! this should not happen */
		LOG_ERROR(0);
		return ( GLOBUS_GASS_CACHE_ERROR_NO_HOME );
	    }

	    if ((f_name_length +
		 strlen(GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME))>=PATH_MAX)
	    {
		CACHE_TRACE("ENAMETOOLONG");
                printf("NAMETOOLONG: f_name_length: %d, "
		       "default_name_length: %d, filename_max: %d\n",
                       f_name_length,
                       strlen(GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME),
                       PATH_MAX);
		LOG_ERROR(0);
		return ( GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG);
	    }

	    /* Allocate a buffer for & build the base directory */
	    cache_handle->cache_directory_path = (char * ) malloc(
		1 +
		strlen( pt ) +
		strlen( GLOBUS_L_DOT_GLOBUS_DIR_NAME ) +
		strlen( GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME) );
	    if ( GLOBUS_NULL == cache_handle->cache_directory_path )
	    {
		LOG_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );
		return GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
	    }
	    strcpy( cache_handle->cache_directory_path, pt );
	    strcat( cache_handle->cache_directory_path,
		    GLOBUS_L_DOT_GLOBUS_DIR_NAME );
	    strcat(cache_handle->cache_directory_path,
		   GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME);
	    cache_handle->global_dir_len = 
		strlen( cache_handle->cache_directory_path );

	    /* Build & verify the whole tree */
	    rc = globus_l_gass_cache_make_dirtree( 
		cache_handle->cache_directory_path );
	    if ( GLOBUS_L_ENOTDIR == rc )
	    {
		CACHE_TRACE( " .globus is not a directory" );
		LOG_ERROR(rc);
		return GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE;
	    }
	    else if ( GLOBUS_SUCCESS != rc )
	    {
		CACHE_TRACE( "Could not create the .globus directory" );
		LOG_ERROR(rc);
		return GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE;
	    }

	}
	else /* *pt is not null or empty */
	{
	    if (f_name_length >= PATH_MAX)
	    {
		CACHE_TRACE("ENAMETOOLONG");
		LOG_ERROR(0);
		return ( GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG);
	    }
	    cache_handle->cache_directory_path = strdup( pt );
	    if ( GLOBUS_NULL == cache_handle->cache_directory_path )
	    {
		LOG_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );
		return GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
	    }
	}
    }
    else			/* cache_directory_path is valid */
    {
	/* For the first version, we do not accept a cache_directory_path */
	{
	    /* for the version which will accept a cache directory not null  */
	    if (f_name_length >= PATH_MAX)
	    {
		CACHE_TRACE("ENAMETOOLONG");
		LOG_ERROR(0);
		return ( GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG);
	    }
	    cache_handle->cache_directory_path = 
		strdup( cache_directory_path );
	    if ( GLOBUS_NULL == cache_handle->cache_directory_path )
	    {
		LOG_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );
		return GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
	    }
	}
    }
    GLOBUS_L_GASS_CACHE_LG2(" cache directory :%s ",
		 cache_handle->cache_directory_path );

    /* here, *cache_handle.cache_directory_path should be defined */
    /* let see if it exists, and create it if it does not */
    rc = globus_l_gass_cache_make_dirtree( 
	cache_handle->cache_directory_path );
    if ( GLOBUS_L_ENOTDIR == rc )
    {
	CACHE_TRACE( " The cache directory is not a directory" );
	LOG_ERROR(rc);
	return GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE;
    }
    else if ( GLOBUS_SUCCESS != rc )
    {
	CACHE_TRACE( "Could not create the cache directory" );
	LOG_ERROR(rc);
		return GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE;
    }


    /* here I suppose cache_directory_path existe and is a directory */
    if ( ( f_name_length + MAX_FILENAME_LEN ) >= PATH_MAX )
    {
	CACHE_TRACE("ENAMETOOLONG");
	LOG_ERROR(0);
	return ( GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG);
    }
    strcpy(f_name,cache_handle->cache_directory_path);
    strcat(f_name,GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME);
    
    /* open the log file and log the some informations */
# if defined GLOBUS_L_GASS_CACHE_LOG
    {
	char	tmp[20];
	strcpy( log_f_name, cache_handle->cache_directory_path );
	strcat( log_f_name, "/" );
	strcat( log_f_name, GLOBUS_L_GASS_CACHE_LOG_DIR );
	rc = globus_l_gass_cache_make_dirtree( log_f_name );
	if ( GLOBUS_SUCCESS != rc )
	{
	    CACHE_TRACE("Could NOT open or create the log directory");
	}
	else
	{
	    sprintf( tmp, "/%05d", getpid() );
	    strcat( log_f_name, tmp );
	    cache_handle->log_FILE = fopen( log_f_name, "a" );
	    if ( cache_handle->log_FILE == GLOBUS_NULL )
	    {
		CACHE_TRACE("Could NOT open or create the log file");
	    }
	    cache_handle->log_file_name = strdup( log_f_name );
	    if ( cache_handle->log_file_name == GLOBUS_NULL )
	    {
		CACHE_TRACE("Could NOT copy log file name");
	    }
	}
    }
# endif

    /* Crate the global directory name & path */
    rc = globus_l_gass_cache_build_filename(
	cache_handle->cache_directory_path,
	GLOBUS_L_GASS_CACHE_GLOBAL_DIR,
	GLOBUS_NULL,
	GLOBUS_FALSE,
	&cache_handle->global_directory_path );
    if ( GLOBUS_SUCCESS != rc )
    {
	LOG_ERROR( rc );
	return rc;
    }
    rc = globus_l_gass_cache_make_dirtree(
	cache_handle->global_directory_path );
    if ( GLOBUS_SUCCESS != rc )
    {
	CACHE_TRACE( "Can't create the global cache directory" );
	LOG_ERROR(0);
	return ( GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG);
    }

    /* Crate the local directory name & path */
    rc = globus_l_gass_cache_build_filename(
	cache_handle->cache_directory_path,
	GLOBUS_L_GASS_CACHE_LOCAL_DIR,
	GLOBUS_NULL,
	GLOBUS_FALSE,
	&cache_handle->local_directory_path );
    if ( GLOBUS_SUCCESS != rc )
    {
	LOG_ERROR( rc );
	return rc;
    }
    rc = globus_l_gass_cache_make_dirtree(
	cache_handle->local_directory_path );
    if ( GLOBUS_SUCCESS != rc )
    {
	CACHE_TRACE( "Can't create the local cache directory" );
	LOG_ERROR(0);
	return ( GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG);
    }

    /* Crate the tmp directory name & path */
    rc = globus_l_gass_cache_build_filename(
	cache_handle->cache_directory_path,
	GLOBUS_L_GASS_CACHE_TMP_DIR,
	GLOBUS_NULL,
	GLOBUS_FALSE,
	&cache_handle->tmp_directory_path );
    if ( GLOBUS_SUCCESS != rc )
    {
	LOG_ERROR( rc );
	return rc;
    }
    rc = globus_l_gass_cache_make_dirtree(
	cache_handle->tmp_directory_path );
    if ( GLOBUS_SUCCESS != rc )
    {
	CACHE_TRACE( "Can't create the tmp cache directory" );
	LOG_ERROR(0);
	return ( GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG);
    }

    /* Finally, initialize the skew calc stuff */
    rc = globus_l_gass_cache_build_uniqname( &uniq );
    if ( GLOBUS_SUCCESS == rc )
    {
	char	*skew_file = GLOBUS_NULL;
	rc = globus_l_gass_cache_build_filename( 
	    cache_handle->tmp_directory_path, GLOBUS_NULL,
	    uniq, GLOBUS_FALSE, &skew_file );
	globus_free( uniq );
	if ( GLOBUS_SUCCESS != rc )
	{
	    LOG_ERROR( GLOBUS_GASS_CACHE_ERROR_NO_MEMORY );
	    return GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
	}
	(void) globus_l_gass_cache_calc_file_age( skew_file,
						  time(NULL), 
						  time(NULL) );
	globus_free( skew_file );
    }
    else
    {
	LOG_ERROR( rc );
	return rc;
    }

    /* Max mangled lengths */
    {
	/* Just take the longest & tack on some "buffer"... */
	int	max_dirlen = strlen( cache_handle->global_directory_path ) + 8;
	int	max_len = _POSIX_PATH_MAX - max_dirlen;

	cache_handle->max_mangled_url = max_len / 2;
	cache_handle->max_mangled_tag = max_len / 2;

	/* Default to enable all mangling options. */
	cache_handle->mangling_options = MANGLING_OPTION_DEFAULT;
    }
    /* Lastly, note that we are initialized. */
    cache_handle->init = &globus_l_gass_cache_is_init;

    /* Done */
    return GLOBUS_SUCCESS;
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
    CHECK_CACHE_IS_INIT(cache_handle);
    CLR_ERROR;

    /* marque this handle as not opened */
    cache_handle->init=&globus_l_gass_cache_is_not_init;
# if defined GLOBUS_L_GASS_CACHE_LOG
    {
	if ( GLOBUS_NULL != cache_handle->log_FILE )
	{
	    fclose(cache_handle->log_FILE);
	    cache_handle->log_FILE = GLOBUS_NULL;
	}
	/* Blow away zero sized log files */
	if ( GLOBUS_NULL != cache_handle->log_file_name )
	{
	    struct stat	statbuf;
	    int		rc;
	    rc = globus_l_gass_cache_stat( 
		cache_handle->log_file_name, &statbuf );
	    if ( GLOBUS_SUCCESS == rc )
	    {
		if ( 0 == statbuf.st_size )
		{
		    globus_l_gass_cache_unlink( cache_handle->log_file_name );
		}
	    }
	    globus_free( cache_handle->log_file_name );
	}
    }
# endif

    /* Free up memory */
    globus_free( cache_handle->cache_directory_path );
    globus_free( cache_handle->global_directory_path );
    globus_free( cache_handle->local_directory_path );
    globus_free( cache_handle->tmp_directory_path );
    
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
    globus_gass_cache_t *	cache_handle,
    const char			*url,
    const char			*tag,
    globus_bool_t		create,
    unsigned long *		timestamp,
    char **			local_filename )
{
    int			rc;			/* general purpose ret code */
    int			retval = GLOBUS_SUCCESS; /* Our return value. */
    cache_names		names;
    int			TODOattempts = 0;
    int			data_count, uniq_count;
    double		TODOstime = TODOGetTime();
    const char		*global_name;
    const char		*global_uniq;
    globus_bool_t	wait_timeout = GLOBUS_FALSE;

    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT(cache_handle);
    CLR_ERROR;
    
    /* Timestamp is unknown for now, no filename, ... */
    *timestamp = GLOBUS_GASS_CACHE_TIMESTAMP_UNKNOWN;
    *local_filename = GLOBUS_NULL;

    /* Generate the local and global filenames */
    rc = globus_l_gass_cache_names_init( cache_handle, url, tag, &names );

    /* Check if it all succeeded. */
    if ( GLOBUS_SUCCESS != rc )
    {
	LOG_ERROR( rc );
	return rc;
    }

    /* I want to do every thing again and again until the data file 
       is ready */
    while ( 1 )
    {
	TODOattempts++;

	/* Create the global directory tree if we need to */
	if ( create )
	{
	    rc = globus_l_gass_cache_make_dirtree( names.global_dir );
	    if ( rc != GLOBUS_SUCCESS )
	    {
		globus_l_gass_cache_names_free( &names );
		LOG_ERROR( rc );
		return rc;
	    }
	}

	/* Check the file *data* file */
	rc = globus_l_gass_cache_check_global_file( &names,
						    &data_count,
						    &uniq_count );

	/* Special case: handle data lock timeout */
	if (  ( GLOBUS_SUCCESS == rc ) &&
	      ( GLOBUS_TRUE == wait_timeout ) &&
	      ( 0 == data_count )  )
	{
	    /* Handle this like the "no data" condition. */
	    rc = GLOBUS_L_ENODATA;
	}

	/* Doesn't exist? */
	if ( GLOBUS_L_ENODATA == rc )
	{
	    CLR_ERROR;
	    /* If we're not supposed to create it, give up.. */
	    if ( ! create )
	    {
		globus_l_gass_cache_names_free( &names );
		return GLOBUS_GASS_CACHE_URL_NOT_FOUND;
	    }

	    /* Now, go create the global file. */
	    CACHE_TRACE4( "Global file DNE; creating %s/%s%s",
			  names.global_dir, UDATA_FILE, names.uniq );
	    rc = globus_l_gass_cache_create_global_file( &names,
							 wait_timeout );
	    if ( GLOBUS_L_ENOENT == rc )
	    {
		/* Directory has disappeared. */
		continue;
	    }
	    else if ( GLOBUS_L_ENOTUNIQ == rc )
	    {
		/* We're not uniq; go back to the top */
		continue;
	    }
	    else if ( GLOBUS_SUCCESS != rc )
	    {
		globus_l_gass_cache_names_free( &names );
		LOG_ERROR( rc );
		return rc;
	    }

	    /* Ok.  We've created the global "uniq" file.  Now, make
	     * the local.  Don't wait for it to become ready - we
	     * created it!! */
	    rc = globus_l_gass_cache_make_local_file( 
		&names,
		UDATA_FILE,
		names.uniq );
	    if ( GLOBUS_L_ENODATA == rc )
	    {
		continue;
	    }
	    else if ( GLOBUS_SUCCESS != rc )
	    {
		globus_l_gass_cache_names_free( &names );
		LOG_ERROR( rc );
		return rc;
	    }

	    /* Ok.  We're done! */
	    retval = GLOBUS_GASS_CACHE_ADD_NEW;
	    break;
	}

	/* Something bad happenned */
	else if ( GLOBUS_SUCCESS != rc )
	{
	    globus_l_gass_cache_names_free( &names );
	    LOG_ERROR( rc );
	    return rc;
	}


	/* Ok, the global data existed before we got here. */
	/*   Wait for it to become ready */
	CACHE_TRACE3( "Global file exists; using %s/%s",
		      names.global_dir, DATA_FILE );
	rc = globus_l_gass_cache_wait_ready( &names, timestamp );
	if ( GLOBUS_L_ENODATA == rc )
	{
	    CACHE_TRACE( "Data file went away; start over" );
	    continue;	/* Data file went away; start over. */
	}
	else if ( GLOBUS_L_ETIMEOUT == rc )
	{
	    CACHE_TRACE( "Wait timed out" );
	    wait_timeout = GLOBUS_TRUE;
	    continue;	/* Wait timed out; go back to the top... */
	}
	else if ( GLOBUS_SUCCESS != rc )
	{
	    globus_l_gass_cache_names_free( &names );
	    LOG_ERROR( rc );
	    return rc;
	}

	/* Lock the file */
#     if ( LOCK_ADD_EXISTS )
	TODOgu( global_dir, uniq, NULL );
	TODOgu( NULL, NULL, "Ready; locking" );
	CACHE_TRACE2( "Global file ready; locking -> %s", names.uniq );
	rc = globus_l_gass_cache_make_unready( &names );
	if ( GLOBUS_L_ENODATA == rc )
	{
	    CACHE_TRACE( "Global file went away!" );
	    continue;		/* Data file went away; start over. */
	}
	else if ( GLOBUS_SUCCESS != rc )
	{
	    globus_l_gass_cache_names_free( &names );
	    LOG_ERROR( rc );
	    return rc;
	}
	/* Lock used; use the uniq file name in make_local_file() */
	global_name = UDATA_FILE;
	global_uniq = names.uniq;
#     else
	/* No lock; use the "raw" data file name in make_local_file() */
	global_name = DATA_FILE;
	global_uniq = GLOBUS_NULL;
#     endif

	/* Ok; it's ready.  Make the local file, then we're done */
	TODOgu( NULL, NULL, "Before MLF" );
	rc = globus_l_gass_cache_make_local_file( 
	    &names,
	    global_name,
	    global_uniq );
	TODOgu( NULL, NULL, "After MLF" );
	if ( GLOBUS_L_ENODATA == rc )
	{
	    CACHE_TRACE( "Global file went away!" );
	    continue;	/* Data file went away; start over. */
	}
	else if ( GLOBUS_SUCCESS != rc )
	{
	    LOG_ERROR( rc );
	    return rc;
	}
	else
	{
	    retval = GLOBUS_GASS_CACHE_ADD_EXISTS;
	    break;
	}
    }

    {
	char buf[256];
	globus_libc_lock();
	sprintf( buf, "%s: %d attempts; %.5fs",
		 (  ( GLOBUS_GASS_CACHE_ADD_NEW == retval ) ?
		    "AddNew" : "AddExists" ),
		 TODOattempts,
		 TODOGetTime() - TODOstime );
	globus_libc_unlock();
	CACHE_TRACE( buf );
	TODOgu( NULL, NULL, "AddExists" );
    }

    if ( retval == GLOBUS_GASS_CACHE_ADD_NEW ||
	 retval == GLOBUS_GASS_CACHE_ADD_EXISTS )
    {
	*local_filename = strdup( names.local_data_file );
    }

    /* Free up the allocated memory */
    globus_l_gass_cache_names_free( &names );
    return retval;
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
    globus_gass_cache_t	*cache_handle,
    const char		*url,
    const char		*tag,
    unsigned long	timestamp)
{
    int		rc;			/* general purpose return code */
    cache_names	names;
    
    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT(cache_handle);
    CLR_ERROR;
    
    /* Generate the local and global filenames */
    rc = globus_l_gass_cache_names_init( 
	cache_handle, url, tag, &names );
    if ( GLOBUS_SUCCESS != rc )
    {
	LOG_ERROR( rc );
	return rc;
    }

    /* Create the ready file */
    rc = globus_l_gass_cache_make_ready( &names, timestamp );

    /* Another process beat us to the punch */
    if ( GLOBUS_L_READY_OTHER == rc )
    {
	/* No harm done, make_ready() killed our uniq file for us. */
	globus_l_gass_cache_names_free( &names );
	return GLOBUS_SUCCESS;
    }
    /* OUR process already has it in the ready state */
    else if ( GLOBUS_L_READY_MYPROC == rc )
    {
# if ( ! LOCK_ADD_EXISTS )
	globus_l_gass_cache_names_free( &names );
	CLR_ERROR;	
	return GLOBUS_SUCCESS;
# else
	CACHE_TRACE3( "Lost my uniq file '%s' in '%s', data exists",
		      names.uniq, names.global_dir );
	globus_l_gass_cache_names_free( &names );
	LOG_ERROR( GLOBUS_GASS_CACHE_ERROR_ALREADY_DONE );
	return GLOBUS_GASS_CACHE_ERROR_ALREADY_DONE;
# endif
    }
    else if ( GLOBUS_SUCCESS != rc )
    {
	globus_l_gass_cache_names_free( &names );
	LOG_ERROR( rc );
	return rc;
    }

    globus_l_gass_cache_names_free( &names );
    return GLOBUS_SUCCESS;

}
/* globus_gass_cache_add_done() */

/*
 * globus_gass_cache_query()
 *
 * Query if an item is in the cache
 *
 * This call will block only if wait_for_lock is GLOBUS_TRUE
 *
 * Parameters:
 *
 *     cache_handle - Handler to the opened cahe directory to use.
 *
 *     url - url of the file to query. It is used as the main
 *     key to the cache entries.
 *
 *     tag - tag specifying which job is/are using the cache. This
 *     is usually the GLOBUS_GRAM_JOB_CONTACT. Can be NULL or empty; the
 *     tag "null" is then used.
 *     create - Tells if the cache entry should be created if it is
 *     not already existing.
 *
 *     wait_for_lock - If GLOBUS_TRUE, wait for any lock existing lock
 *     to be released.  If GLOBUS_FALSE, doesn't wait for a lock to be
 *     released.
 *
 *     timestamp - time stamp of the cached file, set by
 *     globus_gass_cache_done(), (or globus_gass_cache_delete() ).
 *
 *     local_filename - Path the the local file caching the file
 *     specified by "url". NULL if "url" not yet cached and
 *     creation not requested (create false).
 *
 *     is_locked - GLOBUS_TRUE if the file is currently (at return
 *     time) locked.
 *
 * Returns:
 *     GLOBUS_SUCCESS
 *     GLOBUS_GASS_CACHE_URL_NOT_FOUND
 *     or any of the defined gass error code.
 *
 */
int
globus_gass_cache_query(
    globus_gass_cache_t		*cache_handle,
    const char			*url,
    const char			*tag,
    globus_bool_t		wait_for_lock,
    unsigned long		*timestamp,
    char			**local_filename,
    globus_bool_t		*is_locked )
{
    int			rc;			/* general purpose ret code */
    cache_names		names;
    globus_bool_t	locked;
    int			data_count, uniq_count;

    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT(cache_handle);
    CLR_ERROR;
    
    /* Generate the local and global filenames */
    rc = globus_l_gass_cache_names_init( cache_handle, url, tag, &names );

    /* Check if it all succeeded. */
    if ( GLOBUS_SUCCESS != rc )
    {
	LOG_ERROR( rc );
	return rc;
    }

    /* Check the file *data* file */
    rc = globus_l_gass_cache_check_global_file( &names,
						&data_count,
						&uniq_count );

    /* Wait for it to become ready? */
    if (  ( GLOBUS_SUCCESS == rc ) && ( wait_for_lock )  )
    {
	rc = globus_l_gass_cache_wait_ready( &names, timestamp );
	locked = GLOBUS_FALSE;
    }
    else
    {
	locked = ( 0 == data_count ) ? GLOBUS_FALSE : GLOBUS_TRUE;
    }

    /* Does a local file exist? */
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_stat( names.local_data_file, GLOBUS_NULL );
    }

    /* Copy output to passed in ptrs. */
    if ( GLOBUS_SUCCESS == rc )
    {
	if ( local_filename )
	{
	    *local_filename = strdup( names.local_data_file );
	}
	if ( is_locked )
	{
	    *is_locked = locked;
	}
    }

    /* Clean up & finish. */
    globus_l_gass_cache_names_free( &names );
    if ( GLOBUS_L_ENODATA == rc )
    {
	rc = GLOBUS_GASS_CACHE_URL_NOT_FOUND;
    }
    return rc;
}
/*  globus_gass_cache_query() */

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
globus_gass_cache_delete_start(globus_gass_cache_t	*cache_handle,
			       const char		*url,
			       const char		*tag,
			       unsigned long		*timestamp)
{
    int		rc;			/* general purpose return code */
    cache_names	names;
    
    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT(cache_handle);
    CLR_ERROR;
    
    /* Generate the local and global filenames */
    rc = globus_l_gass_cache_names_init( 
	cache_handle, url, tag, &names );
    if ( GLOBUS_SUCCESS != rc )
    {
	LOG_ERROR( rc );
	return rc;
    }

    /* Wait for the file to become "ready" */
    rc = globus_l_gass_cache_wait_ready( &names, timestamp );
    if ( ( GLOBUS_L_ENODATA == rc ) || ( GLOBUS_L_ETIMEOUT == rc ) )
    {
	globus_l_gass_cache_names_free( &names );
	LOG_ERROR( rc );
	return GLOBUS_GASS_CACHE_ERROR_URL_NOT_FOUND;
    }
    else if ( GLOBUS_SUCCESS != rc )
    {
	globus_l_gass_cache_names_free( &names );
	LOG_ERROR( rc );
	return GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT;
    }

    /* Lock the file */
    CACHE_TRACE2( "Global file ready; locking -> %s", names.uniq );
    rc = globus_l_gass_cache_make_unready( &names );

    /* Free up the name buffers before checking for simplicity */
    globus_l_gass_cache_names_free( &names );

    /* Now, check the status */
    if ( GLOBUS_L_ENODATA == rc )
    {
	CACHE_TRACE( "Global file went away!" );
	LOG_ERROR( rc );
	return GLOBUS_GASS_CACHE_ERROR_URL_NOT_FOUND;
    }
    else if ( GLOBUS_SUCCESS != rc )
    {
	LOG_ERROR( rc );
	return GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT;
    }

    /* Done */
    return GLOBUS_SUCCESS;
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
    const char		*url,
    const char		*tag,
    unsigned long        timestamp,
    globus_bool_t        is_locked )
{ 
    int		rc;			/* general purpose return code */
    int		retval = GLOBUS_SUCCESS; /* Our return value. */
    cache_names	names;
    double	TODOstime = TODOGetTime();
    
    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT(cache_handle);
    
    /* Generate the local and global filenames */
    rc = globus_l_gass_cache_names_init( 
	cache_handle, url, tag, &names );

    /* Check if they all succeeded. */
    if ( GLOBUS_SUCCESS != rc )
    {
	LOG_ERROR( rc );
	return rc;
    }

    /* Do the actual delete... */
    rc = globus_l_gass_cache_delete( 
	&names, &timestamp, is_locked );

    /* Free up name buffers */
    globus_l_gass_cache_names_free( &names );

    /* Clean up! */
    if ( GLOBUS_SUCCESS != rc )
    {
	LOG_ERROR( rc );
	return rc;
    }

    /* Build some file names that we'll use. */
    {
	char buf[256];
	globus_libc_lock();
	sprintf( buf, "DELETE; %.3fs", TODOGetTime() - TODOstime );
	globus_libc_unlock();
	CACHE_TRACE( buf );
    }
    return retval;

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
    const char		*url,
    const char		*tag)
{
    int		rc;			/* general purpose return code */
    cache_names	names;
    double	TODOstime = TODOGetTime();
    int		TODOnum = 0;
    
    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT(cache_handle);
    
    /* Generate the local and global filenames */
    rc = globus_l_gass_cache_names_init( 
	cache_handle, url, tag, &names );

    /* Check if they all succeeded. */
    if ( GLOBUS_SUCCESS != rc )
    {
	LOG_ERROR( rc );
	return rc;
    }

    /* It's got a mangled name; kill it! */
    rc = globus_l_gass_cache_delete( &names, GLOBUS_NULL, GLOBUS_FALSE );

    /* Free up the name strings */
    globus_l_gass_cache_names_free( &names );

    /* Check our status */
    if ( GLOBUS_SUCCESS != rc )
    {
	LOG_ERROR( rc );
	return rc;
    }

    /* Build some file names that we'll use. */
    {
	char buf[256];
	globus_libc_lock();
	sprintf( buf, "Cleanup %d; %.3fs", TODOnum, TODOGetTime()-TODOstime );
	globus_libc_unlock();
	CACHE_TRACE( buf );
    }
    return rc;
    
}
/*globus_gass_cache_add_cleanup_tag() */

/*
 * globus_gass_cache_cleanup_tag_all()
 *
 * Remove all instances of the tag from the cache entry's tag list.
 * If there are no more tags in the tag list, then remove this cache entry
 * and delete the associated local cache file.
 * If the cache entry is locked with the same tag as is passed to this
 * function, then the entry is unlocked after removing the tags.
 * Otherwise, the cache entry's lock is left untouched.
 *
 * This function does not block on a locked reference.  This function
 * differs from globus_gass_cache_cleanup_tag() in that this cleans up
 * *all* URLs related with this tag.
 *
 * Note: The GLOBUS_GRAM job manager will automatically call this function
 * with a tag of getenv("GLOBUS_GRAM_JOB_CONTACT") upon completion of a job.
 *
 * Parameters:
 *
 *     cache_handle - Handler to the opened cahe directory to use.
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
globus_gass_cache_cleanup_tag_all(
    globus_gass_cache_t *cache_handle,
    char                *tag )
{
    int			rc;			/* Temp return code */
    int			retval = GLOBUS_SUCCESS; /* Our return value. */
    cache_names		names;
    char		*base_local_dir;
    double		TODOstime = TODOGetTime();
    url_list_head	url_list;
    url_list_elem	*url_elem, *url_next;
    int			data_num;
    
    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT(cache_handle);
    
    /* Build the base local directory to use. */
    rc = globus_l_gass_cache_names_init( 
	cache_handle, GLOBUS_NULL, tag, &names );
    if ( GLOBUS_SUCCESS == rc )
    {
	rc = globus_l_gass_cache_build_dirname(
	    names.local_root,
	    names.mangled_tag,
	    GLOBUS_NULL,
	    &base_local_dir,
	    GLOBUS_NULL );
    }

    /* Scan for URLs */
    url_list.head = GLOBUS_NULL;
    url_list.count = 0;
    rc = globus_l_gass_cache_list_all_urls( base_local_dir,
					    "",
					    &url_list );
    CACHE_TRACE4( "cleanup: scanned '%s' (tag '%s'), found %d", 
		  base_local_dir, tag, url_list.count );

    /* Walk through 'em all */
    url_elem = url_list.head;
    while ( GLOBUS_NULL != url_elem )
    {
	/* It's got a mangled name; kill it! */
	if ( ( GLOBUS_NULL != url_elem->mangled ) &&
	     ( strlen( url_elem->mangled ) > 0 )  )
	{

	    /* Put the new mangled URL into the name structure */
	    rc = globus_l_gass_cache_names_new_murl(
		url_elem->mangled, &names );
	    if ( GLOBUS_SUCCESS != rc )
	    {
		MARK_ERRORMSG( rc, url_elem->mangled );
		LOG_ERROR( rc );
		retval = rc;
		continue;
	    }

	    /* Loop through all of the "data" links found */
	    for( data_num = 0;  data_num < url_elem->data_count;  data_num++ )
	    {
		rc = globus_l_gass_cache_delete( &names, GLOBUS_NULL, 
						 GLOBUS_FALSE);
		if ( GLOBUS_SUCCESS != rc )
		{
		    char	buff[1024];
		    sprintf(buff,"MURL=\"%s\"", url_elem->mangled);
		    MARK_ERRORMSG( rc, buff );
		    LOG_ERROR( rc );
		    retval = rc;
		    break;
		}
	    }
	}

	/* Free up the mangled URL buffer */
	if ( GLOBUS_NULL != url_elem->mangled )
	{
	    free( url_elem->mangled );
	}

	/* Free up the URL list structure & name buffer */
	url_next = url_elem->next;
	free( url_elem );
	url_elem = url_next;
    }

    /* Done */
    globus_l_gass_cache_names_free( &names );

    /* Build some file names that we'll use. */
    {
	char buf[256];
	globus_libc_lock();
	sprintf( buf, "CleanupAll %.3fs", TODOGetTime()-TODOstime );
	globus_libc_unlock();
	CACHE_TRACE( buf );
    }
    return retval;
}
/*globus_gass_cache_add_cleanup_tag_all() */

/*
 * globus_gass_cache_mangle_url()
 *
 * Mangles the given URL into a chunk suitable for using as a file /
 * path name.  This is exported for use in the globus_gass_cache
 * program.
 *  
 * Parameters:
 *      cache_handle - Handler to the opened cahe directory to use.
 *
 *	url - The incoming URL to mangle (\0 terminated)
 *
 *	mangled_url - Pointer to the output string; a buffer for the
 *	real string is malloc()ed for the application.  If mangled is
 *	NULL, then no such buffer is allocated, and no mangled string
 *	is created.  This can be useful to just get the length of the
 *	mangled string.
 *
 *	Length - The length of the resulting string.  If NULL, this is
 *	not assigned to.
 *
 * Returns:
 *	GLOBUS_SUCCESS
 *	GLOBUS_GASS_CACHE_ERROR_NO_MEMORY
 *
 */
int
globus_gass_cache_mangle_url( const globus_gass_cache_t	*cache_handle,
			      const char		*url,
			      char			**mangled_url,
			      int			*length )
{

    /* Let _mangle() do all the work! */
    return globus_l_gass_cache_mangle( url,
				       cache_handle->mangling_options,
				       cache_handle->max_mangled_url,
				       mangled_url,
				       length );

} /* globus_gass_cache_mangle_url() */

/*
 * globus_gass_cache_mangle_tag()
 *
 * Mangles the given tag into a chunk suitable for using as a file /
 * path name.  This is exported for use in the globus_gass_cache
 * program.
 *  
 * Parameters:
 *      cache_handle - Handler to the opened cahe directory to use.
 *
 *	tag - The incoming tag to mangle (\0 terminated)
 *
 *	mangled_tag - Pointer to the output string; a buffer for the
 *	real string is malloc()ed for the application.  If mangled is
 *	NULL, then no such buffer is allocated, and no mangled string
 *	is created.  This can be useful to just get the length of the
 *	mangled string.
 *
 *	Length - The length of the resulting string.  If NULL, this is
 *	not assigned to.
 *
 * Returns:
 *	GLOBUS_SUCCESS
 *	GLOBUS_GASS_CACHE_ERROR_NO_MEMORY
 *
 */
int
globus_gass_cache_mangle_tag( const globus_gass_cache_t	*cache_handle,
			      const char		*tag,
			      char			**mangled_tag,
			      int			*length )
{

    /* Let _mangle() do all the work! */
    return globus_l_gass_cache_mangle( tag,
				       cache_handle->mangling_options,
				       cache_handle->max_mangled_tag,
				       mangled_tag,
				       length );

} /* globus_gass_cache_mangle_tag() */

/*
 * globus_gass_cache_get_dirs()
 *
 * Gets a bunch of directories.  This is exported for use in the
 * globus_gass_cache program.
 *  
 * Parameters:
 *      cache_handle - Handler to the opened cahe directory to use.
 *
 *	URL - The incoming URL
 *
 *	tag - The incoming tag
 *
 *	local_root - Pointer to the "local root" directory
 *
 *	global_root - Pointer to the "global root" directory
 *
 *	tmp_root - Pointer to the "tmp root" directory
 *
 *	log_root - Pointer to the root log directory
 *
 *	local_dir - Pointer to the related "local" directory
 *
 *	global_dir - Pointer to the related "global" directory
 *
 * Returns:
 *	GLOBUS_SUCCESS
 *	GLOBUS_GASS_CACHE_ERROR_NO_MEMORY
 *
 */
int
globus_gass_cache_get_dirs( const globus_gass_cache_t	*cache_handle,
			    const char			*url,
			    const char			*tag,
			    char			**global_root,
			    char			**local_root,
			    char			**tmp_root,
			    char			**log_root,
			    char			**global_dir,
			    char			**local_dir )
{
    int		rc = GLOBUS_SUCCESS;	/* general purpose return code */
    cache_names	names;

    /* Initialize 'em all to NULL */
    if ( global_root )
    {
	*global_root = GLOBUS_NULL;
    }
    if ( local_root )
    {
	*local_root = GLOBUS_NULL;
    }
    if ( tmp_root )
    {
	*tmp_root = GLOBUS_NULL;
    }
    if ( log_root )
    {
	*log_root = GLOBUS_NULL;
    }
    if ( global_dir )
    {
	*global_dir = GLOBUS_NULL;
    }
    if ( local_dir )
    {
	*local_dir = GLOBUS_NULL;
    }
    
    /* simply check if the cache has been opened */
    CHECK_CACHE_IS_INIT(cache_handle);
    
    /* Generate the local and global filenames */
    rc = globus_l_gass_cache_names_init( 
	cache_handle, url, tag, &names );

    /* Check if they all succeeded. */
    if ( GLOBUS_SUCCESS != rc )
    {
	LOG_ERROR( rc );
	return rc;
    }

    /* Copy out the path pieces.... */
    if ( ( global_root ) && ( names.global_root ) )
    {
	if (  ( *global_root = strdup( names.global_root ) ) == GLOBUS_NULL )
	{
	    rc = GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
	}
    }
    if ( ( local_root ) && ( names.local_root ) )
    {
	if (  ( *local_root = strdup( names.local_root ) ) == GLOBUS_NULL )
	{
	    rc = GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
	}
    }
    if ( ( tmp_root ) && ( names.tmp_root ) )
    {
	if (  ( *tmp_root = strdup( names.tmp_root ) ) == GLOBUS_NULL )
	{
	    rc = GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
	}
    }
    if ( ( log_root ) && ( names.log_root ) )
    {
	if (  ( *log_root = strdup( names.log_root ) ) == GLOBUS_NULL )
	{
	    rc = GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
	}
    }
    if ( ( global_dir ) && ( names.global_dir ) )
    {
	if (  ( *global_dir = strdup( names.global_dir ) ) == GLOBUS_NULL )
	{
	    rc = GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
	}
    }
    if ( ( local_dir ) && ( names.local_dir ) )
    {
	if (  ( *local_dir = strdup( names.local_dir ) ) == GLOBUS_NULL )
	{
	    rc = GLOBUS_GASS_CACHE_ERROR_NO_MEMORY;
	}
    }

    /* Free up name buffers */
    globus_l_gass_cache_names_free( &names );

    /* Done if all ok. */
    if ( GLOBUS_SUCCESS == rc )
    {
	return GLOBUS_SUCCESS;
    }

    /* Handle errors w/o leaking memory! */
    if ( ( global_root ) && ( *global_root ) )
    {
	globus_free( *global_root );
	*global_root = GLOBUS_NULL;
    }
    if ( ( local_root ) && ( *local_root ) )
    {
	globus_free( *local_root );
	*local_root = GLOBUS_NULL;
    }
    if ( ( tmp_root ) && ( *tmp_root ) )
    {
	globus_free( *tmp_root );
	*tmp_root = GLOBUS_NULL;
    }
    if ( ( log_root ) && ( *log_root ) )
    {
	globus_free( *log_root );
	*log_root = GLOBUS_NULL;
    }
    if ( ( global_dir ) && ( *global_dir ) )
    {
	globus_free( *global_dir );
	*global_dir = GLOBUS_NULL;
    }
    if ( ( local_dir ) && ( *local_dir ) )
    {
	globus_free( *local_dir );
	*local_dir = GLOBUS_NULL;
    }

    return rc;

} /* globus_gass_cache_get_dirs() */

#if 0
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
    CHECK_CACHE_IS_INIT(cache_handle);

    rc = globus_l_gass_cache_lock_open(cache_handle);
    if (rc != GLOBUS_SUCCESS)
    {
	LOG_ERROR(rc);
	return(rc);
    }
    
    rc = globus_l_gass_cache_lookfor_url(&entry_found_pt,
					 url,
					 cache_handle);
    if (rc != GLOBUS_SUCCESS)
    {
	globus_l_gass_cache_unlock_close(cache_handle,
					 GLOBUS_L_DO_NOT_COMMIT);
	LOG_ERROR(rc);
	return(rc);
    }
    
    if (entry_found_pt == GLOBUS_NULL)   /* url not found */
    {
	GLOBUS_L_GASS_CACHE_LG("Function globus_gass_cache_cleanup_file() "
			       "called with  URL not in cache state file");
	globus_l_gass_cache_unlock_close(cache_handle,
					 GLOBUS_L_DO_NOT_COMMIT);
	LOG_ERROR(0);
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
	       GLOBUS_L_EXT_NOTREADY);
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
					  GLOBUS_L_COMMIT);
    /* and return */
    return(rc);
    
}
/*globus_gass_cache_add_cleanup_file() */
#endif


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
    unsigned	pos_errcode = ( unsigned ) ( 0 - error_code );
    unsigned	max_errcode = ( sizeof( globus_gass_cache_error_strings ) /
				sizeof( globus_gass_cache_error_strings[0] ) );

    /* Check; is this a valid error code? */
    if (  ( error_code > 0 ) || ( pos_errcode >= max_errcode )  )
    {
        return("Invalid error code");
    }
    return ( globus_gass_cache_error_strings[ pos_errcode ] );
}
/* globus_gass_cache_error_string() */

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

/******************************************************************************
globus_gass_cache.h
 
Description:
    Header of the GASS CACHE MANAGEMENT API.

    CVS Information:
 
    $Source$
    $Date$
    $Revision$

******************************************************************************/
#ifndef _GLOBUS_GASS_INCLUDE_GLOBUS_GASS_CACHE_H_
#define _GLOBUS_GASS_INCLUDE_GLOBUS_GASS_CACHE_H_

#ifndef EXTERN_C_BEGIN
#ifdef __cplusplus
#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }
#else
#define EXTERN_C_BEGIN
#define EXTERN_C_END
#endif
#endif

#ifndef WIN32
#include <sys/param.h>
#endif

#include "globus_common.h"

EXTERN_C_BEGIN


/*
 * Codes returned by globus_gass_cache module
 */

#define GLOBUS_GASS_CACHE_ADD_NEW                       1
#define GLOBUS_GASS_CACHE_URL_NOT_FOUND                 2
#define GLOBUS_GASS_CACHE_ADD_EXISTS                    3

#define GLOBUS_GASS_CACHE_ERROR_NO_HOME                -1
#define GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE         -2
#define GLOBUS_GASS_CACHE_ERROR_NAME_TOO_LONG          -3
#define GLOBUS_GASS_CACHE_ERROR_LOCK_ERROR             -4
/* not used in a first impl.: */
#define GLOBUS_GASS_CACHE_ERROR_LOCK_TIME_OUT          -5 
#define GLOBUS_GASS_CACHE_ERROR_OPEN_STATE             -6
#define GLOBUS_GASS_CACHE_ERROR_STATE_F_CORRUPT        -7
#define GLOBUS_GASS_CACHE_ERROR_NO_MEMORY              -8
#define GLOBUS_GASS_CACHE_ERROR_CAN_NOT_CREATE_DATA_F  -9
/* only for "done" or delete  :*/
#define GLOBUS_GASS_CACHE_ERROR_URL_NOT_FOUND          -10 
#define GLOBUS_GASS_CACHE_ERROR_CAN_NOT_DEL_LOCK       -11
#define GLOBUS_GASS_CACHE_ERROR_WRONG_TAG              -12
#define GLOBUS_GASS_CACHE_ERROR_ALREADY_DONE           -13
#define GLOBUS_GASS_CACHE_ERROR_CAN_NOT_WRITE          -14
#define GLOBUS_GASS_CACHE_ERROR_CAN_NOT_READ           -15
#define GLOBUS_GASS_CACHE_ERROR_CAN_NOT_DELETE_DATA_F  -16
#define GLOBUS_GASS_CACHE_ERROR_CACHE_NOT_OPENED       -17
#define GLOBUS_GASS_CACHE_ERROR_CACHE_ALREADY_OPENED   -18
#define GLOBUS_GASS_CACHE_ERROR_INVALID_PARRAMETER     -19
#define GLOBUS_GASS_CACHE_ERROR_INVALID_VERSION        -20
#define GLOBUS_GASS_CACHE_ERROR_NO_SPACE	       -21
#define GLOBUS_GASS_CACHE_ERROR_QUOTA_EXCEEDED         -22

#define GLOBUS_GASS_CACHE_TIMESTAMP_UNKNOWN 0UL

#if !defined(PATH_MAX) && defined(MAXPATHLEN)
#   define PATH_MAX MAXPATHLEN
#endif

/*
 *  Other definitions
 */


/*
 * Structure: globus_gass_cache_t
 *
 * Data structure used to store informations concerning an open cache
 * directory. This structure MUST NOT be modified directly, but passed to
 * the globus_gass_cache functions
 */
typedef struct globus_i_gass_cache_t * globus_gass_cache_t;


/*
 *
 *  FUNCTIONS
 *
 */

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
extern
int 
globus_gass_cache_open(const char*          cache_directory_path,
		       globus_gass_cache_t*  cache_handle);


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
extern int
globus_gass_cache_close(globus_gass_cache_t *  cache_handle);

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
 * GLOBUS_GASS_TIMESTAMP_UNKNOWN, lock the cache entry, and
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
extern
int
globus_gass_cache_add(globus_gass_cache_t    cache_handle,
	       const char	*url,
	       const char	*tag,
	       globus_bool_t	create,
	       unsigned long	*timestamp,
	       char		**local_filename);

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
extern int
globus_gass_cache_add_done(
    globus_gass_cache_t  cache_handle,
    const char		*url,
    const char		*tag,
    unsigned long	timestamp);

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
    globus_gass_cache_t		 cache_handle,
    const char			*url,
    const char			*tag,
    globus_bool_t		wait_for_lock,
    unsigned long		*timestamp,
    char			**local_filename,
    globus_bool_t		*is_locked );


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

extern
int
globus_gass_cache_delete_start(
    globus_gass_cache_t	 cache_handle,
    const char		*url,
    const char		*tag,
    unsigned long	*timestamp);

extern
int
globus_gass_cache_delete(
    globus_gass_cache_t  cache_handle,
    const char		*url,
    const char		*tag,
    unsigned long	timestamp,
    globus_bool_t	is_locked);

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
extern
int
globus_gass_cache_cleanup_tag(
    globus_gass_cache_t	 cache_handle,
    const char		*url,
    const char		*tag);

extern
int
globus_gass_cache_cleanup_tag_all(
    globus_gass_cache_t  cache_handle,
    char                *tag );

/*
 * globus_l_gass_cache_mangle_url()
 *
 * Mangles the given URL into a chunk suitable for using as a file /
 * path name.
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
globus_gass_cache_mangle_url( const globus_gass_cache_t	cache_handle,
			      const char		*url,
			      char			**mangled_url,
			      int			*length );

/*
 * globus_l_gass_cache_mangle_tag()
 *
 * Mangles the given tag into a chunk suitable for using as a file /
 * path name.
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
globus_gass_cache_mangle_tag( const globus_gass_cache_t	cache_handle,
			      const char		*tag,
			      char			**mangled_tag,
			      int			*length );

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
globus_gass_cache_get_dirs( const globus_gass_cache_t	 cache_handle,
			    const char			*url,
			    const char			*tag,
			    char			**global_root,
			    char			**local_root,
			    char			**tmp_root,
			    char			**log_root,
			    char			**global_dir,
			    char			**local_dir );

/*
 * globus_gass_cache_get_cache_dir()
 *
 * Gets a the root cache of directory.  This is exported for use in the
 * globus_gass_cache program.
 *  
 * Parameters:
 *      cache_handle - Handler to the opened cahe directory to use.
 *
 *	cache_dir - Pointer to the cache directory
 *
 * Returns:
 *	GLOBUS_SUCCESS
 *	GLOBUS_GASS_CACHE_ERROR_NO_MEMORY
 *
 */
int
globus_gass_cache_get_cache_dir( const globus_gass_cache_t	 cache_handle,
				 char			**cache_dir );

/*
 * globus_gass_cache_get_cache_type_string()
 *
 * Gets a string which describes the cache type ("normal" or "flat")
 *  
 * Parameters:
 *      cache_handle - Handler to the opened cahe directory to use.
 *
 *	cache_type - Pointer to the strdup()ed string
 *
 * Returns:
 *	GLOBUS_SUCCESS
 *	GLOBUS_GASS_CACHE_ERROR_NO_MEMORY
 *
 */
int
globus_gass_cache_get_cache_type_string( const globus_gass_cache_t	 cache_handle,
					 char			**cache_type );

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
extern
const
char *
globus_gass_cache_error_string(
    int error_code);

EXTERN_C_END

/*
 *                    Module Definition
 */

#define GLOBUS_GASS_CACHE_MODULE (&globus_i_gass_cache_module)

extern globus_module_descriptor_t globus_i_gass_cache_module;


#endif   /* _GLOBUS_GASS_INCLUDE_GLOBUS_GASS_CACHE_H */

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
globus_i_gass_cache.h

Description:

  Internal header file for globus_gass_cache.
  
CVS Information:
 
    $Source$
    $Date$
    $Revision$
    $Author$
    
******************************************************************************/

#include "globus_symboltable.h"

/* defines the environment variable to be used as default cache dir.         */
#define GLOBUS_L_GASS_CACHE_DEFAULT_DIR_ENV_VAR "GLOBUS_GASS_CACHE_DEFAULT"
#define GLOBUS_L_GASS_CACHE_DEBUG		"GLOBUS_GASS_CACHE_DEBUG"

/* if GLOBUS_L_GASS_CACHE_DEFAULT_DIR_ENV_VAR is not defined in user env. */
/* we use $HOME and  GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME below */
/* before V0.9:
#define GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME    "/.globus_gass_cache"
*/
#define GLOBUS_L_DOT_GLOBUS_DIR_NAME		"/.globus"
#define GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME    "/.gass_cache"
#define GLOBUS_L_GASS_CACHE_GLOBAL_DIR		"global"
#define GLOBUS_L_GASS_CACHE_LOCAL_DIR		"local"
#define GLOBUS_L_GASS_CACHE_TMP_DIR		"tmp"
#define GLOBUS_L_GASS_CACHE_LOG_DIR		"log"

/* Files are created with 777 and the access restriction is left to umask    */
#define GLOBUS_L_GASS_CACHE_MODE_RWX	\
	(S_IRWXU|S_IRWXG|S_IRWXO)
#define GLOBUS_L_GASS_CACHE_MODE_RW	\
	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
#define GLOBUS_L_GASS_CACHE_DIR_MODE		GLOBUS_L_GASS_CACHE_MODE_RWX
#define GLOBUS_L_GASS_CACHE_DATAFILE_MODE	GLOBUS_L_GASS_CACHE_MODE_RWX
#define GLOBUS_L_GASS_CACHE_UNIQFILE_MODE	GLOBUS_L_GASS_CACHE_MODE_RWX
#define GLOBUS_L_GASS_CACHE_URLFILE_MODE	GLOBUS_L_GASS_CACHE_MODE_RW
#define GLOBUS_L_GASS_CACHE_TAGFILE_MODE	GLOBUS_L_GASS_CACHE_MODE_RW
#define GLOBUS_L_GASS_CACHE_SKEWFILE_MODE	GLOBUS_L_GASS_CACHE_MODE_RW

/* Length of sleep while waiting for ready */
#define LOCK_SLEEP_USEC		500000

/* Special file names */
#define DATA_FILE		"data"		/* Name of the data file */
#define DATA_FILE_PAT		"data"		/* Pattern for matching */
#define DATA_FILE_PAT_LEN	4		/*  It's length */
#define UDATA_FILE		"data."		/* Uniq data file name */
#define UDATA_FILE_PAT		"data."		/* Uniq data file pattern */
#define UDATA_FILE_PAT_LEN	5		/*  Length of it */
#define LOCK_FILE		"lock"		/* Name of the lock file */
#define URL_FILE		"url"		/* Name of the URL file */
#define TAG_FILE		"tag"		/* Name of the tag file */
#define UNIQ_NAME_FORMAT	"%s_%lx_%lx"
#define UNIQ_NAME_MAX		(20 + MAXHOSTNAMELEN) /* Reserved for uniq */
/* Largest possible file */
#define MAX_FILENAME_LEN	( DATA_FILE_PAT_LEN + UNIQ_NAME_MAX )

/* Time limits, etc. */
#define LOCK_MAX_SECONDS	30
#define LOCK_SLEEP_USEC		500000
#define NOTREADY_MAX_SECONDS	300	/* mtime age before NR "broken" */
#define NOTREADY_CHECK_SECONDS	10	/* Seconds between NR lock checks. */
#define SKEWCALC_SECONDS	3600	/* Seconds between skew calcs. */
#define EBUSY_SLEEP_USEC	10000	/* Retry delay after EBUSY */

/*
 * RedHat 6.2 link seems to return ENOENT sometimes even though it
 * *does* exist & stat() says so.  So, we'll stat() it, and, if it does
 * exist, sleep a bit & try again.  These define how long to wait before
 * the retry, and how many times we're willing to try before giving up.
*/
#define LINKBUG_SLEEP_USEC	50000	/* Sleep before trying link() again */
#define LINKBUG_MAX_RETRY	100	/* Max times to retry.. */

/* Various functions will keep trying in several cases, but should
   eventually give up.  This controls how many times to try before
   that.. */
#define MAKE_DIRTREE_MAX_TRIES	100
#define UNLINK_MAX_TRIES	20
#define CREATE_MAX_TRIES	20

/* If compilled with LOCK_TOUT defined, the lock will timeout after
   LOCK_TOUT try to get the lock, if the file to lock is older than
   LOCK_TOUT*LOOP_TIME
   
   LOOPTIME is currently define as 50000 (50ms)
   If I define  LOCK_TOUT 600, I will wait until the lock file and temp file
   are untouched for more than 30s before I break the lock.*/
#define LOCK_TOUT 600
    
#define GLOBUS_L_GASS_CACHE_NULL_TAG "null"



/******************************************************************************
 macro to trace the code during debug phase and to log the cache activity
******************************************************************************/

#ifdef DEBUG 

#define CACHE_TRACE(_f_)\
	globus_l_gass_cache_trace(__FILE__,__LINE__, (_f_) )
#define CACHE_TRACE2(_f_,_a1_)\
	globus_l_gass_cache_trace(__FILE__,__LINE__, (_f_),(_a1_) )
#define CACHE_TRACE3(_f_,_a1_,_a2_)\
	globus_l_gass_cache_trace(__FILE__,__LINE__, (_f_),(_a1_),(_a2_) )
#define CACHE_TRACE4(_f_,_a1_,_a2_,_a3_)\
	globus_l_gass_cache_trace(__FILE__,__LINE__,\
	(_f_),(_a1_),(_a2_),(_a3_) )
#define CACHE_TRACE5(_f_,_a1_,_a2_,_a3_,_a4_)\
	globus_l_gass_cache_trace(__FILE__,__LINE__,\
	(_f_),(_a1_),(_a2_),(_a3_),(_a4_) )

#ifdef GLOBUS_L_GASS_CACHE_LOG 
#define GLOBUS_L_GASS_CACHE_LG(_f_)\
	globus_l_gass_cache_trace(__FILE__,__LINE__, (_f_) );\
	globus_l_gass_cache_log(cache_handle->log_FILE, (_f_) )
#define GLOBUS_L_GASS_CACHE_LG2(_f_,_a1_)\
	globus_l_gass_cache_trace(__FILE__,__LINE__, (_f_),(_a1_) );\
	globus_l_gass_cache_log(cache_handle->log_FILE, (_f_),(_a1_) )
#define GLOBUS_L_GASS_CACHE_LG3(_f_,_a1_,_a2_)\
	globus_l_gass_cache_trace(__FILE__,__LINE__, (_f_),(_a1_),(_a2_) );\
	globus_l_gass_cache_log(cache_handle->log_FILE, (_f_),(_a1_),(_a2_) )
#define GLOBUS_L_GASS_CACHE_LG4(_f_,_a1_,_a2_,_a3_)\
	globus_l_gass_cache_trace(__FILE__,__LINE__,(_f_),(_a1_),(_a2_),(_a3_) );\
	globus_l_gass_cache_log(cache_handle->log_FILE,(_f_),(_a1_),(_a2_),(_a3_) )

#else
#define GLOBUS_L_GASS_CACHE_LG(_f_)
#define GLOBUS_L_GASS_CACHE_LG2(_f_,_a1_)
#define GLOBUS_L_GASS_CACHE_LG3(_f_,_a1_,_a2_)
#define GLOBUS_L_GASS_CACHE_LG4(_f_,_a1_,_a2_,_a3_)
#endif

#else

#define CACHE_TRACE(_f_)
#define CACHE_TRACE2(_f_,_a1_)
#define CACHE_TRACE3(_f_,_a1_,_a2_)
#define CACHE_TRACE4(_f_,_a1_,_a2_,_a3_)
#define CACHE_TRACE5(_f_,_a1_,_a2_,_a3_,_a4_)
#ifdef GLOBUS_L_GASS_CACHE_LOG 
#define GLOBUS_L_GASS_CACHE_LG(_f_)\
	globus_l_gass_cache_log(cache_handle->log_FILE, _f_ ); 
#define GLOBUS_L_GASS_CACHE_LG2(_f_,_a1_)\
	globus_l_gass_cache_log(cache_handle->log_FILE, (_f_),(_a1_) ); 
#define GLOBUS_L_GASS_CACHE_LG3(_f_,_a1_,_a2_)\
	globus_l_gass_cache_log(cache_handle->log_FILE,\
	(_f_),(_a1_),(_a2_) ); 
#define GLOBUS_L_GASS_CACHE_LG4(_f_,_a1_,_a2_,_a3_)\
	globus_l_gass_cache_log(cache_handle->log_FILE,\
	(_f_),(_a1_),(_a2_),(_a3_) ); 
#else
#define GLOBUS_L_GASS_CACHE_LG(_f_)
#define GLOBUS_L_GASS_CACHE_LG2(_f_,_a1_)
#define GLOBUS_L_GASS_CACHE_LG3(_f_,_a1_,_a2_)
#define GLOBUS_L_GASS_CACHE_LG4(_f_,_a1_,_a2_,_a3_)
#endif

typedef struct globus_i_gass_cache_t
{
    /* dirty hack to know if this cache has been opened/init. */
    void*       init;

    /* version number read out of the state file */
    char        *cache_directory_path;
    char        *global_directory_path;
    char        *local_directory_path;
    char        *tmp_directory_path;

    /* Current lengths */
    int         global_dir_len;
    int         local_dir_len;
    int         tmp_dir_len;

    /* Max lengths */
    int         max_mangled_url;
    int         max_mangled_tag;

    /* Valid mangling options */
    unsigned    mangling_options;

    /* Cache directory type (hierarchial, flat,...) */
    int         cache_type;

    /* Cache MD5 directory levels (for non flat) */
    int         directory_levels;

    /* Logging info */
    FILE*       log_FILE;
    char        *log_file_name;
}
globus_i_gass_cache_t;


									      
#endif


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

/* defines the environment variable to be used as default cache dir.         */
#define GLOBUS_L_GASS_CACHE_DEFAULT_DIR_ENV_VAR "GLOBUS_GASS_CACHE_DEFAULT"

/* if GLOBUS_L_GASS_CACHE_DEFAULT_DIR_ENV_VAR is not defined in user env.            */
/* we use $HOME and  GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME below                       */
/* before V0.9:
#define GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME    "/.globus_gass_cache"
*/
#define GLOBUS_L_DOT_GLOBUS_DIR_NAME		"/.globus"
#define GLOBUS_L_GASS_CACHE_DEFAULT_DIR_NAME    "/.gass_cache"

/* name of the files ! if you change one of them, you might have to change   */
/* the definition of LONGER_NAME_USED below !!!                              */
#define GLOBUS_L_GASS_CACHE_STATE_F_NAME        "/globus_gass_cache_state"
#define GLOBUS_L_GASS_CACHE_LOG_F_NAME          "/globus_gass_cache_log"
#define GLOBUS_L_GASS_CACHE_EXT_NOTREADY        ".not_ready"
#define GLOBUS_L_GASS_CACHE_STATE_F_LOCK        "/globus_gass_cache_state.lock"
#define GLOBUS_L_GASS_CACHE_STATE_F_TEMP        "/globus_gass_cache_state.temp"
#define GLOBUS_L_GASS_CACHE_LOCK_EXT            ".lock"

/* 10 char are enough to code the nb of second for 100 years ...            */
#define GLOBUS_L_GASS_CACHE_FILENAME(str) sprintf((str),"%s/globus_gass_cache_%-i_%i_%i",\
					 cache_handle->cache_directory_path,\
					 (int) time(GLOBUS_NULL), \
					 (int) globus_l_gass_cache_pid, \
					 globus_l_gass_cache_fn_fudge++)

/* !! this variable must contain the lenght of the longer name used in       */
/* the cache including cache files, state files and lock files.              */
/* The longuest is the name of a datafile with the not ready extention       */

#define LONGER_NAME_USED               sizeof("%s/globus_gass_cache_") + 10 \
                                       + sizeof(GLOBUS_L_GASS_CACHE_EXT_NOTREADY)

/* Files are created with 777 and the access restriction is left to umask    */
#define GLOBUS_L_GASS_CACHE_DIR_MODE            S_IRWXU
#define GLOBUS_L_GASS_CACHE_STATE_MODE          S_IRWXU|S_IRWXG|S_IRWXO 

/* sleeping time in the globus_l_gass_cache_lock_open() lock loop */
#define LOOP_TIME 50000   /* in micro second */
/* If compilled with LOCK_TOUT defined, the lock will timeout after
   LOCK_TOUT try to get the lock, if the file to lock is older than
   LOCK_TOUT*LOOP_TIME
   
   LOOPTIME is currently define as 50000 (50ms)
   If I define  LOCK_TOUT 600, I will wait until the lock file and temp file
   are untouched for more than 30s before I break the lock.*/
#define LOCK_TOUT 600
    
/* All the numbers stored in the cache state file are coded ascii. This is   */
/*     the number of char used to code those numbers                         */
/*     It is used for storing the lenght of the strings (url, filename, ...) */
/*     as well as integer or unsigned long.                                  */
/* (max (128 bits long) = 2^129-1 = 6.81E38  need 39 char                    */
#define GLOBUS_L_GASS_CACHE_L_LENGHT        40    

#define GLOBUS_L_GASS_CACHE_NULL_TAG "null"

#define GLOBUS_L_GASS_CACHE_COMMIT    0
#define GLOBUS_L_GASS_CACHE_DO_NOT_COMMIT     -1


/******************************************************************************
 macro to trace the code during debug phase and to log the cache activity
******************************************************************************/

#ifdef DEBUG 

#define CACHE_TRACE(str) globus_l_gass_cache_trace(__FILE__,__LINE__, str )
#define CACHE_TRACE2(str1,str2) globus_l_gass_cache_trace(__FILE__,__LINE__, (str1),(str2) )
#define CACHE_TRACE3(str1,str2,str3) globus_l_gass_cache_trace(__FILE__,__LINE__, (str1),(str2),(str3) )

#ifdef GLOBUS_L_GASS_CACHE_LOG 
#define GLOBUS_L_GASS_CACHE_LG(str) globus_l_gass_cache_trace(__FILE__,__LINE__, (str) );globus_l_gass_cache_log(cache_handle->log_FILE, (str) )
#define GLOBUS_L_GASS_CACHE_LG2(str1,str2) globus_l_gass_cache_trace(__FILE__,__LINE__, (str1),(str2) );globus_l_gass_cache_log(cache_handle->log_FILE, (str1),(str2) )
#define GLOBUS_L_GASS_CACHE_LG3(str1,str2,str3) globus_l_gass_cache_trace(__FILE__,__LINE__, (str1),(str2),(str3) );globus_l_gass_cache_log(cache_handle->log_FILE, (str1),(str2),(str3) )

#else
#define GLOBUS_L_GASS_CACHE_LG(str)
#define GLOBUS_L_GASS_CACHE_LG2(str1,str2)
#define GLOBUS_L_GASS_CACHE_LG3(str1,str2,str3)
#endif

#else

#define CACHE_TRACE(str)
#define CACHE_TRACE2(str1,str2)
#define CACHE_TRACE3(str1,str2,str3)
#ifdef GLOBUS_L_GASS_CACHE_LOG 
#define GLOBUS_L_GASS_CACHE_LG(str) globus_l_gass_cache_log(cache_handle->log_FILE, str ); 
#define GLOBUS_L_GASS_CACHE_LG2(str1,str2) globus_l_gass_cache_log(cache_handle->log_FILE, (str1),(str2) ); 
#define GLOBUS_L_GASS_CACHE_LG3(str1,str2,str3) globus_l_gass_cache_log(cache_handle->log_FILE, (str1),(str2),(str3) ); 
#else
#define GLOBUS_L_GASS_CACHE_LG(str)
#define GLOBUS_L_GASS_CACHE_LG2(str1,str2)
#define GLOBUS_L_GASS_CACHE_LG3(str1,str2,str3)
#endif
									      
#endif


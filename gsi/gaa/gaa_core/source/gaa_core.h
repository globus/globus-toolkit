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

#ifndef _GAA_CORE_H
#define _GAA_CORE_H

extern gaa_status
gaacore_set_err(char *s);

extern char *
gaacore_condstat2str(int status);

extern char *
gaacore_majstat_str(int status);

extern char *
gaacore_right_type_to_string(gaa_right_type rtype);

extern char *
gaacore_cred_type_to_string(gaa_cred_type ctype);

typedef int (*gaacore_mutex_create_func)(void **mutex, void *params);
typedef void (*gaacore_mutex_destroy_func)(void *mutex, void *params);
typedef int (*gaacore_mutex_lock_func)(void *mutex, void *params);
typedef int (*gaacore_mutex_unlock_func)(void *mutex, void *params);

struct gaacore_tsdata {
    int initted;
    void *key;
};
typedef struct gaacore_tsdata gaacore_tsdata;
typedef int (*gaacore_tsdata_create_func)(gaacore_tsdata *tsdata,
					  gaa_freefunc freedata,
					  void *params);
typedef int (*gaacore_tsdata_setspecific_func)(void *key, void *data,
					      void *params);
typedef void *(*gaacore_tsdata_getspecific_func)(void *key, void *params);

extern gaa_status
gaacore_set_mutex_callback(gaacore_mutex_create_func create,
			   gaacore_mutex_destroy_func destroy,
			   gaacore_mutex_lock_func lock,
			   gaacore_mutex_unlock_func unlock,
			   gaacore_tsdata_create_func tscreate,
			   gaacore_tsdata_setspecific_func tsset,
			   gaacore_tsdata_getspecific_func tsget,
			   void *params);

extern gaa_status
gaacore_mutex_lock(void *mutex);

extern gaa_status
gaacore_mutex_unlock(void *mutex);

extern gaa_status
gaacore_mutex_create(void **mutex_ptr);

extern void
gaacore_mutex_destroy(void *mutex);

extern gaa_status
gaacore_tsdata_create(gaacore_tsdata *tsdata, gaa_freefunc freedata);

extern gaa_status
gaacore_tsdata_set(gaacore_tsdata *tsdata, void *data);

extern void *
gaacore_tsdata_get(gaacore_tsdata *tsdata);

extern int
gaacore_has_matchrights_callback(gaa_ptr gaa);

extern int
gaacore_has_default_authinfo_callback(gaa_ptr gaa);

#endif /* GAA_CORE_H */

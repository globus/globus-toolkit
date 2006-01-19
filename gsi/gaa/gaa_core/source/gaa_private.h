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

#ifndef _GAA_PRIVATE_H
#define _GAA_PRIVATE_H

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif /* MAX */
#ifndef MIN
#define MIN(x, y) ((x) > (y) ? (x) : (y))
#endif /* MIN */

#include "gaa_core.h"

struct gaaint_list_entry {
    void *data;
    struct gaaint_list_entry *next;
    struct gaaint_list_entry *prev;
};

typedef struct gaaint_list_entry gaaint_list_entry;

struct gaaint_list;
typedef int (*gaa_listcompfunc)(void *d1, void *d2);

typedef gaa_status (*gaaint_listaddfunc)(struct gaaint_list *list, void *data, gaa_listcompfunc stopdups);

struct gaaint_list {
    void *mutex;
    gaaint_listaddfunc addfunc;
    gaa_listcompfunc compare;
    gaa_freefunc freefunc;
    gaaint_list_entry *entries;
    gaaint_list_entry *last;
};

typedef struct gaaint_list gaaint_list;

struct gaaint_cred_pull_callback {
    gaa_cred_pull_func func;	/* function to pull creds */
    void *params;		/* params always passed to func */
    gaa_freefunc free;		/* function to free params */
};

typedef struct gaaint_cred_pull_callback gaaint_cred_pull_callback;

struct gaaint_cred_eval_callback {
    gaa_cred_eval_func func;	/* function to evaluate creds */
    void *params;		/* params always passed to func */
    gaa_freefunc free;		/* function to free params */
};

typedef struct gaaint_cred_eval_callback gaaint_cred_eval_callback;

struct gaaint_mechinfo {
    gaa_string_data mech_type;
    gaa_cred_pull_func cred_pull; 	/* callback func to pull raw creds */
    gaa_cred_eval_func cred_eval; 	/* raw cred -> gaa grantor/principal */
    gaa_cred_verify_func cred_verify;   /* verify raw cred still valid */
    void *param;			/* passed to cred_pull and cred_eval */
    gaa_freefunc freeparam;	/* to free param when mechinfo is freed */
    gaa_freefunc cred_free;	/* to free raw cred */
};

typedef struct gaaint_mechinfo gaaint_mechinfo;

struct gaaint_getpolicy_callback {
    gaa_getpolicy_func func;	/* function to get policy */
    void *param;		/* parameters always passed to getf */
    gaa_freefunc free;		/* function to free param */
};

typedef struct gaaint_getpolicy_callback gaaint_getpolicy_callback;

struct gaaint_cond_eval_callback {
    gaa_cond_eval_func func; /* function to evaluate cond */
    void *params;		/* params always passed to func */
    gaa_freefunc free;		/* function to free params */
    int refcount;		/* reference count */
    void *refcount_mutex;	/* to lock refcount */
};

typedef struct gaaint_cond_eval_callback gaaint_cond_eval_callback;

struct gaaint_cond_eval_entry {
    gaa_string_data type;	/* type this callback applies to (0 for all) */
    gaa_string_data authority;	/* auth this callback applies to (0 for all) */
    int is_idcred;		/* if nonzero, gaa_inquire_policy_info
				 * will consider this an id credential
				 */
    gaaint_cond_eval_callback *cb;
};
typedef struct gaaint_cond_eval_entry gaaint_cond_eval_entry;

struct gaaint_matchrights_callback {
    gaa_matchrights_func func;	/* function to find matching entries */
    void *param;		/* params always passed to func */
    gaa_freefunc free;		/* function to free params */
};

typedef struct gaaint_matchrights_callback gaaint_matchrights_callback;

struct gaaint_sc {
    gaa_list_ptr identity_cred;	/* authenticated credentials */
    gaa_list_ptr authr_cred;	/* authorization creds (capabilities) */
    gaa_list_ptr attr_cred;	/* attribute credentials  */
    gaa_list_ptr group_membership; /* all groups principal is a member of */
    gaa_list_ptr group_non_membership; /* groups not a member of */
    gaa_list_ptr uneval_cred;	/* raw mech-specific credentials */
};

typedef struct gaaint_sc gaaint_sc;

struct gaaint_x_get_authorization_identity_callback {
    gaa_x_get_authorization_identity_func func;	/* function to get policy */
    void *param;		/* parameters always passed to getf */
    gaa_freefunc free;		/* function to free param */
};

typedef struct gaaint_x_get_authorization_identity_callback gaaint_x_get_authorization_identity_callback;

struct gaaint_gaa {
    gaa_list_ptr mechinfo;	/* how to translate raw credentials */
    gaaint_getpolicy_callback *getpolicy; /* callback to get policy */
    gaaint_matchrights_callback *matchrights; /* match rights in policy */
    gaa_list_ptr cond_callbacks;	/* list of gaaint_cond_eval_entry */
    gaa_list_ptr authinfo;	/* list of gaaint_authinfo */
    gaaint_x_get_authorization_identity_callback *authorization_identity_callback;
};

typedef struct gaaint_gaa gaaint_gaa;

struct gaaint_cond {
    void *data;
};
typedef struct gaaint_cond gaaint_cond;

struct gaaint_policy {
    void *data;
};
typedef struct gaaint_policy gaaint_policy;

struct gaaint_request_right {
    gaa_freefunc freeval;
};

typedef struct gaaint_request_right gaaint_request_right;

struct gaaint_request_option {
    gaa_freefunc freeval;
};

typedef struct gaaint_request_option gaaint_request_option;

struct gaaint_policy_right {
    gaa_freefunc freeval;
};

typedef struct gaaint_policy_right gaaint_policy_right;

struct gaaint_valinfo {
    gaa_string2val_func newval;
    gaa_copyval_func copyval;
    gaa_freefunc freeval;
    gaa_val2string_func val2str;
};

typedef struct gaaint_valinfo gaaint_valinfo;

struct gaaint_authinfo {
    char *authority;
    gaaint_valinfo *pvinfo;
    gaaint_valinfo *rvinfo;
    gaa_valmatch_func match;
    void *params;
    gaa_freefunc freeparams;
};

typedef struct gaaint_authinfo gaaint_authinfo;

extern gaaint_list *
gaa_i_new_stack(gaa_freefunc freefunc);

extern gaaint_list *
gaa_i_new_silo(gaa_freefunc freefunc);

extern gaaint_list *
gaa_i_new_sorted_list(gaa_listcompfunc compare, gaa_freefunc freefunc);

extern void
gaa_i_list_clear(gaaint_list *list);

extern void
gaa_i_free_simple(void *val);

extern int
gaa_i_policy_order(gaa_policy_entry *e1, gaa_policy_entry *e2);

extern int
gaa_i_list_empty(gaaint_list *list);

extern gaaint_authinfo *
gaa_i_find_authinfo(gaa_ptr gaa, gaa_policy_right *right);

extern gaaint_authinfo *
gaa_i_auth2authinfo(gaa_ptr gaa, char *authority);

extern gaa_status
gaa_i_list_add_entry(gaa_list_ptr list, void *data);

extern gaa_status
gaa_i_list_merge(gaaint_list *dest, gaaint_list *src);

extern void
gaa_i_free_authinfo(gaaint_authinfo *ai);

extern gaa_status
gaa_i_new_string(char **dest, char *src);

extern gaa_status
gaa_i_list_add_unique_entry(gaa_list_ptr list, void *data,
			    gaa_listcompfunc checkdups);

extern int
gaa_i_tsdata_supported();

#endif /* _GAA_PRIVATE_H */

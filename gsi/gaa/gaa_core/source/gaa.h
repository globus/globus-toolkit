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

#ifndef _GAA_H_
#define _GAA_H_

#ifndef NO_GLOBUS_CONFIG_H
#include "globus_config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "gaa_constants.h"

typedef enum {
    GAA_IDENTITY,
    GAA_GROUP_MEMB,
    GAA_GROUP_NON_MEMB,
    GAA_AUTHORIZED,
    GAA_ATTRIBUTES,
    GAA_UNEVAL,
    GAA_ANY
} gaa_cred_type;

typedef enum {
    gaa_pos_access_right,
    gaa_neg_access_right
} gaa_right_type;

/************************** GAA-API data structures ************************/
typedef	unsigned long gaa_status;
 
typedef char *gaa_string_data;
typedef void (*gaa_freefunc)(void *data);

typedef struct gaaint_list *gaa_list_ptr;

typedef struct gaaint_list_entry *gaa_list_entry_ptr;

typedef struct gaaint_sc *gaa_sc_ptr;

typedef struct gaaint_gaa *gaa_ptr;

struct gaa_sec_attrb {
    gaa_cred_type type;		/* token type */
    gaa_string_data authority;	/* authority defining meaning of token value */
    gaa_string_data value;	/* value (in namespace defined by authority) */
};

typedef struct gaa_sec_attrb gaa_sec_attrb;

struct gaa_condition_struct {
    gaa_string_data type;	/* condition type */
    gaa_string_data authority;	/* defining authority */
    gaa_string_data value;	/* within namespace defined by authority */
    unsigned long status;	/* GAA_COND_EVALUATED, GAA_COND_MET, etc. */
    struct gaaint_cond *i;	/* internal data */
};

typedef struct gaa_condition_struct gaa_condition, *gaa_condition_ptr;

struct gaa_request_option {
    gaa_string_data type;	/* option type */
    gaa_string_data authority;	/* defining authority */
    void *value;		/* within namespace defined by authority */
    struct gaaint_request_option *i; /* internal data */
};

typedef struct gaa_request_option gaa_request_option, *gaa_request_option_ptr;

struct gaa_request_right {
    gaa_string_data authority;	/* defining authority */
    void *value;		/* within namespace defined by authority */
    gaa_list_ptr options;	/* list of gaa_request_option */
    struct gaaint_request_right *i; /* internal data */
};

typedef struct gaa_request_right gaa_request_right, *gaa_request_right_ptr;

struct gaa_policy_right {
    gaa_right_type type;	/* positive or negative */
    gaa_string_data authority;	/* defining authority */
    void *value;		/* within namespace defined by authority */
    gaa_list_ptr conditions;	/* list of gaa_condition_ptr describing
				   the conditions that must be met */
    struct gaaint_policy_right *i; /* internal data */
};

typedef struct gaa_policy_right gaa_policy_right, *gaa_policy_right_ptr;

struct gaa_policy_entry_struct {
    int priority;		/* entry priority */
    int num;			/* entry number (for order within priority) */
    gaa_policy_right *right;	/* what right this entry grants */
};

typedef struct gaa_policy_entry_struct gaa_policy_entry, *gaa_policy_entry_ptr;

struct gaa_policy {
    void *raw_policy;		/* raw policy representation */
    gaa_list_ptr entries;	/* ordered list of gaa_policy_entry_ptr */
    gaa_freefunc freeraw;	/* function to free raw_policy */
    struct gaaint_policy *i;	/* internal data */
};
typedef struct gaa_policy gaa_policy, *gaa_policy_ptr;

typedef gaa_status (*gaa_cred_pull_func)(gaa_ptr gaa, gaa_sc_ptr sc, gaa_cred_type which, void *params);

typedef gaa_status (*gaa_matchrights_func)(gaa_ptr gaa, gaa_policy *inpolicy, gaa_request_right *right, gaa_policy *outpolicy, void *params);

struct gaa_identity_info {
    gaa_list_ptr conditions;	/* list of gaa_condition_ptr describing
				   validity constraints */
};

typedef struct gaa_identity_info gaa_identity_info;

struct gaa_authr_info_struct {
    void *objects;
    gaa_list_ptr /* gaa_policy_right_ptr */ access_rights;
    gaa_freefunc free_objects;
};

typedef struct gaa_authr_info_struct  gaa_authr_info, *gaa_authr_info_ptr;

struct gaa_attribute_info_struct { 
    gaa_string_data  type;
    gaa_string_data  authority;
    gaa_string_data  value;
    gaa_list_ptr /* gaa_condition_ptr */  conditions; 
};

typedef struct gaa_attribute_info_struct  gaa_attribute_info,
    *gaa_attribute_info_ptr;

struct gaa_cred {
    gaa_cred_type type;
    gaa_sec_attrb *grantor;
    gaa_sec_attrb *principal;
    void *mech_spec_cred;
    struct gaaint_mechinfo *mechinfo;
    union {
	gaa_identity_info *id_info;
	gaa_authr_info *authr_info;
	gaa_attribute_info *attr_info;
    } info;
};

typedef struct gaa_cred gaa_cred, *gaa_cred_ptr;

typedef gaa_status (*gaa_cred_eval_func)(gaa_ptr gaa, gaa_sc_ptr sc, struct gaa_cred *cred, void *raw, gaa_cred_type cred_type, void *params);

typedef gaa_status (*gaa_cred_verify_func)(struct gaa_cred *cred, void *params);

struct gaa_time_period_struct {
    time_t start_time;		/* NULL for unconstrained */
    time_t end_time;		/* NULL for unconstrained */
};

typedef struct gaa_time_period_struct gaa_time_period;

struct gaa_answer {
    gaa_time_period *valid_time;
    gaa_list_ptr rights;	/* list of gaa_policy_right_ptr */
};
typedef struct gaa_answer gaa_answer, *gaa_answer_ptr;

typedef struct gaaint_valinfo *gaa_valinfo_ptr;

typedef gaa_status (*gaa_cond_eval_func)(gaa_ptr gaa, gaa_sc_ptr sc, gaa_condition *condition, gaa_time_period *valid_time, gaa_list_ptr req_options, gaa_status *output_flags, void *params);

typedef struct gaaint_cond_eval_callback *gaa_cond_eval_callback_ptr;

typedef gaa_status (*gaa_getpolicy_func)(gaa_ptr gaa, gaa_policy **policy, gaa_string_data object, void *params);

typedef gaa_status (*gaa_string2val_func)(void **val, gaa_string_data authority, gaa_string_data valstr, void *params);
typedef gaa_status (*gaa_copyval_func)(void **newval, gaa_string_data authority, void *oldval, void *params);
typedef char *(*gaa_val2string_func)(char *authority, void *val, gaa_string_data buf, int bsize, void *params);
typedef gaa_status (*gaa_valmatch_func)(gaa_string_data authority, void *rval, void *pval, void *params);


extern gaa_status
gaa_new_condition(gaa_condition **cond, gaa_string_data type,
		  gaa_string_data authority, gaa_string_data value);

extern void
gaa_free_condition(gaa_condition *cond);

extern gaa_status
gaa_new_policy_right(gaa_ptr gaa, gaa_policy_right **right,
		     gaa_right_type type, gaa_string_data authority,
		     gaa_string_data val);

extern gaa_status
gaa_new_valinfo(gaa_valinfo_ptr *valinfo, gaa_copyval_func copyval,
		gaa_string2val_func newval, gaa_freefunc freeval,
		gaa_val2string_func val2str);

extern gaa_status
gaa_new_policy_right_rawval(gaa_ptr gaa, gaa_policy_right **right,
			    gaa_right_type type, gaa_string_data authority,
			    void *val);

extern gaa_status
gaa_new_request_right(gaa_ptr gaa, gaa_request_right **right,
		      gaa_string_data authority, gaa_string_data val);

extern gaa_status
gaa_new_request_right_rawval(gaa_ptr gaa, gaa_request_right **right,
			     gaa_string_data authority, void *value);

extern void
gaa_free_policy_right(gaa_policy_right *right);

extern void
gaa_free_request_right(gaa_request_right *right);

extern gaa_status
gaa_add_condition(gaa_policy_right *right, gaa_condition *condition);

extern gaa_status
gaa_new_policy(gaa_policy **policy);

extern gaa_status
gaa_init_policy(gaa_policy *policy);

extern void
gaa_clear_policy(gaa_policy *policy);

extern void
gaa_free_policy_entry(gaa_policy_entry *ent);

extern gaa_status
gaa_add_policy_entry(gaa_policy *policy, gaa_policy_right *right,
		     int priority, int num);

extern void
gaa_free_policy(gaa_policy *policy);

extern gaa_status
gaa_new_policy_entry(gaa_policy_entry **entry, gaa_policy_right *right,
		     int priority, int num);

extern gaa_status
gaa_new_gaa(gaa_ptr *gaa);

extern gaa_status
gaa_new_sc(gaa_sc_ptr *sc);

extern gaa_status
gaa_new_sec_attrb(gaa_sec_attrb **a, gaa_cred_type type,
		  gaa_string_data authority, gaa_string_data value);

extern void
gaa_free_sec_attrb(gaa_sec_attrb *a);

extern gaa_status
gaa_new_identity_info(gaa_ptr gaa, gaa_identity_info **info);

extern gaa_status
gaa_new_cred(gaa_ptr gaa, gaa_sc_ptr sc, gaa_cred **cred,
	     gaa_string_data mech_type, void *mech_spec_cred,
	     gaa_cred_type cred_type, int evaluate, gaa_status *estat);

extern void
gaa_free_identity_info(gaa_identity_info *info);

extern gaa_status
gaa_new_authr_info(gaa_ptr gaa, gaa_authr_info **info, void *objects,
		   gaa_freefunc free_objects);

extern void
gaa_free_authr_info(gaa_authr_info *info);

extern gaa_status
gaa_add_cred(gaa_ptr gaa, gaa_sc_ptr sc, gaa_cred *cred);

extern gaa_status
gaa_new_answer(gaa_answer **answer);

extern void
gaa_free_answer(gaa_answer *answer);

extern gaa_status
gaa_set_getpolicy_callback(gaa_ptr gaa, gaa_getpolicy_func func,
			   void *param, gaa_freefunc freefunc);

extern gaa_status
gaa_set_matchrights_callback(gaa_ptr gaa, gaa_matchrights_func func,
			     void *param, gaa_freefunc freefunc);

extern void
gaa_free_sc(gaa_sc_ptr sc);

extern void
gaa_free_gaa(gaa_ptr gaa);

extern gaa_status
gaa_add_mech_info(gaa_ptr gaa, gaa_string_data mech_type,
		  gaa_cred_pull_func cred_pull, gaa_cred_eval_func cred_eval,
		  gaa_cred_verify_func cred_verify, gaa_freefunc cred_free,
		  void *param, gaa_freefunc freeparams);

extern gaa_status
gaa_get_object_policy_info(gaa_string_data object, gaa_ptr gaa,
			   gaa_policy_ptr *policy);

extern gaa_status
gaa_pull_creds(gaa_ptr gaa, gaa_sc_ptr sc, gaa_cred_type which,
	       gaa_string_data mech_type);

extern gaa_status
gaa_new_cond_eval_callback(gaa_cond_eval_callback_ptr *cb,
			   gaa_cond_eval_func func, void *params,
			   gaa_freefunc freefunc);

extern void
gaa_free_cond_eval_callback(gaa_cond_eval_callback_ptr cb);

extern gaa_status
gaa_add_cond_eval_callback(gaa_ptr gaa, gaa_cond_eval_callback_ptr cb,
			   gaa_string_data type, gaa_string_data authority,
			   int is_idcred);

extern gaa_status
gaa_check_authorization(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr policy,
			gaa_list_ptr req_rights, gaa_answer_ptr answer);

extern gaa_status
gaa_getcreds(gaa_ptr gaa, gaa_sc_ptr sc, gaa_list_ptr *credlist,
	     gaa_cred_type which);

extern gaa_status
gaa_add_authinfo(gaa_ptr gaa, char *authority, gaa_valinfo_ptr pvinfo,
		 gaa_valinfo_ptr rvinfo, gaa_valmatch_func match,
		 void *params, gaa_freefunc freeparams);

extern gaa_list_ptr
gaa_new_req_rightlist();

extern gaa_status
gaa_add_request_right (gaa_list_ptr rightlist, gaa_request_right *right);

extern gaa_status
gaa_match_rights(gaa_ptr gaa, gaa_request_right *rright,
		 gaa_policy_right *pright, int *match);

extern gaa_status
gaa_inquire_policy_info(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr policy,
			gaa_list_ptr *out_rights);

extern gaa_status
gaa_add_option(gaa_request_right *right, gaa_string_data type,
	       gaa_string_data authority, void *value, gaa_freefunc freeval);

extern gaa_status
gaa_check_condition(gaa_ptr gaa, gaa_sc_ptr sc, gaa_condition *cond,
		    gaa_time_period *vtp, int *ynm, gaa_list_ptr options);

extern void
gaa_free_cred(gaa_cred *cred);

extern gaa_status
gaa_new_attribute_info(gaa_ptr gaa, gaa_attribute_info **info,
		       gaa_string_data type, gaa_string_data authority,
		       gaa_string_data value);

extern void
gaa_free_attribute_info(gaa_attribute_info *info);

extern void
gaa_free_valinfo(gaa_valinfo_ptr valinfo);

extern gaa_status
gaa_add_cred_condition(gaa_cred *cred, gaa_condition *cond);

extern gaa_status
gaa_add_authr_right(gaa_cred *cred, gaa_policy_right *right);

extern char *
gaa_request_rightval_string(gaa_ptr gaa, char *authority, void *val,
			    char *buf, int bsize);

extern char *
gaa_policy_rightval_string(gaa_ptr gaa, char *authority, void *val,
			   char *buf, int bsize);

extern gaa_list_entry_ptr
gaa_list_first(gaa_list_ptr list);

extern gaa_list_entry_ptr
gaa_list_next(gaa_list_entry_ptr entry);

extern void *
gaa_list_entry_value(gaa_list_entry_ptr entry);

extern void
gaa_list_free (gaa_list_ptr list);

extern gaa_status
gaa_verify_cred(gaa_cred *cred);

extern char *
gaa_get_err();

extern gaa_status
gaa_set_callback_err(char *s);

extern char *
gaa_get_callback_err();

extern char *
gaa_x_majstat_str(gaa_status status);

typedef gaa_status(*gaa_x_get_authorization_identity_func)(gaa_ptr *gaa,
							   char **identity_ptr,
							   void *param);

extern gaa_status
gaa_x_get_getpolicy_param(gaa_ptr gaa, void **param);

extern gaa_status
gaa_x_get_get_authorization_identity_param(gaa_ptr gaa, void **param);

extern gaa_status
gaa_x_get_authorization_identity(gaa_ptr gaa, char **identity_ptr);

extern gaa_status
gaa_x_set_get_authorization_identity_callback(
    gaa_ptr gaa,
    gaa_x_get_authorization_identity_func func,
    void *param,
    gaa_freefunc freefunc);

#endif /* _GAA_H_ */

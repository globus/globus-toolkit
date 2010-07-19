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

#ifndef _GAA_PLUGIN_H_
#define _GAA_PLUGIN_H_

enum gaa_plugin_parameter_type {
    GAA_PLUGIN_NULL_PARAM,		/* no parameter set */
    GAA_PLUGIN_TEXT_PARAM,		/* parameter expressed as text */
    GAA_PLUGIN_SYMBOLIC_PARAM,		/* parameter expressed as a symbol */
    GAA_PLUGIN_VALUE_PARAM		/* parameter expressed as a pointer */
};

typedef enum gaa_plugin_parameter_type gaa_plugin_parameter_type;

struct gaa_plugin_symbol_desc {
    char *libname;
    char *symname;
};

typedef struct gaa_plugin_symbol_desc gaa_plugin_symbol_desc;

struct gaa_plugin_parameter {
    gaa_plugin_parameter_type type;
    union {
	gaa_plugin_symbol_desc symdesc;
	char **text;
	void *val;
    } value;
};

typedef struct gaa_plugin_parameter gaa_plugin_parameter;

struct gaa_plugin_mechinfo_args {
    gaa_string_data mech_type;
    gaa_plugin_symbol_desc cred_pull;
    gaa_plugin_symbol_desc cred_eval;
    gaa_plugin_symbol_desc cred_verify;
    gaa_plugin_symbol_desc cred_free;
    gaa_plugin_parameter param;
    gaa_plugin_symbol_desc freeparam;
};
typedef struct gaa_plugin_mechinfo_args gaa_plugin_mechinfo_args;

struct gaa_plugin_cond_eval_args {
    gaa_string_data cond_type;
    gaa_string_data cond_authority;
    int is_idcred;
    gaa_plugin_symbol_desc cond_eval;
    gaa_plugin_parameter param;
    gaa_plugin_symbol_desc freeparam;
};
typedef struct gaa_plugin_cond_eval_args gaa_plugin_cond_eval_args;

struct gaa_plugin_valinfo_args {
    gaa_plugin_symbol_desc copyval;
    gaa_plugin_symbol_desc newval;
    gaa_plugin_symbol_desc freeval;
    gaa_plugin_symbol_desc val2str;
};

typedef struct gaa_plugin_valinfo_args gaa_plugin_valinfo_args;
    
struct gaa_plugin_authinfo_args {
    gaa_string_data authority;
    gaa_plugin_valinfo_args pvinfo;
    gaa_plugin_valinfo_args rvinfo;
    gaa_plugin_symbol_desc valmatch;
    gaa_plugin_parameter param;
    gaa_plugin_symbol_desc freeparam;
};

typedef struct gaa_plugin_authinfo_args gaa_plugin_authinfo_args;

struct gaa_plugin_getpolicy_args {
    gaa_plugin_symbol_desc getpolicy;
    gaa_plugin_parameter param;
    gaa_plugin_symbol_desc freeparam;
};

typedef struct gaa_plugin_getpolicy_args gaa_plugin_getpolicy_args;

struct gaa_plugin_authz_id_args {
    gaa_plugin_symbol_desc get_authz_id;
    gaa_plugin_parameter param;
    gaa_plugin_symbol_desc freeparam;
};

typedef struct gaa_plugin_authz_id_args gaa_plugin_authz_id_args;

struct gaa_plugin_matchrights_args {
    gaa_plugin_symbol_desc matchrights;
    gaa_plugin_parameter param;
    gaa_plugin_symbol_desc freeparam;
};

typedef struct gaa_plugin_matchrights_args gaa_plugin_matchrights_args;

struct gaa_plugin_mutex_args {
    gaa_plugin_symbol_desc create;
    gaa_plugin_symbol_desc destroy;
    gaa_plugin_symbol_desc lock;
    gaa_plugin_symbol_desc unlock;
    gaa_plugin_symbol_desc tscreate;
    gaa_plugin_symbol_desc tsset;
    gaa_plugin_symbol_desc tsget;
    gaa_plugin_parameter param;
};
typedef struct gaa_plugin_mutex_args gaa_plugin_mutex_args;

extern gaa_status
gaa_initialize(gaa_ptr *gaa, void *param);

extern gaa_status
gaa_plugin_install_mechinfo(gaa_ptr gaa, gaa_plugin_mechinfo_args *miargs);

extern gaa_status
gaa_plugin_install_cond_eval(gaa_ptr gaa, gaa_plugin_cond_eval_args *ceargs);

extern gaa_status
gaa_plugin_init_param(gaa_plugin_parameter *param);

extern gaa_status
gaa_plugin_init_cond_eval_args(gaa_plugin_cond_eval_args *ceargs);

extern gaa_status
gaa_plugin_init_mechinfo_args(gaa_plugin_mechinfo_args *miargs);

extern gaa_status
gaa_plugin_install_authinfo(gaa_ptr gaa, gaa_plugin_authinfo_args *aiargs);

extern gaa_status
gaa_plugin_init_matchrights_args(gaa_plugin_matchrights_args *args);

extern gaa_status
gaa_plugin_init_getpolicy_args(gaa_plugin_getpolicy_args *args);

extern gaa_status
gaa_plugin_init_authz_id_args(gaa_plugin_authz_id_args *args);

extern gaa_status
gaa_plugin_install_matchrights(gaa_ptr gaa,
			       gaa_plugin_matchrights_args *mrargs);

extern gaa_status
gaa_plugin_install_getpolicy(gaa_ptr gaa, gaa_plugin_getpolicy_args *mrargs);

extern gaa_status
gaa_plugin_install_authz_id(gaa_ptr gaa, gaa_plugin_authz_id_args *mrargs);

extern gaa_status
gaa_plugin_init_authinfo_args(gaa_plugin_authinfo_args *aiargs);

extern gaa_status
gaa_plugin_add_libdir(char *libdir);

extern gaa_status
gaa_plugin_install_mutex_callbacks(gaa_plugin_mutex_args *mxargs);

extern gaa_status
gaa_plugin_default_matchrights(gaa_ptr		   gaa,
			       gaa_policy *	   inpolicy,
			       gaa_request_right * right,
			       gaa_policy *	   outpolicy,
			       void *		   params);

extern gaa_status
gaa_plugin_default_new_rval(void **	val,
			    char *	authority,
			    char *	valstr,
			    void *	params);

extern gaa_status
gaa_plugin_default_new_pval(void **	val,
			    char *	authority,
			    char *	valstr,
			    void *	params);

extern gaa_status
gaa_plugin_default_copy_pval(void **	newval,
			     char *	authority,
			     void *	oldval,
			     void *	params);
    
extern gaa_status
gaa_plugin_default_copy_rval(void **	newval,
			     char *	authority,
			     void *	oldval,
			     void *	params);

extern gaa_status
gaa_plugin_default_valmatch(char *	authority,
			    void *	rval,
			    void *	pval,
			    void *	params);
    
extern char *
gaa_plugin_default_rval2str(char *	authority,
			    void *	val,
			    char *	buf,
			    int		bsize,
			    void *	params);

extern char *
gaa_plugin_default_pval2str(char *	authority,
			    void *	val,
			    char *	buf,
			    int		bsize,
			    void *	params);

extern void
gaa_plugin_default_free_pval(void *	pval);

#endif /* _GAA_PLUGIN_H_ */

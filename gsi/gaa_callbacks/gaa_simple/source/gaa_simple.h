#ifndef _GAA_SIMPLE_H_
#define _GAA_SIMPLE_H_

struct gaasimple_eacl_args {
    char *dirname;
    FILE *errfile;
};

typedef struct gaasimple_eacl_args gaasimple_eacl_args;

extern gaa_status
gaasimple_read_eacl(gaa_ptr gaa, gaa_policy **policy, gaa_string_data object,
		    void *params);

            
 extern gaa_status
 gaasimple_parse_restrictions(gaa_ptr        gaa,
 gaa_policy **   policy,
 gaa_string_data object,
 void *      params)  ; 

extern gaa_status
gaasimple_assert_cred_pull(gaa_ptr gaa, gaa_sc_ptr sc, gaa_cred_type which,
			   void *params);

extern gaa_status
gaasimple_assert_cred_eval(gaa_ptr gaa, gaa_sc_ptr sc, gaa_cred *cred,
			   void *raw, gaa_cred_type cred_type, void *params);

extern gaa_status
gaasimple_check_id_cond(gaa_ptr gaa, gaa_sc_ptr sc, gaa_condition *cond,
			gaa_time_period *valid_time,
			gaa_list_ptr req_options, gaa_status *output_flags,
			void *params);

extern gaa_status
gaasimple_assert_cred_verify(gaa_cred *cred, void *params);

extern gaa_status
gaasimple_check_group_cond(gaa_ptr gaa, gaa_sc_ptr sc, gaa_condition *cond,
			   gaa_time_period *valid_time,
			   gaa_list_ptr req_options,
			   gaa_status *output_flags, void *params);

extern gaa_status
gaasimple_check_id_cond_nocase(gaa_ptr gaa, gaa_sc_ptr sc,
			       gaa_condition *cond,
			       gaa_time_period *valid_time,
			       gaa_list_ptr req_options,
			       gaa_status *output_flags, void *params);

extern void gaasimple_free_pval(void *pval);

#endif /* _GAA_SIMPLE_H_ */

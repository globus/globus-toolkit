#ifndef _GAA_DEBUG_H_
#define _GAA_DEBUG_H_

extern char *
gaadebug_condstr_r(gaa_condition *cond, char *buf, int bsize);

extern char *
gaadebug_request_right_string(gaa_ptr gaa, char *out, int osize,
			      gaa_request_right *right);

extern char *
gaadebug_policy_right_string(gaa_ptr gaa, char *out, int osize,
			     gaa_policy_right *right);

extern char *
gaadebug_policy_entry_string(gaa_ptr gaa, char *out, int osize,
			     gaa_policy_entry *ent);

extern char *
gaadebug_policy_string(gaa_ptr gaa, char *out, int osize, gaa_policy *policy);

extern char *
gaadebug_sc_string(gaa_ptr gaa, gaa_sc_ptr sc, char *out, int osize);

extern char *
gaadebug_cred_string(char *out, int osize, gaa_ptr gaa, gaa_cred *cred);

extern char *
gaadebug_sec_attrb_string(char *out, int osize, gaa_sec_attrb *a);

extern char *
gaadebug_answer_string(gaa_ptr gaa, char *out, int osize, gaa_answer *ans);

#ifdef USE_GAA_PRIVATE
extern char *
gaadebug_gaa_string(char *out, int osize, gaa_ptr gaa);
#endif /* USE_GAA_PRIVATE */

#endif /* _GAA_DEBUG_H_ */



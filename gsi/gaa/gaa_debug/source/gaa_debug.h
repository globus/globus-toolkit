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



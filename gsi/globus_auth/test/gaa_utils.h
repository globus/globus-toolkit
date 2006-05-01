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

extern char *process_msg(globus_authorization_handle_t handle, char *inbuf, char *outbuf, int outbsize, char **users);
extern gaa_status process_assert(gaa_ptr gaa, gaa_sc_ptr sc, char **users, char *outbuf, int outbsize);
extern gaa_status process_getpolicy(globus_authorization_handle_t handle, char *outbuf, int outbsize);
extern gaa_status process_request(globus_authorization_handle_t handle, char *inbuf, char *outbuf, int outbsize);
extern void process_print(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr *policy, char *outbuf, int outbsize);
extern gaa_status process_inquire(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr *policy, char *outbuf, int outbsize);
extern gaa_status process_clear(gaa_sc_ptr *sc);
extern init_sc(gaa_ptr gaa, gaa_sc_ptr *sc, void *context);
extern gaa_status process_pull(gaa_ptr gaa, gaa_sc_ptr sc, char *out, int osize);

extern char *process_msg(globus_authorization_handle_t handle, char *inbuf, char *outbuf, int outbsize, char **users);
extern gaa_status process_assert(gaa_ptr gaa, gaa_sc_ptr sc, char **users, char *outbuf, int outbsize);
extern gaa_status process_getpolicy(globus_authorization_handle_t handle, char *outbuf, int outbsize);
extern gaa_status process_request(globus_authorization_handle_t handle, char *inbuf, char *outbuf, int outbsize);
extern void process_print(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr *policy, char *outbuf, int outbsize);
extern gaa_status process_inquire(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr *policy, char *outbuf, int outbsize);
extern gaa_status process_clear(gaa_sc_ptr *sc);
extern init_sc(gaa_ptr gaa, gaa_sc_ptr *sc, void *context);
extern gaa_status process_pull(gaa_ptr gaa, gaa_sc_ptr sc, char *out, int osize);

extern char *process_msg(gaa_ptr gaa, gaa_sc_ptr *sc, char *inbuf, char *outbuf, int outbsize, char **users, gaa_policy_ptr *policy);
extern gaa_status process_assert(gaa_ptr gaa, gaa_sc_ptr sc, char **users, char *outbuf, int outbsize);
extern gaa_status process_getpolicy(gaa_ptr gaa, gaa_policy_ptr *policy, char *outbuf, int outbsize);
extern gaa_status process_request(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr policy, char *inbuf, char *outbuf, int outbsize);
extern void process_print(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr *policy, char *outbuf, int outbsize);
extern gaa_status process_inquire(gaa_ptr gaa, gaa_sc_ptr sc, gaa_policy_ptr *policy, char *outbuf, int outbsize);
extern gaa_status process_clear(gaa_sc_ptr *sc);
extern int init_sc(gaa_ptr gaa, gaa_sc_ptr *sc, void *context);
extern gaa_status process_pull(gaa_ptr gaa, gaa_sc_ptr sc, char *out, int osize);

extern gaa_status process_get_authz_id(gaa_ptr gaa,
                                       char *outbuf,
                                       int outbsize);


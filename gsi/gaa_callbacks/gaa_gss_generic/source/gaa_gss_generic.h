#ifndef _GAA_GLOBUS_H_
#define _GAA_GLOBUS_H_

extern gaa_status
gaa_gss_generic_cred_pull(gaa_ptr gaa, gaa_sc_ptr sc, gaa_cred_type which,
			void *params);

extern gaa_status
gaa_gss_generic_cred_eval(gaa_ptr gaa, gaa_sc_ptr sc, gaa_cred *cred,
			void *raw, gaa_cred_type cred_type, void *params);

extern gaa_status
gaa_gss_generic_cred_verify(gaa_cred *cred, void *params);

#endif /* _GAA_GLOBUS_H_ */

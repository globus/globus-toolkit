#ifndef _GAA_GLOBUS_H_
#define _GAA_GLOBUS_H_

typedef enum {
	GAA_GSS_GENERIC_CTX,
	GAA_GSS_GENERIC_CRED
} gaa_gss_generic_param_type;


/*
 * In gaa_gss_generic_param_s, type should be set to GAA_GSS_GENERIC_CTX
 * if param.ctx is used, or GAA_GSS_GENERIC_CRED if param.cred is used.
 */
typedef struct gaa_gss_generic_param_struct {
	gaa_gss_generic_param_type type;
	union {
		gss_ctx_id_t ctx;
		gss_cred_id_t cred;
	} param;
} gaa_gss_generic_param_s, *gaa_gss_generic_param_t ;

extern gaa_status
gaa_gss_generic_cred_pull(gaa_ptr gaa, gaa_sc_ptr sc, gaa_cred_type which,
			void *params);

extern gaa_status
gaa_gss_generic_cred_eval(gaa_ptr gaa, gaa_sc_ptr sc, gaa_cred *cred,
			void *raw, gaa_cred_type cred_type, void *params);

extern gaa_status
gaa_gss_generic_cred_verify(gaa_cred *cred, void *params);

#endif /* _GAA_GLOBUS_H_ */

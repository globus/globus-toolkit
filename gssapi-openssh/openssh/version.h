/* $OpenBSD: version.h,v 1.39 2003/09/16 21:02:40 markus Exp $ */

#ifdef GSI
#define GSI_VERSION	" GSI"
#else
#define GSI_VERSION	""
#endif

#ifdef KRB5
#define KRB5_VERSION	" KRB5"
#else
#define KRB5_VERSION	""
#endif

#ifdef MECHGLUE
#define MGLUE_VERSION	" MECHGLUE"
#else
#define MGLUE_VERSION	""
#endif

#define SSH_VERSION	"OpenSSH_3.7.1p2"	\
			" NCSA_GSSAPI_GPT_2.11" \
			GSI_VERSION KRB5_VERSION MGLUE_VERSION

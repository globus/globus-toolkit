/* $OpenBSD: version.h,v 1.42 2004/08/16 08:17:01 markus Exp $ */

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

#define SSH_VERSION	"OpenSSH_3.9p1"		\
			" NCSA_GSSAPI_20040818" \
			GSI_VERSION KRB5_VERSION MGLUE_VERSION

/* $OpenBSD: version.h,v 1.41 2004/03/20 10:40:59 markus Exp $ */

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

#define SSH_VERSION	"OpenSSH_3.8.1p1"	\
			" NCSA_GSSAPI_20040505" \
			GSI_VERSION KRB5_VERSION MGLUE_VERSION

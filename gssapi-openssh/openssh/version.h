/* $OpenBSD: version.h,v 1.43 2005/03/08 23:49:48 djm Exp $ */

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

#define SSH_VERSION	"OpenSSH_4.0"
#define SSH_PORTABLE	"p1"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE \
			" NCSA_GSSAPI_20050312" \
			GSI_VERSION KRB5_VERSION MGLUE_VERSION

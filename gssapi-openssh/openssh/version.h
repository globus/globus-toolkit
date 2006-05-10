/* $OpenBSD: version.h,v 1.46 2006/02/01 11:27:22 markus Exp $ */

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

#define SSH_VERSION	"OpenSSH_4.3"

#define SSH_PORTABLE	"p2"
#define SSH_HPN		"-hpn"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN \
			" NCSA_GSSAPI_20060510" \
			GSI_VERSION KRB5_VERSION MGLUE_VERSION

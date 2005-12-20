/* $OpenBSD: version.h,v 1.45 2005/08/31 09:28:42 markus Exp $ */

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

#define SSH_VERSION	"OpenSSH_4.2"

#define SSH_PORTABLE	"p1"
#define SSH_HPN		"-hpn"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN \
			" NCSA_GSSAPI_GPT_3.6-Prerelease" \
			GSI_VERSION KRB5_VERSION MGLUE_VERSION

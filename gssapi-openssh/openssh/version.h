/* $OpenBSD: version.h,v 1.50 2007/08/15 08:16:49 markus Exp $ */

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

#define NCSA_VERSION	" NCSA_GSSAPI_20071204"

#define SSH_VERSION	"OpenSSH_4.7"

#define SSH_PORTABLE	"p1"
#define SSH_HPN         "-hpn12v20"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN \
            NCSA_VERSION GSI_VERSION KRB5_VERSION MGLUE_VERSION

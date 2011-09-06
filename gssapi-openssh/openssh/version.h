/* $OpenBSD: version.h,v 1.62 2011/08/02 23:13:01 djm Exp $ */

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

#define GPT_VERSION	" GSI_GSSAPI_GPT_5.4"

#define SSH_VERSION	"OpenSSH_5.9"

#define SSH_PORTABLE	"p1"
#define SSH_HPN         "-hpn13v11"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN \
            GPT_VERSION GSI_VERSION KRB5_VERSION MGLUE_VERSION

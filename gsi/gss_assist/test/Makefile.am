include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = \
	pkgdata

Sources = \
	gss_assist_auth_init.c \
	gss_assist_auth_accept.c \
	gss_assist_impexp_init.c \
	gss_assist_impexp_accept.c

INCLUDES += $(GPT_INCLUDES)

test_PROGRAMS = \
	gss-assist-auth-init \
	gss-assist-auth-accept \
	gss-assist-impexp-init \
	gss-assist-impexp-accept

gss_assist_auth_init_SOURCES = gss_assist_auth_init.c

gss_assist_auth_init_LDFLAGS = $(GPT_LDFLAGS)

gss_assist_auth_init_LDADD = $(GPT_PGM_LINKS)

gss_assist_auth_accept_SOURCES = gss_assist_auth_accept.c

gss_assist_auth_accept_LDFLAGS = $(GPT_LDFLAGS)

gss_assist_auth_accept_LDADD = $(GPT_PGM_LINKS)

gss_assist_impexp_init_SOURCES = gss_assist_impexp_init.c

gss_assist_impexp_init_LDFLAGS = $(GPT_LDFLAGS)

gss_assist_impexp_init_LDADD = $(GPT_PGM_LINKS)

gss_assist_impexp_accept_SOURCES = gss_assist_impexp_accept.c

gss_assist_impexp_accept_LDFLAGS = $(GPT_LDFLAGS)

gss_assist_impexp_accept_LDADD = $(GPT_PGM_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

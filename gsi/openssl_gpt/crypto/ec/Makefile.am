include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	ec_lib.c \
	ecp_smpl.c \
	ecp_mont.c \
	ecp_recp.c \
	ecp_nist.c \
	ec_cvt.c \
	ec_mult.c \
	ec_err.c

opensslinclude_HEADERS= \
	ec.h

noinst_HEADERS = \
	ec_lcl.h

Test_Sources = \
	ectest.c

noinst_LTLIBRARIES = libec_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libec___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libec___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

libec___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post









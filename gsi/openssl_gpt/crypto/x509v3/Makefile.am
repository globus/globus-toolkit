include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources = \
	v3_bcons.c \
	v3_bitst.c \
	v3_conf.c \
	v3_extku.c \
	v3_ia5.c \
	v3_lib.c \
	v3_prn.c \
	v3_utl.c \
	v3err.c \
	v3_genn.c \
	v3_alt.c \
	v3_skey.c \
	v3_akey.c \
	v3_pku.c \
	v3_int.c \
	v3_enum.c \
	v3_sxnet.c \
	v3_cpols.c \
	v3_crld.c \
	v3_purp.c \
	v3_info.c \
	v3_akeya.c \
	v3_ocsp.c

opensslinclude_HEADERS = \
	x509v3.h

noinst_HEADERS = \
	ext_dat.h

noinst_LTLIBRARIES = libx509v3_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libx509v3___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libx509v3___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libx509v3___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post

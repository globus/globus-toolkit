include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	x509_def.c x509_d2.c x509_r2x.c x509_cmp.c \
	x509_obj.c x509_req.c x509spki.c x509_vfy.c \
	x509_set.c x509rset.c x509_err.c \
	x509name.c x509_v3.c x509_ext.c x509_att.c \
	x509type.c x509_lu.c x_all.c x509_txt.c \
	x509_trs.c by_file.c by_dir.c x509cset.c

opensslinclude_HEADERS= \
	x509.h \
	x509_vfy.h

noinst_LTLIBRARIES = libx509_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libx509___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libx509___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libx509___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post

include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

sasllibdir = ${GLOBUS_LOCATION}/lib/sasl

SUBDIRS= \
	pkgdata \
	doxygen

Sources= \
	gssapi.c \
	gssname.c

EXTRA_DIST= \
	mkgssname

INCLUDES = $(GPT_INCLUDES)

AM_CFLAGS = $(GPT_CFLAGS) 

sasllib_LTLIBRARIES = libgssapiv2_gsi_$(GLOBUS_FLAVOR_NAME).la

libgssapiv2_gsi___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libgssapiv2_gsi___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libgssapiv2_gsi___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top


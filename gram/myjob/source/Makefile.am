include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

EXTRA_DIST = \
	version.h.in

Sources = \
	globus_gram_myjob.h \
	globus_gram_myjob_duct.c \
	globus_gram_myjob_mp.c    

INCLUDES = $(GPT_INCLUDES)

flavorinclude_HEADERS=globus_gram_myjob.h

lib_LTLIBRARIES = libglobus_gram_myjob.la

libglobus_gram_myjob_la_SOURCES = $(Sources)

libglobus_gram_myjob_la_LDFLAGS = $(GPT_LDFLAGS)

libglobus_gram_myjob_la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top


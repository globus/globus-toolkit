include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

Sources= \
    globus_xio_test_transport.c

lib_LTLIBRARIES = libglobus_xio_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES) -I../../

libglobus_xio___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_xio___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_xio___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

include $(top_srcdir)/globus_automake_pre

Sources= \
	globus_xio_handle.c                     \
	globus_xio_pass.c                       \
	globus_xio_attr.c                       \
	globus_xio_server.c                     \
	globus_xio_timeout.c

flavorinclude_HEADERS = \
    globus_xio.h

lib_LTLIBRARIES = libglobus_xio_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES) $(NETLOGGER_INCLUDES)

libglobus_xio___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@
libglobus_xio___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@
libglobus_xio___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

EXTRA_DIST = \
	version.h.in
    


include $(top_srcdir)/globus_automake_post


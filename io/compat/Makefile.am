include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
        pkgdata \
        doxygen

Sources= \
	globus_io.h \
	globus_io_error_hierarchy.c \
	globus_io_error_hierarchy.h \
	globus_io_xio_compat.c

flavorinclude_HEADERS = \
	globus_io.h \
	globus_io_error_hierarchy.h

lib_LTLIBRARIES = libglobus_io_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES)

libglobus_io___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@
libglobus_io___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@

libglobus_io___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

EXTRA_DIST = \
        version.h.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

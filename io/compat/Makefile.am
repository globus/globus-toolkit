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

include_HEADERS = \
	globus_io.h \
	globus_io_error_hierarchy.h

lib_LTLIBRARIES = libglobus_io.la

doc_DATA = GLOBUS_LICENSE

INCLUDES = $(GPT_INCLUDES)

libglobus_io_la_LDFLAGS = @GPT_LDFLAGS@
libglobus_io_la_LIBADD = @GPT_LIB_LINKS@

libglobus_io_la_SOURCES = $(Sources)

EXTRA_DIST = version.h.in $(doc_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

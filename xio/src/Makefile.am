include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS=\
	builtins                                    \
	.                                           \
	pkgdata                                     \
	doxygen

Sources= \
	globus_xio_handle.c                         \
	globus_xio_driver.c                         \
	globus_xio_attr.c                           \
	globus_xio_timeout.c                        \
	globus_xio_server.c                         \
	globus_xio_pass.c                           \
	globus_xio_util.c                           \
	globus_xio_system_select.c                  \
	globus_i_xio_system_common.c                \
	globus_xio_load.c

flavorinclude_HEADERS = \
    globus_xio_types.h                          \
    globus_xio_util.h                           \
    globus_xio_load.h                           \
    globus_xio_driver.h                         \
    globus_xio.h                                \
    globus_xio_system.h 

noinst_HEADERS = \
    globus_i_xio.h \
    globus_i_xio_system_common.h

lib_LTLIBRARIES = libglobus_xio_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES)

libglobus_xio___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources) 
libglobus_xio___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_xio___GLOBUS_FLAVOR_NAME__la_LIBADD = \
	$(GPT_LIB_LINKS) \
	$(XIO_BUILTIN_LIBS)

EXTRA_DIST = \
	version.h.in \
	extensions.h.in \
	configure.in.in

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

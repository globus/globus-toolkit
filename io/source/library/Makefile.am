include $(top_srcdir)/globus_automake_pre

Sources= \
	globus_io.h \
	globus_io.tag \
	globus_io_attr.c \
	globus_io_common.c \
	globus_io_core.c \
	globus_io_error_hierarchy.c \
	globus_io_error_hierarchy.h \
	globus_io_error_strings.c \
	globus_io_file.c \
	globus_io_read.c \
	globus_io_securesocket.c \
	globus_io_socket.c \
	globus_io_tcp.c \
	globus_io_udp.c \
	globus_io_write.c \
	globus_l_io.h

flavorinclude_HEADERS = \
	globus_io.h \
	globus_io_error_hierarchy.h

lib_LTLIBRARIES = libglobus_io_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = $(GPT_INCLUDES) $(NETLOGGER_INCLUDES)

libglobus_io___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@
libglobus_io___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@ $(NETLOGGER_LIBS)

libglobus_io___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

EXTRA_DIST = \
	globus_io_error_hierarchy.h.sh \
	globus_io_error_hierarchy.idl


include $(top_srcdir)/globus_automake_post



include $(top_srcdir)/globus_automake_pre

Sources= \
    globus_xio_udt.c \
    globus_xio_udt_attr.c \
    globus_xio_udt_open.c \
    globus_xio_udt_close.c \
    globus_xio_udt_read.c \
    globus_xio_udt_write.c \
    globus_xio_udt_control.c \
    globus_xio_udt_misc.c \
    globus_i_xio_udt.h \
    globus_xio_udt.h    

flavorinclude_HEADERS = \
    globus_xio_udt.h

noinst_HEADERS = \
    globus_i_xio_udt.h 

noinst_LTLIBRARIES = libglobus_xio_udt_driver_$(GLOBUS_FLAVOR_NAME).la 

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/builtins/udp \
-I$(top_srcdir)/builtins/tcp $(GPT_INCLUDES)

libglobus_xio_udt_driver___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_xio_udt_driver___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_xio_udt_driver___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

include $(top_srcdir)/globus_automake_post

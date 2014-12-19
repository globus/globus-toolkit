noinst_LTLIBRARIES = libglobus_net_manager_context.la

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_builddir) -I$(top_srcdir)/attr -I$(srcdir) $(PACKAGE_DEP_CFLAGS) 
AM_LDFLAGS = $(PACKAGE_DEP_LIBS)
libglobus_net_manager_context_la_SOURCES = \
            globus_net_manager_context.h \
            destroy.c \
            init.c \
            post_accept.c \
            post_close.c \
            post_connect.c \
            post_listen.c \
            pre_accept.c \
            pre_close.c \
            pre_connect.c \
            pre_listen.c \
            end_listen.c

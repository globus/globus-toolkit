
include $(top_srcdir)/globus_automake_pre

Sources= \
	globus_gsi_system_config.h \
	globus_i_gsi_system_config.h \
	globus_gsi_system_config.c \
	globus_gsi_system_config_constants.h \
	globus_gsi_system_config_error.c

flavorinclude_HEADERS= \
	globus_gsi_system_config.h \
        globus_gsi_system_config_constants.h

lib_LTLIBRARIES = libglobus_gsi_sysconfig_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I.. @GPT_INCLUDES@

libglobus_gsi_sysconfig___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libglobus_gsi_sysconfig___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@

libglobus_gsi_sysconfig___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@

include $(top_srcdir)/globus_automake_post

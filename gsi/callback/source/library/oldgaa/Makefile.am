lib_LTLIBRARIES = libglobus_oldgaa.la

libglobus_oldgaa_la_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I../..
libglobus_oldgaa_la_LDFLAGS = \
	-version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
	-no-undefined
libglobus_oldgaa_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_oldgaa_la_SOURCES = \
	oldgaa_alloc.c \
	oldgaa_api.c \
	oldgaa_gl_internal_err.c \
	oldgaa_gl_internal_err.h \
	oldgaa_policy_evaluator.c \
	oldgaa_policy_evaluator.h \
	oldgaa_release.c \
	oldgaa_utils.c \
	oldgaa_utils.h \
	globus_oldgaa.h \
	globus_oldgaa_utils.c \
	globus_oldgaa_utils.h \
	rfc1779.c \
	rfc1779.h

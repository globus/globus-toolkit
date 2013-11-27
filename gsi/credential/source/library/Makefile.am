include_HEADERS = \
	globus_gsi_credential.h \
	globus_gsi_cred_constants.h
lib_LTLIBRARIES = libglobus_gsi_credential.la

libglobus_gsi_credential_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_gsi_credential_la_LDFLAGS = \
        -version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined
libglobus_gsi_credential_la_CPPFLAGS = -I$(top_builddir) -I$(srcdir) \
        $(PACKAGE_DEP_CFLAGS)
libglobus_gsi_credential_la_SOURCES = \
	globus_gsi_credential.h \
	globus_gsi_credential.c \
	globus_i_gsi_credential.h \
	globus_gsi_cred_handle.c \
	globus_gsi_cred_handle_attrs.c \
	globus_gsi_cred_constants.h \
	globus_gsi_cred_error.c 

ACLOCAL_AMFLAGS=-I m4

pkgconfigdir = $(libdir)/pkgconfig

include_HEADERS = globus_gass_server_ez.h
lib_LTLIBRARIES = libglobus_gass_server_ez.la
bin_SCRIPTS = globus-gass-server-shutdown
bin_PROGRAMS = globus-gass-server 
doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-gass-server-ez.pc

libglobus_gass_server_ez_la_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)
libglobus_gass_server_ez_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_gass_server_ez_la_LDFLAGS = \
        -version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined
libglobus_gass_server_ez_la_SOURCES = \
        globus_gass_server_ez.c \
        globus_gass_server_ez.h

globus_gass_server_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)
globus_gass_server_SOURCES = globus_gass_server.c
globus_gass_server_LDADD = libglobus_gass_server_ez.la $(PACKAGE_DEP_LIBS) 

EXTRA_DIST = \
	dirt.sh \
	$(doc_DATA)

distuninstallcheck:
	@:

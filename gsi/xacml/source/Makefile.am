AUTOMAKE_OPTIONS=foreign

SUBDIRS=examples schema
EXTRA_DIST=typemap.dat abstract-inheritance.diff Doxyfile doxygen.head doxygen.foot

SCHEMA=schema/xacml_authz_service.wsdl
GSOAP_FILE = xacml_auth_service.gsoap 
GSOAP_FILE_PATCHED = xacml_auth_service-patched.gsoap
GSOAP_SOURCE_FILES= soapStub.h \
                    soapH.h \
                    soapC.cpp \
                    soapClient.cpp \
                    soapClientLib.cpp \
                    soapServer.cpp \
                    soapServerLib.cpp \
                    XACMLAuthorizationPortTypeSOAPBinding.nsmap

AM_CPPFLAGS=-DWITH_OPENSSL=1
AM_CXXFLAGS=-g -Wall -O0
INCLUDES=-I$(GSOAP_DIR)/include
LDADD=-L$(GSOAP_DIR)/lib

lib_LTLIBRARIES = libxacml.la

include_HEADERS = xacml_client.h xacml_server.h xacml.h xacml_datatypes.h xacml_authz_interop_profile.h

bin_PROGRAMS = xacml-client xacml-server

libxacml_la_SOURCES = \
        xacml_authz_interop_profile.h \
        xacml_authz_interop_profile.cpp \
        xacml_ns.cpp \
        xacml_client.cpp \
        xacml_datatypes.cpp \
        xacml_io.cpp \
        xacml_obligation.cpp \
        xacml_request.cpp \
        xacml_response.cpp \
        xacml_resource_attribute.cpp \
        xacml_server.cpp \
        stlvector.h \
        xacml.h \
        xacml_client.h \
        xacml_datatypes.h \
        xacml_i.h \
        xacml_server.h
nodist_libxacml_la_SOURCES = soapStub.h soapH.h soapC.cpp soapClient.cpp soapServer.cpp
libxacml_la_LIBADD = -lgsoap++ -lpthread -ldl

xacml_server_SOURCES = xacml_server_example.c xacml_io_example.h xacml_io_example.c
xacml_server_LDADD = $(LDADD) libxacml.la -lgsoap++ -lpthread -ldl

xacml_client_SOURCES = xacml_client_program.c xacml_io_example.h xacml_io_example.c
xacml_client_LDADD = $(LDADD) libxacml.la -lgsoap++ -lpthread -ldl

# Rules to create gsoap files
$(GSOAP_FILE): $(SCHEMA) typemap.dat
	$(WSDL2H) -a -x -f $(SCHEMA) -o $@

$(GSOAP_SOURCE_FILES): $(GSOAP_FILE_PATCHED)
	$(SOAPCPP2) -1 -w -x $(GSOAP_FILE_PATCHED) || true

$(GSOAP_FILE_PATCHED): $(GSOAP_FILE)
	cp $(GSOAP_FILE) $(GSOAP_FILE_PATCHED)
	patch -p0 < abstract-inheritance.diff

BUILT_SOURCES=$(nodist_libxacml_la_SOURCES)

CLEANFILES=$(GSOAP_FILE) $(GSOAP_SOURCE_FILES) \
	soapXACMLAuthorizationPortTypeSOAPBindingObject.h \
	soapXACMLAuthorizationPortTypeSOAPBindingProxy.h

doc:
	@DOXYGEN@

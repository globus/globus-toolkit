AUTOMAKE_OPTIONS=foreign

EXTRA_DIST=typemap.dat

SCHEMA=$(SCHEMA_DIR)/xacml_authz_service.wsdl
GSOAP_FILE = xacml_auth_service.gsoap 
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
INCLUDES=-I$(GSOAP_DIR)/include -I$(GLOBUS_LOCATION)/include/gcc32dbg
LDADD=-L$(GSOAP_DIR)/lib

noinst_LTLIBRARIES = libxacml_common.la \
                     libxacml_soap_common.la \
                     libxacml_soap_client.la \
                     libxacml_soap_server.la

include_HEADERS = xacml_client.h xacml_server.h xacml.h xacml_datatypes.h

bin_PROGRAMS = xacml-client xacml-server

libxacml_common_la_SOURCES = xacml_response.cpp \
                                   xacml_request.cpp \
                                   xacml_i.h xacml.h \
                                   xacml_datatypes.h xacml_datatypes.cpp

nodist_libxacml_soap_common_la_SOURCES = soapStub.h soapH.h soapC.cpp
libxacml_soap_common_la_SOURCES = stlvector.h
libxacml_soap_common_la_LIBADD = -lgsoapssl++ -lssl -lcrypto


nodist_libxacml_soap_client_la_SOURCES = soapClient.cpp soapStub.h soapH.h
libxacml_soap_client_la_SOURCES = xacml_client.cpp xacml_client.h
libxacml_soap_client_la_LIBADD = libxacml_soap_common.la

nodist_libxacml_soap_server_la_SOURCES = soapServer.cpp soapStub.h soapH.h 
libxacml_soap_server_la_SOURCES = xacml_server.cpp xacml_server.h
libxacml_soap_server_la_LIBADD = libxacml_soap_common.la -lpthread

xacml_server_SOURCES = xacml_server_example.c xacml_ns.cpp 
xacml_server_LDADD = $(LDADD) libxacml_soap_server.la libxacml_common.la 

xacml_client_SOURCES = xacml_ns.cpp xacml_client_program.c 
xacml_client_LDADD = $(LDADD) libxacml_soap_client.la libxacml_common.la 

# Rules to create gsoap files
$(GSOAP_FILE): $(SCHEMA) typemap.dat
	$(WSDL2H) -a -x -f $(SCHEMA) -o $@

$(GSOAP_SOURCE_FILES): $(GSOAP_FILE)
	$(SOAPCPP2) -1 -w -x $(GSOAP_FILE) || true

CLEANFILES=$(GSOAP_FILE) $(GSOAP_SOURCE_FILES) \
	soapXACMLAuthorizationPortTypeSOAPBindingObject.h \
	soapXACMLAuthorizationPortTypeSOAPBindingProxy.h

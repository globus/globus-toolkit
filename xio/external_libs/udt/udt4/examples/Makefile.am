bin_PROGRAMS = udt_appclient udt_appserver udt_recvfile udt_sendfile

udt_appclient_SOURCES = appclient.cpp
udt_appserver_SOURCES = appserver.cpp
udt_recvfile_SOURCES  = recvfile.cpp
udt_sendfile_SOURCES  = sendfile.cpp

udt_appclient_DEPENDENCIES = ../@LIBUDT@
udt_appserver_DEPENDENCIES = ../@LIBUDT@
udt_recvfile_DEPENDENCIES =  ../@LIBUDT@
udt_sendfile_DEPENDENCIES =  ../@LIBUDT@

udt_appclient_LDADD = ../@LIBUDT@
udt_appserver_LDADD = ../@LIBUDT@
udt_recvfile_LDADD =  ../@LIBUDT@
udt_sendfile_LDADD =  ../@LIBUDT@

../@LIBUDT@:
	cd ../src; make; cd ../examples;

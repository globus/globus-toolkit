AM_CPPFLAGS = -I$(top_srcdir) $(PACKAGE_DEP_CFLAGS)
# Some automation is needed to actually get these tests to run

check_PROGRAMS = \
    globus_gs_simple_test    \
    globus_ftp_telnet_client \
    globus_xio_ftp_server 

globus_gs_simple_test_LDADD = \
    ../libglobus_gridftp_server_control.la \
    $(PACKAGE_DEP_LIBS)

globus_ftp_telnet_client_LDADD = \
    ../libglobus_gridftp_server_control.la \
    $(PACKAGE_DEP_LIBS)

globus_xio_ftp_server_LDADD = \
    ../libglobus_gridftp_server_control.la \
    $(PACKAGE_DEP_LIBS)

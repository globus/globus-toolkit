include makefile_header

globus-gridftp-register: globus_gridftp_register.c
	$(GLOBUS_CC) $(GLOBUS_INCLUDES) $(GLOBUS_CFLAGS)	\
		 -o globus-gridftp-register globus_gridftp_register.c $(GLOBUS_LDFLAGS) $(GLOBUS_PKG_LIBS)

shell-ftp: shell_ftp.c
	$(GLOBUS_CC) $(GLOBUS_INCLUDES) $(GLOBUS_CFLAGS)	\
		 -o shell-ftp shell_ftp.c $(GLOBUS_LDFLAGS) $(GLOBUS_PKG_LIBS)

xio-ftp: xio_ftp.c
	$(GLOBUS_CC) $(GLOBUS_INCLUDES) $(GLOBUS_CFLAGS)	\
		 -o xio-ftp xio_ftp.c $(GLOBUS_LDFLAGS) $(GLOBUS_PKG_LIBS)


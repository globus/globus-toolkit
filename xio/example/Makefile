include makefile_header

globus-xio-email: globus_xio_email.c
	$(GLOBUS_CC) $(GLOBUS_CFLAGS) $(GLOBUS_INCLUDES) -o globus-xio-email \
        globus_xio_email.c $(GLOBUS_LDFLAGS) $(GLOBUS_LIBS) $(GLOBUS_PKG_LIBS)

clean:
	rm globus-xio-email 

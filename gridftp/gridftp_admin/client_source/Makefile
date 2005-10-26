include makefile_header

all: get-RP set-RP

reg-client: reg_client.c
	$(GLOBUS_CC) $(GLOBUS_INCLUDES) $(GLOBUS_CFLAGS)  \
        -I. -o reg-client \
		reg_client.c $(GLOBUS_LDFLAGS)  $(GLOBUS_PKG_LIBS)

get-RP: get_RP.c
	$(GLOBUS_CC) $(GLOBUS_INCLUDES) $(GLOBUS_CFLAGS)  \
        -I. -o get-RP \
		get_RP.c $(GLOBUS_LDFLAGS)  $(GLOBUS_PKG_LIBS)

set-RP: set_RP.c
	$(GLOBUS_CC) $(GLOBUS_INCLUDES) $(GLOBUS_CFLAGS)  \
        -I. -o set-RP \
		set_RP.c $(GLOBUS_LDFLAGS)  $(GLOBUS_PKG_LIBS)

clean:
	rm -f reg-client get-RP set-RP *~

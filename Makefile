CFLAGS	=	-g -I/usr/local/gsi/development/i686-pc-linux-gnu_nothreads_standard_debug/include/

TARGETS	=	gsi-packet-test

default:	$(TARGETS)

gsi-packet-test: gsi-packet-test.o gsi-packet.o

clean:
	rm -f *.o
	rm -f $(TARGETS)
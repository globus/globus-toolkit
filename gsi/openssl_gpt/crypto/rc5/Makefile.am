include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

SUBDIRS= \
	asm

Sources= \
	rc5_skey.c \
	rc5_ecb.c \
	rc5cfb64.c \
	rc5ofb64.c

Extra_Sources= \
	rc5_enc.c

Test_Sources = \
	rc5test.c

opensslinclude_HEADERS= \
	rc5.h

noinst_HEADERS = \
	rc5_locl.h

noinst_LTLIBRARIES = librc5_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

librc5___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

EXTRA_librc5___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Extra_Sources)

librc5___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) @RC5_OBJ@ 

librc5___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

librc5___GLOBUS_FLAVOR_NAME__la_DEPENDENCIES = @RC5_OBJ@

asm/r586-sol.lo: asm/r586unix.cpp
	$(CPP) -DSOL asm/r586unix.cpp | sed 's/^#.*//' > asm/r586-sol.s
	$(LTCOMPILE) -c asm/r586-sol.s -o asm/r586-sol.lo
	rm -f asm/r586-sol.s

asm/r586-elf.lo: asm/r586unix.cpp
	$(CPP) -DELF -x c asm/r586unix.cpp > asm/r586-elf.s
	$(LTCOMPILE) -c asm/r586-elf.s -o asm/r586-elf.lo
	rm -f asm/r586-elf.s

# generate the input
# assume we are not on a 386

asm/r586unix.cpp: asm/rc5-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	(cd asm;$(PERL) rc5-586.pl cpp > r586unix.cpp)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post

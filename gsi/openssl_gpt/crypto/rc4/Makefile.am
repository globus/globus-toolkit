include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

SUBDIRS= \
	asm

Sources= \
	rc4_skey.c

Extra_Sources= \
	rc4_enc.c

Test_Sources = \
	rc4test.c

opensslinclude_HEADERS= \
	rc4.h

noinst_HEADERS = \
	rc4_locl.h

noinst_LTLIBRARIES = librc4_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

librc4___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

EXTRA_librc4___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Extra_Sources)

librc4___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) @RC4_OBJ@

librc4___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

librc4___GLOBUS_FLAVOR_NAME__la_DEPENDENCIES =  @RC4_OBJ@

asm/rx86-sol.lo: asm/rx86unix.cpp
	$(CPP) -DSOL asm/rx86unix.cpp | sed 's/^#.*//' > asm/rx86-sol.s
	$(LTCOMPILE) -c asm/rx86-sol.s -o asm/rx86-sol.lo
	rm -f asm/rx86-sol.s

asm/rx86-elf.lo: asm/rx86unix.cpp
	$(CPP) -DELF -x c asm/rx86unix.cpp > asm/rx86-elf.s
	$(LTCOMPILE) -c asm/rx86-elf.s -o asm/rx86-elf.lo
	rm -f asm/rx86-elf.s

# generate the input
# assume we are not on a 386

asm/rx86unix.cpp: asm/rc4-586.pl ../perlasm/x86asm.pl 
	(cd asm;$(PERL) rc4-586.pl cpp > rx86unix.cpp)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post

include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

SUBDIRS= \
	asm

Sources= \
	bf_ecb.c \
	bf_skey.c \
	bf_cfb64.c \
	bf_ofb64.c

Extra_Sources= \
	bf_enc.c

Test_Sources = \
	bftest.c

opensslinclude_HEADERS= \
	blowfish.h

noinst_HEADERS = \
	bf_pi.h \
	bf_locl.h

noinst_LTLIBRARIES = libbf_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libbf___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

EXTRA_libbf___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Extra_Sources)

libbf___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) @BF_OBJ@

libbf___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libbf___GLOBUS_FLAVOR_NAME__la_DEPENDENCIES =  @BF_OBJ@

asm/bx86-sol.lo: asm/bx86unix.cpp
	$(CPP) -DSOL asm/bx86unix.cpp | sed 's/^#.*//' > asm/bx86-sol.s
	$(LTCOMPILE) -c asm/bx86-sol.s -o asm/bx86-sol.lo
	rm -f asm/bx86-sol.s

asm/bx86-elf.lo: asm/bx86unix.cpp
	$(CPP) -DELF -x c asm/bx86unix.cpp > asm/bx86-elf.s
	$(LTCOMPILE) -c asm/bx86-elf.s -o asm/bx86-elf.lo
	rm -f asm/bx86-elf.s

# generate the input
# assume we are not on a 386

asm/bx86unix.cpp: asm/bf-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	(cd asm;$(PERL) bf-586.pl cpp " " > bx86unix.cpp)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post








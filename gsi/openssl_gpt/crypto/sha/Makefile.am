include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

SUBDIRS = \
	asm

Sources = \
	sha_dgst.c \
	sha_one.c \
	sha1dgst.c \
	sha1_one.c

Test_Sources = \
	shatest.c \
	sha1test.c

opensslinclude_HEADERS = \
	sha.h

noinst_HEADERS = \
	sha_locl.h

noinst_LTLIBRARIES = libsha_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libsha___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libsha___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) @SHA1_OBJ@

libsha___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libsha___GLOBUS_FLAVOR_NAME__la_DEPENDENCIES = @SHA1_OBJ@

asm/sx86-sol.lo: asm/sx86unix.cpp
	$(CPP) -DSOL asm/sx86unix.cpp | sed 's/^#.*//' > asm/sx86-sol.s
	$(LTCOMPILE) -c asm/sx86-sol.s -o asm/sx86-sol.lo
	rm -f asm/sx86-sol.s

asm/sx86-elf.lo: asm/sx86unix.cpp
	$(CPP) -DELF -x c asm/sx86unix.cpp > asm/sx86-elf.s
	$(LTCOMPILE) -c asm/sx86-elf.s -o asm/sx86-elf.lo
	rm -f asm/sx86-elf.s

# generate the input
# assume we are not on a 386

asm/sx86unix.cpp: asm/sha1-586.pl ../perlasm/x86asm.pl
	(cd asm;$(PERL) sha1-586.pl cpp " " > sx86unix.cpp)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post


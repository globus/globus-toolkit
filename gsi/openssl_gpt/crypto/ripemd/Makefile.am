include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

SUBDIRS= \
	asm

Sources= \
	rmd_dgst.c \
	rmd_one.c

Test_Sources = \
	rmdtest.c

opensslinclude_HEADERS= \
	ripemd.h

noinst_HEADERS = \
	rmd_locl.h \
	rmdconst.h

noinst_LTLIBRARIES = libripemd_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libripemd___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libripemd___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) @RMD_OBJ@

libripemd___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libripemd___GLOBUS_FLAVOR_NAME__la_DEPENDENCIES = @RMD_OBJ@

asm/rm86-sol.lo: asm/rm86unix.cpp
	$(CPP) -DSOL asm/rm86unix.cpp | sed 's/^#.*//' > asm/rm86-sol.s
	$(LTCOMPILE) -c asm/rm86-sol.s -o asm/rm86-sol.lo
	rm -f asm/rm86-sol.s

asm/rm86-elf.lo: asm/rm86unix.cpp
	$(CPP) -DELF -x c asm/rm86unix.cpp > asm/rm86-elf.s
	$(LTCOMPILE) -c asm/rm86-elf.s -o asm/rm86-elf.lo
	rm -f asm/rm86-elf.s

# generate the input

asm/rm86unix.cpp: asm/rmd-586.pl ../perlasm/x86asm.pl
	(cd asm;$(PERL) rmd-586.pl cpp " " > rm86unix.cpp)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post

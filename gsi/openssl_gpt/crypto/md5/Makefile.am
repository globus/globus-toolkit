include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

SUBDIRS= \
	asm

Sources= \
	md5_dgst.c \
	md5_one.c

Test_Sources = \
	md5test.c

opensslinclude_HEADERS= \
	md5.h

noinst_HEADERS = \
	md5_locl.h

noinst_LTLIBRARIES = libmd5_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libmd5___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libmd5___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) @MD5_OBJ@

libmd5___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libmd5___GLOBUS_FLAVOR_NAME__la_DEPENDENCIES = @MD5_OBJ@

asm/mx86-sol.lo: asm/mx86unix.cpp
	$(CPP) -DSOL asm/mx86unix.cpp | sed 's/^#.*//' > asm/mx86-sol.s
	$(LTCOMPILE) -c asm/mx86-sol.s -o asm/mx86-sol.lo
	rm -f asm/mx86-sol.s

asm/mx86-elf.lo: asm/mx86unix.cpp
	$(CPP) -DELF -x c asm/mx86unix.cpp > asm/mx86-elf.s
	$(LTCOMPILE) -c asm/mx86-elf.s -o asm/mx86-elf.lo
	rm -f asm/mx86-elf.s

# generate the input

asm/mx86unix.cpp: asm/md5-586.pl ../perlasm/x86asm.pl
	(cd asm;$(PERL) md5-586.pl cpp > mx86unix.cpp)

asm/md5-sparcv8plus.lo: asm/md5-sparcv9.S
	$(LTCOMPILE) -DMD5_BLOCK_DATA_ORDER -c \
		-o asm/md5-sparcv8plus.lo asm/md5-sparcv9.S

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post

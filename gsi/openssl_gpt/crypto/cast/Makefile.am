include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

SUBDIRS= \
	asm

Sources= \
	c_ecb.c \
	c_skey.c \
	c_cfb64.c \
	c_ofb64.c

Extra_Sources= \
	c_enc.c

Test_Sources = \
	casttest.c

opensslinclude_HEADERS= \
	cast.h

noinst_HEADERS = \
	cast_s.h \
	cast_lcl.h

noinst_LTLIBRARIES = libcast_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libcast___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

EXTRA_libcast___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Extra_Sources)

libcast___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) @CAST_OBJ@ 

libcast___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libcast___GLOBUS_FLAVOR_NAME__la_DEPENDENCIES = @CAST_OBJ@ 

# x86 elf

asm/cx86-elf.lo: asm/cx86unix.cpp
	$(CPP) -DELF -x c asm/cx86unix.cpp > asm/cx86-elf.s
	$(LTCOMPILE) -c asm/cx86-elf.s -o asm/cx86-elf.lo
	rm -f asm/cx86-elf.s

# x86 solaris

asm/cx86-sol.lo: asm/cx86unix.cpp
	$(CPP) -DSOL asm/cx86unix.cpp | sed 's/^#.*//' > asm/cx86-sol.s
	$(LTCOMPILE) -c asm/cx86-sol.s -o asm/cx86-sol.lo
	rm -f asm/cx86-sol.s

# generate the input

asm/cx86unix.cpp: asm/cast-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	(cd asm;$(PERL) cast-586.pl cpp " " > cx86unix.cpp)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post

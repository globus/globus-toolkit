include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

SUBDIRS= \
	asm

Sources= \
	cbc_cksm.c cbc_enc.c  cfb64enc.c cfb_enc.c  \
	ecb3_enc.c ecb_enc.c  enc_read.c enc_writ.c \
	fcrypt.c ofb64enc.c ofb_enc.c  pcbc_enc.c \
	qud_cksm.c rand_key.c rpc_enc.c  set_key.c  \
	xcbc_enc.c str2key.c cfb64ede.c ofb64ede.c \
	ede_cbcm_enc.c des_old.c des_old2.c read2pwd.c

Extra_Sources= \
	des_enc.c \
	fcrypt_b.c \
	ncbc_enc.c

Test_Sources = \
	destest.c

opensslinclude_HEADERS= \
	des.h \
	des_old.h

noinst_HEADERS = \
	des_locl.h \
	rpc_des.h \
	spr.h \
	des_ver.h

noinst_LTLIBRARIES = libdes_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libdes___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

EXTRA_libdes___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Extra_Sources)

libdes___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) @DES_OBJ@

libdes___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

libdes___GLOBUS_FLAVOR_NAME__la_DEPENDENCIES = @DES_OBJ@

# x86 elf

asm/dx86-elf.lo: asm/dx86unix.cpp
	$(CPP) -DELF -x c asm/dx86unix.cpp > asm/dx86-elf.s
	$(LTCOMPILE) -c asm/dx86-elf.s -o asm/dx86-elf.lo
	rm -f asm/dx86-elf.s

asm/yx86-elf.lo: asm/yx86unix.cpp
	$(CPP) -DELF -x c asm/yx86unix.cpp > asm/yx86-elf.s
	$(LTCOMPILE) -c asm/yx86-elf.s -o asm/yx86-elf.lo
	rm -f asm/yx86-elf.s

# x86 solaris

asm/dx86-sol.lo: asm/dx86unix.cpp
	$(CPP) -DSOL asm/dx86unix.cpp | sed 's/^#.*//' > asm/dx86-sol.s
	$(LTCOMPILE) -c asm/dx86-sol.s -o asm/dx86-sol.lo
	rm -f asm/dx86-sol.s

asm/yx86-sol.lo: asm/yx86unix.cpp
	$(CPP) -DSOL asm/yx86unix.cpp | sed 's/^#.*//' > asm/yx86-sol.s
	$(LTCOMPILE) -c asm/yx86-sol.s -o asm/yx86-sol.lo
	rm -f asm/yx86-sol.s

# generate the input

asm/dx86unix.cpp: asm/des-586.pl ../perlasm/x86asm.pl ../perlasm/cbc.pl
	(cd asm;$(PERL) des-586.pl cpp > dx86unix.cpp)

asm/yx86unix.cpp: asm/crypt586.pl ../perlasm/x86asm.pl
	(cd asm;$(PERL) crypt586.pl cpp >yx86unix.cpp)

EXTRA_DIST = $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post



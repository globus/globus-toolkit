include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

SUBDIRS= \
	asm

Sources= \
	bn_add.c \
	bn_div.c \
	bn_exp.c \
	bn_lib.c \
	bn_ctx.c \
	bn_mul.c \
	bn_print.c \
	bn_rand.c \
	bn_shift.c \
	bn_word.c \
	bn_blind.c \
	bn_gcd.c \
	bn_prime.c \
	bn_err.c \
	bn_sqr.c \
	bn_recp.c \
	bn_mont.c \
	bn_mpi.c \
	bn_exp2.c \
	bn_kron.c \
	bn_mod.c \
	bn_sqrt.c

Extra_Sources= \
	bn_asm.c

opensslinclude_HEADERS= \
	bn.h

noinst_HEADERS = \
	bn_lcl.h

Test_Sources = \
	bntest.c \
	exptest.c  

noinst_LTLIBRARIES = libbn_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libbn___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

EXTRA_libbn___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Extra_Sources)

libbn___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) @BN_OBJ@

libbn___GLOBUS_FLAVOR_NAME__la_DEPENDENCIES = @BN_OBJ@

libbn___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

bn_prime.lo: bn_prime.h bn_prime.c
	$(LTCOMPILE) -c bn_prime.c

bn_prime.h: bn_prime.pl
	$(PERL) bn_prime.pl >bn_prime.h

# x86 elf

asm/bn86-elf.lo: asm/bn86unix.cpp
	$(CPP) -DELF -x c asm/bn86unix.cpp > asm/bn86-elf.s
	$(LTCOMPILE) -c asm/bn86-elf.s -o asm/bn86-elf.lo
	rm -f asm/bn86-elf.s

asm/co86-elf.lo: asm/co86unix.cpp
	$(CPP) -DELF -x c asm/co86unix.cpp > asm/co86-elf.s
	$(LTCOMPILE) -c asm/co86-elf.s -o asm/co86-elf.lo
	rm -f asm/co86-elf.s

# x86 solaris

asm/bn86-sol.lo: asm/bn86unix.cpp
	$(CPP) -DSOL asm/bn86unix.cpp | sed 's/^#.*//' > asm/bn86-sol.s
	$(LTCOMPILE) -c asm/bn86-sol.s -o asm/bn86-sol.lo
	rm -f asm/bn86-sol.s

asm/co86-sol.lo: asm/co86unix.cpp
	$(CPP) -DSOL asm/co86unix.cpp | sed 's/^#.*//' > asm/co86-sol.s
	$(LTCOMPILE) -c asm/co86-sol.s -o asm/co86-sol.lo
	rm -f asm/co86-sol.s

# x86_64

asm/x86_64-gcc.lo: asm/x86_64-gcc.c
	$(LTCOMPILE) -c  asm/x86_64-gcc.c -o asm/x86_64-gcc.lo

# sparcv8 

asm/sparcv8.lo: asm/sparcv8.S
	$(LTCOMPILE) -c asm/sparcv8.S -o asm/sparcv8.lo

# >sparcv8

asm/sparcv8plus.lo: asm/sparcv8plus.S
	$(LTCOMPILE) -c asm/sparcv8plus.S -o asm/sparcv8plus.lo

# ia64

asm/ia64.lo: asm/ia64.S
	$(LTCOMPILE) -c asm/ia64.S -o asm/ia64.lo

# mips

asm/mips3.lo: asm/mips3.s
	$(LTCOMPILE) -c asm/mips3.s -o asm/mips3.lo


# generate the input

asm/bn86unix.cpp: asm/bn-586.pl ../perlasm/x86asm.pl
	(cd asm;$(PERL) bn-586.pl cpp > bn86unix.cpp)

asm/co86unix.cpp: asm/co-586.pl ../perlasm/x86asm.pl
	(cd asm;$(PERL) co-586.pl cpp >co86unix.cpp)

EXTRA_DIST = bn_prime.pl $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post









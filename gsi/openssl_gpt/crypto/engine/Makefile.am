include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

SUBDIRS = vendor_defns

Sources = \
	eng_err.c eng_lib.c eng_list.c eng_init.c eng_ctrl.c \
	eng_table.c eng_pkey.c eng_fat.c eng_all.c \
	tb_rsa.c tb_dsa.c tb_dh.c tb_rand.c tb_cipher.c tb_digest.c \
	eng_openssl.c eng_dyn.c eng_cnf.c \
	hw_atalla.c hw_cswift.c hw_ncipher.c hw_nuron.c hw_ubsec.c \
	hw_cryptodev.c hw_aep.c hw_sureware.c hw_4758_cca.c

opensslinclude_HEADERS = \
	engine.h

noinst_HEADERS = \
	hw_aep_err.h \
	hw_aep_err.c \
	hw_ncipher_err.h \
	hw_ncipher_err.c \
	hw_ubsec_err.h \
	hw_ubsec_err.c \
	eng_int.h \
	hw_atalla_err.h \
	hw_atalla_err.c \
	hw_nuron_err.h \
	hw_nuron_err.c \
	hw_4758_cca_err.h \
	hw_4758_cca_err.c \
	hw_cswift_err.h \
	hw_cswift_err.c \
	hw_sureware_err.h \
	hw_sureware_err.c

Test_Sources = \
	enginetest.c

noinst_LTLIBRARIES = libengine_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libengine___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libengine___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

libengine___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

EXTRA_DIST = README $(Test_Sources)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post









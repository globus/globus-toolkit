include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_openssl_pre

Sources= \
	bio_lib.c \
	bio_cb.c \
	bio_err.c \
	bss_mem.c \
	bss_null.c \
	bss_fd.c \
	bss_file.c \
	bss_sock.c \
	bss_conn.c \
	bf_null.c \
	bf_buff.c \
	b_print.c \
	b_dump.c \
	b_sock.c \
	bss_acpt.c \
	bf_nbio.c \
	bss_log.c \
	bss_bio.c

opensslinclude_HEADERS= \
	bio.h

noinst_HEADERS = \
	bss_file.c

noinst_LTLIBRARIES = libbio_$(GLOBUS_FLAVOR_NAME).la

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/include $(GPT_INCLUDES)

libbio___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

libbio___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS) 

libbio___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_openssl_post
include $(top_srcdir)/globus_automake_post

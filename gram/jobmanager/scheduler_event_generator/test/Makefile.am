include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top


# SUBDIRS is an automake macro which contains 
# the list of subdirectories that have Makefile.am's
SUBDIRS= \
	doxygen \
	pkgdata 


INCLUDES = $(GPT_INCLUDES)

flavorinclude_HEADERS = 

lib_LTLIBRARIES =  \
    libglobus_seg_load_test_module_$(GLOBUS_FLAVOR_NAME).la \
    libglobus_seg_timestamp_test_module_$(GLOBUS_FLAVOR_NAME).la

test_PROGRAMS = seg-module-load-test \
    seg-timestamp-test \
    seg-api-test

CPPFLAGS += -DGLOBUS_FLAVOR_NAME=\"@GLOBUS_FLAVOR_NAME@\"

libglobus_seg_load_test_module___GLOBUS_FLAVOR_NAME__la_SOURCES = \
    seg_module_load_test_module.c
libglobus_seg_load_test_module___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_seg_load_test_module___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)
libglobus_seg_timestamp_test_module___GLOBUS_FLAVOR_NAME__la_SOURCES = \
    seg_timestamp_test_module.c
libglobus_seg_timestamp_test_module___GLOBUS_FLAVOR_NAME__la_LDFLAGS = $(GPT_LDFLAGS)
libglobus_seg_timestamp_test_module___GLOBUS_FLAVOR_NAME__la_LIBADD = $(GPT_LIB_LINKS)

seg_module_load_test_SOURCES = seg_module_load_test.c
seg_module_load_test_LDFLAGS = $(GPT_LDFLAGS)
seg_module_load_test_LDADD = $(GPT_PGM_LINKS)

seg_timestamp_test_SOURCES = seg_timestamp_test.c
seg_timestamp_test_LDFLAGS = $(GPT_LDFLAGS)
seg_timestamp_test_LDADD = $(GPT_PGM_LINKS)

seg_api_test_SOURCES = seg_api_test.c globus_scheduler_event_generator_stdout.c globus_scheduler_event_generator_stdout.h
seg_api_test_LDFLAGS = $(GPT_LDFLAGS)
seg_api_test_LDADD = $(GPT_PGM_LINKS)

test_SCRIPTS = TESTS.pl seg-api-test.pl seg-module-load-test.pl seg-timestamp-test.pl
test_DATA = seg_api_test_data.txt test-data.txt

EXTRA_DIST= version.h.in seg_test.dox $(test_DATA) $(test_SCRIPTS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

AUTOMAKE_OPTIONS = foreign

doc_DATA = GLOBUS_LICENSE
include_HEADERS = globus_gram_jobmanager_callout_error.h
lib_LTLIBRARIES = libglobus_gram_job_manager_callout_error.la

libglobus_gram_job_manager_callout_error_la_CPPFLAGS = $(PACKAGE_DEP_CFLAGS)
libglobus_gram_job_manager_callout_error_la_LIBADD = $(PACKAGE_DEP_LIBS)
libglobus_gram_job_manager_callout_error_la_LDFLAGS = \
        -version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined
libglobus_gram_job_manager_callout_error_la_SOURCES = \
	globus_i_gram_jobmanager_callout_error.c \
	globus_gram_jobmanager_callout_error.h

EXTRA_DIST = dirt.sh $(doc_DATA)

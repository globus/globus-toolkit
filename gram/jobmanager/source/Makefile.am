include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= pkgdata doxygen scripts

# Extra directories we install files into
validationdir = $(datadir)/$(PACKAGE)

# Where targets are installed
noinst_LTLIBRARIES = libglobus_gram_job_manager_$(GLOBUS_FLAVOR_NAME).la
libexec_PROGRAMS = globus-job-manager \
                   globus-gram-rsl-reporter
libexec_SCRIPTS = globus-personal-gatekeeper-version.sh

bin_SCRIPTS = globus-personal-gatekeeper
validation_DATA = globus-gram-job-manager.rvf

sysconf_DATA = \
        grid-info-gram-rsl-reporter.schema

# Mapping of source files to libraries and executables
libglobus_gram_job_manager___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	globus_gram_job_manager.h \
	globus_gram_job_manager_validation.h \
	globus_gram_job_manager_auditing.c \
	globus_gram_job_manager_contact.c \
	globus_gram_job_manager_gsi.c \
	globus_gram_job_manager_history_file.c \
	globus_gram_job_manager_output.c \
	globus_gram_job_manager_query.c \
	globus_gram_job_manager_reporting_file.c \
	globus_gram_job_manager_request.c \
	globus_gram_job_manager_rsl.c \
	globus_gram_job_manager_script.c \
	globus_gram_job_manager_seg.c \
	globus_gram_job_manager_staging.c \
	globus_gram_job_manager_state.c \
	globus_gram_job_manager_state_file.c \
	globus_gram_job_manager_validate.c

globus_job_manager_SOURCES = main.c

globus_gram_rsl_reporter_SOURCES = \
	globus_gram_rsl_reporter.c \
	globus_gram_job_manager_validation.h

# Compiler flags
INCLUDES = $(GPT_INCLUDES)
globus_job_manager_LDFLAGS = $(GPT_LDFLAGS)
globus_job_manager_LDADD = \
	./libglobus_gram_job_manager_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

globus_gram_rsl_reporter_LDFLAGS = $(GPT_LDFLAGS)
globus_gram_rsl_reporter_LDADD = \
	./libglobus_gram_job_manager_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

# Files which we want to put in the source package
EXTRA_DIST = globus-personal-gatekeeper \
	     $(validation_DATA) \
	     $(sysconf_DATA) version.h.in \
	     globus-personal-gatekeeper-version.sh.in \
	     configuration.dox \
	     globus_gram_job_manager_rsl.dox \
	     globus_gram_job_manager_script_interface.dox \
	     globus_gram_job_manager_script_tutorial.dox \
	     globus_job_manager_rsl_validation.dox \
	     job_execution_environment.dox \
	     main.dox \
	     dirt.sh

BUILT_SOURCES = globus_gram_job_manager_rsl.dox

Makefile: $(BUILT_SOURCES)

globus_gram_job_manager_rsl.dox: globus-gram-job-manager.rvf
	perl scripts/create_rsl_documentation.pl \
	    < globus-gram-job-manager.rvf \
	    > globus_gram_job_manager_rsl.dox

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

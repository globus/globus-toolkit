include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= pkgdata doxygen scripts

# Extra directories we install files into
validationdir = $(datadir)/globus-gram-job-manager-rsl-validation

# Where targets are installed
noinst_LTLIBRARIES = libglobus_gram_job_manager_$(GLOBUS_FLAVOR_NAME).la
libexec_PROGRAMS = globus-job-manager
bin_SCRIPTS = globus-personal-gatekeeper
sbin_PROGRAMS = globus-gram-job-manager-print-validation
validation_DATA = globus-gram-job-manager.rvf

# Mapping of source files to libraries and executables
libglobus_gram_job_manager___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	globus_gram_job_manager.h \
	globus_gram_job_manager.c \
	globus_gram_job_manager_output.c \
	globus_gram_job_manager_validate.c

globus_job_manager_SOURCES = globus_job_manager.c

globus_gram_job_manager_print_validation_SOURCES = \
	globus_gram_job_manager_print_validation.c

# Compiler flags
INCLUDES += $(GPT_INCLUDES)
globus_job_manager_LDFLAGS = $(GPT_LDFLAGS)
globus_job_manager_LDADD = $(GPT_PGM_LINKS) \
	./libglobus_gram_job_manager_$(GLOBUS_FLAVOR_NAME).la

globus_gram_job_manager_print_validation_LDFLAGS = $(GPT_LDFLAGS)
globus_gram_job_manager_print_validation_LDADD = $(GPT_PGM_LINKS) \
	./libglobus_gram_job_manager_$(GLOBUS_FLAVOR_NAME).la

# Files which we want to put in the source package
EXTRA_DIST = globus-personal-gatekeeper $(validation_DATA)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top


include $(top_srcdir)/globus_automake_targets

FILELIST_FILES = noflavor_data.filelist \
	$(GLOBUS_FLAVOR_NAME)_dev.filelist \
	noflavor_doc.filelist \
	noflavor_hdr.filelist \
	$(GLOBUS_FLAVOR_NAME)_pgm.filelist \
	$(GLOBUS_FLAVOR_NAME)_pgm_static.filelist \
	noflavor_hdr.filelist \
	$(GLOBUS_FLAVOR_NAME)_rtl.filelist

MAKEFILE_AMS = $(top_srcdir)/Makefile.am \
	$(top_srcdir)/pkgdata/Makefile.am

pkg_DATA = \
	pkg_data_noflavor_data.gpt \
	pkg_data_$(GLOBUS_FLAVOR_NAME)_dev.gpt \
	pkg_data_noflavor_doc.gpt \
	pkg_data_noflavor_hdr.gpt \
	pkg_data_$(GLOBUS_FLAVOR_NAME)_pgm.gpt \
	pkg_data_$(GLOBUS_FLAVOR_NAME)_pgm_static.gpt \
	pkg_data_noflavor_hdr.gpt \
	pkg_data_$(GLOBUS_FLAVOR_NAME)_rtl.gpt \
	$(FILELIST_FILES)

filelist_file: $(MAKEFILE_AMS)
	@mydir=`pwd`; \
	if test -f "master.filelist"; then \
		rm $(FILELIST_FILE); \
	fi

all_filelists: filelist_file $(MAKEFILE_AMS)
	 @(cd .. && $(MAKE) $(AM_MAKEFLAGS) filelist) \
## This trick allows "-k" to keep its natural meaning when running a
## recursive rule.
	  || case "$$amf" in *=*) exit 1;; *k*) fail=yes;; *) exit 1;; esac;


$(FILELIST_FILES): sort_filelist

sort_filelist: all_filelists
	perl -I . $(GLOBUS_INSTALL_PATH)/sbin/gpt_sort_filelist  --flavor=$(GLOBUS_FLAVOR_NAME) ./master.filelist

include $(top_srcdir)/globus_automake_rules

EXTRA_DIST=MyFilelists.pm

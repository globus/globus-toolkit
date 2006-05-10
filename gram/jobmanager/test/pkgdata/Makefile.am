include $(top_srcdir)/globus_automake_pre

flavordir = $(GLOBUS_LOCATION)/etc/$(PACKAGE)

FILELIST_FILES = noflavor_data.filelist \
	$(GLOBUS_FLAVOR_NAME)_dev.filelist \
	noflavor_doc.filelist \
	$(GLOBUS_FLAVOR_NAME)_pgm.filelist \
	$(GLOBUS_FLAVOR_NAME)_pgm_static.filelist \
	$(GLOBUS_FLAVOR_NAME)_rtl.filelist


METADATA_FILES = \
	pkg_data_noflavor_data.gpt \
	pkg_data_$(GLOBUS_FLAVOR_NAME)_dev.gpt \
	pkg_data_noflavor_doc.gpt \
	pkg_data_$(GLOBUS_FLAVOR_NAME)_pgm.gpt \
	pkg_data_$(GLOBUS_FLAVOR_NAME)_pgm_static.gpt \
	pkg_data_$(GLOBUS_FLAVOR_NAME)_rtl.gpt

pkg_DATA = $(FILELIST_FILES) $(METADATA_FILES)

filelist_file: $(MAKEFILE_AMS)
	@mydir=`pwd`; \
	if test -f "master.filelist"; then \
		rm $(FILELIST_FILE); \
	fi

all_filelists: filelist_file
	 @(cd .. && $(MAKE) $(AM_MAKEFLAGS) filelist) \
## This trick allows "-k" to keep its natural meaning when running a
## recursive rule.
	  || case "$$amf" in *=*) exit 1;; *k*) fail=yes;; *) exit 1;; esac;

EXTRA_DIST = MyFilelists.pm

$(FILELIST_FILES): sort_filelist

sort_filelist: all_filelists
	$(GPT_LOCATION)/sbin/gpt_sort_filelist  --flavor=$(GLOBUS_FLAVOR_NAME) ./master.filelist $(GPT_LINKTYPE)

install-pkgDATA: $(pkg_DATA)
	@$(NORMAL_INSTALL)
	test -z "$(pkgdir)" || $(mkdir_p) "$(DESTDIR)$(pkgdir)";
	@list='$(pkg_DATA)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=$(am__strip_dir) \
	  echo " $(pkgDATA_INSTALL) '$$d$$p' '$(DESTDIR)$(pkgdir)/$$f'"; \
	  $(pkgDATA_INSTALL) "$$d$$p" "$(DESTDIR)$(pkgdir)/$$f"; \
	done || true


$(METADATA_FILES): pkg_data_src.gpt
	$(GPT_LOCATION)/sbin/gpt_generate_bin_pkg_data  \
	--flavor=$(GLOBUS_FLAVOR_NAME) pkg_data_src.gpt


distclean-local:
	@if test -f master.filelist; then \
		rm *.filelist; \
	fi; \
	if test -f pkg_data_noflavor_data.gpt; then \
		rm pkg_data_*.gpt; \
	fi

include $(top_srcdir)/globus_automake_post

include $(top_srcdir)/globus_automake_pre

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

pkgconfdir = @pkgconfdir@
## pkgconf = [ DATA ]

pkgconf_DATA = @pkgconffile@

filelist_file: $(MAKEFILE_AMS)
	@for p in $(FILELIST_FILES); do \
	    if test -f "$$p"; then \
	        rm -f $$p; \
	    fi; \
        done

$(pkg_DATA): all_filelists

all_filelists: filelist_file
	 @(cd .. && $(MAKE) $(AM_MAKEFLAGS) filelist) \
## This trick allows "-k" to keep its natural meaning when running a
## recursive rule.
	  || case "$$amf" in *=*) exit 1;; *k*) fail=yes;; *) exit 1;; esac;


#
# Override the normal install target to avoid dying when a given
# kind of metadata file is missing by calling "true"
install-pkgDATA: $(pkg_DATA)
	@$(NORMAL_INSTALL)
	test -z "$(pkgdir)" || $(mkinstalldirs) "$(DESTDIR)$(pkgdir)";
	@list='$(pkg_DATA)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=`echo $$p | sed -e 's|^.*/||'`; \
	  echo " $(INSTALL_DATA) '$$d$$p' '$(DESTDIR)$(pkgdir)/$$f'"; \
	  $(INSTALL_DATA) "$$d$$p" "$(DESTDIR)$(pkgdir)/$$f"; \
        done || true
	@list='$(pkg_DATA)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=`echo $$p | sed -e 's|^.*/||'`; \
          if expr $$p : '.*filelist$$' > /dev/null ; then \
              if test `cat $$d$$p | wc -l` = 2; then \
                  listtype=`echo "$$p" | sed -e 's!\.filelist!!'`; \
                  rm "$(DESTDIR)$(pkgdir)/$$f" ; \
                  rm "$(DESTDIR)$(pkgdir)/pkg_data_$${listtype}.gpt"; \
              fi ; \
          fi; \
	done || true

$(METADATA_FILES): pkg_data_src.gpt
	@$(GPT_LOCATION)/sbin/gpt_generate_bin_pkg_data  \
	--flavor=$(GLOBUS_FLAVOR_NAME) pkg_data_src.gpt

EXTRA_DIST = $(pkgconffile_in)

distclean-local:
	@if test -f master.filelist; then \
		rm *.filelist; \
	fi; \
	if test -f pkg_data_noflavor_data.gpt; then \
		rm pkg_data_*.gpt; \
	fi

include $(top_srcdir)/globus_automake_post

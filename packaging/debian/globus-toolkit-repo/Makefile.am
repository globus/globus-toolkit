pkgdatadir = $(datadir)/$(PACKAGE)
aptsourcesdir = $(pkgdatadir)/sources.list.d
taskseldir = $(datadir)/tasksel

aptsources_DATA = $(STABLE_LISTS) $(TESTING_LISTS) $(UNSTABLE_LISTS)
tasksel_DATA = globus-toolkit-6-tasks.desc

$(STABLE_LISTS): globus-toolkit-6-stable.list.in
	IFS=","; \
	releases="$(RELEASES)"; \
        for release in $${releases}; do \
	    sed -e "s|@RELEASE@|$$release|g" \
	    	< $(srcdir)/globus-toolkit-6-stable.list.in \
		> globus-toolkit-6-stable-$${release}.list; \
	done;

$(TESTING_LISTS): globus-toolkit-6-testing.list.in
	IFS=","; \
	releases="$(RELEASES)"; \
        for release in $${releases}; do \
	    sed -e "s|@RELEASE@|$$release|g" \
	    	< $(srcdir)/globus-toolkit-6-testing.list.in \
		> globus-toolkit-6-testing-$${release}.list; \
	done;

$(UNSTABLE_LISTS): globus-toolkit-6-unstable.list.in
	IFS=","; \
	releases="$(RELEASES)"; \
        for release in $${releases}; do \
	    sed -e "s|@RELEASE@|$$release|g" \
	    	< $(srcdir)/globus-toolkit-6-unstable.list.in \
		> globus-toolkit-6-unstable-$${release}.list; \
	done;

EXTRA_DIST =  \
    $(tasksel_DATA) \
    globus-toolkit-6-stable.list.in \
    globus-toolkit-6-testing.list.in \
    globus-toolkit-6-unstable.list.in \
    debian/README \
    debian/changelog \
    debian/compat \
    debian/control \
    debian/copyright \
    debian/dirs \
    debian/docs \
    debian/globus-toolkit-repo.postinst \
    debian/globus-toolkit-repo.postrm \
    debian/globus-toolkit-repo.prerm \
    debian/rules

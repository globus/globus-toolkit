VERSION = 0.6
DIST_STAGING = globus_connect_multiuser_test-$(VERSION)
DIST_FILE = $(DIST_STAGING).tar.gz

test:
	env GLOBUSONLINE_USER=gcmutest GLOBUSONLINE_PASSWORD=Automatic-GCMU-Test-Cases TERM=vt100 perl TESTS-junit.pl || true

dist:
	rm -rf $(DIST_STAGING)
	mkdir $(DIST_STAGING)
	cp Makefile *.conf *.pl *.css *.png $(DIST_STAGING)
	tar -c -f - $(DIST_STAGING) | gzip -9c > $(DIST_FILE)
	rm -rf $(DIST_STAGING)

distname:
	@echo $(DIST_FILE)
distclean:
	rm *.xml

.PHONY: dist distclean test

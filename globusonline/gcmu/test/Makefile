VERSION = 0.0
DIST_STAGING = globus-connect-multiuser-test-$(VERSION)
DIST_FILE = $(DIST_STAGING).tar.gz

test:
	env GLOBUSONLINE_USERNAME=gcmutest GLOBUSONLINE_PASSWORD=Automatic-GCMU-Test-Cases perl TESTS-junit.pl

dist:
	rm -rf $(DIST_STAGING)
	mkdir $(DIST_STAGING)
	cp Makefile *.conf *.pl $(DIST_STAGING)
	tar -c -f - $(DIST_STAGING) | gzip -9c > $(DIST_FILE)
	rm -rf $(DIST_STAGING)

distname:
	@echo $(DIST_FILE)
distclean:
	rm *.xml

.PHONY: dist distclean test

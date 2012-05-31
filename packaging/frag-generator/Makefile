FRAG_VERSION=$(shell cat ../fait_accompli/version | sed -e 's/rc[0-9]\{1,\}//')
all:
	if [ -d $(FRAG_VERSION) ]; then \
            rm -rf $(FRAG_VERSION) ; \
        fi ;
	mkdir $(FRAG_VERSION)
	sh advisories-to-xml > $(FRAG_VERSION)/advisories.xml
	xsltproc --stringparam output-dir "$(FRAG_VERSION)" \
            --stringparam release-version "$(FRAG_VERSION)" \
            generate-frags-docbook.xsl frag-defs.xml
	for known in $(FRAG_VERSION)/*_Known_Problems_Frag.xml; do \
	    mv $$known $${known}.old ; \
	    xsltproc --stringparam release-version '$(FRAG_VERSION)' \
	        update-known-problems.xsl $${known}.old > $$known; \
	    rm $${known}.old ; \
	done ;

clean:
	rm -rf $(FRAG_VERSION)
.PHONY: all clean

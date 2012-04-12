FRAG_VERSION=$(shell cat ../fait_accompli/version | sed -e 's/rc[0-9]\{1,\}//')
all:
	if [ -d $(FRAG_VERSION) ]; then \
            rm -rf $(FRAG_VERSION) ; \
        fi ;
	mkdir $(FRAG_VERSION)
	xsltproc --stringparam output-dir "$(FRAG_VERSION)" \
            --stringparam release-version "GT $(FRAG_VERSION)" \
            generate-frags-docbook.xsl frag-defs.xml

clean:
	rm -rf $(FRAG_VERSION)
.PHONY: all clean

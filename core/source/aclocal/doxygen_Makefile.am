include $(top_srcdir)/globus_automake_pre
#
# Automake rules for installing and building doxygen docs
#

doxygen_installdox = @lac_doxygen_installdox@
all-local: @DOXYFILE@
	@if test ! -z "@DOXYGEN@"; then \
		@DOXYGEN@  @DOXYFILE@;  \
		if test -n "$(doxygen_installdox)"; then \
		    if test -x ./doc/html/installdox; then \
		        $(PERL) ./doc/html/installdox $(doxygen_installdox) ./doc/html/*;\
		    fi ; \
		fi ; \
	fi

install-data-local:
	@if test ! -z "@DOXYGEN@"; then                     \
		for dir in `find ./doc/* -type d -print|sed "s,./doc/,,"`; do \
			if test -z "`echo $${dir}|sed -n '/^man/ p'`"; then \
				$(INSTALL) -d -m 755 \
					$(DESTDIR)$(docdir)/@PACKAGE@/$${dir}; \
			else \
				$(INSTALL) -d -m 755 \
					$(DESTDIR)$(prefix)/$${dir}; \
			fi \
		done; \
		for file in `find ./doc -type f -print|sed "s,./doc/,,"`; do \
			if test -z "`echo $${file}|sed -n '/^man/ p'`"; then \
				$(INSTALL) -m 644 ./doc/$${file} \
					$(DESTDIR)$(docdir)/@PACKAGE@/$${file}; \
			else \
				$(INSTALL) -m 644 ./doc/$${file} \
					$(DESTDIR)$(prefix)/$${file};\
			fi \
		done \
	fi

clean-data-local:
	@if test ! -z "@DOXYGEN@"; then \
		rm -rf ./doc*;          \
	fi

filelist:
	@if test ! -z "@DOXYGEN@"; then \
		find ./doc -type f -print| \
		sed "s,./doc/man,$(prefix)/man,"| \
		sed "s,./doc,$(docdir)/@PACKAGE@," \
		>> $(FILELIST_FILE); \
	fi

dist-hook: all-local
	@if test ! -z "@DOXYGEN@"; then \
		if test -d doc; then \
		    cp -r doc $(distdir)/doc ; \
		fi ; \
		if test -d doc-internal; then \
		    cp -r doc-internal $(distdir)/doc-internal ; \
		fi ; \
	fi ;

include $(top_srcdir)/globus_automake_post


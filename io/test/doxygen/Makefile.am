include $(top_srcdir)/globus_automake_config
include $(top_srcdir)/globus_automake_targets

all-local: @DOXYFILE@
	@if test ! -z "@DOXYGEN@"; then \
		@DOXYGEN@  @DOXYFILE@;  \
	fi

install-data-local:
	@if test ! -z "@DOXYGEN@"; then                     \
		for dir in `find ./doc/* -type d -print|sed "s,./doc/,,"`; do \
			$(INSTALL) -d -m 755 \
				@prefix@/share/doc/@PACKAGE@/$${dir}; \
		done; \
		for file in `find ./doc -type f -print|sed "s,./doc/,,"`; do \
			$(INSTALL) -m 644 ./doc/$${file} \
				@prefix@/share/doc/@PACKAGE@/$${file}; \
		done \
	fi

clean-data-local:
	@if test ! -z "@DOXYGEN@"; then \
		rm -rf ./doc*;          \
	fi

filelist:
	@if test ! -z "@DOXYGEN@"; then \
		find ./doc -type f -print| \
		sed "s,./doc,@prefix@/share/doc/@PACKAGE@," \
		>> $(FILELIST_FILE); \
	fi



include $(top_srcdir)/aclocal/automake_targets

all-local: @DOXYFILE@
	@if test ! -z "@DOXYGEN@"; then \
		@DOXYGEN@  @DOXYFILE@;  \
	fi

install-data-local:
	@if test ! -z "@DOXYGEN@"; then                     \
		for dir in `find ./doc/* -type d -print|sed "s,./doc/,,"`; do \
			if test -z `echo $${dir}|sed -n "/^man/ p"`; then \
				$(INSTALL) -d -m 755 \
					@prefix@/share/doc/@PACKAGE@/$${dir}; \
			else \
				$(INSTALL) -d -m 755 \
					@prefix@/$${dir}; \
			fi \
		done; \
		for file in `find ./doc -type f -print|sed "s,./doc/,,"`; do \
			if test -z `echo $${file}|sed -n "/^man/ p"`; then \
				$(INSTALL) -m 644 ./doc/$${file} \
					@prefix@/share/doc/@PACKAGE@/$${file};\
			else \
				$(INSTALL) -m 644 ./doc/$${file} \
					@prefix@/$${file};\
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
		sed "s,./doc,@prefix@/share/doc/@PACKAGE@," \
		>> $(FILELIST_FILE); \
	fi



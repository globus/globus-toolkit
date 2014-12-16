ACLOCAL_AMFLAGS=-I m4

SUBDIRS = attr context exec logging python .  xio_driver test
pkgconfigdir = $(libdir)/pkgconfig

doc_DATA = GLOBUS_LICENSE
pkgconfig_DATA = globus-net-manager.pc
include_HEADERS = globus_net_manager.h attr/globus_net_manager_attr.h
lib_LTLIBRARIES = libglobus_net_manager.la

AM_CPPFLAGS = $(PACKAGE_DEP_CFLAGS) -I$(top_srcdir) -I$(top_builddir) -I$(top_srcdir)/attr -I$(top_srcdir)/context -I$(top_srcdir)/exec -I$(top_srcdir)/logging
if ENABLE_PYTHON
AM_CPPFLAGS += -DENABLE_PYTHON -I$(top_srcdir)/python
python_libadd = python/libglobus_net_manager_python.la
endif

libglobus_net_manager_la_LIBADD = \
        attr/libglobus_net_manager_attr.la \
        context/libglobus_net_manager_context.la \
        exec/libglobus_net_manager_exec.la \
        logging/libglobus_net_manager_logging.la \
        $(python_libadd) \
        $(PACKAGE_DEP_LIBS)
libglobus_net_manager_la_SOURCES = module.c register.c unregister.c
libglobus_net_manager_la_LDFLAGS = \
	-version-info $(MAJOR_VERSION):$(MINOR_VERSION):$(AGE_VERSION) \
        -no-undefined

EXTRA_DIST = dirt.sh version.h.in globus-vararg-enums-doxygen-filter.pl

DOC_STAMPS =
if ENABLE_DOXYGEN
DOC_STAMPS += doc-stamp

doc-stamp: Doxyfile
	rm -rf doc
	$(DOXYGEN)
	touch $@

clean-local:
	rm -rf doc doc-stamp
endif

distuninstallcheck:
	@:

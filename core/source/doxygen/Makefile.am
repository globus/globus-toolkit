include $(top_srcdir)/aclocal/automake_targets

doxygen_DATA = Doxyfile-internal.include \
	Doxyfile.include \
	globus.css \
	globus_foot.html \
	globus_head.html \
	globus_head.tex

nodist_sbin_SCRIPTS = \
    globus-build-doxygen-dependencies
sbin_SCRIPTS = \
    globus-update-doxygen-index \
    globus-vararg-enums-doxygen-filter.pl

EXTRA_DIST = $(doxygen_DATA) $(sbin_SCRIPTS) \
    globus-build-doxygen-dependencies.in

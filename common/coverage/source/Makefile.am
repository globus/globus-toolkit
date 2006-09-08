include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS = pkgdata

globusperldir = $(GLOBUS_LOCATION)/lib/perl/Globus
coverageperldir = $(globusperldir)/Coverage

globusperl_SCRIPTS = Coverage.pm
coverageperl_SCRIPTS = File.pm Function.pm GCovParser.pm \
		       Package.pm Parser.pm Bundle.pm


pkgdata_DATA = bundle.template \
	       coverage.css \
               file.template \
	       package.template \
	       source.template

sbin_SCRIPTS = globus-coverage

EXTRA_DIST = $(pkgdata_DATA) $(sbin_SCRIPTS) \
		$(globusperl_SCRIPTS) $(coverageperl_SCRIPTS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top




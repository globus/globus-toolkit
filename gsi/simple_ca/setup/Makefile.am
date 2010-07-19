include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

Scripts = setup-simple-ca

setup_SCRIPTS = $(Scripts) 

setup_DATA = globus_simple_ca_setup_template.tar.gz

SUBDIRS = pkgdata

EXTRA_DIST = $(Scripts) template_list \
	     globus_simple_ca_setup_template.tar.gz

globus_simple_ca_setup_template.tar.gz:
	tar cvf - -C template `cat template_list` | gzip -c > globus_simple_ca_setup_template.tar.gz

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

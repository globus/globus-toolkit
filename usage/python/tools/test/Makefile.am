include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= pkgdata

Scripts = TESTS.pl uploader-test.pl

Data = 00.00.gup 01.01.gup 03.01.gup 03.02.gup 03.03.gup \
       04.01.gup 04.02.gup 05.01.gup 06.00.gup 07.00.gup \
       08.00.gup 09.09.gup 10.01.gup

test_DATA=$(Data)
test_SCRIPTS=$(Scripts)

EXTRA_DIST = $(Scripts) $(Data)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top

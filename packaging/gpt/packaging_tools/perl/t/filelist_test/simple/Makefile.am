foodir = $(prefix)/foo/local/bar
fumdir = $(prefix)/foo/fum/bar

foo_PROGRAMS = foo fee fow fum
bin_PROGRAMS = boo bee$(flavor) bow bum
fum_LIBRARIES = libfoo.a \
	libfee.a \
	libfow$(flavor).a \
	libfum.a
lib_LTLIBRARIES = libfoo.la \
	libfee.la \
	libfow.la \
	libfum$(flavor).la
fum_SCRIPTS = foo.sh fee.sh fow.sh fum.sh
foo_DATA = boo.conf bee.conf bow.conf bum.conf

man_MANS = boo.1 bee.2 bow.3 bum.4

include_HEADERS = foo.h fee.h fow.h fum.h
fum_HEADERS =  xfoo.h xfee.h xfow.h xfum.h
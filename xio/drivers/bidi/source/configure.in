dnl

AC_REVISION($Revision$)
AC_INIT(Makefile.am)

GLOBUS_INIT

AM_PROG_LIBTOOL

dnl config header goes here

dnl Initialize the automake rules the last argument
AM_INIT_AUTOMAKE($GPT_NAME, $GPT_VERSION)

LAC_DOXYGEN("../")

GLOBUS_FINALIZE

AC_OUTPUT(
	Makefile
	pkgdata/Makefile
        doxygen/Makefile
        doxygen/Doxyfile 
        doxygen/Doxyfile-internal
	pkgdata/pkg_data_src.gpt
        version.h
)

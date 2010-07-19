dnl

AC_REVISION($Revision$)
AC_INIT(Makefile.am)

GLOBUS_INIT

AM_PROG_LIBTOOL

dnl config header goes here

dnl Initialize the automake rules the last argument
AM_INIT_AUTOMAKE($GPT_NAME, $GPT_VERSION)

XXX_AM_CONFIG_HEADER_XXX

LAC_DOXYGEN([XXX_DOXYGEN_SRC_DIRS_XXX])

GLOBUS_FINALIZE

AC_OUTPUT(
	Makefile
	pkgdata/Makefile
	pkgdata/pkg_data_src.gpt
        XXX_AC_OUTPUT_XXX
	,
	$GPT_LOCATION/sbin/gpt_generate_bin_pkg_data \
	--flavor=$GLOBUS_FLAVOR_NAME "./pkgdata/pkg_data_src.gpt"
	,
	GLOBUS_FLAVOR_NAME=$GLOBUS_FLAVOR_NAME
	GLOBUS_LOCATION=$GLOBUS_LOCATION
	GPT_LOCATION=$GPT_LOCATION
)

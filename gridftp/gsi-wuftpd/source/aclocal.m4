dnl aclocal.m4 generated automatically by aclocal 1.2

dnl GSSAPI_CONFIG
dnl
dnl Figure out our GSSAPI configuration
dnl
dnl Sets the following variables:
dnl  gssapi_type              The type of GSSAPI the user requested.
dnl                           May be: "globus", "krb5" or "none".
dnl  GSSAPI_LIBS              Libraries that need to be linked in for GSSAPI
dnl  GSSAPI_LDFLAGS           Linker flags needed for GSSAPI
dnl  GSSAPI_CFLAGS            Compiler flags needed for GSSAPI
dnl
dnl Called AC_DEFINE with one or more of the following:
dnl  GSSAPI                   The user requested GSSAPI support
dnl  GSSAPI_GLOBUS            The user requested Globus/GSI GSSAPI support   
dnl  GSSAPI_KRB5              The user requested Kerberos 5 GSSAPI support
dnl  HAVE_GSS_SEAL            The gss_seal() function is present.
dnl  HAVE_GSS_UNSEAL          The gss_unseal() function is present.
dnl  HAVE_GSS_EXPORT_NAME     The gss_export_name() function is present.
dnl  GRIDMAP_WITH_KRB5        Use the gridmap with Kerberos


AC_DEFUN([GSSAPI_CONFIG],
[

AC_MSG_CHECKING(for type of gssapi support)

AC_ARG_ENABLE(gssapi,
[  --enable-gssapi=<type>  Specify type of GSSAPI [default=globus]
                          Options are: none, krb5, globus, gsi],
[gssapi_type=$enableval], [gssapi_type="globus"])

AC_ARG_ENABLE(authorization,
[  --enable-authorization=<type>
                          Type of authorization : krb5 or gridmap
			  gridmap always used with globus or gsi
			  and can be used with krb5],
[authorization_type=$enableval], [authorization_type="krb5"])

GPT_LINKTYPE=shared
AC_ARG_ENABLE(static-only,
              [ --enable-static-only      Don't do any dynamic linking],
	      [
	      case $enableval in
	        no)
		  GPT_LINKTYPE="shared"
		  ;;
		yes)
		  GPT_LINKTYPE="static"
		  ;;
		*)
		  AC_MSG_ERROR(--enable-static-only has no arguments)
		  ;;
	      esac
	      ])
AC_SUBST(GPT_LDFLAGS)
AC_ARG_WITH(globus-paths,
[  --with-globus-paths     Use ftp configuration files in \$GLOBUS_LOCATION],
[globus_paths=$withval], [globus_paths="no"])

if test "X$globus_paths" = "Xyes"; then
    AC_DEFINE(USE_GLOBUS_PATHS)
fi

AC_ARG_WITH(flavor,
[  --with-flavor=FLAVOR    Choose globus flavor],
                    globus_flavor=$withval)
AC_ARG_WITH(krb5-dir,
[  --with-krb5-dir=<DIR>   Location of krb5],
[krb5_dir=$withval], 
[if test -z "$krb5_dir"; then
	krb5_dir="no"
fi])

AC_ARG_WITH(globus-dir,
	[  --with-globus-dir=<DIR> Location of globus or gsi],
	globus_dir=$withval,
	globus_dir="none"
)


case $gssapi_type in
  no|none)	# No support
		AC_MSG_RESULT(none)
		;;
  krb5) # Kerberos 5 support
		AC_MSG_RESULT([Kerberos 5])
		gssapi_type="krb5"
		;;
  gsi|globus) # Globus SSLeasy
		AC_MSG_RESULT([Globus/GSI SSLeay])
		# Make sure it is "globus" and not "gsi"
		gssapi_type="globus"
		authorization_type="gridmap"
		;;
  *)	# Unrecognized type
		gssapi_type="none"
		AC_MSG_ERROR(Unrecognized GSSAPI type $gssapi_type)
		;;
esac

if test "$gssapi_type" != "none" ; then
	# Do stuff here for any GSSAPI library
	AC_DEFINE(GSSAPI)
fi

if test "$gssapi_type" = "globus" ; then
	# Globus GSSAPI configuration
	AC_DEFINE(GSSAPI_GLOBUS)

	CHECK_GLOBUS_DEVELOPMENT_PATH()
	AC_MSG_CHECKING(Globus GSSAPI dependencies)

	if test -z "$GPT_LOCATION" ; then
	    GPT_LOCATION=$GLOBUS_LOCATION
	fi
	${GPT_LOCATION}/sbin/gpt_build_config -src=pkg_data_src.gssapi \
	                 -flavor=${globus_flavor} \
			 -link $GPT_LINKTYPE > /dev/null
	if test "$?" = "0"; then
	    AC_MSG_RESULT(ok)
	else
	    AC_MSG_ERROR(failed)
	fi
	. ./gpt_build_temp.sh
	rm ./gpt_build_temp.sh

	inc="${GLOBUS_LOCATION}/include"
	GSSAPI_CFLAGS="-I${inc} -I${inc}/${globus_flavor} ${GPT_CONFIG_CFLAGS}"
	GSSAPI_LDFLAGS="-L${GLOBUS_LOCATION}/lib"
	GSSAPI_LIBS="${GPT_CONFIG_PGM_LINKS} ${GPT_CONFIG_LIBS}"
    
       # End Globus/GSI section
elif test "$gssapi_type" = "krb5" ; then

	# Kerberos 5 GSSAPI configuration
	AC_DEFINE(GSSAPI_KRB5)

	# Find Kerberos 5 installation directory
	AC_MSG_CHECKING(for Krb5 installation directory)

	krb5_install_dir=$krb5_dir

	if test "$krb5_install_dir" = "none" ; then
		if test -d /usr/local/krb5 ; then
			krb5_install_dir="/usr/local/krb5"
		elif test -d /krb5 ; then
			krb5_install_dir="/krb5"
		else
			AC_MSG_ERROR(Cannot find Kerberos 5 installation directory)
		fi	
	fi
	AC_MSG_RESULT($krb5_install_dir)

	GSSAPI_LDFLAGS="-L${krb5_install_dir}/lib"

	# In v1.1 of the MIT release libcrypto was renamed to libk5crypto
  # so check from libcrypto and use it if found, otherwise assume
  # libk5crypto
	save_LDFLAGS=${LDFLAGS}
	LDFLAGS=${GSSAPI_LDFLAGS}
	AC_CHECK_LIB(crypto, mit_des_string_to_key,
		[krb5_crypto_lib=crypto],
	  [krb5_crypto_lib=k5crypto])
	LDFLAGS=${save_LDFLAGS}

	GSSAPI_LIBS="-lgssapi_krb5 -lkrb5 -l${krb5_crypto_lib} -lcom_err"

	# For <krb5.h>
	GSSAPI_CFLAGS="-I${krb5_install_dir}/include $GSSAPI_CFLAGS"
	# For <gssapi.h>
	GSSAPI_CFLAGS="-I${krb5_install_dir}/include/gssapi $GSSAPI_CFLAGS"
	
	if test "$authorization_type" = "gridmap" ; then 
	    CHECK_GLOBUS_DEVELOPMENT_PATH()
	    AC_MSG_CHECKING(Globus gridmap dependencies)

	    inc="${GLOBUS_LOCATION}/include"
	    GLOBUS_GRIDMAP_CFLAGS="-I${inc} -I${inc}/${globus_flavor} ${GPT_CONFIG_CFLAGS}"
	    GLOBUS_GRIDMAP_LDFLAGS="-L${GLOBUS_LOCATION}/lib ${GPT_CONFIG_LIBS}"
	    GLOBUS_GRIDMAP_LIBS="-lglobus_gss_assist_${globus_flavor}"
    
            GSSAPI_CFLAGS="$GSSAPI_LIBS $GLOBUS_GRIDMAP_CFLAGS"
            GSSAPI_LDFLAGS="$GSSAPI_LIBS $GLOBUS_GRIDMAP_LDFLAGS"
            GSSAPI_LIBS="$GSSAPI_LIBS $GLOBUS_GRIDMAP_LIBS"

	    AC_DEFINE(GRIDMAP_WITH_KRB5)
	# End Kerberos 5 Section
	fi
    fi

AC_SUBST(GSSAPI_LIBS)
AC_SUBST(GSSAPI_LDFLAGS)
AC_SUBST(GSSAPI_CFLAGS)

if test "$gssapi_type" != "none" ; then
  dnl Check for the existance of specific GSSAPI routines.
  dnl Need to do this after GSSAPI_LIBS is completely filled out
  ORIG_LIBS="$LIBS"
  ORIG_LDFLAGS="$LDFLAGS"
  LDFLAGS="$LDFLAGS $GSSAPI_LDFLAGS"
  LIBS="$LIBS $GSSAPI_LIBS"

  AC_MSG_CHECKING(for gss_seal)
  AC_TRY_LINK([],[gss_seal();],
      [AC_MSG_RESULT(yes)
       AC_DEFINE(HAVE_GSS_SEAL)],
      AC_MSG_RESULT(no))

  AC_MSG_CHECKING(for gss_unseal)
  AC_TRY_LINK([],[gss_unseal();],
      [AC_MSG_RESULT(yes)
       AC_DEFINE(HAVE_GSS_UNSEAL)],
      AC_MSG_RESULT(no))

  AC_MSG_CHECKING(for gss_export_name)
  AC_TRY_LINK([],[gss_export_name();],
      [AC_MSG_RESULT(yes)
       AC_DEFINE(HAVE_GSS_EXPORT_NAME)],
      AC_MSG_RESULT(no))

  LIBS="$ORIG_LIBS"
  LDFLAGS="$ORIG_LDFLAGS"
fi

]) dnl AC_GSSAPI_CONFIG
dnl
dnl AFS configuration macros
dnl

AC_DEFUN([AFS_CONFIG],
[
dnl
dnl --with-afs		  Use transarc AFS libraries
AC_MSG_CHECKING(whether to use Transarc AFS libraries)
AC_ARG_WITH([afs],
[  --with-afs=<PATH>	  Use transarc AFS libraries],
,with_afs=no)dnl
AC_MSG_RESULT($with_afs)
case "$with_afs" in
	no)	;;
	yes)	with_afs="/usr/afsws" ;;
	*)	;;
esac

if test $with_afs != no; then
	if test ! -d "$with_afs"; then
		AC_MSG_ERROR(Could not find AFS directory $with_afs)
	fi
	AC_DEFINE(AFS)
	AC_DEFINE(HAVE_TRANSARC_AFS)
	AFS_LDFLAGS="-L${with_afs}/lib -L${with_afs}/lib/afs"
	AFS_LIBS="-lauth -lsys -lrx -llwp"
	AFS_CFLAGS="-I${with_afs}/include"
	dnl case $krb5_cv_host in
	dnl *-*-solaris*)
	dnl 	AFSLIBS="$AFSLIBS -lc -L/usr/ucblib -lucb -R/usr/ucblib"
	dnl	;;
	dnl *-*-hpux*)
	dnl	AFSLIBS="$AFSLIBS -lBSD -lm"
	dnl 	;;
	dnl *-*-netbsd*)
	dnl 	AFSLIBS="$AFSLIBS -lcompat"
	dnl 	;;
	dnl esac
fi

dnl
dnl --with-krbafs	  Use krbafs libraries
dnl
AC_MSG_CHECKING(whether to use libkrbafs)
AC_ARG_WITH(krbafs,
[  --with-krbafs=<PATH>    Use libkrbafs libraries],,with_krbafs=no)
AC_MSG_RESULT($with_krbafs)
case "$with_krbafs" in
  no)   ;;
  *)
	if test ! -d "$with_krbafs"; then
		AC_MSG_ERROR(Could not find krbafs directory $with_krbafs)
	fi
	AC_DEFINE(AFS)	
	AC_DEFINE(HAVE_LIBKRBAFS)
	dnl Set with_afs so that we can use that as a test for AFS
	with_afs="yes"
	AFS_LIBS="-lkrbafs"
	AFS_CFLAGS="-I${with_krbafs}/include"
	AFS_LIBS="-L${withval}/lib -lkrbafs"
   ;;
esac

]) dnl AFS_CONFIG

dnl
dnl check for POSIX signal handling -- CHECK_SIGNALS
dnl
dnl Taken from Kerberos 5 distribution
dnl
AC_DEFUN(CHECK_SIGNALS,[
 AC_CHECK_FUNC(sigprocmask,
  [AC_MSG_CHECKING(for sigset_t and POSIX_SIGNALS)
   AC_TRY_COMPILE(
    [#include <signal.h>],
    [sigset_t x],
    type_sigset_t=yes, type_sigset_t=no)
   AC_MSG_RESULT($type_sigset_t)
   if test $type_sigset_t = yes; then
    AC_DEFINE(POSIX_SIGNALS)
   fi
  ]
 )
])dnl CHECK_SIGNALS
dnl
dnl check for POSIX setjmp/longjmp -- CHECK_SETJMP
dnl
dnl Taken from Kerberos 5 distribution
dnl
AC_DEFUN(CHECK_SETJMP,[
 AC_FUNC_CHECK(sigsetjmp,
  [AC_MSG_CHECKING(for sigjmp_buf)
   AC_TRY_COMPILE(
    [#include <setjmp.h>],
    [sigjmp_buf x],
    struct_sigjmp_buf=yes,struct_sigjmp_buf=no)
   AC_MSG_RESULT($struct_sigjmp_buf)
   if test $struct_sigjmp_buf = yes; then
    AC_DEFINE(POSIX_SETJMP)
   fi
  ]
 )
])dnl CHECK_SETJMP

AC_DEFUN(CHECK_GLOBUS_DEVELOPMENT_PATH,[dnl

	GLOBUS_FLAVOR_NAME=$globus_flavor

	if test -z "$GLOBUS_FLAVOR_NAME" -o "$GLOBUS_FLAVOR_NAME" = "no"; then
            AC_MSG_ERROR(must specify globus flavor)
	fi

    if test -z "$globus_cv_development_path"; then

	AC_MSG_CHECKING(for Globus/GSI installation directory)

	if test x"$globus_dir" = x"none" \
	     -o x"$globus_dir" = x""; then
	    if test -n "$GLOBUS_LOCATION" ; then
		    globus_dir=$GLOBUS_LOCATION
	    elif test -n "$GLOBUS_INSTALL_PATH" ; then
		    globus_dir=$GLOBUS_INSTALL_PATH
	    elif test -d /usr/local/globus ; then
		    globus_dir="/usr/local/globus"
	    elif test -d /usr/local/gsi ; then
		    globus_dir="/usr/local/gsi"
	    else
		    AC_MSG_ERROR(Cannot find Globus/GSI installation directory)
	    fi	
	fi
	AC_MSG_RESULT($globus_dir)

	GLOBUS_LOCATION=$globus_dir
	AC_MSG_CHECKING(for Globus packaging tools)
	if test -d ${GLOBUS_LOCATION}/etc/globus_packages; then
	    AC_MSG_RESULT(ok)
	    if test -z "$GPT_LOCATION" ; then
		GPT_LOCATION=$GLOBUS_LOCATION
	    fi
	elif test -n "${GPT_LOCATION}" -a -d "${GPT_LOCATION}"; then
	    AC_MSG_RESULT(ok)
	else
	    AC_MSG_ERROR(missing)
	fi
        GLOBUS_LIBTOOL=${GLOBUS_LOCATION}/sbin/libtool-${GLOBUS_FLAVOR_NAME}
	globus_cv_development_path=${GLOBUS_LOCATION}
    fi
])dnl CHECK_GLOBUS_DEVELOPMENT_PATH

AC_DEFUN(GLOBUS_DATA_CONFIG,[
AC_ARG_ENABLE(globus-data, [  --disable-globus-data   don't use globus data code],
	[ globus_data=$enableval ], [ globus_data=yes ])

    if test $globus_data = yes; then
	AC_DEFINE(USE_GLOBUS_DATA_CODE)
	CHECK_GLOBUS_DEVELOPMENT_PATH()
	AC_MSG_CHECKING(Globus data dependencies)

	${GPT_LOCATION}/sbin/gpt_build_config -src=pkg_data_src.gpt \
	                 -flavor=${globus_flavor} \
			 -link $GPT_LINKTYPE > /dev/null
	if test "$?" = "0"; then
	    AC_MSG_RESULT(ok)
	else
	    AC_MSG_ERROR(failed)
	fi
	. ./gpt_build_temp.sh
	rm ./gpt_build_temp.sh

	inc="${GLOBUS_LOCATION}/include"
	GLOBUS_DATA_CFLAGS="-I${inc} -I${inc}/${globus_flavor} ${GPT_CONFIG_CFLAGS}"
	GLOBUS_DATA_LDFLAGS=" -L${GLOBUS_LOCATION}/lib ${GPT_CONFIG_LIBS}"
	GLOBUS_DATA_LIBS="${GPT_CONFIG_PGM_LINKS}"
    
	AC_SUBST(GLOBUS_DATA_CFLAGS)
	AC_SUBST(GLOBUS_DATA_LDFLAGS)
	AC_SUBST(GLOBUS_DATA_LIBS)
    fi
])

#serial 4

dnl By default, many hosts won't let programs access large files;
dnl one must use special compiler options to get large-file access to work.
dnl For more details about this brain damage please see:
dnl http://www.sas.com/standards/large.file/x_open.20Mar96.html

dnl Written by Paul Eggert <eggert@twinsun.com>.

dnl Internal subroutine of AC_SYS_LARGEFILE.
dnl AC_SYS_LARGEFILE_FLAGS(FLAGSNAME)
AC_DEFUN(AC_SYS_LARGEFILE_FLAGS,
  [AC_CACHE_CHECK([for $1 value to request large file support],
     ac_cv_sys_largefile_$1,
     [ac_cv_sys_largefile_$1=`($GETCONF LFS_$1) 2>/dev/null` || {
	ac_cv_sys_largefile_$1=no
      }])])

dnl Internal subroutine of AC_SYS_LARGEFILE.
dnl AC_SYS_LARGEFILE_SPACE_APPEND(VAR, VAL)
AC_DEFUN(AC_SYS_LARGEFILE_SPACE_APPEND,
  [case $2 in
   no) ;;
   ?*)
     case "[$]$1" in
     '') $1=$2 ;;
     *) $1=[$]$1' '$2 ;;
     esac ;;
   esac])

dnl Internal subroutine of AC_SYS_LARGEFILE.
dnl AC_SYS_LARGEFILE_MACRO_VALUE(C-MACRO, CACHE-VAR, COMMENT, CODE-TO-SET-DEFAULT)
AC_DEFUN(AC_SYS_LARGEFILE_MACRO_VALUE,
  [AC_CACHE_CHECK([for $1], $2,
     [$2=no
changequote(, )dnl
      $4
      for ac_flag in $ac_cv_sys_largefile_CFLAGS no; do
	case "$ac_flag" in
	-D$1)
	  $2=1 ;;
	-D$1=*)
	  $2=`expr " $ac_flag" : '[^=]*=\(.*\)'` ;;
	esac
      done
changequote([, ])dnl
      ])
   if test "[$]$2" != no; then
     AC_DEFINE_UNQUOTED([$1], [$]$2, [$3])
   fi])

AC_DEFUN(AC_SYS_LARGEFILE,
  [AC_REQUIRE([AC_CANONICAL_HOST])
   AC_ARG_ENABLE(largefile,
     [  --disable-largefile     omit support for large files])
   if test "$enable_largefile" != no; then
     AC_CHECK_TOOL(GETCONF, getconf)
     AC_SYS_LARGEFILE_FLAGS(CFLAGS)
     AC_SYS_LARGEFILE_FLAGS(LDFLAGS)
     AC_SYS_LARGEFILE_FLAGS(LIBS)
	
     for ac_flag in $ac_cv_sys_largefile_CFLAGS no; do
       case "$ac_flag" in
       no) ;;
       -D_FILE_OFFSET_BITS=*) ;;
       -D_LARGEFILE_SOURCE | -D_LARGEFILE_SOURCE=*) ;;
       -D_LARGE_FILES | -D_LARGE_FILES=*) ;;
       -D?* | -I?*)
	 AC_SYS_LARGEFILE_SPACE_APPEND(CPPFLAGS, "$ac_flag") ;;
       *)
	 AC_SYS_LARGEFILE_SPACE_APPEND(CFLAGS, "$ac_flag") ;;
       esac
     done
     AC_SYS_LARGEFILE_SPACE_APPEND(LDFLAGS, "$ac_cv_sys_largefile_LDFLAGS")
     AC_SYS_LARGEFILE_SPACE_APPEND(LIBS, "$ac_cv_sys_largefile_LIBS")
     AC_SYS_LARGEFILE_MACRO_VALUE(_FILE_OFFSET_BITS,
       ac_cv_sys_file_offset_bits,
       [Number of bits in a file offset, on hosts where this is settable.],
       [case "$host_os" in
	# HP-UX 10.20 and later
	hpux10.[2-9][0-9]* | hpux1[1-9]* | hpux[2-9][0-9]*)
	  ac_cv_sys_file_offset_bits=64 ;;
	esac])
     AC_SYS_LARGEFILE_MACRO_VALUE(_LARGEFILE_SOURCE,
       ac_cv_sys_largefile_source,
       [Define to make fseeko etc. visible, on some hosts.],
       [case "$host_os" in
	# HP-UX 10.20 and later
	hpux10.[2-9][0-9]* | hpux1[1-9]* | hpux[2-9][0-9]*)
	  ac_cv_sys_largefile_source=1 ;;
	esac])
     AC_SYS_LARGEFILE_MACRO_VALUE(_LARGE_FILES,
       ac_cv_sys_large_files,
       [Define for large files, on AIX-style hosts.],
       [case "$host_os" in
	# AIX 4.2 and later
	aix4.[2-9]* | aix4.1[0-9]* | aix[5-9].* | aix[1-9][0-9]*)
	  ac_cv_sys_large_files=1 ;;
	esac])
   fi
  ])

dnl CHECK_STAT_WORKS
dnl some versions of libc fail to stat files which are > 2GB. Redhat 6.1
dnl is one of those. Others OSes should be added if they fail.
AC_DEFUN(CHECK_STAT_WORKS,[dnl
     AC_MSG_CHECKING([for stat which doesn't support large files])
     broken_stat=no
     if test -r /etc/redhat-release && \
        grep "Red Hat Linux release 6" /etc/redhat-release > /dev/null; then
	     broken_stat="yes"
	     AC_DEFINE(HAVE_BROKEN_STAT)
     fi
     AC_MSG_RESULT($broken_stat)
     ])

AC_SUBST(GLOBUS_LIBTOOL)




dnl
dnl Doxygen related macros
dnl



AC_DEFUN(LAC_DOXYGEN_PROJECT,dnl
[
    lac_doxygen_project=`echo "$1" | sed -e 's/_/ /g'`
    AC_SUBST(lac_doxygen_project)
])

AC_DEFUN(LAC_DOXYGEN_SOURCE_DIRS,dnl
[
    lac_doxygen_srcdirs=[$1]
    AC_SUBST(lac_doxygen_srcdirs)
])


AC_DEFUN(LAC_DOXYGEN_OUTPUT_TAGFILE,dnl
[
    lac_doxygen_output_tagfile=[$1]
    AC_SUBST(lac_doxygen_output_tagfile)
])

AC_DEFUN(LAC_DOXYGEN_TAGFILES,dnl
[
    lac_doxygen_tagfiles=""
    for x in "" $1; do
        if test "X$x" != "X" ; then
	    lac_tag_base=`echo ${x} | sed -e 's|.*/||' -e 's|\.tag$||'`
	    lac_tag="${lac_tag_base}.tag"
            lac_doxygen_tagfiles="$lac_doxygen_tagfiles $x"
            lac_doxygen_internal_tagfiles="$lac_doxygen_internal_tagfiles ${x}i"
	    lac_doxygen_installdox="$lac_doxygen_installdox -l${lac_tag}@../../${lac_tag_base}/html"
	fi
    done
    AC_SUBST(lac_doxygen_tagfiles)
    AC_SUBST(lac_doxygen_internal_tagfiles)
    AC_SUBST(lac_doxygen_installdox)
])

AC_DEFUN(LAC_DOXYGEN_FILE_PATTERNS,dnl
[
    lac_doxygen_file_patterns=[$1]
])

AC_DEFUN(LAC_DOXYGEN_EXAMPLE_DIR,dnl
[
    lac_doxygen_examples=[$1]
])

AC_DEFUN(LAC_DOXYGEN_PREDEFINES,dnl
[
    lac_doxygen_predefines=[$1]
])

AC_DEFUN(LAC_DOXYGEN,dnl
[
    AC_ARG_ENABLE(doxygen,
	changequote(<<, >>)dnl	
	<<  --enable-doxygen[=PATH]	use Doxygen to generate documentation>>,
	changequote([, ])dnl
	[
	    if test "$enableval" = "yes"; then
		AC_PATH_PROG(DOXYGEN,
		    doxygen,
		    [
			AC_MSG_ERROR(Doxygen installation not found)
		    ])
	    else
		DOXYGEN="$enableval"
		AC_SUBST(DOXYGEN)
	    fi
	],
	[
	    DOXYGEN=""
	    AC_SUBST(DOXYGEN)
	])


    AC_ARG_ENABLE(internal-doc,
    [  --enable-internal-doc	Generate Doxygen documentation for
				 internal functions. Requires --enable-doxygen],
    [
	DOXYFILE="Doxyfile-internal"
	AC_SUBST(DOXYFILE) 
    ],
    [
	DOXYFILE="Doxyfile"
	AC_SUBST(DOXYFILE)
    ])


    if test -n "$DOXYGEN" ; then
	AC_PATH_PROG(DOT, dot)
	
	if test -z "$GLOBUS_SH_PERL" ; then
	   AC_PATH_PROG(PERL, perl)
	else
	    PERL="$GLOBUS_SH_PERL"
	    AC_SUBST(PERL)
	fi
	if test "$DOT" != ""; then
	    HAVE_DOT=YES
	else
	    HAVE_DOT=NO
	fi

	AC_SUBST(HAVE_DOT)

	LAC_DOXYGEN_SOURCE_DIRS($1)
	LAC_DOXYGEN_FILE_PATTERNS($2)	

	LAC_DOXYGEN_PROJECT($GPT_NAME)
	LAC_DOXYGEN_OUTPUT_TAGFILE($GPT_NAME)

	LAC_DOXYGEN_TAGFILES($tagfiles)

	AC_SUBST(lac_doxygen_file_patterns)
	AC_SUBST(lac_doxygen_examples)
	AC_SUBST(lac_doxygen_predefines)
    fi
]
)

AC_DEFUN(LAC_STATIC_FLAGS,dnl
[
case $GPT_LINKTYPE in
	static)
	        STATIC_FLAGS="-static"
		AC_SUBST(STATIC_FLAGS)
	;;
esac
])


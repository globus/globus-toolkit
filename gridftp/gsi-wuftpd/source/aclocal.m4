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


AC_DEFUN([GSSAPI_CONFIG],
[

AC_MSG_CHECKING(for type of gssapi support)

AC_ARG_ENABLE(gssapi,
[  --enable-gssapi=<type>      Specify type of GSSAPI
                              Options are: krb5, globus, gsi],
[gssapi_type=$enableval], [gssapi_type="none"])

AC_ARG_WITH(gssapi,
[  --with-gssapi=<type>        Obsolete. Use --enable-gssapi instead.],
[gssapi_type=$withval],
[if test -z "$gssapi_type"; then
     gssapi_type="none"
fi])


case $gssapi_type in
  no|none)	# No support
		AC_MSG_RESULT(none)
		;;
  krb5) # Kerberos 5 support
		AC_MSG_RESULT([Kerberos 5])
		;;
  gsi|globus) # Globus SSLeasy
		AC_MSG_RESULT([Globus/GSI SSLeay])
		# Make sure it is "globus" and not "gsi"
		gssapi_type="globus"
		;;
  *)	# Unrecognized type
		gssapi_type="none"
		AC_MSG_ERROR(Unrecognized GSSAPI type $gssapi_type)
		;;
esac

if test "$gssapi_type" != "none" ; then

	# Do stuff here for any GSSAPI library
	AC_DEFINE(GSSAPI)

	AC_ARG_WITH(gssapi-dir,
		[  --with-gssapi-dir=<DIR>  Specify install directory for GSSAPI package],
		gssapi_dir=$withval,
		gssapi_dir="none"
	)

fi

if test "$gssapi_type" = "globus" ; then
	# Globus GSSAPI configuration
	AC_DEFINE(GSSAPI_GLOBUS)

	# Find GLOBUS/GSI installation Directory
	CHECK_GLOBUS_DEVELOPMENT_PATH(true)

        if test "$globus_install_dir" != "$globus_dev_dir"; then
            GSSAPI_LIBS='$(INSTALL_LIBDIR) $(GLOBUS_GSSAPI_LIBS)'
            GSSAPI_LDFLAGS='$(GLOBUS_GSSAPI_LDFLAGS)'
            GSSAPI_CFLAGS='$(INSTALL_INCLUDE) $(GLOBUS_GSSAPI_CFLAGS)'
        else
            GSSAPI_LIBS="-lglobus_gss_assist -lglobus_gss -lglobus_gaa"
            GSSAPI_LDFLAGS="-L${globus_dev_dir}/lib"
            GSSAPI_CFLAGS="-I${globus_dev_dir}/include"

            dnl Find SSLeay installation directory
            GSSAPI_LIBS="$GSSAPI_LIBS -lssl"

            dnl Find SSLeay installation directory
            GSSAPI_LIBS="$GSSAPI_LIBS -lssl"

            dnl XXX Should be able to figure this out from Globus/GSI install dir
            AC_MSG_CHECKING(for ssleay directory)
            AC_ARG_WITH(ssl-dir,
                    [  --with-ssl-dir=<DIR>  Root directory for ssleay stuff],
                    ssleay_dir=$withval,
                    ssleay_dir="/usr/local/ssl")
	    if test ! -d ${ssleay_dir} ; then
		AC_MSG_ERROR(Cannot find SSLeay installation directory)
	    fi

            AC_MSG_RESULT($ssleay_dir)

            if test "$ssleay_dir" != "none" ; then
                GSSAPI_LDFLAGS="-L${ssleay_dir}/lib $GSSAPI_LDFLAGS"
                GSSAPI_CFLAGS="-I${ssleay_dir}/include $GSSAPI_CFLAGS"
		# Specify full path to ssleay's libcrypto so we don't conflict
		# with Keberos libcrypto.a
		GSSAPI_LIBS="$GSSAPI_LIBS ${ssleay_dir}/lib/libcrypto.a"
	    else
		GSSAPI_LIBS="$GSSAPI_LIBS -lcrypto}"
            fi
        fi

       # End Globus/GSI section
elif test "$gssapi_type" = "krb5" ; then

	# Kerberos 5 GSSAPI configuration
	AC_DEFINE(GSSAPI_KRB5)

	# Find Kerberos 5 installation directory
	AC_MSG_CHECKING(for Krb5 installation directory)

	krb5_install_dir=$gssapi_dir

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

	# End Kerberos 5 Section
fi

AC_SUBST(GSSAPI_LIBS)
AC_SUBST(GSSAPI_LDFLAGS)
AC_SUBST(GSSAPI_CFLAGS)
AC_SUBST(INCLUDE_GLOBUS_MAKEFILE_HEADER)

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
dnl --with-afs		Use transarc AFS libraries
AC_MSG_CHECKING(whether to use Transarc AFS libraries)
AC_ARG_WITH([afs],
[  --with-afs=<PATH>	Use transarc AFS libraries],
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
dnl --with-krbafs	Use krbafs libraries
dnl
AC_MSG_CHECKING(whether to use libkrbafs)
AC_ARG_WITH(krbafs,
[  --with-krbafs=<PATH>  Use libkrbafs libraries],,with_krbafs=no)
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

dnl CHECK_GLOBUS_DEVELOPMENT_PATH([true|false])
dnl if $1 is true, then an installation which did not do
dnl globus-install is ok. Otherwise, fail in that case.
AC_DEFUN(CHECK_GLOBUS_DEVELOPMENT_PATH,[dnl

    AC_MSG_CHECKING(for Globus/GSI installation directory)

    globus_install_dir=$gssapi_dir

    if test x"$globus_install_dir" = x"none" -o x"$globus_install_dir" = x""; then
	if test -n "$GLOBUS_INSTALL_PATH" ; then
		globus_install_dir=$GLOBUS_INSTALL_PATH
	elif test -d /usr/local/globus ; then
		globus_install_dir="/usr/local/globus"
	elif test -d /usr/local/gsi ; then
		globus_install_dir="/usr/local/gsi"
	else
		AC_MSG_ERROR(Cannot find Globus/GSI installation directory)
	fi	
    fi
    AC_MSG_RESULT($globus_install_dir)

    dnl Find GLOBUS/GSI development directory
    AC_MSG_CHECKING(for Globus/GSI development directory)

    if test -d ${globus_install_dir}/lib ; then
        # Looks like a flat directory structure from configure/make and not
        # globus-install or gsi-install
	if test x"$1" = x"true"; then
	    globus_dev_dir=$globus_install_dir
	else
	    AC_MSG_ERROR(Globus/GSI not properly installed. Use globus-install or gsi-install)
	fi
    else
	# Assume a true globus installation with architecture
	# directories and run globus-development-path to find
	# the development directory

	# Make sure GLOBUS_INSTALL_PATH is set
	if test -z "$GLOBUS_INSTALL_PATH" ; then
		GLOBUS_INSTALL_PATH=$globus_install_dir
		export GLOBUS_INSTALL_PATH
	fi

	dev_path_program=${globus_install_dir}/bin/globus-development-path

	if test ! -x ${dev_path_program} ; then
		AC_MSG_ERROR(Cannot find Globus/GSI installation directory: program ${dev_path_program} does not exist or is not executable)
	fi

	globus_dev_dir=`${dev_path_program}`
	if test -z "$globus_dev_dir" -o "X$globus_dev_dir" = "X<not found>" ; then
			AC_MSG_ERROR(Cannot find Globus/GSI development directory)
	fi

	if test ! -d "$globus_dev_dir" ; then
		AC_MSG_ERROR(Cannot find Globus/GSI development directory: $globus_dev_dir does not exist)
	fi
    fi
    AC_MSG_RESULT($globus_dev_dir)

    if test "$globus_install_dir" != "$globus_dev_dir"; then
        INCLUDE_GLOBUS_MAKEFILE_HEADER="include $globus_dev_dir/etc/makefile_header"
    fi

])dnl CHECK_GLOBUS_DEVELOPMENT_PATH

AC_DEFUN(GLOBUS_DATA_CONFIG,[
AC_ARG_ENABLE(globus-data, [  --enable-globus-data    use globus data code],
	[ globus_data=$enableval ], [ globus_data=no ])

GLOBUS_DATA_CFLAGS=""
GLOBUS_DATA_LDFLAGS=""
GLOBUS_DATA_LIBS=""

if test $globus_data = yes; then
	AC_DEFINE(USE_GLOBUS_DATA_CODE)
	CHECK_GLOBUS_DEVELOPMENT_PATH(false)
	GLOBUS_DATA_CFLAGS='$(INSTALL_INCLUDE) $(GLOBUS_FTP_CONTROL_CFLAGS)'
	GLOBUS_DATA_LDFLAGS='$(GLOBUS_FTP_CONTROL_LDFLAGS)'
	GLOBUS_DATA_LIBS='$(INSTALL_LIBDIR) $(GLOBUS_FTP_CONTROL_LIBS)'
fi

AC_SUBST(GLOBUS_DATA_CFLAGS)
AC_SUBST(GLOBUS_DATA_LDFLAGS)
AC_SUBST(GLOBUS_DATA_LIBS)
])

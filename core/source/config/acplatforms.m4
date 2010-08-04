dnl
dnl Set TARGET_ARCH_*
dnl
AC_DEFUN([LAC_TARGET_ARCH],
[
GLOBUS_HOST=$host
AC_SUBST(GLOBUS_HOST)


case "$host" in
  *sunos5* | *solaris2* )
    AC_DEFINE(TARGET_ARCH_SOLARIS)
  ;;
  *-ibm-aix5* )
    AC_DEFINE(TARGET_ARCH_AIX)
    AC_DEFINE(TARGET_ARCH_AIX5)
  ;;
  *-*-hpux11*)
    AC_DEFINE(TARGET_ARCH_HPUX)
    AC_DEFINE(TARGET_ARCH_HPUX11)
  ;;
  *-*-hpux* )
    AC_DEFINE(TARGET_ARCH_HPUX)
  ;;
  i*86-*-linux* )
    AC_DEFINE(TARGET_ARCH_LINUX)
    AC_DEFINE(TARGET_ARCH_X86)
  ;;
  *x86_64-*linux* )
    AC_DEFINE(TARGET_ARCH_LINUX)
    AC_DEFINE(TARGET_ARCH_X86_64)
  ;;
  *ia64-*linux* )
    AC_DEFINE(TARGET_ARCH_LINUX)
    AC_DEFINE(TARGET_ARCH_IA64)
  ;;
  alpha*-linux* )
    AC_DEFINE(TARGET_ARCH_LINUX)
    AC_DEFINE(TARGET_ARCH_AXP)
  ;;
  *freebsd* )
    AC_DEFINE(TARGET_ARCH_FREEBSD)
    AC_DEFINE(TARGET_ARCH_BSD)
  ;;
  *-darwin* )
    AC_DEFINE(TARGET_ARCH_DARWIN)
    AC_DEFINE(TARGET_ARCH_BSD)
  ;;
  i*86-*-cygwin* )
    AC_DEFINE(TARGET_ARCH_CYGWIN)
    AC_DEFINE(TARGET_ARCH_X86)
  ;;
  sparc64-pc-linux-gnu )
    AC_DEFINE(TARGET_ARCH_LINUX)
  ;;
  *-*-linux* )
    AC_DEFINE(TARGET_ARCH_LINUX)
  ;;
  arm* )
    AC_DEFINE(TARGET_ARCH_NETOS)
    AC_DEFINE(TARGET_ARCH_ARM)
  ;;
  *mingw32* )
    AC_DEFINE(TARGET_ARCH_WIN32)
    AC_DEFINE(TARGET_ARCH_X86)
  ;;
  * )
	echo "platform not configured with TARGET_ARCH_*"
  ;;
esac
])


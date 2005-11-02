dnl
dnl Set TARGET_ARCH_*
dnl
AC_DEFUN([LAC_TARGET_ARCH],
[
GLOBUS_HOST=$host
AC_SUBST(GLOBUS_HOST)


case "$host" in
  *sunos4* | *solaris1* )
    AC_DEFINE(TARGET_ARCH_SUNOS41)
  ;;
  *sunos5* | *solaris2* )
    AC_DEFINE(TARGET_ARCH_SOLARIS)
  ;;
  *-ibm-aix3* )
    AC_DEFINE(TARGET_ARCH_AIX)
    AC_DEFINE(TARGET_ARCH_AIX3)
  ;;
  *-ibm-aix4* )
    AC_DEFINE(TARGET_ARCH_AIX)
    AC_DEFINE(TARGET_ARCH_AIX4)
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
  i860-intel-osf* )
    AC_DEFINE(TARGET_ARCH_PARAGON)
  ;;
  mips-sgi-irix5* )
    AC_DEFINE(TARGET_ARCH_SGI)
    AC_DEFINE(TARGET_ARCH_IRIX)
    AC_DEFINE(TARGET_ARCH_IRIX5)
  ;;
  mips-sgi-irix6* )
    AC_DEFINE(TARGET_ARCH_SGI)
    AC_DEFINE(TARGET_ARCH_IRIX)
    AC_DEFINE(TARGET_ARCH_IRIX6)
  ;;
  *dec* )
    AC_DEFINE(TARGET_ARCH_AXP)
    AC_DEFINE(TARGET_ARCH_OSF1)
    dnl --- more stuff to go here.. need to check with John
  ;;
  *c90* )
    AC_DEFINE(TARGET_ARCH_CRAYC90)
  ;;
  alpha-cray-unicosmk* | alphaev5-cray-unicosmk* | alphaev6-cray-unicosmk* )
    AC_DEFINE(TARGET_ARCH_CRAYT3E)
  ;;
  *SV1* )
    AC_DEFINE(TARGET_ARCH_CRAYSV1)
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
  *bsdi* )
    AC_DEFINE(TARGET_ARCH_BSDI)
    AC_DEFINE(TARGET_ARCH_BSD)
  ;;
  *nextstep* )
    AC_DEFINE(TARGET_ARCH_NEXTSTEP)
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
  * )
	echo "platform not configured with TARGET_ARCH_*"
  ;;
esac
])


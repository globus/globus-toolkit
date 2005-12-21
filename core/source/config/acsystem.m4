AC_DEFUN([CHECK_HEADERS], [

dnl
dnl System header files
dnl
AC_CHECK_HEADERS(pwd.h)
AC_CHECK_HEADERS(io.h)
AC_CHECK_HEADERS(netinet/in.h)
AC_CHECK_HEADERS(sys/socket.h)
AC_CHECK_HEADERS(libc.h)
AC_CHECK_HEADERS(malloc.h)
AC_CHECK_HEADERS(unistd.h)
AC_CHECK_HEADERS(stdarg.h)
AC_CHECK_HEADERS(netdb.h)
AC_CHECK_HEADERS(values.h)
AC_CHECK_HEADERS(getopt.h)
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS(sys/types.h)
AC_CHECK_HEADERS(proj.h)
AC_CHECK_HEADERS(sys/param.h)
AC_CHECK_HEADERS(sys/access.h)
AC_CHECK_HEADERS(sys/errno.h)
AC_CHECK_HEADERS(sys/sysmp.h)
AC_CHECK_HEADERS(sys/lwp.h)
AC_CHECK_HEADERS(sys/stat.h)
AC_CHECK_HEADERS(sys/file.h)
AC_CHECK_HEADERS(sys/uio.h)
AC_CHECK_HEADERS(sys/time.h)
AC_CHECK_HEADERS(sys/signal.h)
AC_CHECK_HEADERS(sys/select.h)
AC_CHECK_HEADERS(sys/cnx_pattr.h)
AC_CHECK_HEADERS(stdint.h)
AC_CHECK_HEADERS(sys/inttypes.h)
AC_CHECK_HEADERS(inttypes.h)
AC_CHECK_HEADERS(dce/cma.h)
AC_CHECK_HEADERS(dce/cma_ux.h)
AC_CHECK_HEADERS(sys/param.h)
AC_CHECK_HEADERS(limits.h)
AC_CHECK_HEADERS(sys/limits.h)
AC_CHECK_HEADERS(string.h)
AC_CHECK_HEADERS(ctype.h)
AC_CHECK_HEADERS(fcntl.h)
AC_CHECK_HEADERS(utime.h)
AC_CHECK_HEADERS(arpa/inet.h)
AC_CHECK_HEADERS(net/if_arp.h)
AC_CHECK_HEADERS(net/if_dl.h)
AC_CHECK_HEADERS(ifaddrs.h)
AC_CHECK_HEADERS(sys/ioctl.h)
AC_CHECK_HEADERS(net/if.h)
AC_CHECK_HEADERS(signal.h)
AC_CHECK_HEADERS(syslog.h)

dnl these are Net+OS headers
AC_CHECK_HEADERS(sockapi.h)
AC_CHECK_HEADERS(tx_api.h)

dnl Broken IRIX 6.5.3 headers
case $target in
    *irix*6.*)
        AC_DEFINE(HAVE_NETINET_TCP_H)
        ac_cv_header_netinet_tcp_h=1
	;;
    *)
       AC_CHECK_HEADERS(netinet/tcp.h)
       ;;
esac

AC_HEADER_SYS_WAIT
dnl
dnl System types
dnl
AC_CHECK_TYPE(ssize_t, int)
AC_CHECK_TYPE(size_t, unsigned int)
AC_TYPE_SIGNAL
AC_HEADER_DIRENT

AC_MSG_CHECKING(for DIR)
AC_TRY_COMPILE([
#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif
],
[
DIR * x;
],
ac_have_DIR=yes,
ac_have_DIR=no)

if test "$ac_have_DIR" = "yes"; then
    AC_DEFINE(HAVE_DIR, 1, [DIR found])
else
    AC_MSG_RESULT([DIR not found])
fi


AC_MSG_CHECKING(for socklen_t)
AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
],
[
socklen_t len = 1;
return 0;
],
ac_have_socklen_t=yes,
ac_have_socklen_t=no)

if test "$ac_have_socklen_t" = "yes"; then
  AC_DEFINE(HAVE_SOCKLEN_T, 1, [socklen_t found])
fi
AC_MSG_RESULT($ac_have_socklen_t)

])

AC_DEFUN([CHECK_FUNCS], [
dnl
dnl System function
dnl
AC_CHECK_FUNCS(waitpid)
AC_CHECK_FUNCS(strtoul)
AC_CHECK_FUNCS(wait3)
dnl AC_FUNC_WAIT3
AC_CHECK_FUNCS(sighold)
AC_CHECK_FUNCS(sigblock)
AC_CHECK_FUNCS(sigset)
AC_CHECK_FUNCS(getwd)
AC_CHECK_FUNCS(getcwd)
AC_CHECK_FUNCS(memmove)
AC_CHECK_FUNCS(usleep)
AC_CHECK_FUNCS(strptime)
AC_CHECK_FUNCS(gethostbyaddr)
AC_CHECK_FUNCS(getservbyname)
AC_CHECK_FUNCS(getprotobynumber)
AC_CHECK_FUNCS(getaddrinfo)
AC_CHECK_FUNCS(freeaddrinfo)
AC_CHECK_FUNCS(getnameinfo)
AC_CHECK_FUNCS(opendir)
AC_CHECK_FUNCS(closedir)
AC_CHECK_FUNCS(telldir)
AC_CHECK_FUNCS(seekdir)
AC_CHECK_FUNCS(readdir)
AC_CHECK_FUNCS(rewinddir)
AC_CHECK_FUNCS(nrand48)
AC_CHECK_FUNCS(mktime)
AC_CHECK_FUNCS(writev)
AC_CHECK_FUNCS(readv)
AC_CHECK_FUNCS(strerror)
AC_CHECK_FUNCS(gai_strerror)
AC_CHECK_FUNCS(gethostname)
AC_CHECK_FUNCS(inet_ntoa)
AC_CHECK_FUNCS(inet_pton)
AC_CHECK_FUNCS(inet_addr)
AC_CHECK_FUNCS(fork)
AC_CHECK_FUNCS(sigaction)
AC_CHECK_FUNCS(sendmsg)
AC_CHECK_FUNCS(recvmsg)
AC_CHECK_FUNCS(geteuid)
AC_CHECK_FUNCS(getpwnam)
AC_CHECK_FUNCS(getpwuid)

dnl used in RSL
AC_FUNC_ALLOCA

AC_CHECK_FUNCS(poll)

])

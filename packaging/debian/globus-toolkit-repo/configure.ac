AC_INIT([globus-toolkit-repo], [6])

AM_INIT_AUTOMAKE([foreign])

releases="squeeze,wheezy,lucid,precise,quantal,saucy"

AC_ARG_WITH([releases],
    [AS_HELP_STRING([--with-releases=RELEASE,...],
    [Create repository configuration for RELEASE])],
    [if test x"$releases" != "xno" && test x"$releases" != "xyes";  then
        releases="$withval"
    fi])

oldifs="$IFS"
IFS=","
for release in $releases
do
    stable_lists="${stable_lists:+$stable_lists }globus-toolkit-6-stable-${release}.list"
    testing_lists="${testing_lists:+$testing_lists }globus-toolkit-6-testing-${release}.list"
    unstable_lists="${unstable_lists:+$unstable_lists }globus-toolkit-6-unstable-${release}.list"
done
IFS="$oldifs"

AC_SUBST([RELEASES], ["$releases"])
AC_SUBST([STABLE_LISTS], ["$stable_lists"])
AC_SUBST([TESTING_LISTS], ["$testing_lists"])
AC_SUBST([UNSTABLE_LISTS], ["$unstable_lists"])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

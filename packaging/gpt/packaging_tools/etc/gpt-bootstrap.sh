#!/bin/sh
error()
{
    echo ""
    echo "ERROR: bootstrap failed!"
    echo ""
    exit 1
}

# Always include globus macros
config="$aclocal_includes"

# test for local macros
if test -d "./config"; then
    config="$config -I ./config"
fi

# test to see if GPT macros are in a seperate location
if test ! -f "${GPT_LOCATION:=$GLOBUS_LOCATION}/share/globus/aclocal/gpt_autoconf_macros.m4"; then
    echo "ERROR Globus Packaging Tools not found" >&2
    echo "ERROR either set GPT_LOCATION or install them in $GLOBUS_LOCATION" >&2
    exit 1
else
    config="$config -I $GPT_LOCATION/share/globus/aclocal"
fi

if test ! -h pkgdata/Makefile.am ; then
    echo "installing Makefile.am in the pkgdata directory"
    ln -s $GPT_LOCATION/share/globus/amdir/pkgdata_Makefile.am \
    pkgdata/Makefile.am
fi

echo "running aclocal $config"
aclocal $config || error

if test -f acconfig.h ; then
echo "running autoheader"
    autoheader || error
fi

OLDIFS="$IFS"
IFS="
"
for x in `echo "${PATH}" | tr ":" "\n"`; do
    if test -x "$x/libtoolize"; then
        libtoolize=libtoolize
        break
    elif test -x "$x/glibtoolize"; then
        libtoolize=glibtoolize
        break
    fi
done
IFS="$OLDIFS"

echo "running libtoolize --copy --force"
$libtoolize --copy --force || \
  $libtoolize --copy --force || error

echo "Running gpt-to-pkgconfig"
$GPT_LOCATION/sbin/gpt-to-pkgconfig pkgdata/pkg_data_src.gpt.in || error

echo "running automake --copy -add-missing --force-missing --foreign"
automake --copy --add-missing --force-missing --foreign || \
  automake --copy --add-missing --force-missing --foreign || error

echo "running gpt_create_automake_rules --excludes=doxygen"
$GPT_LOCATION/sbin/gpt_create_automake_rules --excludes=doxygen || error

echo "running autoconf"
autoconf || error


